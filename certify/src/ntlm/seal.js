// NTLM message confidentiality (sign + seal) on top of the NTLMv2 auth in
// ntlm.js. ADWS runs over .NET NegotiateStream (MS-NNS), which — unlike the
// LDAP GSS-SPNEGO bind in the adidns tool — REQUIRES every post-auth message to
// be signed and sealed. The key-derivation and SEAL/MAC here mirror impacket's
// ntlm.py (SIGNKEY / SEALKEY / SEAL / MAC), which in turn implements MS-NLMP
// §3.4.5 (key derivation) and §3.4.4 (message signature).

import { md5, hmacMd5 } from '../crypto/md5.js';
import { Rc4, rc4 } from '../crypto/rc4.js';
import { concat } from '../ldap/ber.js';
import {
  utf16le, computeNtlmv2Response, nowFiletime, randomClientChallenge,
} from './ntlm.js';

const enc = new TextEncoder();
const SIGNATURE = Uint8Array.of(0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00); // "NTLMSSP\0"

// Negotiate flags. We always drive Extended Session Security + Key Exchange +
// 128-bit, with SEAL/SIGN, so the derived keys and MAC take the ESS+KEY_EXCH
// path (the only one ADWS accepts).
export const NF = {
  UNICODE: 0x00000001,
  REQUEST_TARGET: 0x00000004,
  SIGN: 0x00000010,
  SEAL: 0x00000020,
  NTLM: 0x00000200,
  ALWAYS_SIGN: 0x00008000,
  EXTENDED_SESSIONSECURITY: 0x00080000,
  TARGET_INFO: 0x00800000,
  KEY_EXCH: 0x40000000,
  N128: 0x20000000,
  N56: 0x80000000,
};

// The negotiate-flag set advertised in our NEGOTIATE and AUTHENTICATE messages.
export const NEGOTIATE_FLAGS =
  NF.UNICODE | NF.REQUEST_TARGET | NF.SIGN | NF.SEAL | NF.NTLM |
  NF.ALWAYS_SIGN | NF.EXTENDED_SESSIONSECURITY | NF.TARGET_INFO |
  NF.KEY_EXCH | NF.N128 | (NF.N56 >>> 0);

function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function field(len, offset) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setUint16(0, len, true);
  dv.setUint16(2, len, true);
  dv.setUint32(4, offset, true);
  return b;
}

// NEGOTIATE (type 1) advertising sign+seal.
export function buildNegotiate() {
  return concat([
    SIGNATURE, u32le(1), u32le(NEGOTIATE_FLAGS),
    field(0, 0), // DomainName
    field(0, 0), // Workstation
  ]);
}

// AUTHENTICATE (type 3) with key exchange. Generates a random ExportedSessionKey,
// wraps it under the NTLMv2 KeyExchangeKey (= SessionBaseKey), and returns the
// session key so the caller can derive sign/seal keys.
export function buildAuthenticate({ user, domain, password, type2, workstation = '', exportedSessionKey }) {
  const clientChallenge = randomClientChallenge();
  const timestamp = type2.timestamp || nowFiletime();
  const resp = computeNtlmv2Response(
    user, domain, password,
    type2.serverChallenge, clientChallenge, timestamp, type2.targetInfo,
  );
  // NTLMv2 KeyExchangeKey == SessionBaseKey.
  const keyExchangeKey = resp.sessionBaseKey;
  const sessionKey = exportedSessionKey || randomClientChallenge16();
  const encryptedRandomSessionKey = rc4(keyExchangeKey, sessionKey);

  const domainB = utf16le(domain || '');
  const userB = utf16le(user || '');
  const wsB = utf16le(workstation || '');
  const lm = resp.lmChallengeResponse;
  const nt = resp.ntChallengeResponse;

  const HEADER = 64;
  let off = HEADER;
  const lmField = field(lm.length, off); off += lm.length;
  const ntField = field(nt.length, off); off += nt.length;
  const domainField = field(domainB.length, off); off += domainB.length;
  const userField = field(userB.length, off); off += userB.length;
  const wsField = field(wsB.length, off); off += wsB.length;
  const skField = field(encryptedRandomSessionKey.length, off); off += encryptedRandomSessionKey.length;

  const type3 = concat([
    SIGNATURE, u32le(3),
    lmField, ntField, domainField, userField, wsField, skField,
    u32le(NEGOTIATE_FLAGS),
    lm, nt, domainB, userB, wsB, encryptedRandomSessionKey,
  ]);
  return { type3, exportedSessionKey: sessionKey };
}

function randomClientChallenge16() {
  const b = new Uint8Array(16);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return b;
}

// ---- Key derivation (MS-NLMP §3.4.5.2 / §3.4.5.3, ESS path) ----------------

function signKey(sessionKey, mode) {
  const magic = mode === 'client'
    ? 'session key to client-to-server signing key magic constant\0'
    : 'session key to server-to-client signing key magic constant\0';
  return md5(concat([sessionKey, enc.encode(magic)]));
}

function sealKey(sessionKey, mode) {
  // NEGOTIATE_128 -> full 16-byte session key feeds the seal-key MD5.
  const magic = mode === 'client'
    ? 'session key to client-to-server sealing key magic constant\0'
    : 'session key to server-to-client sealing key magic constant\0';
  return md5(concat([sessionKey, enc.encode(magic)]));
}

// A live NTLM security session: holds per-direction sign keys, RC4 seal handles
// and sequence numbers, and seals/unseals NNS data payloads.
export class NtlmSession {
  // role 'client' (default) sends with the client-to-server keys and receives
  // with the server-to-client keys; role 'server' is the mirror (used in tests
  // to model the peer for round-trip verification).
  constructor(exportedSessionKey, role = 'client') {
    this.clientSignKey = signKey(exportedSessionKey, 'client');
    this.serverSignKey = signKey(exportedSessionKey, 'server');
    this.clientSeal = new Rc4(sealKey(exportedSessionKey, 'client'));
    this.serverSeal = new Rc4(sealKey(exportedSessionKey, 'server'));
    if (role === 'server') {
      this._sendKey = this.serverSignKey; this._sendSeal = this.serverSeal;
      this._recvKey = this.clientSignKey; this._recvSeal = this.clientSeal;
    } else {
      this._sendKey = this.clientSignKey; this._sendSeal = this.clientSeal;
      this._recvKey = this.serverSignKey; this._recvSeal = this.serverSeal;
    }
    this.sendSeq = 0;
    this.recvSeq = 0;
  }

  // MAC over plaintext with the ESS + KEY_EXCH path: the 8-byte HMAC checksum is
  // itself RC4-sealed by the same handle that just sealed the message, so the
  // keystream continues message-bytes -> checksum-bytes.
  _mac(handle, signKeyBytes, seq, plaintext) {
    const hmac = hmacMd5(signKeyBytes, concat([u32le(seq), plaintext])).slice(0, 8);
    const checksum = handle.update(hmac);
    return concat([u32le(1), checksum, u32le(seq)]); // Version=1, Checksum, SeqNum
  }

  // Returns the NNS data-frame payload: signature(16) || sealedMessage.
  seal(plaintext) {
    const sealed = this._sendSeal.update(plaintext);
    const sig = this._mac(this._sendSeal, this._sendKey, this.sendSeq, plaintext);
    this.sendSeq = (this.sendSeq + 1) >>> 0;
    return concat([sig, sealed]);
  }

  // RPC packet-privacy (MS-RPCE): encrypt `toEncrypt` (the stub + auth pad) but
  // MAC over `toSign` (the whole PDU minus the 16-byte signature — header,
  // request fields, plaintext stub+pad and sec_trailer). Returns { sealed, signature }.
  sealRpc(toEncrypt, toSign) {
    const sealed = this._sendSeal.update(toEncrypt);
    const hmac = hmacMd5(this._sendKey, concat([u32le(this.sendSeq), toSign])).slice(0, 8);
    const checksum = this._sendSeal.update(hmac);
    const signature = concat([u32le(1), checksum, u32le(this.sendSeq)]);
    this.sendSeq = (this.sendSeq + 1) >>> 0;
    return { sealed, signature };
  }

  // RPC: decrypt a sealed response payload. The server's MAC is not re-verified
  // (single request/response), we just advance the receive cipher.
  decryptRpc(cipher) { return this._recvSeal.update(cipher); }

  // Takes an NNS data-frame payload (signature(16) || cipherText) and returns
  // the verified plaintext. Throws if the recomputed signature mismatches.
  unseal(payload) {
    const wireSig = payload.subarray(0, 16);
    const cipher = payload.subarray(16);
    const plaintext = this._recvSeal.update(cipher);
    const expected = this._mac(this._recvSeal, this._recvKey, this.recvSeq, plaintext);
    this.recvSeq = (this.recvSeq + 1) >>> 0;
    if (!eq(wireSig, expected)) {
      throw new Error('NTLM signature verification failed (channel out of sync or tampered)');
    }
    return plaintext;
  }
}

function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
