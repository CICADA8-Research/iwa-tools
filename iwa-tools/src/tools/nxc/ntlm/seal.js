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
  VERSION: 0x02000000,
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
  const flagsWithVer = (NEGOTIATE_FLAGS | NF.VERSION) >>> 0;
  const versionBlock = new Uint8Array([10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
  return concat([
    SIGNATURE, u32le(1), u32le(flagsWithVer),
    field(0, 0),
    field(0, 0),
    versionBlock,
  ]);
}

// If the challenge contains an MsvAvTimestamp (AV id 7), insert MsvAvFlags
// (id 6) with value 0x00000002 before the EOL — per MS-NLMP §3.2.5.1.2 this
// signals the server that a MIC follows in the AUTHENTICATE message.
function extendTargetInfoForMic(targetInfo) {
  if (!targetInfo || targetInfo.length < 4) return { info: targetInfo, needMic: false };
  const dv = new DataView(targetInfo.buffer, targetInfo.byteOffset, targetInfo.byteLength);
  let hasTimestamp = false;
  let p = 0;
  let eolPos = -1;
  while (p + 4 <= targetInfo.length) {
    const id = dv.getUint16(p, true);
    const len = dv.getUint16(p + 2, true);
    if (id === 7) hasTimestamp = true;
    if (id === 0) { eolPos = p; break; }
    p += 4 + len;
  }
  if (!hasTimestamp || eolPos < 0) return { info: targetInfo, needMic: false };
  const flagsAv = Uint8Array.of(0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00);
  const info = concat([
    targetInfo.subarray(0, eolPos),
    flagsAv,
    targetInfo.subarray(eolPos),
  ]);
  return { info, needMic: true };
}

// AUTHENTICATE (type 3) with key exchange. Generates a random ExportedSessionKey,
// wraps it under the NTLMv2 KeyExchangeKey (= SessionBaseKey), and returns the
// session key so the caller can derive sign/seal keys.
//
// When `negotiateMessage` and `challengeMessage` are supplied AND the challenge
// contained MsvAvTimestamp, this also emits a MIC (16-byte HMAC_MD5 over
// NEG||CHAL||AUTH with MIC=0) that modern Windows servers require.
export function buildAuthenticate({
  user, domain, password, hash, type2, workstation = '', exportedSessionKey,
  negotiateMessage, challengeMessage,
}) {
  const clientChallenge = randomClientChallenge();
  const timestamp = type2.timestamp || nowFiletime();

  // Only extend targetInfo with MsvAvFlags when we're going to emit a MIC.
  // Otherwise the server sees "MIC follows" but finds none and rejects auth.
  const canComputeMic = !!(negotiateMessage && challengeMessage);
  const { info: effectiveTargetInfo, needMic: micNeeded } = canComputeMic
    ? extendTargetInfoForMic(type2.targetInfo || new Uint8Array(0))
    : { info: type2.targetInfo || new Uint8Array(0), needMic: false };
  const emitMic = canComputeMic && micNeeded;

  const resp = computeNtlmv2Response(
    user, domain, password,
    type2.serverChallenge, clientChallenge, timestamp, effectiveTargetInfo,
    hash,
  );
  const keyExchangeKey = resp.sessionBaseKey;
  const sessionKey = exportedSessionKey || randomClientChallenge16();
  const encryptedRandomSessionKey = rc4(keyExchangeKey, sessionKey);

  const domainB = utf16le(domain || '');
  const userB = utf16le(user || '');
  const wsB = utf16le(workstation || '');
  const lm = resp.lmChallengeResponse;
  const nt = resp.ntChallengeResponse;

  const HEADER = emitMic ? 88 : 64;
  let off = HEADER;
  const lmField = field(lm.length, off); off += lm.length;
  const ntField = field(nt.length, off); off += nt.length;
  const domainField = field(domainB.length, off); off += domainB.length;
  const userField = field(userB.length, off); off += userB.length;
  const wsField = field(wsB.length, off); off += wsB.length;
  const skField = field(encryptedRandomSessionKey.length, off); off += encryptedRandomSessionKey.length;

  // If we're emitting Version+MIC blocks, we MUST advertise NEGOTIATE_VERSION
  // in NegotiateFlags per MS-NLMP §3.1.5.1.1, otherwise the server treats the
  // Version bytes as junk / misplaces the payload.
  const effectiveFlags = (emitMic ? (NEGOTIATE_FLAGS | NF.VERSION) : NEGOTIATE_FLAGS) >>> 0;

  const parts = [
    SIGNATURE, u32le(3),
    lmField, ntField, domainField, userField, wsField, skField,
    u32le(effectiveFlags),
  ];
  if (emitMic) {
    // VERSION per MS-NLMP §2.2.2.10: ProductMajor(1)=10, ProductMinor(1)=0,
    // ProductBuild(2 LE)=19041, Reserved(3)=0, NTLMRevisionCurrent(1)=0x0F.
    const versionBlock = new Uint8Array([10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
    parts.push(versionBlock);
    parts.push(new Uint8Array(16));
  }
  parts.push(lm, nt, domainB, userB, wsB, encryptedRandomSessionKey);
  const type3 = concat(parts);

  if (emitMic) {
    const micOffset = 72;
    const mic = hmacMd5(sessionKey, concat([negotiateMessage, challengeMessage, type3]));
    type3.set(mic.subarray(0, 16), micOffset);
  }

  return { type3, exportedSessionKey: sessionKey, micUsed: emitMic };
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

  // WinRM message-encryption shape: the NTLM signature is always 16 bytes, so
  // the on-the-wire <sigLen><signature||cipher> uses sigLen=16. Uniform with
  // KerberosSession.wrapForHttp so crypt.js carries either SSP.
  wrapForHttp(plaintext) {
    return { sigLen: 16, blob: this.seal(plaintext) };
  }

  // MS-RPCE PKT_PRIVACY. Options:
  //   macFirst=true  → MAC then SEAL (impacket spec order, ks[0..7] for
  //                     checksum, ks[8..N+7] for cipher)
  //   macFirst=false → SEAL then MAC (WinRM order)
  //   signInput      → override the HMAC input (e.g. to include preamble)
  sealRpc(encPlain, { signInput, macFirst = false } = {}) {
    const macInput = signInput || encPlain;
    let sig, sealed;
    if (macFirst) {
      sig = this._mac(this._sendSeal, this._sendKey, this.sendSeq, macInput);
      sealed = this._sendSeal.update(encPlain);
    } else {
      sealed = this._sendSeal.update(encPlain);
      sig = this._mac(this._sendSeal, this._sendKey, this.sendSeq, macInput);
    }
    this.sendSeq = (this.sendSeq + 1) >>> 0;
    return { sig, sealed };
  }

  // Reverse of sealRpc. `signInputBuilder` gets called with recovered plaintext
  // and must return the bytes the peer signed (typically full PDU minus 16-byte
  // sig, with the sealed stub replaced by the plaintext).
  //   macFirst=true  → skip 8 keystream bytes, decrypt, verify sig
  //   macFirst=false → decrypt, verify sig (SEAL-first per impacket)
  unsealRpc(sealedStub, wireSig, { signInputBuilder, secTrailerPreamble, macFirst = false } = {}) {
    let plaintext, expectedEnc;
    if (macFirst) {
      const ksForMac = this._recvSeal.update(new Uint8Array(8));
      plaintext = this._recvSeal.update(sealedStub);
      const macInput = signInputBuilder
        ? signInputBuilder(plaintext)
        : (secTrailerPreamble ? concat([plaintext, secTrailerPreamble]) : plaintext);
      const hmac = hmacMd5(this._recvKey, concat([u32le(this.recvSeq), macInput])).slice(0, 8);
      expectedEnc = new Uint8Array(8);
      for (let i = 0; i < 8; i++) expectedEnc[i] = hmac[i] ^ ksForMac[i];
    } else {
      plaintext = this._recvSeal.update(sealedStub);
      const macInput = signInputBuilder
        ? signInputBuilder(plaintext)
        : (secTrailerPreamble ? concat([plaintext, secTrailerPreamble]) : plaintext);
      const hmac = hmacMd5(this._recvKey, concat([u32le(this.recvSeq), macInput])).slice(0, 8);
      expectedEnc = this._recvSeal.update(hmac);
    }
    this.recvSeq = (this.recvSeq + 1) >>> 0;
    const wireEnc = wireSig.subarray(4, 12);
    if (!eq(expectedEnc, wireEnc)) {
      throw new Error('NTLM signature verification failed (RPC seal channel out of sync or tampered)');
    }
    return plaintext;
  }

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
