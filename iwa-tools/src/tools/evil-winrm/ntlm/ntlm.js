// NTLM (NTLMSSP) message construction and NTLMv2 response computation, per
// [MS-NLMP]. Stage 1: authentication only — no message signing or sealing.
// The NTLMv2 maths mirrors impacket's ntlm.py (computeResponseNTLMv2).

import { md4 } from '../crypto/md4.js';
import { hmacMd5 } from '../crypto/md5.js';
import { concat } from '../ldap/ber.js';

const SIGNATURE = Uint8Array.of(0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00); // "NTLMSSP\0"

// NTLMSSP negotiate flags (subset we use).
export const FLAG = {
  UNICODE: 0x00000001,
  OEM: 0x00000002,
  REQUEST_TARGET: 0x00000004,
  NTLM: 0x00000200,
  ALWAYS_SIGN: 0x00008000,
  EXTENDED_SESSIONSECURITY: 0x00080000, // a.k.a. NTLM2
  TARGET_INFO: 0x00800000,
};

// AV_PAIR ids inside a CHALLENGE target-info block.
const AV_EOL = 0x0000;
const AV_TIMESTAMP = 0x0007;

export function utf16le(str) {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = (c >> 8) & 0xff;
  }
  return out;
}

// The NT hash = MD4(UTF16LE(password)). For pass-the-hash this is supplied
// directly instead of a password.
export function nthash(password) {
  return md4(utf16le(password));
}

// NTOWFv2 = HMAC_MD5(NThash, UTF16LE(Uppercase(user) + domain)).
export function ntowfv2(user, domain, password) {
  return ntowfv2FromHash(user, domain, nthash(password));
}
export function ntowfv2FromHash(user, domain, ntHash) {
  return hmacMd5(ntHash, utf16le(user.toUpperCase() + domain));
}

// Compute the NTLMv2 and LMv2 responses given the pieces taken from the
// server CHALLENGE. `secret` is either a password string or a 16-byte NT-hash
// Uint8Array (pass-the-hash). `timestamp`, `serverChallenge`, `clientChallenge`
// are Uint8Arrays (8 bytes); `targetInfo` is the raw AV_PAIR block.
export function computeNtlmv2Response(
  user, domain, secret, serverChallenge, clientChallenge, timestamp, targetInfo,
) {
  const responseKey = secret instanceof Uint8Array
    ? ntowfv2FromHash(user, domain, secret)
    : ntowfv2(user, domain, secret);
  const temp = concat([
    Uint8Array.of(0x01, 0x01, 0, 0, 0, 0, 0, 0), // RespType, HiRespType, Z(6)
    timestamp,                                    // 8 bytes
    clientChallenge,                              // 8 bytes
    Uint8Array.of(0, 0, 0, 0),                    // Z(4)
    targetInfo,                                   // ServerName (AV pairs)
    Uint8Array.of(0, 0, 0, 0),                    // Z(4)
  ]);
  const ntProofStr = hmacMd5(responseKey, concat([serverChallenge, temp]));
  const ntChallengeResponse = concat([ntProofStr, temp]);
  const sessionBaseKey = hmacMd5(responseKey, ntProofStr);
  const lmProof = hmacMd5(responseKey, concat([serverChallenge, clientChallenge]));
  const lmChallengeResponse = concat([lmProof, clientChallenge]);
  return { ntProofStr, ntChallengeResponse, sessionBaseKey, lmChallengeResponse };
}

function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

// 8-byte field descriptor: len, maxLen, offset.
function field(len, offset) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setUint16(0, len, true);
  dv.setUint16(2, len, true);
  dv.setUint32(4, offset, true);
  return b;
}

// NEGOTIATE (type 1). No signing/sealing flags so the server does not expect
// a sealed security layer on subsequent traffic.
export function buildType1() {
  const flags = FLAG.UNICODE | FLAG.REQUEST_TARGET | FLAG.NTLM
    | FLAG.EXTENDED_SESSIONSECURITY | FLAG.ALWAYS_SIGN;
  return concat([
    SIGNATURE,
    u32le(1),
    u32le(flags),
    field(0, 0), // DomainName
    field(0, 0), // Workstation
  ]);
}

// Parse a CHALLENGE (type 2): extract the server challenge, negotiate flags
// and the target-info AV block (and timestamp if present).
export function parseType2(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const messageType = dv.getUint32(8, true);
  if (messageType !== 2) throw new Error(`expected NTLM CHALLENGE, got message type ${messageType}`);
  const flags = dv.getUint32(20, true);
  const serverChallenge = buf.slice(24, 32);
  const tiLen = dv.getUint16(40, true);
  const tiOffset = dv.getUint32(44, true);
  const targetInfo = tiLen ? buf.slice(tiOffset, tiOffset + tiLen) : new Uint8Array(0);

  let timestamp = null;
  let pos = 0;
  while (pos + 4 <= targetInfo.length) {
    const id = targetInfo[pos] | (targetInfo[pos + 1] << 8);
    const len = targetInfo[pos + 2] | (targetInfo[pos + 3] << 8);
    if (id === AV_EOL) break;
    if (id === AV_TIMESTAMP && len === 8) timestamp = targetInfo.slice(pos + 4, pos + 12);
    pos += 4 + len;
  }
  return { serverChallenge, flags, targetInfo, timestamp };
}

// Current time as a Windows FILETIME (100ns ticks since 1601-01-01), 8 bytes LE.
export function nowFiletime() {
  const ticks = (BigInt(Date.now()) + 11644473600000n) * 10000n;
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, ticks, true);
  return b;
}

// AUTHENTICATE (type 3). No EncryptedRandomSessionKey / MIC in stage 1.
export function buildType3({ domain, user, workstation = '', ntResponse, lmResponse }) {
  const flags = FLAG.UNICODE | FLAG.REQUEST_TARGET | FLAG.NTLM | FLAG.EXTENDED_SESSIONSECURITY;
  const domainB = utf16le(domain);
  const userB = utf16le(user);
  const wsB = utf16le(workstation);

  const HEADER = 64; // 8 sig + 4 type + 6*8 fields + 4 flags
  let off = HEADER;
  const lmField = field(lmResponse.length, off); off += lmResponse.length;
  const ntField = field(ntResponse.length, off); off += ntResponse.length;
  const domainField = field(domainB.length, off); off += domainB.length;
  const userField = field(userB.length, off); off += userB.length;
  const wsField = field(wsB.length, off); off += wsB.length;
  const sessionKeyField = field(0, off);

  return concat([
    SIGNATURE,
    u32le(3),
    lmField, ntField, domainField, userField, wsField, sessionKeyField,
    u32le(flags),
    lmResponse, ntResponse, domainB, userB, wsB,
  ]);
}

export function randomClientChallenge() {
  const b = new Uint8Array(8);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return b;
}
