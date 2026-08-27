// DPAPI blob decryption (MS-BKRP / CryptUnprotectData).
// Given a plaintext master key, decrypts DPAPI blobs found in credential files,
// WiFi profiles, and other Windows secrets.

import { concat } from '../ldap/ber.js';
import { sha1, hmacSha1 } from './sha1.js';
import { sha256 } from './sha256.js';
import { Aes } from './aes.js';
import { desEncrypt, desDecrypt } from './des.js';

// ---- 3DES-CBC ---------------------------------------------------------------

function des3CbcDecrypt(key24, iv, data) {
  const k1 = key24.subarray(0, 8);
  const k2 = key24.subarray(8, 16);
  const k3 = key24.subarray(16, 24);
  const out = new Uint8Array(data.length);
  let prev = new Uint8Array(iv);
  for (let i = 0; i < data.length; i += 8) {
    const block = data.subarray(i, i + 8);
    const d3 = desDecrypt(k3, block);
    const e2 = desEncrypt(k2, d3);
    const d1 = desDecrypt(k1, e2);
    for (let j = 0; j < 8; j++) out[i + j] = d1[j] ^ prev[j];
    prev = new Uint8Array(block);
  }
  return out;
}

// ---- AES-256-CBC ------------------------------------------------------------

function aesCbcDecrypt(key, iv, data) {
  const aes = new Aes(key);
  const out = new Uint8Array(data.length);
  let prev = new Uint8Array(iv);
  for (let i = 0; i < data.length; i += 16) {
    const block = data.subarray(i, i + 16);
    const plain = aes.decryptBlock(block);
    for (let j = 0; j < 16; j++) out[i + j] = plain[j] ^ prev[j];
    prev = new Uint8Array(block);
  }
  return out;
}

function unpad(data) {
  if (data.length === 0) return data;
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) return data;
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) return data;
  }
  return data.subarray(0, data.length - pad);
}

// ---- GUID -------------------------------------------------------------------

function guidToString(buf, offset) {
  const dv = new DataView(buf.buffer, buf.byteOffset + offset);
  const d1 = dv.getUint32(0, true).toString(16).padStart(8, '0');
  const d2 = dv.getUint16(4, true).toString(16).padStart(4, '0');
  const d3 = dv.getUint16(6, true).toString(16).padStart(4, '0');
  let d4 = '';
  for (let i = 8; i < 16; i++) d4 += buf[offset + i].toString(16).padStart(2, '0');
  return `${d1}-${d2}-${d3}-${d4.slice(0, 4)}-${d4.slice(4)}`;
}

// ---- DPAPI algorithms -------------------------------------------------------

const CALG_3DES = 0x6603;
const CALG_AES_256 = 0x6610;
const CALG_SHA1 = 0x8004;
const CALG_SHA256 = 0x800E;
const CALG_SHA512 = 0x800F;

// MS CryptDeriveKey: XOR-based key expansion from a hash value
function cryptDeriveKey(hashValue, hashFn, blockLen = 64) {
  const ipad = new Uint8Array(blockLen);
  const opad = new Uint8Array(blockLen);
  for (let i = 0; i < blockLen; i++) {
    const b = i < hashValue.length ? hashValue[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }
  return concat([hashFn(ipad), hashFn(opad)]);
}

// ---- DPAPI blob parsing + decryption ----------------------------------------

export function parseDpapiBlob(data) {
  if (data.length < 60) throw new Error('DPAPI blob too short');
  const dv = new DataView(data.buffer, data.byteOffset);
  let off = 0;

  const version = dv.getUint32(off, true); off += 4;
  const provider = guidToString(data, off); off += 16;
  const mkVersion = dv.getUint32(off, true); off += 4;
  const masterKeyGuid = guidToString(data, off); off += 16;
  const flags = dv.getUint32(off, true); off += 4;

  const descLen = dv.getUint32(off, true); off += 4;
  const description = descLen > 0
    ? new TextDecoder('utf-16le').decode(data.subarray(off, off + descLen))
    : '';
  off += descLen;

  const algCrypt = dv.getUint32(off, true); off += 4;
  const algCryptLen = dv.getUint32(off, true); off += 4;
  const saltLen = dv.getUint32(off, true); off += 4;
  const salt = data.slice(off, off + saltLen); off += saltLen;

  const hmacKeyLen = dv.getUint32(off, true); off += 4;
  const hmacKey = data.slice(off, off + hmacKeyLen); off += hmacKeyLen;

  const algHash = dv.getUint32(off, true); off += 4;
  const algHashLen = dv.getUint32(off, true); off += 4;
  const hmacLen = dv.getUint32(off, true); off += 4;
  const hmac = data.slice(off, off + hmacLen); off += hmacLen;

  const cipherLen = dv.getUint32(off, true); off += 4;
  const cipherText = data.slice(off, off + cipherLen);

  return {
    version, provider, mkVersion, masterKeyGuid, flags,
    description: description.replace(/\0+$/, ''),
    algCrypt, algCryptLen, salt, hmacKey, algHash, algHashLen,
    hmac, cipherText,
  };
}

function selectHash(algHash) {
  if (algHash === CALG_SHA256) return { fn: sha256, len: 32 };
  if (algHash === CALG_SHA512) throw new Error('SHA-512 not implemented');
  return { fn: sha1, len: 20 };
}

function selectHmac(algHash) {
  if (algHash === CALG_SHA256) return (k, d) => hmacSha256(k, d);
  if (algHash === CALG_SHA512) throw new Error('SHA-512 HMAC not implemented');
  return hmacSha1;
}

// hmacSha256 built from sha256
function hmacSha256(key, data) {
  let k = key;
  if (k.length > 64) k = sha256(k);
  const kp = new Uint8Array(64);
  kp.set(k);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = kp[i] ^ 0x36; opad[i] = kp[i] ^ 0x5c; }
  return sha256(concat([opad, sha256(concat([ipad, data]))]));
}

export function decryptDpapiBlob(blob, masterKey, entropy = null) {
  const { fn: hashFn } = selectHash(blob.algHash);
  const hmacFn = selectHmac(blob.algHash);

  const derivedBlob = hmacFn(masterKey, concat([blob.hmacKey, blob.salt]));
  let cryptoKey = cryptDeriveKey(derivedBlob, hashFn);

  if (entropy) {
    cryptoKey = hmacFn(cryptoKey.subarray(0, hashFn(new Uint8Array(0)).length), entropy);
  }

  let plaintext;
  if (blob.algCrypt === CALG_3DES) {
    const key = cryptoKey.subarray(0, 24);
    plaintext = des3CbcDecrypt(key, new Uint8Array(8), blob.cipherText);
  } else if (blob.algCrypt === CALG_AES_256) {
    const key = cryptoKey.subarray(0, 32);
    plaintext = aesCbcDecrypt(key, new Uint8Array(16), blob.cipherText);
  } else {
    throw new Error(`unsupported DPAPI cipher 0x${blob.algCrypt.toString(16)}`);
  }

  return unpad(plaintext);
}

// ---- DPAPI_SYSTEM (from LSA secrets) ----------------------------------------

export function parseDpapiSystem(data) {
  if (data.length < 44) throw new Error('DPAPI_SYSTEM too short');
  const dv = new DataView(data.buffer, data.byteOffset);
  return {
    version: dv.getUint32(0, true),
    machineKey: data.slice(4, 24),
    userKey: data.slice(24, 44),
  };
}

// ---- Credential file parser (decrypted DPAPI blob content) ------------------

export function parseCredential(data) {
  if (data.length < 60) return { raw: data };
  const dv = new DataView(data.buffer, data.byteOffset);
  let off = 0;
  const version = dv.getUint32(off, true); off += 4;
  const flags = dv.getUint32(off, true); off += 4;
  const size = dv.getUint32(off, true); off += 4;
  off += 4; // unk0

  const type = dv.getUint32(off, true); off += 4;
  const flagsEx = dv.getUint32(off, true); off += 4;
  const lastWritten = off; off += 8;

  off += 4; // unk1
  const persist = dv.getUint32(off, true); off += 4;
  const attrCount = dv.getUint32(off, true); off += 4;
  off += 8; // unk2

  const readStr = () => {
    const len = dv.getUint32(off, true); off += 4;
    if (len === 0) return '';
    const s = new TextDecoder('utf-16le').decode(data.subarray(off, off + len));
    off += len;
    return s.replace(/\0+$/, '');
  };

  const targetName = readStr();
  const targetAlias = readStr();
  const comment = readStr();
  const unkData = readStr();
  const userName = readStr();

  const credLen = dv.getUint32(off, true); off += 4;
  const credData = data.slice(off, off + credLen);
  let password = '';
  try { password = new TextDecoder('utf-16le').decode(credData).replace(/\0+$/, ''); } catch {}

  return { targetName, targetAlias, comment, userName, password, credData };
}

// ---- Master Key File parsing ------------------------------------------------

export function parseMasterKeyFile(data) {
  if (data.length < 128) throw new Error('master key file too short');
  const dv = new DataView(data.buffer, data.byteOffset);
  const version = dv.getUint32(0, true);
  const guid = new TextDecoder('utf-16le').decode(data.subarray(12, 84)).replace(/\0+$/, '');
  const policy = dv.getUint32(88, true);
  const mkLen = Number(dv.getBigUint64(92, true));
  const bkLen = Number(dv.getBigUint64(100, true));
  const chLen = Number(dv.getBigUint64(108, true));
  const dkLen = Number(dv.getBigUint64(116, true));
  let off = 124;

  let masterKey = null;
  if (mkLen > 0 && off + mkLen <= data.length) {
    masterKey = parseMasterKeyBlob(data.subarray(off, off + mkLen));
    off += mkLen;
  }
  let backupKey = null;
  if (bkLen > 0 && off + bkLen <= data.length) {
    backupKey = parseMasterKeyBlob(data.subarray(off, off + bkLen));
    off += bkLen;
  }

  return { version, guid, policy, masterKey, backupKey };
}

function parseMasterKeyBlob(data) {
  if (data.length < 28) return null;
  const dv = new DataView(data.buffer, data.byteOffset);
  return {
    version: dv.getUint32(0, true),
    salt: data.slice(4, 20),
    iterations: dv.getUint32(20, true),
    hashAlg: dv.getUint32(24, true),
    cryptAlg: dv.getUint32(28, true),
    encrypted: data.slice(32),
  };
}

// Decrypt a master key blob using a pre-computed password hash (SHA1 or NT hash)
export function decryptMasterKey(mkBlob, passwordHash, sid = null) {
  const hmacFn = mkBlob.hashAlg === CALG_SHA512
    ? () => { throw new Error('SHA-512 not supported'); }
    : hmacSha1;

  let hmacData = mkBlob.salt;
  if (sid) {
    const sidUtf16 = new Uint8Array(sid.length * 2 + 2);
    for (let i = 0; i < sid.length; i++) {
      sidUtf16[i * 2] = sid.charCodeAt(i) & 0xFF;
      sidUtf16[i * 2 + 1] = (sid.charCodeAt(i) >> 8) & 0xFF;
    }
    hmacData = concat([mkBlob.salt, sidUtf16]);
  }

  const derivedBlob = hmacFn(passwordHash, hmacData);
  const cryptoKey = cryptDeriveKey(derivedBlob, sha1);

  let plaintext;
  if (mkBlob.cryptAlg === CALG_3DES) {
    plaintext = des3CbcDecrypt(cryptoKey.subarray(0, 24), new Uint8Array(8), mkBlob.encrypted);
  } else if (mkBlob.cryptAlg === CALG_AES_256) {
    plaintext = aesCbcDecrypt(cryptoKey.subarray(0, 32), new Uint8Array(16), mkBlob.encrypted);
  } else {
    throw new Error(`unsupported master key cipher 0x${mkBlob.cryptAlg.toString(16)}`);
  }

  // The decrypted master key is the last 64 bytes of the plaintext
  if (plaintext.length >= 64) {
    return plaintext.subarray(plaintext.length - 64);
  }
  return plaintext;
}
