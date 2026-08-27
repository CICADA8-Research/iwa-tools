// Kerberos 5 cryptosystem (RFC 3961 framework) for the enctypes a modern AD
// account uses: AES{128,256}-CTS-HMAC-SHA1-96 (RFC 3962, etype 17/18) and the
// legacy RC4-HMAC (RFC 4757, etype 23). A direct port of the maths in
// impacket/krb5/crypto.py, built on the synchronous primitives vendored here
// (aes.js, sha1.js, rc4.js, md4.js, md5.js) so the whole path stays sync and
// is testable offline against the published RFC test vectors.

import { Aes } from '../crypto/aes.js';
import { sha1, hmacSha1, pbkdf2Sha1 } from '../crypto/sha1.js';
import { rc4 } from '../crypto/rc4.js';
import { md4 } from '../crypto/md4.js';
import { md5, hmacMd5 } from '../crypto/md5.js';
import { concat } from '../ldap/ber.js';
import { ETYPE } from './constants.js';
import { utf16le } from '../ntlm/ntlm.js';

const enc = new TextEncoder();

export function randomBytes(n) {
  const b = new Uint8Array(n);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return b;
}

function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ---- RFC 3961 n-fold -------------------------------------------------------
// Spreads an input over `nbytes` by replicating it (rotating each copy 13 bits
// from the last) up to lcm(len, nbytes), then ones'-complement-adding the
// nbyte-sized chunks. Ported from impacket's _nfold.

function gcd(a, b) { while (b) { const t = a % b; a = b; b = t; } return a; }

function rotateRight(b, nbits) {
  const len = b.length;
  const nbytes = Math.floor(nbits / 8) % len;
  const remain = nbits % 8;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    const i1 = ((i - nbytes) % len + len) % len;
    const i2 = ((i - nbytes - 1) % len + len) % len;
    out[i] = ((b[i1] >> remain) | (b[i2] << (8 - remain))) & 0xff;
  }
  return out;
}

export function nfold(input, nbytes) {
  const slen = input.length;
  const lcm = (nbytes * slen) / gcd(nbytes, slen);
  const big = new Uint8Array(lcm);
  for (let i = 0; i < lcm / slen; i++) big.set(rotateRight(input, 13 * i), i * slen);

  let v = new Array(nbytes).fill(0);
  for (let i = 0; i < big.length; i += nbytes) {
    for (let k = 0; k < nbytes; k++) v[k] += big[i + k];
    // Propagate the end-around carry until every column fits in a byte.
    while (v.some((x) => x > 0xff)) {
      const nv = new Array(nbytes);
      for (let k = 0; k < nbytes; k++) nv[k] = (v[(k + 1) % nbytes] >> 8) + (v[k] & 0xff);
      v = nv;
    }
  }
  return Uint8Array.from(v, (x) => x & 0xff);
}

// ---- AES CTS (ciphertext stealing) over a raw block cipher -----------------
// basic_encrypt / basic_decrypt operate with IV=0 and no padding, exactly as
// RFC 3962 specifies. For a single block, CTS degenerates to ECB.

function basicEncrypt(aes, plaintext) {
  if (plaintext.length < 16) throw new Error('CTS needs at least one block');
  const nblocks = Math.ceil(plaintext.length / 16);
  // CBC over zero-padded input.
  const padded = new Uint8Array(nblocks * 16);
  padded.set(plaintext);
  const out = new Uint8Array(nblocks * 16);
  let prev = new Uint8Array(16);
  for (let i = 0; i < nblocks; i++) {
    const blk = xor(padded.subarray(i * 16, i * 16 + 16), prev);
    prev = aes.encryptBlock(blk);
    out.set(prev, i * 16);
  }
  if (plaintext.length === 16) return out;
  // CTS: swap the last two cipher blocks; truncate the final one to the length
  // of the trailing partial plaintext block.
  const lastLen = plaintext.length % 16 || 16;
  const cn1 = out.slice(out.length - 32, out.length - 16); // second-to-last
  const cn = out.slice(out.length - 16);                   // last (full)
  const result = out.slice(0, out.length - 32);
  return concat([result, cn, cn1.subarray(0, lastLen)]);
}

function basicDecrypt(aes, ciphertext) {
  if (ciphertext.length < 16) throw new Error('CTS needs at least one block');
  if (ciphertext.length === 16) return aes.decryptBlock(ciphertext);

  const total = ciphertext.length;
  const lastLen = total % 16 || 16;
  // Split: [ full blocks ... ][ Cn-1 (16) ][ Cn (lastLen) ]
  const cnStart = total - lastLen;
  const cn1Start = cnStart - 16;
  const head = ciphertext.subarray(0, cn1Start);
  const cn1 = ciphertext.subarray(cn1Start, cnStart);
  const cn = ciphertext.subarray(cnStart);

  let prev = new Uint8Array(16);
  const out = [];
  for (let i = 0; i < head.length; i += 16) {
    const c = head.subarray(i, i + 16);
    out.push(xor(aes.decryptBlock(c), prev));
    prev = c.slice();
  }
  // Decrypt Cn-1: its left `lastLen` bytes (xor Cn) give the final plaintext
  // block; its right bytes are the ciphertext stolen from the last block.
  const dn1 = aes.decryptBlock(cn1);
  const lastPlain = xor(dn1.subarray(0, lastLen), cn);
  const omitted = dn1.subarray(lastLen);
  const fullCn = concat([cn, omitted]); // restore the full final cipher block
  const secondLastPlain = xor(aes.decryptBlock(fullCn), prev);
  out.push(secondLastPlain);
  out.push(lastPlain);
  return concat(out);
}

// ---- AES enctype profile (RFC 3962) ---------------------------------------

const AES_PARAMS = {
  [ETYPE.AES128_CTS_HMAC_SHA1_96]: { keysize: 16 },
  [ETYPE.AES256_CTS_HMAC_SHA1_96]: { keysize: 32 },
};
const AES_MACSIZE = 12; // HMAC-SHA1-96

// RFC 3961 DK(key, constant) = random-to-key(DR(key, constant)). For AES
// random-to-key is the identity, so DK == DR truncated to the key size.
function aesDeriveKey(key, constant) {
  const aes = new Aes(key);
  const seedsize = key.length;
  let block = nfold(constant, 16);
  const out = [];
  let have = 0;
  while (have < seedsize) {
    block = basicEncrypt(aes, block); // single block -> ECB
    out.push(block);
    have += block.length;
  }
  return concat(out).slice(0, seedsize);
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

// 5-byte usage constant: 4-byte big-endian key usage + one role byte.
function usageConstant(keyUsage, role) {
  return concat([u32be(keyUsage), Uint8Array.of(role)]);
}

function aesEncrypt(etype, key, keyUsage, plaintext, confounder) {
  const ke = aesDeriveKey(key, usageConstant(keyUsage, 0xaa));
  const ki = aesDeriveKey(key, usageConstant(keyUsage, 0x55));
  const conf = confounder || randomBytes(16);
  const basicPlain = concat([conf, plaintext]); // no padding (CTS)
  const cipher = basicEncrypt(new Aes(ke), basicPlain);
  const mac = hmacSha1(ki, basicPlain).subarray(0, AES_MACSIZE);
  return concat([cipher, mac]);
}

function aesDecrypt(etype, key, keyUsage, ciphertext) {
  if (ciphertext.length < 16 + AES_MACSIZE) throw new Error('AES ciphertext too short');
  const ke = aesDeriveKey(key, usageConstant(keyUsage, 0xaa));
  const ki = aesDeriveKey(key, usageConstant(keyUsage, 0x55));
  const cipher = ciphertext.subarray(0, ciphertext.length - AES_MACSIZE);
  const mac = ciphertext.subarray(ciphertext.length - AES_MACSIZE);
  const basicPlain = basicDecrypt(new Aes(ke), cipher);
  const expMac = hmacSha1(ki, basicPlain).subarray(0, AES_MACSIZE);
  if (!macEqual(mac, expMac)) throw new Error('AES integrity check failed (wrong key?)');
  return basicPlain.subarray(16); // strip the confounder
}

// HMAC-SHA1-96 keyed checksum (cksumtype 15/16), key usage derived with 0x99.
function aesChecksum(etype, key, keyUsage, data) {
  const kc = aesDeriveKey(key, usageConstant(keyUsage, 0x99));
  return hmacSha1(kc, data).subarray(0, AES_MACSIZE);
}

// RFC 3962 string-to-key: PBKDF2-HMAC-SHA1 then DK(.,"kerberos").
function aesStringToKey(etype, password, salt, iterations = 4096) {
  const keysize = AES_PARAMS[etype].keysize;
  const tkey = pbkdf2Sha1(enc.encode(password), salt, iterations, keysize);
  return aesDeriveKey(tkey, enc.encode('kerberos'));
}

// ---- RC4-HMAC enctype profile (RFC 4757) ----------------------------------

// RFC 4757 reuses a handful of usage numbers from RFC 1964; translate them.
function rc4UsageStr(keyUsage) {
  const map = { 3: 8, 9: 8, 23: 13 };
  const u = map[keyUsage] !== undefined ? map[keyUsage] : keyUsage;
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, u >>> 0, true); // little-endian
  return b;
}

// RC4 long-term key is just the NT hash: MD4(UTF16LE(password)).
function rc4StringToKey(password) {
  return md4(utf16le(password));
}

function rc4Encrypt(key, keyUsage, plaintext, confounder) {
  const conf = confounder || randomBytes(8);
  const ki = hmacMd5(key, rc4UsageStr(keyUsage));
  const data = concat([conf, plaintext]);
  const cksum = hmacMd5(ki, data);
  const ke = hmacMd5(ki, cksum);
  return concat([cksum, rc4(ke, data)]);
}

function rc4Decrypt(key, keyUsage, ciphertext) {
  if (ciphertext.length < 24) throw new Error('RC4 ciphertext too short');
  const cksum = ciphertext.subarray(0, 16);
  const ki = hmacMd5(key, rc4UsageStr(keyUsage));
  const ke = hmacMd5(ki, cksum);
  const data = rc4(ke, ciphertext.subarray(16)); // confounder(8) + plaintext
  const expCksum = hmacMd5(ki, data);
  if (!macEqual(cksum, expCksum)) throw new Error('RC4 integrity check failed (wrong key?)');
  return data.subarray(8);
}

// HMAC-MD5 keyed checksum (cksumtype -138), RFC 4757 §4.
function rc4Checksum(key, keyUsage, data) {
  const ksign = hmacMd5(key, concat([enc.encode('signaturekey'), Uint8Array.of(0)]));
  const tmp = md5Concat(rc4UsageStr(keyUsage), data);
  return hmacMd5(ksign, tmp);
}

function macEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function md5Concat(a, b) { return md5(concat([a, b])); }

// ---- Public dispatcher -----------------------------------------------------
// A uniform interface keyed by etype, so the message layer never branches on
// the algorithm. Keys are { etype, key: Uint8Array }.

export const RC4_CKSUM = -138;       // hmac-md5
export const AES_SHA1_CKSUM = { 17: 15, 18: 16 }; // hmac-sha1-96-aes{128,256}

export function keySize(etype) {
  if (etype === ETYPE.RC4_HMAC) return 16;
  if (AES_PARAMS[etype]) return AES_PARAMS[etype].keysize;
  throw new Error(`unsupported etype ${etype}`);
}

// Derive a principal's long-term key from a password. `salt` is required for
// AES (Uint8Array, usually UPPER-REALM + username); ignored for RC4.
export function stringToKey(etype, password, salt, iterations) {
  if (etype === ETYPE.RC4_HMAC) return rc4StringToKey(password);
  if (AES_PARAMS[etype]) return aesStringToKey(etype, password, salt, iterations);
  throw new Error(`unsupported etype ${etype}`);
}

export function encrypt(etype, key, keyUsage, plaintext, confounder) {
  if (etype === ETYPE.RC4_HMAC) return rc4Encrypt(key, keyUsage, plaintext, confounder);
  if (AES_PARAMS[etype]) return aesEncrypt(etype, key, keyUsage, plaintext, confounder);
  throw new Error(`unsupported etype ${etype}`);
}

export function decrypt(etype, key, keyUsage, ciphertext) {
  if (etype === ETYPE.RC4_HMAC) return rc4Decrypt(key, keyUsage, ciphertext);
  if (AES_PARAMS[etype]) return aesDecrypt(etype, key, keyUsage, ciphertext);
  throw new Error(`unsupported etype ${etype}`);
}

export function checksum(etype, key, keyUsage, data) {
  if (etype === ETYPE.RC4_HMAC) return rc4Checksum(key, keyUsage, data);
  if (AES_PARAMS[etype]) return aesChecksum(etype, key, keyUsage, data);
  throw new Error(`unsupported etype ${etype}`);
}

// The cksumtype paired with an etype, for the value we put on the wire.
export function checksumType(etype) {
  if (etype === ETYPE.RC4_HMAC) return RC4_CKSUM;
  if (AES_SHA1_CKSUM[etype]) return AES_SHA1_CKSUM[etype];
  throw new Error(`unsupported etype ${etype}`);
}

// Default AD salt for a principal: UPPERCASE(realm) + username (RFC 4120),
// with no separator. Used when an ETYPE-INFO2 entry omits its salt.
export function defaultSalt(realm, username) {
  return enc.encode(realm.toUpperCase() + username);
}

// Exposed for unit testing the inner block transforms.
export const _internals = { nfold, aesDeriveKey, basicEncrypt, basicDecrypt };
