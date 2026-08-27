// DES-ECB via crypto-js — used only for SAM/DRSUAPI hash de-obfuscation.
// Our previous hand-rolled DES had a bug in the C/D key-schedule rotation
// (worked with 28-bit data in top bits of a 32-bit int, but rotated as if
// it were in the bottom 28); rather than chase individual bit issues we
// use a well-tested library.

import CryptoJS from 'crypto-js';

function u8ToWordArray(u8) {
  const words = [];
  for (let i = 0; i < u8.length; i += 4) {
    words.push(((u8[i] || 0) << 24) | ((u8[i + 1] || 0) << 16) |
               ((u8[i + 2] || 0) << 8) | (u8[i + 3] || 0));
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

function wordArrayToU8(wa) {
  const out = new Uint8Array(wa.sigBytes);
  for (let i = 0; i < wa.sigBytes; i++) {
    out[i] = (wa.words[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return out;
}

export function desEncrypt(key8, block8) {
  const enc = CryptoJS.DES.encrypt(u8ToWordArray(block8), u8ToWordArray(key8), {
    mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding,
  });
  return wordArrayToU8(enc.ciphertext).slice(0, 8);
}

export function desDecrypt(key8, block8) {
  const dec = CryptoJS.DES.decrypt(
    { ciphertext: u8ToWordArray(block8) },
    u8ToWordArray(key8),
    { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding },
  );
  return wordArrayToU8(dec).slice(0, 8);
}

function setOddParity(b) {
  let bits = 0;
  for (let i = 1; i < 8; i++) if (b & (1 << i)) bits++;
  return (bits & 1) ? (b & 0xFE) : (b | 0x01);
}

// Convert a 7-byte input to an 8-byte DES key (7-in-8 bit spreading + parity).
export function strToKey(s7) {
  return Uint8Array.of(
    setOddParity(s7[0] >> 1 << 1),
    setOddParity(((s7[0] & 0x01) << 6 | s7[1] >> 2) << 1),
    setOddParity(((s7[1] & 0x03) << 5 | s7[2] >> 3) << 1),
    setOddParity(((s7[2] & 0x07) << 4 | s7[3] >> 4) << 1),
    setOddParity(((s7[3] & 0x0F) << 3 | s7[4] >> 5) << 1),
    setOddParity(((s7[4] & 0x1F) << 2 | s7[5] >> 6) << 1),
    setOddParity(((s7[5] & 0x3F) << 1 | s7[6] >> 7) << 1),
    setOddParity((s7[6] & 0x7F) << 1),
  );
}

// Derive the two 8-byte DES keys from a SAM RID per MS-SAMR §2.2.11.1.3.
export function ridToKeys(rid) {
  const s1 = Uint8Array.of(
    rid & 0xFF, (rid >> 8) & 0xFF, (rid >> 16) & 0xFF, (rid >> 24) & 0xFF,
    rid & 0xFF, (rid >> 8) & 0xFF, (rid >> 16) & 0xFF,
  );
  const s2 = Uint8Array.of(
    (rid >> 24) & 0xFF, rid & 0xFF, (rid >> 8) & 0xFF, (rid >> 16) & 0xFF,
    (rid >> 24) & 0xFF, rid & 0xFF, (rid >> 8) & 0xFF,
  );
  return [strToKey(s1), strToKey(s2)];
}

// Reverse the DES-obfuscation layer applied to 16-byte hashes stored under
// a RID (used by both LSA/SAM local secrets and DRSUAPI replicated ones).
export function desDeobfuscate(rid, obfuscated) {
  const [k1, k2] = ridToKeys(rid);
  const h1 = desDecrypt(k1, obfuscated.slice(0, 8));
  const h2 = desDecrypt(k2, obfuscated.slice(8, 16));
  const out = new Uint8Array(16);
  out.set(h1, 0);
  out.set(h2, 8);
  return out;
}
