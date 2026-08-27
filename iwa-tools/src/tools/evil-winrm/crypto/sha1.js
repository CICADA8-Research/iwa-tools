// SHA-1 (FIPS 180-4), HMAC-SHA1 (RFC 2104) and PBKDF2-HMAC-SHA1 (RFC 8018).
// Kerberos AES enctypes (RFC 3962) need all three: HMAC-SHA1 for the message
// integrity tag and key-derivation checksums, PBKDF2 for string-to-key. None
// are in WebCrypto in a *synchronous* form, and the rest of the crypto stack
// here is synchronous, so we vendor them like md4/md5. Operates on and returns
// Uint8Array.

const rotl = (x, c) => ((x << c) | (x >>> (32 - c))) >>> 0;

function pad(input) {
  const len = input.length;
  let padded = len + 1;
  while (padded % 64 !== 56) padded++;
  const out = new Uint8Array(padded + 8);
  out.set(input);
  out[len] = 0x80;
  // 64-bit big-endian bit length.
  const bits = len * 8;
  const dv = new DataView(out.buffer);
  dv.setUint32(padded, Math.floor(bits / 0x100000000), false);
  dv.setUint32(padded + 4, bits >>> 0, false);
  return out;
}

export function sha1(input) {
  const msg = pad(input);
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + (f >>> 0) + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }

    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0, false); odv.setUint32(4, h1, false); odv.setUint32(8, h2, false);
  odv.setUint32(12, h3, false); odv.setUint32(16, h4, false);
  return out;
}

const BLOCK = 64;

export function hmacSha1(key, data) {
  let k = key;
  if (k.length > BLOCK) k = sha1(k);
  const ipad = new Uint8Array(BLOCK + data.length);
  const opadHead = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    const kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opadHead[i] = kb ^ 0x5c;
  }
  ipad.set(data, BLOCK);
  const inner = sha1(ipad);
  const outer = new Uint8Array(BLOCK + inner.length);
  outer.set(opadHead);
  outer.set(inner, BLOCK);
  return sha1(outer);
}

// PBKDF2 with HMAC-SHA1 as the PRF. `dkLen` is the desired key length in bytes.
export function pbkdf2Sha1(password, salt, iterations, dkLen) {
  const hLen = 20;
  const blocks = Math.ceil(dkLen / hLen);
  const out = new Uint8Array(blocks * hLen);
  const saltBlock = new Uint8Array(salt.length + 4);
  saltBlock.set(salt);
  const dv = new DataView(saltBlock.buffer);

  for (let i = 1; i <= blocks; i++) {
    dv.setUint32(salt.length, i, false); // INT_32_BE(i)
    let u = hmacSha1(password, saltBlock);
    const t = u.slice();
    for (let c = 1; c < iterations; c++) {
      u = hmacSha1(password, u);
      for (let k = 0; k < hLen; k++) t[k] ^= u[k];
    }
    out.set(t, (i - 1) * hLen);
  }
  return out.slice(0, dkLen);
}
