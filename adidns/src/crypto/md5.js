// MD5 (RFC 1321) and HMAC-MD5 (RFC 2104). Neither is in WebCrypto, but NTLMv2
// needs HMAC-MD5 throughout. Operates on and returns Uint8Array.

const rotl = (x, c) => ((x << c) | (x >>> (32 - c))) >>> 0;
const add = (...xs) => xs.reduce((s, x) => (s + x) >>> 0, 0);

// Per-round left-rotate amounts.
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// K[i] = floor(abs(sin(i+1)) * 2^32) — the canonical MD5 additive constants.
const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;

function pad(input) {
  const len = input.length;
  let padded = len + 1;
  while (padded % 64 !== 56) padded++;
  const out = new Uint8Array(padded + 8);
  out.set(input);
  out[len] = 0x80;
  const bits = len * 8;
  const dv = new DataView(out.buffer);
  dv.setUint32(padded, bits >>> 0, true);
  dv.setUint32(padded + 4, Math.floor(bits / 0x100000000), true);
  return out;
}

export function md5(input) {
  const msg = pad(input);
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;

    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (B & C) | (~B & D); g = i; }
      else if (i < 32) { f = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { f = C ^ (B | (~D >>> 0)); g = (7 * i) % 16; }
      f = add(f >>> 0, A, K[i], M[g]);
      A = D; D = C; C = B;
      B = add(B, rotl(f, S[i]));
    }

    a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
  }

  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true);
  odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return out;
}

const BLOCK = 64;

export function hmacMd5(key, data) {
  let k = key;
  if (k.length > BLOCK) k = md5(k);
  const padded = new Uint8Array(BLOCK);
  padded.set(k);
  const ipad = new Uint8Array(BLOCK + data.length);
  const opadHead = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = padded[i] ^ 0x36;
    opadHead[i] = padded[i] ^ 0x5c;
  }
  ipad.set(data, BLOCK);
  const inner = md5(ipad);
  const outer = new Uint8Array(BLOCK + inner.length);
  outer.set(opadHead);
  outer.set(inner, BLOCK);
  return md5(outer);
}
