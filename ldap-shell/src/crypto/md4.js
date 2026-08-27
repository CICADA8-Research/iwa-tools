// MD4 (RFC 1320). Not available in WebCrypto, but required for NTLM:
// NTOWFv1 = MD4(UTF16LE(password)). Operates on and returns Uint8Array.

const rotl = (x, c) => ((x << c) | (x >>> (32 - c))) >>> 0;
const add = (...xs) => xs.reduce((s, x) => (s + x) >>> 0, 0);

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

export function md4(input) {
  const msg = pad(input);
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const X = new Uint32Array(16);

  const F = (x, y, z) => ((x & y) | (~x & z)) >>> 0;
  const G = (x, y, z) => ((x & y) | (x & z) | (y & z)) >>> 0;
  const H = (x, y, z) => (x ^ y ^ z) >>> 0;
  const ff = (p, q, r, s, k, sh) => rotl(add(p, F(q, r, s), X[k]), sh);
  const gg = (p, q, r, s, k, sh) => rotl(add(p, G(q, r, s), X[k], 0x5a827999), sh);
  const hh = (p, q, r, s, k, sh) => rotl(add(p, H(q, r, s), X[k], 0x6ed9eba1), sh);

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
    let A = a, B = b, C = c, D = d;

    // Round 1
    A = ff(A, B, C, D, 0, 3); D = ff(D, A, B, C, 1, 7); C = ff(C, D, A, B, 2, 11); B = ff(B, C, D, A, 3, 19);
    A = ff(A, B, C, D, 4, 3); D = ff(D, A, B, C, 5, 7); C = ff(C, D, A, B, 6, 11); B = ff(B, C, D, A, 7, 19);
    A = ff(A, B, C, D, 8, 3); D = ff(D, A, B, C, 9, 7); C = ff(C, D, A, B, 10, 11); B = ff(B, C, D, A, 11, 19);
    A = ff(A, B, C, D, 12, 3); D = ff(D, A, B, C, 13, 7); C = ff(C, D, A, B, 14, 11); B = ff(B, C, D, A, 15, 19);

    // Round 2
    A = gg(A, B, C, D, 0, 3); D = gg(D, A, B, C, 4, 5); C = gg(C, D, A, B, 8, 9); B = gg(B, C, D, A, 12, 13);
    A = gg(A, B, C, D, 1, 3); D = gg(D, A, B, C, 5, 5); C = gg(C, D, A, B, 9, 9); B = gg(B, C, D, A, 13, 13);
    A = gg(A, B, C, D, 2, 3); D = gg(D, A, B, C, 6, 5); C = gg(C, D, A, B, 10, 9); B = gg(B, C, D, A, 14, 13);
    A = gg(A, B, C, D, 3, 3); D = gg(D, A, B, C, 7, 5); C = gg(C, D, A, B, 11, 9); B = gg(B, C, D, A, 15, 13);

    // Round 3
    A = hh(A, B, C, D, 0, 3); D = hh(D, A, B, C, 8, 9); C = hh(C, D, A, B, 4, 11); B = hh(B, C, D, A, 12, 15);
    A = hh(A, B, C, D, 2, 3); D = hh(D, A, B, C, 10, 9); C = hh(C, D, A, B, 6, 11); B = hh(B, C, D, A, 14, 15);
    A = hh(A, B, C, D, 1, 3); D = hh(D, A, B, C, 9, 9); C = hh(C, D, A, B, 5, 11); B = hh(B, C, D, A, 13, 15);
    A = hh(A, B, C, D, 3, 3); D = hh(D, A, B, C, 11, 9); C = hh(C, D, A, B, 7, 11); B = hh(B, C, D, A, 15, 15);

    a = add(a, A); b = add(b, B); c = add(c, C); d = add(d, D);
  }

  const out = new Uint8Array(16);
  new DataView(out.buffer).setUint32(0, a, true);
  new DataView(out.buffer).setUint32(4, b, true);
  new DataView(out.buffer).setUint32(8, c, true);
  new DataView(out.buffer).setUint32(12, d, true);
  return out;
}
