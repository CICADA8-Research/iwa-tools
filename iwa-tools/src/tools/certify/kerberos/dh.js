// Diffie-Hellman for PKINIT (RFC 4556): MODP group 14 (2048-bit, RFC 3526),
// BigInt modular exponentiation, and the octetstring2key reply-key derivation.
// The client picks the DH parameters and sends them in the AuthPack; the reply
// key is derived from the shared secret with the KDC.

import { sha1 } from '../crypto/sha1.js';
import { concat } from '../ldap/ber.js';

// RFC 3526 group 14 prime, g = 2.
const P14 = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
const p = BigInt('0x' + P14);
const g = 2n;
export const DH = { p, g, q: (p - 1n) / 2n, byteLen: 256 };

export function modpow(base, exp, mod) {
  let r = 1n; base %= mod;
  while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
  return r;
}

export function intToBytes(n, len = 0) {
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  let b = Uint8Array.from(hex.match(/.{1,2}/g).map((h) => parseInt(h, 16)));
  if (len && b.length < len) { const pad = new Uint8Array(len); pad.set(b, len - b.length); return pad; }
  if (len && b.length > len) return b.subarray(b.length - len);
  return b;
}
export function bytesToInt(b) { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; }

export function genKeyPair() {
  const x = bytesToInt(globalThis.crypto.getRandomValues(new Uint8Array(32))) % DH.q; // ephemeral private
  return { x, y: modpow(g, x, p) };                                                   // public y = g^x mod p
}

// Shared secret g^(xy) mod p, big-endian padded to the modulus length.
export function sharedSecret(kdcPublicY, x) {
  return intToBytes(modpow(bytesToInt(kdcPublicY), x, p), DH.byteLen);
}

// RFC 4556 §3.2.3.1: octetstring2key(x) = random-to-key(K-truncate(
//   SHA1(0x00|x) || SHA1(0x01|x) || …)). random-to-key is identity for AES.
export function octetstring2key(secret, keysize) {
  const blocks = [];
  let counter = 0, have = 0;
  while (have < keysize) { const h = sha1(concat([Uint8Array.of(counter & 0xff), secret])); blocks.push(h); have += h.length; counter++; }
  return concat(blocks).slice(0, keysize);
}
