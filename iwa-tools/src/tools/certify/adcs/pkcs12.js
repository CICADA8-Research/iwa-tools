// PKCS#12 (PFX) builder — password-less bundle of one x509 certificate + one
// unencrypted PKCS#8 private key. Written to match what OpenSSL and Windows
// import cleanly. The MacData is included with an empty password (RFC 7292 §B
// PKCS#12 v2 KDF) so tools that refuse un-MACd PFX (modern OpenSSL, some
// certutil paths) still accept the file.

import { tlv, sequence, set, oid, integer, octetString, concat } from '../ldap/ber.js';

const ctx = (n, val) => tlv(0xa0 | n, val);                       // [n] EXPLICIT
const nullDer = tlv(0x05, new Uint8Array(0));

const OID = {
  data:            '1.2.840.113549.1.7.1',
  keyBag:          '1.2.840.113549.1.12.10.1.1',                  // unencrypted PKCS#8
  certBag:         '1.2.840.113549.1.12.10.1.3',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  localKeyId:      '1.2.840.113549.1.9.21',
  sha1:            '1.3.14.3.2.26',
};

// SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, bagAttrs SET OPT }
function safeBag(bagIdOid, bagValueDer, attrs) {
  const items = [oid(bagIdOid), ctx(0, bagValueDer)];
  if (attrs && attrs.length) items.push(set(...attrs));
  return sequence(...items);
}

// CertBag { certId, certValue [0] EXPLICIT OCTET STRING(certDER) }
function certBagValue(x509Der) {
  return sequence(oid(OID.x509Certificate), ctx(0, octetString(x509Der)));
}

// PKCS-12 attribute: localKeyId = OCTET STRING(<20 random bytes>) — links the
// keyBag and certBag so the private key opens the right cert on import.
function localKeyIdAttr(id) {
  return sequence(oid(OID.localKeyId), set(octetString(id)));
}

// ContentInfo (data) wrapping an OCTET STRING of `inner` bytes.
function contentInfoData(inner) {
  return sequence(oid(OID.data), ctx(0, octetString(inner)));
}

// ---- PKCS#12 v2 KDF (RFC 7292 §B.2) — SHA-1 only, produces MAC key. ---------
// id = 3 (MAC key). password: Uint8Array (BMP-encoded, with double-NUL
// terminator; empty password → empty byte string). salt: Uint8Array.
async function pkcs12KdfSha1(password, salt, iterations, keyLen, id = 3) {
  const v = 64;                              // SHA-1 block bytes
  const u = 20;                              // SHA-1 output bytes
  const D = new Uint8Array(v);               // v bytes of id
  for (let i = 0; i < v; i++) D[i] = id;
  const fill = (src, len) => {
    if (src.length === 0) return new Uint8Array(0);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = src[i % src.length];
    return out;
  };
  const Slen = Math.ceil(salt.length / v) * v;
  const Plen = Math.ceil(password.length / v) * v;
  const S = fill(salt, Slen);
  const P = fill(password, Plen);
  const I = new Uint8Array(Slen + Plen); I.set(S, 0); I.set(P, Slen);
  const c = Math.ceil(keyLen / u);
  const out = new Uint8Array(c * u);
  const sha1 = async (bytes) => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-1', bytes));
  for (let i = 0; i < c; i++) {
    let A = await sha1(concat([D, I]));
    for (let j = 1; j < iterations; j++) A = await sha1(A);
    out.set(A, i * u);
    // I_j = (I_j + B + 1) mod 2^v, treating v-byte blocks as big-endian ints.
    const B = fill(A, v);
    for (let off = 0; off < I.length; off += v) {
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const s = I[off + k] + B[k] + carry;
        I[off + k] = s & 0xff;
        carry = s >>> 8;
      }
    }
  }
  return out.subarray(0, keyLen);
}

// HMAC-SHA1 (via WebCrypto) — returns 20-byte MAC.
async function hmacSha1(key, data) {
  const k = await globalThis.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, data));
}

// Build a password-less PFX bundle: one unencrypted keyBag (PKCS#8) + one
// certBag, linked by a common 20-byte localKeyId, wrapped in an empty-password
// SHA-1 MAC. `pkcs8` is the private-key info DER; `x509` is the leaf cert DER.
export async function buildPfx(pkcs8, x509) {
  const localKeyId = globalThis.crypto.getRandomValues(new Uint8Array(20));
  const kBag = safeBag(OID.keyBag, pkcs8, [localKeyIdAttr(localKeyId)]);
  const cBag = safeBag(OID.certBag, certBagValue(x509), [localKeyIdAttr(localKeyId)]);
  const safeContents = sequence(kBag, cBag);
  const authenticatedSafe = sequence(contentInfoData(safeContents));

  const salt = globalThis.crypto.getRandomValues(new Uint8Array(8));
  const iterations = 2048;
  // Empty password per RFC 7292 §B.2 → P is empty.
  const macKey = await pkcs12KdfSha1(new Uint8Array(0), salt, iterations, 20, 3);
  const mac = await hmacSha1(macKey, authenticatedSafe);
  const macData = sequence(
    sequence(sequence(oid(OID.sha1), nullDer), octetString(mac)),
    octetString(salt),
    integer(iterations),
  );

  return sequence(
    integer(3),                              // PFX version v3
    contentInfoData(authenticatedSafe),
    macData,
  );
}
