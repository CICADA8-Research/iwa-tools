// CMS SignedData (RFC 5652) for PKINIT: wrap the AuthPack in a SignedData signed
// by the client certificate's RSA key, and parse the KDC's PA-PK-AS-REP DH reply
// to recover the KDC's Diffie-Hellman public value.

import { tlv, sequence, set, oid, octetString, integer, concat, readTLV } from '../ldap/ber.js';

const ctx = (n, v) => tlv(0xa0 | n, v);
const nullDer = tlv(0x05, new Uint8Array(0));

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  pkinitAuthData: '1.3.6.1.5.2.3.1',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
};

// IssuerAndSerialNumber from a certificate DER (the SignerIdentifier).
function issuerAndSerial(certDer) {
  const cert = readTLV(certDer, 0);
  const tbs = readTLV(certDer, cert.valueStart);
  let serial = null; const seqs = [];
  for (let q = tbs.valueStart; q < tbs.valueEnd;) {
    const t = readTLV(certDer, q);
    if (t.tag === 0x02 && !serial && seqs.length === 0) serial = certDer.subarray(q, t.next);
    if (t.tag === 0x30) seqs.push(certDer.subarray(q, t.next));
    q = t.next;
  }
  return sequence(seqs[1], serial); // { issuer Name, serialNumber } (issuer is the 2nd SEQUENCE in tbs)
}

// Build the CMS ContentInfo (SignedData) over `authPackDer`, signed by `privateKey`
// (a WebCrypto RSASSA-PKCS1-v1_5/SHA-256 key) with `certDer` embedded.
export async function buildSignedAuthPack(authPackDer, certDer, privateKey) {
  const md = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', authPackDer));
  const attrContentType = sequence(oid(OID.contentType), set(oid(OID.pkinitAuthData)));
  const attrDigest = sequence(oid(OID.messageDigest), set(octetString(md)));
  const attrsForSign = set(attrContentType, attrDigest);                 // SET OF for signing (tag 0x31)
  const sig = new Uint8Array(await globalThis.crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, attrsForSign));

  const signerInfo = sequence(
    integer(1),
    issuerAndSerial(certDer),
    sequence(oid(OID.sha256), nullDer),
    ctx(0, concat([attrContentType, attrDigest])),                       // signedAttrs [0] IMPLICIT
    sequence(oid(OID.rsaEncryption), nullDer),
    octetString(sig),
  );
  const signedData = sequence(
    integer(3),
    set(sequence(oid(OID.sha256), nullDer)),                             // digestAlgorithms
    sequence(oid(OID.pkinitAuthData), ctx(0, octetString(authPackDer))), // encapContentInfo
    ctx(0, certDer),                                                     // certificates [0] IMPLICIT
    set(signerInfo),
  );
  return sequence(oid(OID.signedData), ctx(0, signedData));              // ContentInfo
}

// From a SignedData ContentInfo, return the eContent OCTET STRING value.
function eContentOf(ci) {
  const outer = readTLV(ci, 0);
  let sd = null;
  for (let p = outer.valueStart; p < outer.valueEnd;) { const t = readTLV(ci, p); if (t.tag === 0xa0) sd = t; p = t.next; }
  const signedData = readTLV(ci, sd.valueStart);
  let encap = null;
  for (let p = signedData.valueStart; p < signedData.valueEnd;) { const t = readTLV(ci, p); if (t.tag === 0x30) { encap = t; break; } p = t.next; }
  for (let p = encap.valueStart; p < encap.valueEnd;) { const t = readTLV(ci, p); if (t.tag === 0xa0) { const oct = readTLV(ci, t.valueStart); return ci.subarray(oct.valueStart, oct.valueEnd); } p = t.next; }
  return null;
}

// Parse PA-PK-AS-REP (dhInfo) -> the KDC's DH public value y (big-endian bytes).
export function extractKdcDhPublicKey(bytes) {
  const dhInfoCtx = readTLV(bytes, 0);                     // [0] dhInfo
  const dhRepInfo = readTLV(bytes, dhInfoCtx.valueStart);  // DHRepInfo SEQUENCE
  const dhSigned = readTLV(bytes, dhRepInfo.valueStart);   // dhSignedData [0] IMPLICIT OCTET STRING
  const contentInfo = bytes.subarray(dhSigned.valueStart, dhSigned.valueEnd);
  const kdcDhKeyInfo = eContentOf(contentInfo);            // KDCDHKeyInfo DER
  const ki = readTLV(kdcDhKeyInfo, 0);
  const spkCtx = readTLV(kdcDhKeyInfo, ki.valueStart);     // subjectPublicKey [0]
  const bitStr = readTLV(kdcDhKeyInfo, spkCtx.valueStart); // BIT STRING
  const intTlv = readTLV(kdcDhKeyInfo, bitStr.valueStart + 1); // skip unused-bits byte -> INTEGER
  let y = kdcDhKeyInfo.subarray(intTlv.valueStart, intTlv.valueEnd);
  if (y[0] === 0x00) y = y.subarray(1);                    // strip DER sign byte
  return y;
}
