// tls-server-end-point channel binding (RFC 5929) + the GSS channel-bindings
// application data used by LDAP/HTTP Extended Protection for Authentication.
//
// RFC 5929: the binding is the hash of the server certificate (DER). The hash
// is the certificate's signatureAlgorithm hash, except MD5/SHA-1 are upgraded
// to SHA-256. Windows EPA feeds "tls-server-end-point:" + that hash as the GSS
// channel-bindings application_data; the GSS authenticator's 16-byte Bnd field
// is MD5(gss_channel_bindings_struct) over it (addresses zeroed).

const enc = new TextEncoder();

// Minimal DER walk to read the certificate's signatureAlgorithm OID.
function certSigAlgOid(der) {
  const rd = (pos) => { // returns {tag, vStart, vEnd, next}
    let i = pos; const tag = der[i++]; let len = der[i++];
    if (len & 0x80) { let n = len & 0x7f; len = 0; while (n--) len = len * 256 + der[i++]; }
    return { tag, vStart: i, vEnd: i + len, next: i + len };
  };
  const cert = rd(0);              // Certificate ::= SEQUENCE
  const tbs = rd(cert.vStart);     // tbsCertificate ::= SEQUENCE
  const sigAlg = rd(tbs.next);     // signatureAlgorithm ::= SEQUENCE { OID, ... }
  const oid = rd(sigAlg.vStart);   // OBJECT IDENTIFIER
  return decodeOid(der.subarray(oid.vStart, oid.vEnd));
}

function decodeOid(bytes) {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

// Map a signatureAlgorithm OID to the WebCrypto digest name (RFC 5929 §4.1).
function hashForSigAlg(oid) {
  const m = {
    '1.2.840.113549.1.1.11': 'SHA-256', // sha256WithRSAEncryption
    '1.2.840.113549.1.1.12': 'SHA-384',
    '1.2.840.113549.1.1.13': 'SHA-512',
    '1.2.840.10045.4.3.2': 'SHA-256',   // ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': 'SHA-384',
    '1.2.840.10045.4.3.4': 'SHA-512',
    '1.2.840.113549.1.1.10': 'SHA-256', // RSASSA-PSS (assume SHA-256 default)
  };
  return m[oid] || 'SHA-256'; // SHA-1/MD5 and unknowns upgrade to SHA-256
}

// Returns { hashName, certHash (Uint8Array), applicationData (Uint8Array) }.
export async function tlsServerEndPoint(certDer) {
  const hashName = hashForSigAlg(certSigAlgOid(certDer));
  const digest = await (globalThis.crypto).subtle.digest(hashName, certDer);
  const certHash = new Uint8Array(digest);
  const prefix = enc.encode('tls-server-end-point:');
  const applicationData = new Uint8Array(prefix.length + certHash.length);
  applicationData.set(prefix, 0);
  applicationData.set(certHash, prefix.length);
  return { hashName, certHash, applicationData };
}
