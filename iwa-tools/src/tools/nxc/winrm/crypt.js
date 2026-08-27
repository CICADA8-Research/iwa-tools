// WinRM message encryption (MS-WSMV 2.2.9.1). Over HTTP, WinRM requires the SOAP
// payload to be wrapped as multipart/encrypted using the negotiated SSP. For
// NTLM/Negotiate the "encrypted" octet-stream is:
//     <4-byte LE signature length><signature(16)><sealed SOAP bytes>
// which is exactly the NTLM GSS_WrapEx output we already produce in
// NtlmSession.seal() (signature(16) || sealed) with a length prefix. Using
// encryption unconditionally works against both default (AllowUnencrypted=false)
// and relaxed WinRM configs.

const enc = new TextEncoder();
const dec = new TextDecoder();

const BOUNDARY = 'Encrypted Boundary';
const PROTOCOL = 'application/HTTP-SPNEGO-session-encrypted';
export const ENCRYPTED_CONTENT_TYPE =
  `multipart/encrypted;protocol="${PROTOCOL}";boundary="${BOUNDARY}"`;

function concat(arrays) {
  let t = 0; for (const a of arrays) t += a.length;
  const o = new Uint8Array(t); let off = 0;
  for (const a of arrays) { o.set(a, off); off += a.length; }
  return o;
}
function u32le(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }

// SOAP XML string -> { contentType, body } for an encrypted WinRM POST.
export function wrapEncrypted(session, soapXml) {
  const plain = enc.encode(soapXml);
  // signature/trailer length differs per SSP (NTLM=16; Kerberos AES varies),
  // so the session reports it. blob = securityTrailer || encryptedData.
  const { sigLen, blob } = session.wrapForHttp(plain);
  const octet = concat([u32le(sigLen), blob]);
  const body = concat([
    enc.encode(`--${BOUNDARY}\r\n`),
    enc.encode(`\tContent-Type: ${PROTOCOL}\r\n`),
    enc.encode(`\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${plain.length}\r\n`),
    enc.encode(`--${BOUNDARY}\r\n`),
    enc.encode('\tContent-Type: application/octet-stream\r\n'),
    octet,
    enc.encode(`--${BOUNDARY}--\r\n`),
  ]);
  return { contentType: ENCRYPTED_CONTENT_TYPE, body };
}

function indexOfSeq(buf, seq, from = 0) {
  outer: for (let i = from; i <= buf.length - seq.length; i++) {
    for (let j = 0; j < seq.length; j++) if (buf[i + j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}

// Encrypted multipart response bytes -> SOAP XML string.
export function unwrapEncrypted(session, bodyBytes) {
  // The octet-stream payload begins right after this header line; it ends at the
  // next boundary marker.
  const marker = enc.encode('Content-Type: application/octet-stream\r\n');
  const start = indexOfSeq(bodyBytes, marker);
  if (start < 0) throw new Error('WinRM: no octet-stream part in encrypted response');
  let p = start + marker.length;
  const bEnd = indexOfSeq(bodyBytes, enc.encode(`--${BOUNDARY}`), p);
  const octet = bodyBytes.subarray(p, bEnd < 0 ? bodyBytes.length : bEnd);
  // <4-byte sig length><signature><ciphertext>; unseal() takes signature||cipher.
  const sigLen = new DataView(octet.buffer, octet.byteOffset).getUint32(0, true);
  const plain = session.unseal(octet.subarray(4));
  void sigLen;
  return dec.decode(plain);
}
