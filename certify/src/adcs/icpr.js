// MS-ICPR (ICertPassage Remote Protocol): submit a PKCS#10 CSR to a CA and get
// the issued certificate back, over the project's SMB2 + DCE-RPC stack (\cert
// named pipe on the CA host). CertServerRequest is opnum 0.

import { Smb2Client } from '../smb/smb2.js';
import { DceRpc } from '../smb/dcerpc.js';
import { NdrReader, ndrUniqueWString } from '../smb/ndr.js';
import { concat, readTLV } from '../ldap/ber.js';

const ICPR_UUID = '91ae6020-9e3c-11cf-8d7c-00aa00c091be';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const utf16leZ = (s) => { const b = new Uint8Array(s.length * 2 + 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };

// CERTTRANSBLOB { DWORD cb; [size_is(cb), unique] BYTE* pb; }
function certTransBlob(bytes, ref) {
  if (!bytes || !bytes.length) return concat([u32(0), u32(0)]); // cb=0, pb=NULL
  const pad = (4 - (bytes.length % 4)) % 4;
  return concat([u32(bytes.length), u32(ref), u32(bytes.length), bytes, new Uint8Array(pad)]);
}

const DISPOSITION = { 0: 'incomplete', 1: 'error', 2: 'denied', 3: 'issued', 4: 'issued out-of-band', 5: 'under submission', 6: 'revoked' };

export async function requestCertificate(host, creds, { caName, template, csr, log = () => {} }) {
  const c = new Smb2Client(host, 445, () => {});
  try {
    await c.connect(); await c.negotiate(); await c.login(creds);
    const tid = await c.treeConnect('IPC$');
    const fid = await c.createPipe(tid, 'cert');
    const rpc = new DceRpc((b) => c.transceive(tid, fid, b), { writeOnly: (b) => c.writePipe(tid, fid, b) });
    await rpc.bind(ICPR_UUID, '0.0', { user: creds.user, domain: creds.domain, password: creds.password, level: 6 }); // ICPR needs RPC auth (packet privacy)
    log(`ICPR bound (authenticated) on \\\\${host}\\cert; requesting ${template} from ${caName} …`);

    const attribs = utf16leZ(`CertificateTemplate:${template}`);
    const stub = concat([
      u32(0),                             // dwFlags
      ndrUniqueWString(caName),           // pwszAuthority
      u32(0),                             // pdwRequestId (in)
      certTransBlob(attribs, 0x00030000), // pctbAttribs
      certTransBlob(csr, 0x00040000),     // pctbRequest
    ]);
    const out = await rpc.call(0, stub);
    if (globalThis.__ICPR_DEBUG) log(`raw response (${out.length}B): ${[...out.slice(0, 48)].map((x) => x.toString(16).padStart(2, '0')).join('')}`);

    const r = new NdrReader(out);
    const requestId = r.u32();
    const disposition = r.u32();
    const readBlob = () => { const cb = r.u32(); const ref = r.u32(); if (!ref) return new Uint8Array(0); r.u32(); const b = Uint8Array.from(r.bytes(cb)); r.align(4); return b; };
    const cert = readBlob();          // pctbCert (usually a PKCS#7)
    readBlob();                       // pctbEncodedCert
    const dispMsgRaw = readBlob();    // pctbDispositionMessage (UTF-16LE)
    let dispMsg = ''; for (let i = 0; i + 1 < dispMsgRaw.length; i += 2) { const ch = dispMsgRaw[i] | (dispMsgRaw[i + 1] << 8); if (ch) dispMsg += String.fromCharCode(ch); }

    await c.closeFile(tid, fid); await c.close();
    return { requestId, disposition, dispositionText: DISPOSITION[disposition] || `0x${disposition.toString(16)}`, message: dispMsg, cert };
  } catch (e) {
    try { await c.close(); } catch { /* ignore */ }
    throw e;
  }
}

// True if a Certificate's Issuer and Subject Names are identical (a CA/root cert).
function isSelfSigned(cert) {
  try {
    const outer = readTLV(cert, 0);
    const tbs = readTLV(cert, outer.valueStart);
    const seqs = [];
    for (let q = tbs.valueStart; q < tbs.valueEnd;) { const t = readTLV(cert, q); if (t.tag === 0x30) seqs.push([q, t.next]); q = t.next; }
    const [is, ie] = seqs[1]; const [ss, se] = seqs[3]; // sigAlg, issuer, validity, subject
    if (ie - is !== se - ss) return false;
    for (let i = 0; i < ie - is; i++) if (cert[is + i] !== cert[ss + i]) return false;
    return true;
  } catch { return false; }
}

// Extract the end-entity (leaf) certificate (DER) from a CMS/PKCS#7 SignedData
// blob. The CA returns a chain; the leaf is the one whose Subject != Issuer.
export function extractLeafCert(der) {
  try {
    const outer = readTLV(der, 0);                    // ContentInfo SEQUENCE
    let contentTypeOid = null; let sdTLV = null;
    for (let p = outer.valueStart; p < outer.valueEnd;) {
      const t = readTLV(der, p);
      if (t.tag === 0x06) contentTypeOid = der.subarray(t.valueStart, t.valueEnd);
      else if (t.tag === 0xa0) sdTLV = t;             // [0] EXPLICIT SignedData
      p = t.next;
    }
    const isP7 = contentTypeOid && [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02].every((b, i) => contentTypeOid[i] === b);
    if (!isP7 || !sdTLV) return der;                  // not a PKCS#7 — assume a bare certificate
    const sd = readTLV(der, sdTLV.valueStart);        // SignedData SEQUENCE
    for (let q = sd.valueStart; q < sd.valueEnd;) {
      const t = readTLV(der, q);
      if (t.tag === 0xa0) {                           // certificates [0] IMPLICIT SET OF Certificate
        const certs = [];
        for (let c = t.valueStart; c < t.valueEnd;) { const e = readTLV(der, c); certs.push(der.subarray(c, e.next)); c = e.next; }
        return certs.find((c) => !isSelfSigned(c)) || certs[certs.length - 1] || der;
      }
      q = t.next;
    }
    return der;
  } catch { return der; }
}
