// Kerberos ticket import for the iwa-tools console: parse an MIT credential
// cache (ccache) or a Windows/Rubeus .kirbi (KRB-CRED) into the same ticket
// object shape the Kerberos client produces from getTGT/getTGS, so a stored
// ticket can drive a GSS-SPNEGO bind without ever touching a password.
//
// A parsed ticket object matches KerberosClient's:
//   { ticket:Uint8Array   — the raw [APPLICATION 1] Ticket element
//     sessionKey:{ etype, key:Uint8Array }
//     crealm, cname:[…]    — the client principal (used in the AP-REQ)
//     realm, spn?          — the server principal (spn present for service tickets)
//     clockOffsetMs:0 }
//
// parseTicketFile returns { tgts:[…], serviceTickets:[…] }: tickets whose server
// principal is krbtgt/REALM are TGTs, everything else is a service ticket. The
// console prefers a matching service ticket (pure pass-the-ticket, no KDC) and
// falls back to a TGT (one TGS exchange).

import { readTLV, children, readInt } from './tools/adidns/ldap/ber.js';

const dec = new TextDecoder();

// ---- input coercion (raw DER/ccache bytes, or base64 text) ----------------

function b64ToBytes(s) {
  const clean = s.replace(/\s+/g, '');
  if (typeof atob === 'function') {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(clean, 'base64')); // Node fallback
}

const isBase64Text = (s) => /^[A-Za-z0-9+/=\s]+$/.test(s) && s.replace(/\s+/g, '').length % 4 === 0;

// Normalise assorted inputs (binary bytes, base64 text held as bytes, or a JS
// string) into the binary ticket bytes.
function coerceBytes(input) {
  if (typeof input === 'string') {
    return isBase64Text(input) ? b64ToBytes(input) : new TextEncoder().encode(input);
  }
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  // Binary ccache starts 0x05 0x0N; binary KRB-CRED is [APPLICATION 22] = 0x76.
  if (bytes[0] === 0x05 || bytes[0] === 0x76) return bytes;
  const text = dec.decode(bytes);
  if (isBase64Text(text)) { try { return b64ToBytes(text); } catch { /* fall through */ } }
  return bytes;
}

const isKrbtgt = (components) => (components[0] || '').toLowerCase() === 'krbtgt';

// ---- ccache (MIT credential cache) ----------------------------------------
// Big-endian throughout. Format per the MIT ccache spec / impacket ccache.py.

class Reader {
  constructor(bytes) { this.b = bytes; this.p = 0; this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
  u8() { return this.b[this.p++]; }
  u16() { const v = this.dv.getUint16(this.p, false); this.p += 2; return v; }
  u32() { const v = this.dv.getUint32(this.p, false); this.p += 4; return v; }
  bytes(n) { const v = this.b.subarray(this.p, this.p + n); this.p += n; return v; }
  counted() { return this.bytes(this.u32()); } // counted_octet_string: uint32 len + data
  eof() { return this.p >= this.b.length; }
}

// principal ::= uint32 name_type, uint32 num_components, realm, components…
// (version 0x0501 stores num_components as count+1).
function readPrincipal(r, version) {
  const nameType = r.u32();
  let count = r.u32();
  if (version === 0x0501) count -= 1;
  const realm = dec.decode(r.counted());
  const components = [];
  for (let i = 0; i < count; i++) components.push(dec.decode(r.counted()));
  return { nameType, realm, components };
}

// keyblock ::= uint16 keytype, [uint16 etype only in 0x0503], uint16 keylen, data
function readKeyBlock(r, version) {
  const keytype = r.u16();
  if (version === 0x0503) r.u16(); // duplicate etype, ignored
  const keylen = r.u16();
  return { etype: keytype, key: r.bytes(keylen) };
}

function parseCcache(bytes) {
  const r = new Reader(bytes);
  const version = r.u16();
  if (version < 0x0501 || version > 0x0504) throw new Error(`unsupported ccache version 0x${version.toString(16)}`);
  if (version === 0x0504) { const hlen = r.u16(); r.bytes(hlen); } // tagged header, skip
  readPrincipal(r, version); // default principal, unused

  const tgts = [], serviceTickets = [];
  while (!r.eof()) {
    const client = readPrincipal(r, version);
    const server = readPrincipal(r, version);
    const key = readKeyBlock(r, version);
    r.u32(); r.u32(); r.u32(); r.u32();                       // times: auth/start/end/renew
    r.u8();                                                    // is_skey
    r.u32();                                                   // tktflags
    const nAddr = r.u32();
    for (let i = 0; i < nAddr; i++) { r.u16(); r.counted(); }  // addresses
    const nAuth = r.u32();
    for (let i = 0; i < nAuth; i++) { r.u16(); r.counted(); }  // authdata
    const ticket = r.counted();
    r.counted();                                              // second_ticket (usually empty)
    if (!ticket.length) continue;                             // config entries carry no ticket

    const t = {
      ticket: ticket.slice(),
      sessionKey: { etype: key.etype, key: key.key.slice() },
      crealm: client.realm, cname: client.components,
      realm: server.realm, spn: server.components.join('/'),
      clockOffsetMs: 0,
    };
    (isKrbtgt(server.components) ? tgts : serviceTickets).push(t);
  }
  return { tgts, serviceTickets };
}

// ---- kirbi (KRB-CRED, [APPLICATION 22]) -----------------------------------
// DER helpers over the shared ber reader. A context tag [n] is 0xa0|n and wraps
// exactly one inner element.

// Value slice of the [n] context child within [start,end).
function ctx(buf, start, end, n) {
  for (const c of children(buf, start, end)) {
    if (c.tag === (0xa0 | n)) return { start: c.valueStart, end: c.valueEnd };
  }
  return null;
}
// The one inner element inside a context wrapper.
const inner = (buf, r) => (r ? readTLV(buf, r.start) : null);
const intIn = (buf, r) => { const t = inner(buf, r); return t ? readInt(buf, t.valueStart, t.valueEnd) : null; };
const strIn = (buf, r) => { const t = inner(buf, r); return t ? dec.decode(buf.subarray(t.valueStart, t.valueEnd)) : ''; };

// PrincipalName ::= SEQUENCE { [0] name-type, [1] name-string SEQ OF GeneralString }
function nameStrings(buf, r) {
  if (!r) return [];
  const seq = readTLV(buf, r.start);
  const ns = ctx(buf, seq.valueStart, seq.valueEnd, 1);
  if (!ns) return [];
  const list = readTLV(buf, ns.start);
  const out = [];
  for (const c of children(buf, list.valueStart, list.valueEnd)) out.push(dec.decode(buf.subarray(c.valueStart, c.valueEnd)));
  return out;
}

// EncryptionKey ::= SEQUENCE { [0] keytype INTEGER, [1] keyvalue OCTET STRING }
function encKey(buf, r) {
  const seq = readTLV(buf, r.start);
  const kt = ctx(buf, seq.valueStart, seq.valueEnd, 0);
  const kv = inner(buf, ctx(buf, seq.valueStart, seq.valueEnd, 1));
  return { etype: intIn(buf, kt), key: buf.slice(kv.valueStart, kv.valueEnd) };
}

// KrbCredInfo ::= SEQUENCE { [0] key, [1] prealm, [2] pname, …, [8] srealm, [9] sname }
function krbCredInfo(buf, s, e) {
  const keyF = ctx(buf, s, e, 0);
  return {
    key: keyF ? encKey(buf, keyF) : null,
    prealm: strIn(buf, ctx(buf, s, e, 1)),
    pname: nameStrings(buf, ctx(buf, s, e, 2)),
    srealm: strIn(buf, ctx(buf, s, e, 8)),
    sname: nameStrings(buf, ctx(buf, s, e, 9)),
  };
}

// EncKrbCredPart ::= [APPLICATION 29]=0x7d SEQUENCE { [0] ticket-info SEQ OF KrbCredInfo, … }
function encKrbCredPart(buf, start, end) {
  const app = readTLV(buf, start);
  const seq = readTLV(buf, app.valueStart);
  const ti = ctx(buf, seq.valueStart, seq.valueEnd, 0);
  const tiSeq = readTLV(buf, ti.start);
  const infos = [];
  for (const c of children(buf, tiSeq.valueStart, tiSeq.valueEnd)) infos.push(krbCredInfo(buf, c.valueStart, c.valueEnd));
  return infos;
}

function parseKirbi(bytes) {
  const app = readTLV(bytes, 0);
  if (!app || app.tag !== 0x76) throw new Error('not a KRB-CRED (kirbi)');
  const seq = readTLV(bytes, app.valueStart);
  const s = seq.valueStart, e = seq.valueEnd;

  const ticketsField = ctx(bytes, s, e, 2); // [2] tickets SEQUENCE OF Ticket
  const encPartField = ctx(bytes, s, e, 3); // [3] enc-part EncryptedData
  if (!ticketsField || !encPartField) throw new Error('malformed KRB-CRED');

  // tickets: each child is a raw [APPLICATION 1] Ticket (0x61…); keep the whole
  // element (tag+len+value) by slicing from its own offset to its end.
  const ticketSeq = readTLV(bytes, ticketsField.start);
  const rawTickets = [];
  for (let pos = ticketSeq.valueStart; pos < ticketSeq.valueEnd;) {
    const c = readTLV(bytes, pos);
    if (!c) break;
    rawTickets.push(bytes.slice(pos, c.next));
    pos = c.next;
  }

  // enc-part cipher (etype 0 = plaintext EncKrbCredPart — the Rubeus case).
  const edSeq = readTLV(bytes, encPartField.start);
  const edEtype = intIn(bytes, ctx(bytes, edSeq.valueStart, edSeq.valueEnd, 0));
  if (edEtype !== 0) throw new Error('encrypted KRB-CRED not supported (need a plaintext .kirbi)');
  const cipher = inner(bytes, ctx(bytes, edSeq.valueStart, edSeq.valueEnd, 2)); // OCTET STRING
  const infos = encKrbCredPart(bytes, cipher.valueStart, cipher.valueEnd);

  const tgts = [], serviceTickets = [];
  rawTickets.forEach((rawTicket, i) => {
    const info = infos[i] || infos[0] || {};
    const t = {
      ticket: rawTicket,
      sessionKey: info.key || { etype: 0, key: new Uint8Array(0) },
      crealm: info.prealm || '', cname: info.pname || [],
      realm: info.srealm || '', spn: (info.sname || []).join('/'),
      clockOffsetMs: 0,
    };
    (isKrbtgt(info.sname || []) ? tgts : serviceTickets).push(t);
  });
  return { tgts, serviceTickets };
}

// ---- entry point -----------------------------------------------------------

export function parseTicketFile(input) {
  const bytes = coerceBytes(input);
  if (bytes[0] === 0x05) return parseCcache(bytes);
  if (bytes[0] === 0x76) return parseKirbi(bytes);
  throw new Error('unrecognised ticket file (expected ccache 0x05… or kirbi/KRB-CRED 0x76…)');
}

// ---- ccache writer --------------------------------------------------------
// Minimal MIT ccache v4 (0x0504) with a single credential entry. Impacket's
// ccache.py, MIT klist, and Rubeus /ptt all accept this layout.

const encB = new TextEncoder();
const be16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, false); return b; };
const be32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
function catBytes(...arrs) { let total = 0; for (const a of arrs) total += a.length; const out = new Uint8Array(total); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; }
function counted(bytes) { return catBytes(be32(bytes.length), bytes); }

// principal ::= u32 name_type, u32 num_components, counted(realm), counted(component)*
function encPrincipal({ nameType = 1, realm, components }) {
  const parts = [be32(nameType), be32(components.length), counted(encB.encode(realm))];
  for (const c of components) parts.push(counted(encB.encode(c)));
  return catBytes(...parts);
}
// keyblock v4: u16 keytype, u16 keylen, key bytes
function encKeyBlockV4({ etype, key }) {
  return catBytes(be16(etype), be16(key.length), key);
}

// Build a ccache 0x0504 that carries one TGT. `tgt` matches the shape returned
// by KerberosClient.getTGT / getTgtPkinit:
//   { ticket:Uint8Array, sessionKey:{etype,key}, username, realm, cname?[], crealm? }
export function buildCcache(tgt) {
  const realm = tgt.realm || tgt.crealm;
  const client = { nameType: 1, realm: tgt.crealm || realm, components: tgt.cname && tgt.cname.length ? tgt.cname : [tgt.username] };
  const server = { nameType: 2, realm, components: ['krbtgt', realm] };
  const nowSec = Math.floor(Date.now() / 1000);
  const endSec = nowSec + 10 * 3600;                 // 10-hour lifetime placeholder
  const flags = 0x50a00000;                          // forwardable | proxiable | renewable | initial | pre-auth
  const cred = catBytes(
    encPrincipal(client),
    encPrincipal(server),
    encKeyBlockV4(tgt.sessionKey),
    be32(nowSec), be32(nowSec), be32(endSec), be32(endSec),
    Uint8Array.of(0),                                 // is_skey
    be32(flags),
    be32(0),                                          // addresses count
    be32(0),                                          // authdata count
    counted(tgt.ticket),
    counted(new Uint8Array(0)),                       // second_ticket
  );
  const header = catBytes(be16(1), be16(8), be32(nowSec * 1000), be32(0));  // tag 1 = DeltaTime, len 8, sec+usec
  return catBytes(
    be16(0x0504),                                     // version
    be16(header.length), header,
    encPrincipal(client),                             // default principal
    cred,
  );
}
