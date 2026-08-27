// Kerberos 5 ASN.1 (RFC 4120), encoded straight onto the BER helpers in
// ldap/ber.js. We build the request messages the AS/TGS/AP exchanges need and
// parse the replies — only the fields the client flow touches, in the spirit
// of the minimal LDAP encoder rather than a full pyasn1-style schema.

import {
  tlv, concat, octetString, sequence, oid as berOid, readTLV, children,
} from '../ldap/ber.js';
import { MSG_TYPE, NAME_TYPE } from './constants.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- low-level DER helpers -------------------------------------------------

// Minimal two's-complement INTEGER (handles the negative cksumtypes, e.g. -138).
function intBytes(n) {
  if (n === 0) return Uint8Array.of(0);
  let v = BigInt(n);
  const bytes = [];
  if (v > 0n) {
    while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
    if (bytes[0] & 0x80) bytes.unshift(0);
  } else {
    while (v < -1n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
    bytes.unshift(Number(v & 0xffn));
    if (!(bytes[0] & 0x80)) bytes.unshift(0xff);
  }
  return Uint8Array.from(bytes);
}

export const asnInt = (n) => tlv(0x02, intBytes(n));
export const generalString = (s) => tlv(0x1b, typeof s === 'string' ? enc.encode(s) : s);

// [n] constructed context wrapper around one or more already-encoded children.
export const ctx = (n, ...items) => tlv(0xa0 | n, concat(items));
// [APPLICATION n] constructed wrapper (n < 31).
export const app = (n, value) => tlv(0x60 | n, value);

// KerberosTime ::= GeneralizedTime "YYYYMMDDHHMMSSZ".
export function kerberosTime(date) {
  const p = (x, w = 2) => String(x).padStart(w, '0');
  const s = `${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}`
    + `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(0x18, enc.encode(s));
}

// 32-bit BIT STRING for KDCOptions / APOptions (0 unused bits, MSB first).
export function bitString32(value) {
  const b = new Uint8Array(5);
  b[0] = 0x00; // unused bits
  new DataView(b.buffer).setUint32(1, value >>> 0, false);
  return tlv(0x03, b);
}

// ---- composite structures --------------------------------------------------

export function principalName(nameType, components) {
  return sequence(
    ctx(0, asnInt(nameType)),
    ctx(1, sequence(...components.map((c) => generalString(c)))),
  );
}

export function encryptedData(etype, cipher, kvno = null) {
  const parts = [ctx(0, asnInt(etype))];
  if (kvno != null) parts.push(ctx(1, asnInt(kvno)));
  parts.push(ctx(2, octetString(cipher)));
  return sequence(...parts);
}

export function paData(type, valueBytes) {
  return sequence(ctx(1, asnInt(type)), ctx(2, octetString(valueBytes)));
}

// PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1] INTEGER }
export function paEncTsEnc(date, usec = 0) {
  return sequence(ctx(0, kerberosTime(date)), ctx(1, asnInt(usec)));
}

// Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
export function checksumValue(cksumType, bytes) {
  return sequence(ctx(0, asnInt(cksumType)), ctx(1, octetString(bytes)));
}

// EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
export function encryptionKey(etype, keyBytes) {
  return sequence(ctx(0, asnInt(etype)), ctx(1, octetString(keyBytes)));
}

// KDC-REQ-BODY. `cname` may be null (TGS-REQ identifies the client via the
// ticket); `additionalTickets` is a list of raw Ticket byte arrays.
export function kdcReqBody({
  kdcOptions, cname, cnameType = NAME_TYPE.PRINCIPAL, realm,
  sname, snameType = NAME_TYPE.SRV_INST, till, nonce, etypes, additionalTickets = null,
}) {
  const parts = [ctx(0, bitString32(kdcOptions))];
  if (cname) parts.push(ctx(1, principalName(cnameType, cname)));
  parts.push(ctx(2, generalString(realm)));
  if (sname) parts.push(ctx(3, principalName(snameType, sname)));
  parts.push(ctx(5, kerberosTime(till)));
  parts.push(ctx(7, asnInt(nonce)));
  parts.push(ctx(8, sequence(...etypes.map((e) => asnInt(e)))));
  if (additionalTickets) parts.push(ctx(11, sequence(...additionalTickets))); // [11] SEQUENCE OF Ticket (U2U)
  return sequence(...parts);
}

// AS-REQ / TGS-REQ ::= [APPLICATION 10|12] KDC-REQ.
export function kdcReq(msgType, reqBody, padatas = []) {
  const parts = [ctx(1, asnInt(5)), ctx(2, asnInt(msgType))];
  if (padatas.length) parts.push(ctx(3, sequence(...padatas)));
  parts.push(ctx(4, reqBody));
  return app(msgType, sequence(...parts));
}

// Authenticator ::= [APPLICATION 2] SEQUENCE { ... }
export function authenticator({
  crealm, cname, cnameType = NAME_TYPE.PRINCIPAL, ctime, cusec = 0, cksum = null, subkey = null, seqNumber = null,
}) {
  const parts = [
    ctx(0, asnInt(5)),                              // authenticator-vno
    ctx(1, generalString(crealm)),
    ctx(2, principalName(cnameType, cname)),
  ];
  if (cksum) parts.push(ctx(3, cksum));
  parts.push(ctx(4, asnInt(cusec)));
  parts.push(ctx(5, kerberosTime(ctime)));
  if (subkey) parts.push(ctx(6, subkey));
  if (seqNumber != null) parts.push(ctx(7, asnInt(seqNumber)));
  return app(2, sequence(...parts));
}

// AP-REQ ::= [APPLICATION 14] SEQUENCE { ... }. `ticket` is the raw Ticket
// element; `encAuthenticator` is the EncryptedData wrapping the authenticator.
export function apReq({ apOptions, ticket, encAuthenticator }) {
  return app(14, sequence(
    ctx(0, asnInt(5)),
    ctx(1, asnInt(MSG_TYPE.AP_REQ)),
    ctx(2, bitString32(apOptions)),
    ctx(3, ticket),
    ctx(4, encAuthenticator),
  ));
}

// ---- parsing ---------------------------------------------------------------

function tagMap(buf, start, end) {
  const m = {};
  for (const t of children(buf, start, end)) if (m[t.tag] === undefined) m[t.tag] = t;
  return m;
}

// The single element carried inside a [n] context wrapper.
function inner(buf, ctxTlv) { return readTLV(buf, ctxTlv.valueStart); }
function readIntTlv(buf, t) {
  // signed INTEGER -> Number (values here fit comfortably).
  let n = 0n;
  let first = buf[t.valueStart];
  const neg = (first & 0x80) !== 0;
  for (let i = t.valueStart; i < t.valueEnd; i++) n = (n << 8n) | BigInt(buf[i]);
  if (neg) n -= 1n << BigInt(8 * (t.valueEnd - t.valueStart));
  return Number(n);
}
function bytesOf(buf, t) { return buf.slice(t.valueStart, t.valueEnd); }
function strOf(buf, t) { return dec.decode(buf.subarray(t.valueStart, t.valueEnd)); }

// Strip the outer [APPLICATION n] tag and return the inner SEQUENCE TLV.
function unwrapApp(buf) {
  const a = readTLV(buf, 0);
  const seq = readTLV(buf, a.valueStart);
  return { appTag: a.tag & 0x1f, seqStart: seq.valueStart, seqEnd: seq.valueEnd };
}

// EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }.
function parseEncryptedData(buf, t) {
  const m = tagMap(buf, t.valueStart, t.valueEnd);
  return {
    etype: readIntTlv(buf, inner(buf, m[0xa0])),
    kvno: m[0xa1] ? readIntTlv(buf, inner(buf, m[0xa1])) : null,
    cipher: bytesOf(buf, inner(buf, m[0xa2])),
  };
}

// KDC-REP (AS-REP app 11 / TGS-REP app 13). Returns the raw ticket element and
// the EncryptedData enc-part; the caller decrypts enc-part with the right key.
export function parseKdcRep(buf) {
  const { appTag, seqStart, seqEnd } = unwrapApp(buf);
  const m = tagMap(buf, seqStart, seqEnd);
  const msgType = readIntTlv(buf, inner(buf, m[0xa1]));
  return {
    appTag,
    msgType,
    crealm: strOf(buf, inner(buf, m[0xa3])),
    ticket: bytesOf(buf, m[0xa5]), // [5] holds exactly the Ticket element
    encPart: parseEncryptedData(buf, inner(buf, m[0xa6])),
  };
}

// EncKDCRepPart ::= [APPLICATION 25|26] SEQUENCE { key [0] EncryptionKey, ...,
// nonce [2], ..., srealm [9], sname [10] }. We pull out the session key (and a
// few useful fields) after the caller has decrypted it.
export function parseEncKdcRepPart(buf) {
  const { seqStart, seqEnd } = unwrapApp(buf);
  const m = tagMap(buf, seqStart, seqEnd);
  const keyT = inner(buf, m[0xa0]);              // EncryptionKey SEQUENCE
  const km = tagMap(buf, keyT.valueStart, keyT.valueEnd);
  const out = {
    key: {
      etype: readIntTlv(buf, inner(buf, km[0xa0])),
      keyvalue: bytesOf(buf, inner(buf, km[0xa1])),
    },
    nonce: m[0xa2] ? readIntTlv(buf, inner(buf, m[0xa2])) : null,
    srealm: m[0xa9] ? strOf(buf, inner(buf, m[0xa9])) : null,
  };
  if (m[0xa7]) out.endtime = strOf(buf, inner(buf, m[0xa7]));
  return out;
}

// AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0], msg-type [1], enc-part [2] }.
export function parseApRep(buf) {
  const { seqStart, seqEnd } = unwrapApp(buf);
  const m = tagMap(buf, seqStart, seqEnd);
  return { encPart: parseEncryptedData(buf, inner(buf, m[0xa2])) };
}

// EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime [0], cusec [1],
// subkey [2] EncryptionKey OPTIONAL, seq-number [3] OPTIONAL }. The acceptor
// subkey (if present) keys the server's GSS Wrap tokens.
export function parseEncApRepPart(buf) {
  const { seqStart, seqEnd } = unwrapApp(buf);
  const m = tagMap(buf, seqStart, seqEnd);
  const out = { subkey: null, seqNumber: null };
  if (m[0xa2]) {
    const k = inner(buf, m[0xa2]);
    const km = tagMap(buf, k.valueStart, k.valueEnd);
    out.subkey = { etype: readIntTlv(buf, inner(buf, km[0xa0])), keyvalue: bytesOf(buf, inner(buf, km[0xa1])) };
  }
  if (m[0xa3]) out.seqNumber = readIntTlv(buf, inner(buf, m[0xa3]));
  return out;
}

// KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ..., stime [4], susec [5],
// error-code [6], ..., e-data [12] }. We also surface the server time so the
// client can stamp PA-ENC-TIMESTAMP with the KDC's own clock and sidestep
// KRB_AP_ERR_SKEW from a mis-set local clock/timezone.
export function parseKrbError(buf) {
  const { seqStart, seqEnd } = unwrapApp(buf);
  const m = tagMap(buf, seqStart, seqEnd);
  return {
    stime: m[0xa4] ? strOf(buf, inner(buf, m[0xa4])) : null,
    susec: m[0xa5] ? readIntTlv(buf, inner(buf, m[0xa5])) : null,
    errorCode: readIntTlv(buf, inner(buf, m[0xa6])),
    eData: m[0xac] ? bytesOf(buf, inner(buf, m[0xac])) : null,
    realm: m[0xa9] ? strOf(buf, inner(buf, m[0xa9])) : null,
  };
}

// Parse a KerberosTime "YYYYMMDDHHMMSSZ" (always UTC) back to a Date.
export function parseKerberosTime(s) {
  return new Date(Date.UTC(
    +s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8),
    +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14),
  ));
}

// METHOD-DATA ::= SEQUENCE OF PA-DATA. Used to read the PA-ETYPE-INFO2 the KDC
// returns inside a PREAUTH_REQUIRED error's e-data.
export function parseMethodData(buf) {
  const top = readTLV(buf, 0);
  const out = [];
  for (const pa of children(buf, top.valueStart, top.valueEnd)) {
    const m = tagMap(buf, pa.valueStart, pa.valueEnd);
    out.push({
      type: readIntTlv(buf, inner(buf, m[0xa1])),
      value: bytesOf(buf, inner(buf, m[0xa2])),
    });
  }
  return out;
}

// PA-ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY { etype [0], salt [1] OPTIONAL }.
// Returns [{ etype, salt: Uint8Array|null }] in the KDC's preference order.
export function parseEtypeInfo2(buf) {
  const top = readTLV(buf, 0);
  const out = [];
  for (const entry of children(buf, top.valueStart, top.valueEnd)) {
    const m = tagMap(buf, entry.valueStart, entry.valueEnd);
    out.push({
      etype: readIntTlv(buf, inner(buf, m[0xa0])),
      salt: m[0xa1] ? bytesOf(buf, inner(buf, m[0xa1])) : null,
    });
  }
  return out;
}

export { berOid as oid };
