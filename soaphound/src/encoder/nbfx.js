// .NET Binary Format: XML (MC-NBFX) record codec — the binary XML SOAP bodies
// ADWS exchanges. Ported from SoaPy's src/encoder/records/*. We ENCODE requests
// using only literal (non-dictionary) record forms; we DECODE responses across
// the full range of element/attribute/text records the server emits, resolving
// dictionary strings against the static table plus the server's in-band session
// dictionary.

import { STATIC_DICTIONARY } from './dictionary.js';
import { el, text } from './xml.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const dec16 = new TextDecoder('utf-16le');

// ---- byte reader ----------------------------------------------------------
class Reader {
  constructor(buf) { this.b = buf; this.p = 0; this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength); }
  eof() { return this.p >= this.b.length; }
  u8() { return this.b[this.p++]; }
  i8() { return this.dv.getInt8(this.p++); }
  u16() { const v = this.dv.getUint16(this.p, true); this.p += 2; return v; }
  i16() { const v = this.dv.getInt16(this.p, true); this.p += 2; return v; }
  i32() { const v = this.dv.getInt32(this.p, true); this.p += 4; return v; }
  u32() { const v = this.dv.getUint32(this.p, true); this.p += 4; return v; }
  f32() { const v = this.dv.getFloat32(this.p, true); this.p += 4; return v; }
  f64() { const v = this.dv.getFloat64(this.p, true); this.p += 8; return v; }
  i64() { const v = this.dv.getBigInt64(this.p, true); this.p += 8; return v; }
  u64() { const v = this.dv.getBigUint64(this.p, true); this.p += 8; return v; }
  bytes(n) { const s = this.b.subarray(this.p, this.p + n); this.p += n; return s; }
  mbi() { let v = 0, sh = 0, b; do { b = this.b[this.p++]; v |= (b & 0x7f) << sh; sh += 7; } while (b & 0x80); return v >>> 0; }
  utf8() { const n = this.mbi(); return dec.decode(this.bytes(n)); }
}

// ---- varint / string writers (encoder) ------------------------------------
export function mbiBytes(n) {
  const out = []; let v = n >>> 0;
  do { let b = v & 0x7f; v >>>= 7; if (v) b |= 0x80; out.push(b); } while (v);
  return Uint8Array.from(out);
}
function concat(arrays) {
  let t = 0; for (const a of arrays) t += a.length;
  const o = new Uint8Array(t); let off = 0;
  for (const a of arrays) { o.set(a, off); off += a.length; }
  return o;
}
function strBytes(s) { const u = enc.encode(s); return concat([mbiBytes(u.length), u]); }

// Text value record for a string (encoder): Chars8/16/32 by length.
function textRecord(s) {
  const u = enc.encode(s);
  if (u.length < 0x100) return concat([Uint8Array.of(0x98, u.length), u]);
  if (u.length < 0x10000) { const h = new Uint8Array(2); new DataView(h.buffer).setUint16(0, u.length, true); return concat([Uint8Array.of(0x9a), h, u]); }
  const h = new Uint8Array(4); new DataView(h.buffer).setUint32(0, u.length, true);
  return concat([Uint8Array.of(0x9c), h, u]);
}

// ---- dictionary lookup ----------------------------------------------------
// Even key -> static dictionary; odd key -> server in-band session dictionary.
function dictLookup(key, session) {
  if (key & 1) return session[key] !== undefined ? session[key] : `dict_${key}`;
  return STATIC_DICTIONARY[key] !== undefined ? STATIC_DICTIONARY[key] : `dict_${key}`;
}

// ---- ENCODER: XML forest -> NBFX bytes ------------------------------------
export function encodeRecords(nodes) {
  const parts = [];
  for (const n of nodes) emitNode(n, parts);
  return concat(parts);
}

function emitNode(n, parts) {
  if (n.kind === 'text') { parts.push(textRecord(n.value)); return; }
  // element
  if (n.prefix) parts.push(Uint8Array.of(0x41), strBytes(n.prefix), strBytes(n.name));
  else parts.push(Uint8Array.of(0x40), strBytes(n.name));
  for (const a of n.attrs) {
    if (a.xmlns) {
      if (a.prefix) parts.push(Uint8Array.of(0x09), strBytes(a.prefix), strBytes(a.value));
      else parts.push(Uint8Array.of(0x08), strBytes(a.value));
    } else if (a.prefix) {
      parts.push(Uint8Array.of(0x05), strBytes(a.prefix), strBytes(a.name), textRecord(a.value));
    } else {
      parts.push(Uint8Array.of(0x04), strBytes(a.name), textRecord(a.value));
    }
  }
  for (const c of n.children) emitNode(c, parts);
  parts.push(Uint8Array.of(0x01)); // EndElement
}

// ---- DECODER: NBFX bytes -> XML forest ------------------------------------
export function decodeRecords(buf, session = {}) {
  const r = new Reader(buf);
  const roots = [];
  const stack = [{ children: roots, attrs: null }];
  const top = () => stack[stack.length - 1];
  let lastEl = null;

  while (!r.eof()) {
    const type = r.u8();
    if (type === 0x01) { // EndElement
      if (stack.length > 1) stack.pop();
      lastEl = null;
      continue;
    }
    if (type === 0x02) { r.utf8(); continue; }            // Comment — skip
    if (type >= 0x40 && type <= 0x77) {                   // element
      const node = parseElement(type, r, session);
      top().children.push(node);
      stack.push(node);
      lastEl = node;
      continue;
    }
    if (type >= 0x04 && type <= 0x3f) {                   // attribute
      const a = parseAttribute(type, r, session);
      if (lastEl) lastEl.attrs.push(a);
      continue;
    }
    if (type >= 0x80) {                                   // text value
      const isEnd = (type & 1) === 1;
      const base = isEnd ? type - 1 : type;
      const value = parseText(base, r, session);
      top().children.push(text(value));
      if (isEnd && stack.length > 1) { stack.pop(); lastEl = null; }
      continue;
    }
    if (type === 0x03) { skipArray(r, session); continue; } // Array — best effort
    // Unknown record: stop to avoid desync.
    throw new Error(`NBFX: unknown record 0x${type.toString(16)} at ${r.p - 1}`);
  }
  return roots;
}

function parseElement(type, r, session) {
  if (type === 0x40) return el('', r.utf8());
  if (type === 0x41) { const p = r.utf8(); return el(p, r.utf8()); }
  if (type === 0x42) return el('', dictLookup(r.mbi(), session));
  if (type === 0x43) { const p = r.utf8(); return el(p, dictLookup(r.mbi(), session)); }
  if (type >= 0x44 && type <= 0x5d) { const ch = String.fromCharCode(type - 0x44 + 97); return el(ch, dictLookup(r.mbi(), session)); }
  // 0x5e..0x77 PrefixElement[a-z]
  const ch = String.fromCharCode(type - 0x5e + 97);
  return el(ch, r.utf8());
}

function parseAttribute(type, r, session) {
  switch (type) {
    case 0x04: { const name = r.utf8(); return { xmlns: false, prefix: '', name, value: parseValue(r, session) }; }
    case 0x05: { const p = r.utf8(); const name = r.utf8(); return { xmlns: false, prefix: p, name, value: parseValue(r, session) }; }
    case 0x06: { const name = dictLookup(r.mbi(), session); return { xmlns: false, prefix: '', name, value: parseValue(r, session) }; }
    case 0x07: { const p = r.utf8(); const name = dictLookup(r.mbi(), session); return { xmlns: false, prefix: p, name, value: parseValue(r, session) }; }
    case 0x08: return { xmlns: true, prefix: '', name: '', value: r.utf8() };
    case 0x09: { const p = r.utf8(); return { xmlns: true, prefix: p, name: '', value: r.utf8() }; }
    case 0x0a: return { xmlns: true, prefix: '', name: '', value: dictLookup(r.mbi(), session) };
    case 0x0b: { const p = r.utf8(); return { xmlns: true, prefix: p, name: '', value: dictLookup(r.mbi(), session) }; }
    default:
      if (type >= 0x0c && type <= 0x25) { const ch = String.fromCharCode(type - 0x0c + 97); const name = dictLookup(r.mbi(), session); return { xmlns: false, prefix: ch, name, value: parseValue(r, session) }; }
      // 0x26..0x3f PrefixAttribute[a-z]
      { const ch = String.fromCharCode(type - 0x26 + 97); const name = r.utf8(); return { xmlns: false, prefix: ch, name, value: parseValue(r, session) }; }
  }
}

// An attribute's value is itself a text record.
function parseValue(r, session) {
  const t = r.u8();
  const base = (t & 1) === 1 && t >= 0x80 ? t - 1 : t;
  return parseText(base, r, session);
}

function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoaPoly(s);
}
function btoaPoly(s) {
  if (typeof btoa === 'function') return btoa(s);
  return Buffer.from(s, 'binary').toString('base64');
}
function hex2(n) { return n.toString(16).padStart(2, '0'); }
function uuidStr(b, urn) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const a = dv.getUint32(0, true), c = dv.getUint16(4, true), d = dv.getUint16(6, true);
  let tail = '';
  for (let i = 8; i < 16; i++) tail += hex2(b[i]);
  const s = `${a.toString(16).padStart(8, '0')}-${c.toString(16).padStart(4, '0')}-${d.toString(16).padStart(4, '0')}-${tail.slice(0, 4)}-${tail.slice(4)}`;
  return urn ? `urn:uuid:${s}` : s;
}

function parseText(base, r, session) {
  switch (base) {
    case 0x80: return '0';
    case 0x82: return '1';
    case 0x84: return 'false';
    case 0x86: return 'true';
    case 0x88: return String(r.i8());
    case 0x8a: return String(r.i16());
    case 0x8c: return String(r.i32());
    case 0x8e: return String(r.i64());
    case 0x90: return String(r.f32());
    case 0x92: return String(r.f64());
    case 0x94: { r.bytes(16); return '0'; }                 // Decimal — rare, stub
    case 0x96: return dateTimeText(r.u64());                // DateTime
    case 0x98: return dec.decode(r.bytes(r.u8()));          // Chars8
    case 0x9a: return dec.decode(r.bytes(r.u16()));         // Chars16
    case 0x9c: return dec.decode(r.bytes(r.u32()));         // Chars32
    case 0x9e: return b64(r.bytes(r.u8()));                 // Bytes8 -> base64
    case 0xa0: return b64(r.bytes(r.u16()));                // Bytes16
    case 0xa2: return b64(r.bytes(r.u32()));                // Bytes32
    case 0xa8: return '';                                   // EmptyText
    case 0xaa: return dictLookup(r.mbi(), session);         // DictionaryText
    case 0xac: return uuidStr(r.bytes(16), true);           // UniqueId (urn:uuid)
    case 0xb0: return uuidStr(r.bytes(16), false);          // Uuid
    case 0xb2: return String(r.u64());                      // UInt64
    case 0xb4: return r.u8() === 1 ? 'true' : 'false';      // Bool
    case 0xb6: return dec16.decode(r.bytes(r.u8()));        // UnicodeChars8
    case 0xb8: return dec16.decode(r.bytes(r.u16()));       // UnicodeChars16
    case 0xba: return dec16.decode(r.bytes(r.u32()));       // UnicodeChars32
    case 0xbc: { const pre = String.fromCharCode(r.u8() + 97); return `${pre}:${dictLookup(r.mbi(), session)}`; }
    case 0xa4: case 0xa6: return '';                        // Start/End list
    default: throw new Error(`NBFX: unsupported text record 0x${base.toString(16)}`);
  }
}

// .NET DateTime: low 62 bits = ticks (100ns since 0001-01-01), top 2 = kind.
function dateTimeText(u64) {
  const ticks = u64 & 0x3fffffffffffffffn;
  const ms = ticks / 10000n - 62135596800000n; // ticks->ms, shift epoch to 1970
  try { return new Date(Number(ms)).toISOString(); } catch { return String(ticks); }
}

// Array records are uncommon in ADWS query responses; skip safely if seen.
function skipArray(r, session) {
  const elemType = r.u8();
  parseElement(elemType, r, session);
  let b; do { b = r.u8(); } while (b !== 0x01); // to EndElement
  const recType = r.u8();
  const count = r.mbi();
  for (let i = 0; i < count; i++) parseText(recType - 1, r, session);
}
