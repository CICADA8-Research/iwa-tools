// Minimal ASN.1 BER encoder/decoder, just enough for the LDAP messages this
// app sends and receives (RFC 4511). Definite-length form only.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  ENUMERATED: 0x0a,
  SEQUENCE: 0x30,
  SET: 0x31,
};

export function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return enc.encode(v);
  throw new TypeError('expected string or Uint8Array');
}

export function concat(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function encodeLength(len) {
  if (len < 0x80) return Uint8Array.of(len);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

// Build a tag-length-value triple from an already-encoded value.
export function tlv(tag, value) {
  const v = value instanceof Uint8Array ? value : toBytes(value);
  const len = encodeLength(v.length);
  const out = new Uint8Array(1 + len.length + v.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(v, 1 + len.length);
  return out;
}

// Encode a non-negative integer as a minimal two's-complement INTEGER body.
function encUInt(n) {
  const bytes = [];
  let v = n;
  if (v === 0) bytes.push(0);
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes[0] & 0x80) bytes.unshift(0); // keep it positive
  return Uint8Array.from(bytes);
}

export const integer = (n) => tlv(TAG.INTEGER, encUInt(n));
export const enumerated = (n) => tlv(TAG.ENUMERATED, encUInt(n));

// DER OBJECT IDENTIFIER encoder, for SPNEGO/GSS mech types.
export function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v = Math.floor(v / 128);
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    bytes.push(...stack);
  }
  return tlv(0x06, Uint8Array.from(bytes));
}
export const boolean = (b) => tlv(TAG.BOOLEAN, Uint8Array.of(b ? 0xff : 0x00));
export const octetString = (s) => tlv(TAG.OCTET_STRING, toBytes(s));
export const sequence = (...items) => tlv(TAG.SEQUENCE, concat(items));
export const set = (...items) => tlv(TAG.SET, concat(items));

// ---- Decoding -------------------------------------------------------------

// Reads one TLV starting at `pos`. Returns the tag, the byte range of the
// value, and the offset of the next element.
export function readTLV(buf, pos = 0) {
  if (pos + 2 > buf.length) return null;
  const tag = buf[pos];
  let i = pos + 1;
  let len = buf[i++];
  if (len & 0x80) {
    const num = len & 0x7f;
    if (i + num > buf.length) return null;
    len = 0;
    for (let k = 0; k < num; k++) len = len * 256 + buf[i++];
  }
  const valueStart = i;
  const valueEnd = i + len;
  if (valueEnd > buf.length) return null; // incomplete
  return { tag, length: len, valueStart, valueEnd, next: valueEnd };
}

// Iterate the child TLVs contained in [start, end).
export function* children(buf, start, end) {
  let pos = start;
  while (pos < end) {
    const t = readTLV(buf, pos);
    if (!t) break;
    yield t;
    pos = t.next;
  }
}

export function readInt(buf, start, end) {
  let n = 0;
  for (let i = start; i < end; i++) n = n * 256 + buf[i];
  return n;
}

export function readString(buf, start, end) {
  return dec.decode(buf.subarray(start, end));
}
