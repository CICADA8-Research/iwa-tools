// Just enough NDR (little-endian) marshalling for the SAMR/LSAT calls the host
// collector makes: reading context handles and SID arrays, and writing SIDs and
// `[string, unique]` wide strings.

import { concat } from '../ldap/ber.js';

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

// "S-1-5-32" -> RPC_SID conformant bytes (MaxCount + Revision + Count + IdAuth + SubAuthorities).
export function sidStringToNdr(sidStr) {
  const p = sidStr.split('-');
  const rev = Number(p[1]); const idauth = Number(p[2]);
  const subs = p.slice(3).map(Number);
  const out = new Uint8Array(12 + subs.length * 4);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, subs.length, true); // MaxCount = SubAuthorityCount
  out[4] = rev; out[5] = subs.length;
  dv.setUint32(8, idauth, false);     // IdentifierAuthority: 6 bytes BE (high 2 are 0)
  let off = 12;
  for (const s of subs) { dv.setUint32(off, s >>> 0, true); off += 4; }
  return out;
}

// A `[string, unique]` wide string: referent + conformant-varying wchar array.
export function ndrUniqueWString(s) {
  const n = s.length + 1; // include NUL
  const body = new Uint8Array(n * 2);
  for (let i = 0; i < s.length; i++) { body[i * 2] = s.charCodeAt(i) & 0xff; body[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  const padded = new Uint8Array(body.length + ((4 - (body.length % 4)) % 4));
  padded.set(body);
  return concat([u32(0x00020000), u32(n), u32(0), u32(n), padded]); // referent, MaxCount, Offset, ActualCount, chars
}

export class NdrReader {
  constructor(buf) { this.b = buf; this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength); this.p = 0; }
  align(n) { this.p = (this.p + (n - 1)) & ~(n - 1); }
  u8() { return this.b[this.p++]; }
  u16() { this.align(2); const v = this.dv.getUint16(this.p, true); this.p += 2; return v; }
  u32() { this.align(4); const v = this.dv.getUint32(this.p, true); this.p += 4; return v; }
  bytes(n) { const v = this.b.subarray(this.p, this.p + n); this.p += n; return v; }
  remaining() { return this.b.length - this.p; }

  // A deferred RPC_UNICODE_STRING buffer: MaxCount, Offset, ActualCount, chars.
  uniString() {
    this.u32(); this.u32(); const actual = this.u32();
    let s = '';
    for (let i = 0; i < actual; i++) { const c = this.u16(); if (c) s += String.fromCharCode(c); }
    return s;
  }

  wstring() {
    const max = this.u32(); const off = this.u32(); const actual = this.u32();
    let s = '';
    for (let i = 0; i < actual; i++) { const c = this.u16(); if (c) s += String.fromCharCode(c); }
    this.align(4);
    return s;
  }

  // RPC_SID (conformant) -> "S-1-5-…".
  sid() {
    const sub = this.u32();          // MaxCount = SubAuthorityCount
    const rev = this.u8(); const cnt = this.u8();
    const ia = this.bytes(6);
    let auth = 0; for (const x of ia) auth = auth * 256 + x;
    const subs = [];
    for (let i = 0; i < cnt; i++) subs.push(this.u32());
    void sub;
    return `S-${rev}-${auth}-${subs.join('-')}`;
  }
}
