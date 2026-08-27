// Binary SID / GUID decoding. ADWS returns objectSid and objectGUID as
// base64-encoded binary (the NBFX Bytes records), so the modes decode them to
// the canonical string forms BloodHound and operators expect.

export function b64ToBytes(b64) {
  if (typeof atob === 'function') {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

// [MS-DTYP] SID: revision(1) subAuthCount(1) idAuthority(6, big-endian)
// subAuthorities(subAuthCount * 4, little-endian).
export function bytesToSid(bytes) {
  if (!bytes || bytes.length < 8) return null;
  const rev = bytes[0];
  const count = bytes[1];
  let authority = 0;
  for (let i = 2; i < 8; i++) authority = authority * 256 + bytes[i];
  let sid = `S-${rev}-${authority}`;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < count; i++) sid += '-' + dv.getUint32(8 + i * 4, true);
  return sid;
}

export const sidFromB64 = (b64) => bytesToSid(b64ToBytes(b64));

// objectGUID layout: first three fields little-endian, last 8 bytes in order.
export function bytesToGuid(bytes) {
  if (!bytes || bytes.length < 16) return null;
  const h = (n) => n.toString(16).padStart(2, '0');
  const le = (a, b) => { let s = ''; for (let i = b - 1; i >= a; i--) s += h(bytes[i]); return s; };
  const be = (a, b) => { let s = ''; for (let i = a; i < b; i++) s += h(bytes[i]); return s; };
  return `${le(0, 4)}-${le(4, 6)}-${le(6, 8)}-${be(8, 10)}-${be(10, 16)}`;
}

export const guidFromB64 = (b64) => bytesToGuid(b64ToBytes(b64));
