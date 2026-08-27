// Parse an nTSecurityDescriptor ([MS-DTYP] SECURITY_DESCRIPTOR) into a BloodHound
// "Aces" list. We read the owner and the DACL, then map each ACE's access mask
// (and object-type GUID, for object ACEs) to a BloodHound right name following
// SharpHound's ACL processing. Inbound descriptors are base64 (NBFX bytes).

import { bytesToSid, b64ToBytes } from './sid.js';

// ADS access-right bits we care about.
const R = {
  GENERIC_ALL: 0x10000000,
  GENERIC_WRITE: 0x40000000,
  WRITE_OWNER: 0x00080000,
  WRITE_DACL: 0x00040000,
  CONTROL_ACCESS: 0x00000100, // DS-Control-Access (extended right)
  WRITE_PROP: 0x00000020,
  SELF: 0x00000008,
  ALL_FULL: 0x000f01ff,
};

// Well-known schema GUIDs (object-type of object ACEs).
const GUID = {
  GetChanges: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
  GetChangesAll: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
  GetChangesInFilteredSet: '89e95b76-444d-4c62-991a-0facbeda640c',
  ForceChangePassword: '00299570-246d-11d0-a768-00aa006e0529',
  AddMember: 'bf9679c0-0de6-11d0-a285-00aa003049e2',
  AddKeyCredentialLink: '5b47d60f-6090-40b2-9f37-2a4de88f3063',
  WriteSPN: 'f3a64788-5306-11d1-a9c5-0000f80367c1',
  AllowedToAct: '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79',
};

function guidLE(bytes, off) {
  const h = (n) => bytes[n].toString(16).padStart(2, '0');
  const le = (a, b) => { let s = ''; for (let i = b - 1; i >= a; i--) s += h(off + i); return s; };
  const be = (a, b) => { let s = ''; for (let i = a; i < b; i++) s += h(off + i); return s; };
  return `${le(0, 4)}-${le(4, 6)}-${le(6, 8)}-${be(8, 10)}-${be(10, 16)}`;
}

// Returns { ownerSid, control, aces:[{sid, mask, objectType, flags}] }
export function parseDescriptor(bytes) {
  if (!bytes || bytes.length < 20) return { ownerSid: null, control: 0, aces: [] };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const control = dv.getUint16(2, true);
  const ownerOff = dv.getUint32(4, true);
  const daclOff = dv.getUint32(16, true);
  const ownerSid = ownerOff ? bytesToSid(bytes.subarray(ownerOff)) : null;

  const aces = [];
  if (daclOff && daclOff + 8 <= bytes.length) {
    const aceCount = dv.getUint16(daclOff + 4, true);
    let p = daclOff + 8;
    for (let i = 0; i < aceCount && p + 4 <= bytes.length; i++) {
      const aceType = bytes[p];
      const flags = bytes[p + 1];
      const size = dv.getUint16(p + 2, true);
      const mask = dv.getUint32(p + 4, true);
      let q = p + 8;
      let objectType = null;
      if (aceType === 0x05 || aceType === 0x06 || aceType === 0x07) { // *_OBJECT aces
        const objFlags = dv.getUint32(q, true); q += 4;
        if (objFlags & 0x1) { objectType = guidLE(bytes, q); q += 16; }       // ACE_OBJECT_TYPE_PRESENT
        if (objFlags & 0x2) { q += 16; }                                       // INHERITED_OBJECT_TYPE_PRESENT
      }
      const sid = bytesToSid(bytes.subarray(q));
      if (aceType === 0x00 || aceType === 0x05) { // ACCESS_ALLOWED / _OBJECT
        aces.push({ sid, mask, objectType, flags });
      }
      p += size;
    }
  }
  return { ownerSid, control, aces };
}

// Map one parsed ACE to zero or more BloodHound right names.
function rightsFor(ace) {
  const m = ace.mask;
  const out = [];
  if ((m & R.GENERIC_ALL) || (m & R.ALL_FULL) === R.ALL_FULL) { out.push('GenericAll'); return out; }
  if (m & R.WRITE_OWNER) out.push('WriteOwner');
  if (m & R.WRITE_DACL) out.push('WriteDacl');
  if (m & R.GENERIC_WRITE) out.push('GenericWrite');

  const ot = ace.objectType;
  if (m & R.CONTROL_ACCESS) {
    if (!ot) out.push('AllExtendedRights');
    else if (ot === GUID.GetChanges) out.push('GetChanges');
    else if (ot === GUID.GetChangesAll) out.push('GetChangesAll');
    else if (ot === GUID.GetChangesInFilteredSet) out.push('GetChangesInFilteredSet');
    else if (ot === GUID.ForceChangePassword) out.push('ForceChangePassword');
  }
  if (m & (R.WRITE_PROP | R.SELF)) {
    if (!ot) { if (!(m & R.GENERIC_WRITE)) out.push('GenericWrite'); }
    else if (ot === GUID.AddMember) out.push((m & R.SELF) && !(m & R.WRITE_PROP) ? 'AddSelf' : 'AddMember');
    else if (ot === GUID.AddKeyCredentialLink) out.push('AddKeyCredentialLink');
    else if (ot === GUID.WriteSPN) out.push('WriteSPN');
    else if (ot === GUID.AllowedToAct) out.push('WriteAccountRestrictions');
  }
  return out;
}

// Produce BloodHound Aces from a base64 nTSecurityDescriptor. `typeOf(sid)`
// resolves a SID to a BloodHound principal type via the cache.
export function acesFromDescriptor(b64, typeOf) {
  if (!b64) return [];
  let parsed;
  try { parsed = parseDescriptor(b64ToBytes(b64)); } catch { return []; }
  const aces = [];
  if (parsed.ownerSid) {
    aces.push({ PrincipalSID: parsed.ownerSid, PrincipalType: typeOf(parsed.ownerSid), RightName: 'Owns', IsInherited: false });
  }
  for (const ace of parsed.aces) {
    if (!ace.sid) continue;
    const inherited = (ace.flags & 0x10) !== 0; // INHERITED_ACE
    for (const right of rightsFor(ace)) {
      aces.push({ PrincipalSID: ace.sid, PrincipalType: typeOf(ace.sid), RightName: right, IsInherited: inherited });
    }
  }
  return aces;
}

// True if the DACL is protected from inheritance (SE_DACL_PROTECTED) — BloodHound
// IsACLProtected.
export function descriptorIsProtected(b64) {
  if (!b64) return false;
  try { return (parseDescriptor(b64ToBytes(b64)).control & 0x1000) !== 0; } catch { return false; }
}

// The trustee SIDs allowed in a descriptor's DACL — used to read the principals
// out of msDS-AllowedToActOnBehalfOfOtherIdentity (resource-based delegation).
export function daclPrincipals(b64) {
  if (!b64) return [];
  try { return parseDescriptor(b64ToBytes(b64)).aces.map((a) => a.sid).filter(Boolean); } catch { return []; }
}
