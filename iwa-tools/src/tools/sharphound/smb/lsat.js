// LSAT (MS-LSAT) over DCE-RPC: resolve SIDs to account names + types via
// LsarLookupSids. Used to name principals that aren't in the directory cache —
// local accounts/groups on a member host, well-known SIDs, and cross-domain SIDs.

import { DceRpc } from './dcerpc.js';
import { NdrReader, sidStringToNdr } from './ndr.js';
import { concat } from '../ldap/ber.js';

const LSA_UUID = '12345778-1234-abcd-ef00-0123456789ab';
const POLICY_LOOKUP_NAMES = 0x00000800;
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

// SID_NAME_USE -> BloodHound ObjectType.
const USE_TYPE = { 1: 'User', 2: 'Group', 4: 'Group', 5: 'Group', 8: 'Domain', 9: 'Computer' };

const OP = { CLOSE: 0, LOOKUP_SIDS: 15, OPEN_POLICY2: 44 };

export class Lsat {
  constructor(transceive) { this.rpc = new DceRpc(transceive); }
  async bind() { await this.rpc.bind(LSA_UUID, '0.0'); }

  async openPolicy() {
    const objectAttributes = concat([u32(24), u32(0), u32(0), u32(0), u32(0), u32(0)]); // Length=24, all ptrs null
    const stub = concat([u32(0) /* SystemName=null */, objectAttributes, u32(POLICY_LOOKUP_NAMES)]);
    const out = await this.rpc.call(OP.OPEN_POLICY2, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    if (dv.getUint32(out.length - 4, true)) throw new Error('LsarOpenPolicy2 failed');
    return out.slice(0, 20);
  }

  // sids: ["S-1-5-…", …] -> [{ sid, name, domain, type }]
  async lookupSids(policy, sids) {
    const arr = [u32(sids.length), u32(0x00020000), u32(sids.length)];
    for (let i = 0; i < sids.length; i++) arr.push(u32(0x00030000 + i)); // a referent per SID pointer
    for (const s of sids) arr.push(sidStringToNdr(s));
    const stub = concat([
      policy,                 // PolicyHandle
      concat(arr),            // LSAPR_SID_ENUM_BUFFER
      u32(0), u32(0),         // TranslatedNames in: Entries=0, Names=null
      u32(1),                 // LookupLevel = LsapLookupWksta
      u32(0),                 // MappedCount
    ]);
    return this._parse(await this.rpc.call(OP.LOOKUP_SIDS, stub), sids);
  }

  _parse(out, sids) {
    const r = new NdrReader(out);
    // --- ReferencedDomains: PLSAPR_REFERENCED_DOMAIN_LIST* ---
    const domains = [];
    if (r.u32()) {                       // referent
      const entries = r.u32();
      const arrRef = r.u32();
      r.u32();                           // MaxEntries
      if (arrRef) {
        r.u32();                         // MaxCount
        const tmp = [];
        for (let i = 0; i < entries; i++) { r.u16(); r.u16(); const bref = r.u32(); const sref = r.u32(); tmp.push({ bref, sref }); }
        for (const t of tmp) { t.name = t.bref ? r.uniString() : ''; if (t.sref) r.sid(); }
        for (const t of tmp) domains.push(t.name);
      }
    }
    // --- TranslatedNames: [in,out] LSAPR_TRANSLATED_NAMES ---
    const result = sids.map((s) => ({ sid: s, name: null, domain: null, type: 'Base' }));
    const tnEntries = r.u32();
    if (r.u32()) {                       // Names referent
      r.u32();                           // MaxCount
      const tmp = [];
      for (let i = 0; i < tnEntries; i++) { const use = r.u16(); r.u16(); r.u16(); const bref = r.u32(); const domIdx = r.u32() | 0; tmp.push({ use, bref, domIdx }); }
      for (let i = 0; i < tnEntries; i++) {
        const t = tmp[i];
        const name = t.bref ? r.uniString() : '';
        const domain = t.domIdx >= 0 && t.domIdx < domains.length ? domains[t.domIdx] : null;
        result[i] = { sid: sids[i], name, domain, type: USE_TYPE[t.use] || 'Base' };
      }
    }
    return result;
  }

  async close(h) { try { await this.rpc.call(OP.CLOSE, h); } catch { /* ignore */ } }
}
