// WKSSVC (MS-WKST) over DCE-RPC: NetrWkstaUserEnum level 1 — the accounts
// currently logged on to a host (interactive + service logons). BloodHound turns
// these into sessions (user -> this computer).

import { DceRpc } from './dcerpc.js';
import { NdrReader } from './ndr.js';
import { concat } from '../ldap/ber.js';

const WKSSVC_UUID = '6bffd098-a112-3610-9833-46c3f87e345a';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

export class Wkssvc {
  constructor(transceive) { this.rpc = new DceRpc(transceive); }
  async bind() { await this.rpc.bind(WKSSVC_UUID, '1.0'); }

  // -> [{ user, domain }]
  async userEnum() {
    const userInfo = concat([
      u32(1),             // Level
      u32(1),             // WKSTA_USER_ENUM_UNION discriminant
      u32(0x00020000),    // WKSTA_USER_INFO_1_CONTAINER referent
      u32(0),             // EntriesRead = 0
      u32(0),             // Buffer = null
    ]);
    const stub = concat([
      u32(0),             // ServerName = null
      userInfo,
      u32(0xffffffff),    // PreferedMaximumLength
      u32(0),             // ResumeHandle = null
    ]);
    const out = await this.rpc.call(2, stub);
    return this._parse(out);
  }

  _parse(out) {
    const r = new NdrReader(out);
    r.u32(); r.u32();              // Level, union discriminant
    const users = [];
    if (r.u32()) {                 // container referent
      const entriesRead = r.u32();
      if (r.u32()) {               // Buffer referent
        r.u32();                   // MaxCount
        const tmp = [];
        for (let i = 0; i < entriesRead; i++) {
          const uref = r.u32(); const dref = r.u32(); const oref = r.u32(); const sref = r.u32();
          tmp.push({ uref, dref, oref, sref });
        }
        for (const t of tmp) {
          t.user = t.uref ? r.uniString() : '';
          t.domain = t.dref ? r.uniString() : '';
          if (t.oref) r.uniString();   // oth_domains (discard)
          if (t.sref) r.uniString();   // logon_server (discard)
        }
        for (const t of tmp) users.push({ user: t.user, domain: t.domain });
      }
    }
    return users;
  }
}
