// SRVSVC (MS-SRVS) over DCE-RPC: NetrSessionEnum level 10 — the SMB sessions on a
// host. Each entry is a user + the client computer they're connecting from, which
// BloodHound turns into a session (user -> originating computer).

import { DceRpc } from './dcerpc.js';
import { NdrReader, ndrUniqueWString } from './ndr.js';
import { concat } from '../ldap/ber.js';

const SRVSVC_UUID = '4b324fc8-1670-01d3-1278-5a47bf6ee188';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

export class Srvsvc {
  constructor(transceive) { this.rpc = new DceRpc(transceive); }
  async bind() { await this.rpc.bind(SRVSVC_UUID, '3.0'); }

  // -> [{ user, cname }]  (cname = originating client computer)
  async sessionEnum(server) {
    const infoStruct = concat([
      u32(10),            // Level
      u32(10),            // SESSION_ENUM_UNION discriminant
      u32(0x00020000),    // SESSION_INFO_10_CONTAINER referent
      u32(0),             // EntriesRead = 0
      u32(0),             // Buffer = null
    ]);
    const stub = concat([
      ndrUniqueWString(`\\\\${server}`), // ServerName
      u32(0),             // ClientName = null
      u32(0),             // UserName = null
      infoStruct,
      u32(0xffffffff),    // PreferedMaximumLength
      u32(0),             // ResumeHandle = null
    ]);
    const out = await this.rpc.call(12, stub);
    return this._parse(out);
  }

  async shareEnum(server) {
    const infoStruct = concat([
      u32(1),
      u32(1),
      u32(0x00020000),
      u32(0),
      u32(0),
    ]);
    const stub = concat([
      ndrUniqueWString(`\\\\${server}`),
      infoStruct,
      u32(0xffffffff),
      u32(0),
    ]);
    const out = await this.rpc.call(15, stub);
    return this._parseShares(out);
  }

  _parseShares(out) {
    const r = new NdrReader(out);
    r.u32(); r.u32();
    const shares = [];
    if (r.u32()) {
      const entriesRead = r.u32();
      if (r.u32()) {
        r.u32();
        const tmp = [];
        for (let i = 0; i < entriesRead; i++) {
          const nref = r.u32(); const type = r.u32(); const rref = r.u32();
          tmp.push({ nref, type, rref });
        }
        for (const t of tmp) {
          t.name = t.nref ? r.uniString() : '';
          t.remark = t.rref ? r.uniString() : '';
        }
        for (const t of tmp) shares.push({ name: t.name, type: t.type, remark: t.remark });
      }
    }
    return shares;
  }

  _parse(out) {
    const r = new NdrReader(out);
    r.u32(); r.u32();              // Level, union discriminant
    const sessions = [];
    if (r.u32()) {                 // container referent
      const entriesRead = r.u32();
      if (r.u32()) {               // Buffer referent
        r.u32();                   // MaxCount
        const tmp = [];
        for (let i = 0; i < entriesRead; i++) { const cref = r.u32(); const uref = r.u32(); r.u32(); r.u32(); tmp.push({ cref, uref }); }
        for (const t of tmp) { t.cname = t.cref ? r.uniString() : ''; t.user = t.uref ? r.uniString() : ''; }
        for (const t of tmp) sessions.push({ user: t.user, cname: t.cname });
      }
    }
    return sessions;
  }
}
