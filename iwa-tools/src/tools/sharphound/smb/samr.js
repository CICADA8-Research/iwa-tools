// SAMR (MS-SAMR) over DCE-RPC: enumerate the members of a local alias (group)
// on a host — Administrators, Remote Desktop Users, Distributed COM Users,
// Remote Management Users — which become BloodHound LocalAdmins / RDP / DCOM /
// PSRemote edges. Members come back as SIDs; types are resolved against the
// directory cache the LDAP collection already built.

import { DceRpc } from './dcerpc.js';
import { NdrReader, sidStringToNdr, ndrUniqueWString } from './ndr.js';
import { concat } from '../ldap/ber.js';

const SAMR_UUID = '12345778-1234-abcd-ef00-0123456789ac';
const MAX_ALLOWED = 0x02000000;
const BUILTIN = 'S-1-5-32';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

// Local alias RIDs -> BloodHound LocalGroup edge buckets.
export const LOCAL_GROUPS = [
  { rid: 544, edge: 'LocalAdmins' },
  { rid: 555, edge: 'RemoteDesktopUsers' },
  { rid: 562, edge: 'DcomUsers' },
  { rid: 580, edge: 'PSRemoteUsers' },
];

const OP = { CLOSE: 1, OPEN_DOMAIN: 7, OPEN_ALIAS: 27, GET_MEMBERS: 33, CONNECT2: 57 };

export class Samr {
  constructor(transceive, log = () => {}) { this.rpc = new DceRpc(transceive, log); }
  async bind() { await this.rpc.bind(SAMR_UUID, '1.0'); }

  _handle(out) {
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    return { handle: out.slice(0, 20), status: dv.getUint32(out.length - 4, true) };
  }

  async connect2(server) {
    const r = this._handle(await this.rpc.call(OP.CONNECT2, concat([ndrUniqueWString(`\\\\${server}`), u32(MAX_ALLOWED)])));
    if (r.status) throw new Error(`SamrConnect2 0x${r.status.toString(16)}`);
    return r.handle;
  }
  async openBuiltin(serverHandle) {
    // DomainId is a [ref] PRPC_SID — no referent, the conformant SID is inline.
    const r = this._handle(await this.rpc.call(OP.OPEN_DOMAIN, concat([serverHandle, u32(MAX_ALLOWED), sidStringToNdr(BUILTIN)])));
    if (r.status) throw new Error(`SamrOpenDomain 0x${r.status.toString(16)}`);
    return r.handle;
  }
  async openAlias(domainHandle, rid) {
    const r = this._handle(await this.rpc.call(OP.OPEN_ALIAS, concat([domainHandle, u32(MAX_ALLOWED), u32(rid)])));
    return r.status ? null : r.handle; // some aliases may not exist on a host
  }
  async getMembers(aliasHandle) {
    const out = await this.rpc.call(OP.GET_MEMBERS, aliasHandle);
    const r = new NdrReader(out);
    const count = r.u32();
    const arrRef = r.u32();
    const sids = [];
    if (arrRef) {
      r.u32(); // MaxCount
      const refs = [];
      for (let i = 0; i < count; i++) refs.push(r.u32());
      for (let i = 0; i < count; i++) if (refs[i]) sids.push(r.sid());
    }
    return sids;
  }
  async closeHandle(h) { try { await this.rpc.call(OP.CLOSE, h); } catch { /* ignore */ } }

  // Enumerate every local group's members in one go: { LocalAdmins:[sid…], … }.
  async collectLocalGroups(server) {
    await this.bind();
    const sc = await this.connect2(server);
    const dom = await this.openBuiltin(sc);
    const result = {};
    for (const g of LOCAL_GROUPS) {
      const al = await this.openAlias(dom, g.rid);
      result[g.edge] = al ? await this.getMembers(al) : [];
      if (al) await this.closeHandle(al);
    }
    await this.closeHandle(dom); await this.closeHandle(sc);
    return result;
  }
}
