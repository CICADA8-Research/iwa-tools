// SAMR (MS-SAMR) over DCE-RPC: enumerate the members of a local alias (group)
// on a host — Administrators, Remote Desktop Users, Distributed COM Users,
// Remote Management Users — which become BloodHound LocalAdmins / RDP / DCOM /
// PSRemote edges. Members come back as SIDs; types are resolved against the
// directory cache the LDAP collection already built.

import { DceRpc } from './dcerpc.js';
import { NdrReader, sidStringToNdr, ndrUniqueWString } from './ndr.js';
import { concat } from '../ldap/ber.js';
import { md5 } from '../crypto/md5.js';
import { rc4 } from '../crypto/rc4.js';

const SAMR_UUID = '12345778-1234-abcd-ef00-0123456789ac';
const MAX_ALLOWED = 0x02000000;
const BUILTIN = 'S-1-5-32';
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

// Build an inline RPC_UNICODE_STRING (MS-DTYP §2.3.10) with its Buffer as a
// non-null unique pointer. `withNul` controls whether the string ends with a
// terminator (Length always excludes the terminator per MS-RPCE).
function buildRpcUnicodeString(s, withNul = false) {
  const nchars = s.length + (withNul ? 1 : 0);
  const wchars = new Uint8Array(nchars * 2);
  for (let i = 0; i < s.length; i++) {
    wchars[i * 2] = s.charCodeAt(i) & 0xff;
    wchars[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  const pad = (4 - (wchars.length % 4)) % 4;
  const padded = new Uint8Array(wchars.length + pad);
  padded.set(wchars);
  const lengthBytes = s.length * 2;
  return concat([
    u16(lengthBytes),        // Length (bytes, excluding NUL)
    u16(nchars * 2),         // MaximumLength (bytes)
    u32(0x00020000),         // Buffer referent (non-null)
    u32(nchars),             // MaxCount
    u32(0),                  // Offset
    u32(nchars),             // ActualCount
    padded,
  ]);
}

// Local alias RIDs -> BloodHound LocalGroup edge buckets.
export const LOCAL_GROUPS = [
  { rid: 544, edge: 'LocalAdmins' },
  { rid: 555, edge: 'RemoteDesktopUsers' },
  { rid: 562, edge: 'DcomUsers' },
  { rid: 580, edge: 'PSRemoteUsers' },
];

const OP = { CLOSE: 1, LOOKUP_IDS: 5, OPEN_DOMAIN: 7, ENUM_DOMAINS: 6, LOOKUP_DOMAIN: 5, OPEN_ALIAS: 27, GET_MEMBERS: 33, ENUM_USERS: 13, ENUM_GROUPS: 11, ENUM_ALIASES: 15, CONNECT2: 57 };

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

  // SamrEnumerateDomainsInSamServer response layout (MS-SAMR §3.1.5.2.1):
  //   ULONG EnumerationContext            (4 bytes)
  //   PSAMPR_ENUMERATION_BUFFER Buffer    (referent u32)
  //     ULONG EntriesRead                 (4 bytes)
  //     PSAMPR_RID_ENUMERATION_ARRAY      (referent u32)
  //       ULONG MaxCount                  (4 bytes)
  //       [each entry, 12 bytes fixed]
  //         ULONG RelativeId              (4 bytes)
  //         RPC_UNICODE_STRING Name       (Length u16 + MaxLen u16 + Buf ref u32)
  //       [then, deferred, per non-null referent]
  //         uniString (MaxCount+Offset+ActualCount + WCHAR[]) with 4-byte alignment
  //   ULONG CountReturned                 (4 bytes)
  //   NTSTATUS                            (4 bytes)
  async enumDomains(serverHandle) {
    const stub = concat([serverHandle, u32(0), u32(0xffff)]);
    const out = await this.rpc.call(OP.ENUM_DOMAINS, stub);
    return this._parseRidEnumeration(out);
  }

  _parseRidEnumeration(out) {
    const r = new NdrReader(out);
    r.bytes(4);                        // EnumerationContext
    const entries = [];
    if (!r.u32()) return entries;      // buffer referent
    const cnt = r.u32();               // EntriesRead
    if (!r.u32()) return entries;      // array referent
    r.u32();                           // MaxCount (conformant array header)
    const heads = [];
    for (let i = 0; i < cnt; i++) {
      const rid = r.u32();
      const len = r.u16();
      const maxLen = r.u16();
      const ref = r.u32();
      heads.push({ rid, len, maxLen, ref });
    }
    for (const h of heads) {
      h.name = h.ref ? r.uniString() : '';
      entries.push(h.name);
    }
    return entries;
  }

  // Same layout as _parseRidEnumeration but returns rid+name pairs.
  _parseRidEnumerationPairs(out) {
    const r = new NdrReader(out);
    r.bytes(4);
    if (!r.u32()) return [];
    const cnt = r.u32();
    if (!r.u32()) return [];
    r.u32();
    const heads = [];
    for (let i = 0; i < cnt; i++) {
      const rid = r.u32();
      const len = r.u16();
      const maxLen = r.u16();
      const ref = r.u32();
      heads.push({ rid, len, maxLen, ref });
    }
    for (const h of heads) h.name = h.ref ? r.uniString() : '';
    return heads.map((h) => ({ rid: h.rid, name: h.name }));
  }

  // SamrLookupDomainInSamServer takes an RPC_UNICODE_STRING (inline in the
  // stub) whose Buffer is a non-null unique pointer. The old code sent
  // Length/MaxLength but skipped the referent — the server rejected the stub
  // with fault 0x6f7 (nca_s_fault_invalid_stub). Length excludes the NUL, and
  // the WCHAR array is padded to 4-byte alignment.
  async lookupDomain(serverHandle, domainName) {
    const stub = concat([serverHandle, buildRpcUnicodeString(domainName, false)]);
    const out = await this.rpc.call(OP.LOOKUP_DOMAIN, stub);
    const r = new NdrReader(out);
    if (r.u32()) return r.sid();
    return null;
  }

  async openDomain(serverHandle, domainSid) {
    const r = this._handle(await this.rpc.call(OP.OPEN_DOMAIN, concat([serverHandle, u32(MAX_ALLOWED), sidStringToNdr(domainSid)])));
    if (r.status) throw new Error(`SamrOpenDomain 0x${r.status.toString(16)}`);
    return r.handle;
  }

  async enumDomainUsers(domainHandle) {
    const stub = concat([domainHandle, u32(0), u32(0x10), u32(0xffff), u32(0)]);
    const out = await this.rpc.call(OP.ENUM_USERS, stub);
    return this._parseRidEnumerationPairs(out);
  }

  async enumDomainGroups(domainHandle) {
    const stub = concat([domainHandle, u32(0), u32(0xffff), u32(0)]);
    const out = await this.rpc.call(OP.ENUM_GROUPS, stub);
    return this._parseRidEnumerationPairs(out);
  }

  async enumDomainAliases(domainHandle) {
    const stub = concat([domainHandle, u32(0), u32(0xffff)]);
    const out = await this.rpc.call(OP.ENUM_ALIASES, stub);
    return this._parseRidEnumerationPairs(out);
  }

  // SamrLookupIdsInDomain (opnum 18, MS-SAMR §3.1.5.5.5) takes a Count u32
  // plus a conformant-varying ULONG array of RIDs. The array wire form is
  // MaxCount(4) + Offset(4) + ActualCount(4) + entries*4 — the previous code
  // omitted the Offset field so the server read every request as garbage.
  async lookupRids(domainHandle, rids) {
    const count = rids.length;
    const stub = concat([
      domainHandle,
      u32(count),                       // Count parameter
      u32(1000),                        // MaxCount (size_is on the array)
      u32(0),                           // Offset
      u32(count),                       // ActualCount
      ...rids.map((r) => u32(r)),
    ]);
    try {
      const out = await this.rpc.call(18, stub);
      const r = new NdrReader(out);
      const namesCount = r.u32();
      const names = [];
      const namesPtr = r.u32();
      if (namesPtr && namesCount > 0) {
        r.u32();
        const hdrs = [];
        for (let i = 0; i < namesCount; i++) {
          const len = r.u16(); const maxLen = r.u16(); const ptr = r.u32();
          hdrs.push({ len, maxLen, ptr });
        }
        for (const h of hdrs) names.push(h.ptr ? r.uniString() : '');
      }
      const useCount = r.u32();
      const uses = [];
      const usePtr = r.u32();
      if (usePtr && useCount > 0) {
        r.u32();
        for (let i = 0; i < useCount; i++) uses.push(r.u32());
      }
      const found = [];
      for (let i = 0; i < names.length; i++) {
        const use = uses[i] || 0;
        if (use !== 0 && names[i]) found.push({ rid: rids[i], name: names[i], type: use });
      }
      return found;
    } catch { return []; }
  }

  async openUser(domainHandle, rid, access = MAX_ALLOWED) {
    const r = this._handle(await this.rpc.call(34, concat([domainHandle, u32(access), u32(rid)])));
    if (r.status) throw new Error(`SamrOpenUser 0x${r.status.toString(16)}`);
    return r.handle;
  }

  async setPassword(userHandle, newPassword, sessionKey) {
    const pwdUnicode = new Uint8Array(newPassword.length * 2);
    for (let i = 0; i < newPassword.length; i++) {
      pwdUnicode[i * 2] = newPassword.charCodeAt(i) & 0xFF;
      pwdUnicode[i * 2 + 1] = (newPassword.charCodeAt(i) >> 8) & 0xFF;
    }
    const buf = new Uint8Array(516);
    crypto.getRandomValues(buf.subarray(0, 512 - pwdUnicode.length));
    buf.set(pwdUnicode, 512 - pwdUnicode.length);
    new DataView(buf.buffer).setUint32(512, pwdUnicode.length, true);
    const encBuf = rc4(md5(sessionKey), buf);
    const stub = concat([
      userHandle,
      u16(24), u16(0),
      u32(0x00020000),
      u16(24), u16(0),
      encBuf,
      Uint8Array.of(0, 0, 0, 0),
    ]);
    const out = await this.rpc.call(58, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`SamrSetInformationUser2 0x${status.toString(16)}`);
    return true;
  }

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
