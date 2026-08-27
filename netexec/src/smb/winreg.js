// WINREG (MS-RRP) over DCE-RPC: enumerate HKEY_USERS subkeys. Subkeys named like a
// user SID (and not the *_Classes companion) are loaded user hives — i.e. users
// with an active profile on the host. BloodHound turns these into the
// RegistrySessions edge (user -> this computer), the registry-based session method
// that doesn't depend on an active SMB share session.

import { DceRpc } from './dcerpc.js';
import { NdrReader } from './ndr.js';
import { concat } from '../ldap/ber.js';

const WINREG_UUID = '338cd001-2244-31f1-aaaa-900038001003';
const KEY_READ = 0x00020019;
const MAXIMUM_ALLOWED = 0x02000000;
const REG_OPTION_BACKUP_RESTORE = 0x00000004;
const ERROR_NO_MORE_ITEMS = 259;
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

const OP = { OPEN_HKLM: 2, OPEN_USERS: 4, CLOSE_KEY: 5, ENUM_KEY: 9, QUERY_INFO_KEY: 16, OPEN_KEY: 15, QUERY_VALUE: 17 };

export class Winreg {
  constructor(transceive, read) { this.rpc = new DceRpc(transceive, read); }
  async bind() { await this.rpc.bind(WINREG_UUID, '1.0'); }

  // OpenUsers -> HKEY_USERS handle (20-byte context handle).
  async openUsers() {
    const out = await this.rpc.call(OP.OPEN_USERS, concat([u32(0) /* ServerName=null */, u32(KEY_READ)]));
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    if (dv.getUint32(out.length - 4, true)) throw new Error('OpenUsers failed');
    return out.slice(0, 20);
  }

  // BaseRegEnumKey(index) -> { name, status }.
  async enumKey(hKey, index, maxChars = 512) {
    const stub = concat([
      hKey,                                       // RPC_HKEY (20)
      u32(index),                                 // dwIndex
      // lpNameIn (RRP_UNICODE_STRING with an empty, MaximumLength-sized buffer)
      u16(0), u16(maxChars * 2), u32(0x00020000), // Length=0, MaximumLength(bytes), Buffer referent
      u32(maxChars), u32(0), u32(0),              //   deferred buffer: MaxCount, Offset, ActualCount=0
      // lpClassIn (unique -> empty RRP_UNICODE_STRING)
      u32(0x00020004), u16(0), u16(0), u32(0),    // referent, Length=0, MaxLength=0, Buffer=null
      // lpftLastWriteTime (unique -> zero FILETIME)
      u32(0x00020008), u32(0), u32(0),            // referent, FILETIME=0
    ]);
    const out = await this.rpc.call(OP.ENUM_KEY, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    let name = '';
    if (status === 0) {
      const r = new NdrReader(out);
      r.u16(); r.u16();                           // lpNameOut: Length, MaximumLength
      if (r.u32()) name = r.uniString();          // Buffer referent -> chars
    }
    return { name, status };
  }

  async openLocalMachine(access = MAXIMUM_ALLOWED) {
    const out = await this.rpc.call(OP.OPEN_HKLM, concat([u32(0), u32(access)]));
    if (out.length < 24) throw new Error(`OpenLocalMachine: response too short (${out.length})`);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const st = dv.getUint32(out.length - 4, true);
    if (st) throw new Error(`OpenLocalMachine failed: 0x${st.toString(16)}`);
    return out.slice(0, 20);
  }

  async openKey(parentKey, subKeyPath, access = MAXIMUM_ALLOWED, options = REG_OPTION_BACKUP_RESTORE) {
    const n = subKeyPath.length + 1;
    const nBytes = n * 2;
    const aligned = nBytes + ((4 - nBytes % 4) % 4);
    const buf = new Uint8Array(aligned);
    for (let i = 0; i < subKeyPath.length; i++) { buf[i * 2] = subKeyPath.charCodeAt(i) & 0xff; buf[i * 2 + 1] = (subKeyPath.charCodeAt(i) >> 8) & 0xff; }
    const stub = concat([
      parentKey,
      u16(nBytes), u16(nBytes), u32(0x00020000),
      u32(n), u32(0), u32(n),
      buf,
      u32(options),
      u32(access),
    ]);
    const out = await this.rpc.call(OP.OPEN_KEY, stub);
    if (out.length < 24) throw new Error(`OpenKey '${subKeyPath}': response too short (${out.length})`);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const st = dv.getUint32(out.length - 4, true);
    if (st) throw new Error(`OpenKey '${subKeyPath}' failed: 0x${st.toString(16)}`);
    return out.slice(0, 20);
  }

  async queryValue(hKey, valueName, maxDataSize = 65536) {
    const n = valueName.length + 1;
    const nBytes = n * 2;
    const aligned = nBytes + ((4 - nBytes % 4) % 4);
    const nameBuf = new Uint8Array(aligned);
    for (let i = 0; i < valueName.length; i++) { nameBuf[i * 2] = valueName.charCodeAt(i) & 0xff; nameBuf[i * 2 + 1] = (valueName.charCodeAt(i) >> 8) & 0xff; }
    const stub = concat([
      hKey,
      u16(nBytes), u16(nBytes), u32(0x00020000),
      u32(n), u32(0), u32(n), nameBuf,
      u32(0x00020004), u32(0),
      u32(0x00020008), u32(maxDataSize), u32(0), u32(0),
      u32(0x0002000C), u32(maxDataSize),
      u32(0x00020010), u32(0),
    ]);
    const out = await this.rpc.call(OP.QUERY_VALUE, stub);
    if (out.length < 4) throw new Error(`QueryValue '${valueName}': response too short (${out.length})`);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`QueryValue failed: ${valueName} (0x${status.toString(16)})`);
    {
      const rdv = new DataView(out.buffer, out.byteOffset, out.byteLength);
      let pos = 0;
      const typeRef = rdv.getUint32(pos, true); pos += 4;
      let regType = 0;
      if (typeRef) { regType = rdv.getUint32(pos, true); pos += 4; }
      const dataRef = rdv.getUint32(pos, true); pos += 4;
      let data = new Uint8Array(0);
      if (dataRef) {
        const maxCount = rdv.getUint32(pos, true); pos += 4;
        pos += 4; // offset
        const actualCount = rdv.getUint32(pos, true); pos += 4;
        data = out.slice(pos, pos + actualCount);
      }
      return { type: regType, data };
    }
  }

  async queryInfoKey(hKey) {
    const maxChars = 256;
    const stub = concat([
      hKey,
      u16(0), u16(maxChars * 2), u32(0x00020000),
      u32(maxChars), u32(0), u32(0),
    ]);
    const out = await this.rpc.call(OP.QUERY_INFO_KEY, stub);
    if (out.length < 4) throw new Error(`QueryInfoKey: response too short (${out.length})`);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    let className = '';
    if (status === 0) {
      const r = new NdrReader(out);
      const len = r.u16();
      r.u16();
      if (r.u32()) className = r.uniString();
    }
    return className;
  }

  async closeKey(hKey) { try { await this.rpc.call(OP.CLOSE_KEY, hKey); } catch { /* ignore */ } }

  // -> [user SID, …] for loaded HKU hives.
  async registrySessions() {
    await this.bind();
    const hku = await this.openUsers();
    const sids = [];
    for (let i = 0; i < 10000; i++) {
      const { name, status } = await this.enumKey(hku, i);
      if (status === ERROR_NO_MORE_ITEMS) break;
      if (status !== 0) break;
      if (/^S-1-5-21-[\d-]+$/.test(name)) sids.push(name); // *_Classes excluded by the charset
    }
    await this.closeKey(hku);
    return sids;
  }
}
