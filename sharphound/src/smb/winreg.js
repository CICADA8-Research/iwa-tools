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
const ERROR_NO_MORE_ITEMS = 259;
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

const OP = { OPEN_USERS: 4, CLOSE_KEY: 5, ENUM_KEY: 9 };

export class Winreg {
  constructor(transceive) { this.rpc = new DceRpc(transceive); }
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
