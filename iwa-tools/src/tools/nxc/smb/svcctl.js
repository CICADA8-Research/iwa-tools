import { DceRpc } from './dcerpc.js';
import { NdrReader, ndrUniqueWString } from './ndr.js';
import { concat } from '../ldap/ber.js';

const SVCCTL_UUID = '367abb81-9844-35f1-ad32-98f038001003';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

const OP = {
  CLOSE_HANDLE: 0,
  CONTROL_SERVICE: 1,
  DELETE_SERVICE: 2,
  QUERY_SERVICE_STATUS: 6,
  CHANGE_SERVICE_CONFIG: 11,
  CREATE_SERVICE: 12,
  ENUM_SERVICES_STATUS: 14,
  OPEN_SC_MANAGER: 15,
  OPEN_SERVICE: 16,
  QUERY_SERVICE_CONFIG: 17,
  START_SERVICE: 19,
};

export const SERVICE_STATE = { STOPPED: 1, START_PENDING: 2, STOP_PENDING: 3, RUNNING: 4 };
export const SERVICE_START = { BOOT: 0, SYSTEM: 1, AUTO: 2, DEMAND: 3, DISABLED: 4, NO_CHANGE: 0xffffffff };
export const SERVICE_TYPE_NO_CHANGE = 0xffffffff;

const SC_MANAGER_ALL = 0x000f003f;
const SERVICE_ALL = 0x000f01ff;
const SERVICE_WIN32_OWN_PROCESS = 0x10;
const SERVICE_DEMAND_START = 0x03;
const SERVICE_ERROR_IGNORE = 0x00;

function ndrWString(s) {
  const n = s.length + 1;
  const body = new Uint8Array(n * 2);
  for (let i = 0; i < s.length; i++) { body[i * 2] = s.charCodeAt(i) & 0xff; body[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  const pad = (4 - (body.length % 4)) % 4;
  const padded = new Uint8Array(body.length + pad);
  padded.set(body);
  return concat([u32(n), u32(0), u32(n), padded]);
}

export class Svcctl {
  constructor(transceive) { this.rpc = new DceRpc(transceive); }
  async bind() { await this.rpc.bind(SVCCTL_UUID, '2.0'); }

  async openSCManager(host) {
    const stub = concat([
      ndrUniqueWString(`\\\\${host}`),
      u32(0),
      u32(SC_MANAGER_ALL),
    ]);
    const out = await this.rpc.call(OP.OPEN_SC_MANAGER, stub);
    const r = new NdrReader(out);
    const handle = r.bytes(20);
    const status = r.u32();
    if (status) throw new Error(`OpenSCManager failed: 0x${status.toString(16)}`);
    return handle;
  }

  async openService(scmHandle, serviceName, desiredAccess = 0x00020014) {
    const stub = concat([scmHandle, ndrWString(serviceName), u32(desiredAccess)]);
    const out = await this.rpc.call(OP.OPEN_SERVICE, stub);
    const r = new NdrReader(out);
    const handle = r.bytes(20);
    const status = r.u32();
    if (status) throw new Error(`OpenService '${serviceName}' failed: 0x${status.toString(16)}`);
    return handle;
  }

  async queryServiceStatus(svcHandle) {
    const out = await this.rpc.call(OP.QUERY_SERVICE_STATUS, svcHandle);
    const r = new NdrReader(out);
    const serviceType = r.u32();
    const currentState = r.u32();
    return currentState;
  }

  async createService(scmHandle, serviceName, binPath) {
    const svcNameBuf = ndrWString(serviceName);
    const displayNameRef = u32(0);
    const binPathBuf = ndrWString(binPath);
    const stub = concat([
      scmHandle,
      svcNameBuf,
      displayNameRef,
      u32(SERVICE_ALL),
      u32(SERVICE_WIN32_OWN_PROCESS),
      u32(SERVICE_DEMAND_START),
      u32(SERVICE_ERROR_IGNORE),
      binPathBuf,
      u32(0),
      u32(0),
      u32(0), u32(0),
      u32(0), u32(0),
      u32(0), u32(0),
    ]);
    const out = await this.rpc.call(OP.CREATE_SERVICE, stub);
    const r = new NdrReader(out);
    r.u32();
    const handle = r.bytes(20);
    const status = r.u32();
    if (status) throw new Error(`CreateService failed: 0x${status.toString(16)}`);
    return handle;
  }

  async startService(svcHandle) {
    const stub = concat([svcHandle, u32(0), u32(0)]);
    const out = await this.rpc.call(OP.START_SERVICE, stub);
    const r = new NdrReader(out);
    const status = r.u32();
    if (status && status !== 0x00000420) throw new Error(`StartService failed: 0x${status.toString(16)}`);
  }

  async deleteService(svcHandle) {
    const out = await this.rpc.call(OP.DELETE_SERVICE, svcHandle);
    const r = new NdrReader(out);
    const status = r.u32();
    if (status) throw new Error(`DeleteService failed: 0x${status.toString(16)}`);
  }

  async closeHandle(handle) {
    try { await this.rpc.call(OP.CLOSE_HANDLE, handle); } catch {}
  }

  async controlService(svcHandle, control = 1) {
    const stub = concat([svcHandle, u32(control)]);
    const out = await this.rpc.call(OP.CONTROL_SERVICE, stub);
    const r = new NdrReader(out);
    r.u32(); r.u32(); r.u32(); r.u32(); r.u32(); r.u32(); r.u32();
    const status = r.u32();
    if (status && status !== 0x00000426) throw new Error(`ControlService failed: 0x${status.toString(16)}`);
  }

  async stopService(svcHandle) { return this.controlService(svcHandle, 1); }

  async changeServiceConfig(svcHandle, serviceType, startType, errorControl = 0xffffffff) {
    const stub = concat([
      svcHandle, u32(serviceType), u32(startType), u32(errorControl),
      u32(0), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0),
    ]);
    const out = await this.rpc.call(OP.CHANGE_SERVICE_CONFIG, stub);
    const r = new NdrReader(out);
    r.u32();
    const status = r.u32();
    if (status) throw new Error(`ChangeServiceConfig failed: 0x${status.toString(16)}`);
  }

  async queryServiceConfig(svcHandle) {
    const stub = concat([svcHandle, u32(8192)]);
    const out = await this.rpc.call(OP.QUERY_SERVICE_CONFIG, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`QueryServiceConfig failed: 0x${status.toString(16)}`);
    const r = new NdrReader(out);
    const serviceType = r.u32();
    const startType = r.u32();
    const errorControl = r.u32();
    const binPathRef = r.u32();
    const loadGroupRef = r.u32();
    const tagId = r.u32();
    const depRef = r.u32();
    const startNameRef = r.u32();
    const displayNameRef = r.u32();
    let binPath = '', startName = '', displayName = '';
    try {
      if (binPathRef) binPath = r.uniString();
      if (loadGroupRef) r.uniString();
      if (depRef) r.uniString();
      if (startNameRef) startName = r.uniString();
      if (displayNameRef) displayName = r.uniString();
    } catch {}
    return { serviceType, startType, errorControl, binPath, startName, displayName };
  }

  async enumServicesStatus(scmHandle) {
    const stub = concat([scmHandle, u32(0x30), u32(0x03), u32(65536)]);
    try {
      const out = await this.rpc.call(OP.ENUM_SERVICES_STATUS, stub);
      const r = new NdrReader(out);
      const services = [];
      const bytesNeeded = r.u32();
      const servicesReturned = r.u32();
      const resumeHandle = r.u32();
      return services;
    } catch {
      return [];
    }
  }

  // Impacket-style smbexec wrapper: write the actual command into a batch
  // file, then chain-run it. The `^`-escaped redirects in the outer echo
  // become literal redirects in the batch's contents, isolating cmd.exe's
  // parsing quirks from SCM's binPath argument split.
  async exec(scmHandle, host, command, outputFile) {
    const svcName = `nxc${Math.random().toString(36).slice(2, 8)}`;
    const batchFile = `${svcName}.bat`;
    const cmdEsc = command.replace(/[><|&^]/g, '^$&');
    const binPath = `%COMSPEC% /Q /c echo ${cmdEsc} ^> %SYSTEMROOT%\\${outputFile} 2^>^&1 > %SYSTEMROOT%\\${batchFile} & %COMSPEC% /Q /c %SYSTEMROOT%\\${batchFile} & del /f /q %SYSTEMROOT%\\${batchFile}`;
    const svcHandle = await this.createService(scmHandle, svcName, binPath);
    try {
      await this.startService(svcHandle);
    } catch {}
    return { outputFile, batchFile, svcHandle };
  }

  async cleanup(svcHandle) {
    try { await this.deleteService(svcHandle); } catch {}
    await this.closeHandle(svcHandle);
  }
}
