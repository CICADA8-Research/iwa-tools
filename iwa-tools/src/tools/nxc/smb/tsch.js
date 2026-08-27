import { DceRpc } from './dcerpc.js';
import { NdrReader } from './ndr.js';
import { concat } from '../ldap/ber.js';

const TSCH_UUID = '86d35949-83c9-4044-b424-db363231fd0c';
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

function ndrUString(s) {
  const n = s.length + 1;
  const body = new Uint8Array(n * 2);
  for (let i = 0; i < s.length; i++) { body[i * 2] = s.charCodeAt(i) & 0xff; body[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  const pad = (4 - (body.length % 4)) % 4;
  const padded = new Uint8Array(body.length + pad);
  padded.set(body);
  return concat([u32(n), u32(0), u32(n), padded]);
}

function taskXml(command, outputFile) {
  // Mirror impacket atexec.py XML exactly — Principal id="LocalSystem" with
  // UserId=S-1-5-18 and no LogonType, Actions Context="LocalSystem", split
  // Command/Arguments.
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const args = `/C ${command} > ${outputFile} 2>&1`;
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>${esc(args)}</Arguments>
    </Exec>
  </Actions>
</Task>`;
}

export class Tsch {
  // `transceive` is required. `read`/`write` are optional but `write` MUST be
  // supplied when calling `bindAuth` (AUTH3 has no server response, so it can't
  // go through the transceive round-trip — see DceRpc.bindAuth).
  constructor(transceive, read = null, write = null) { this.rpc = new DceRpc(transceive, read, write); }
  async bind() { await this.rpc.bind(TSCH_UUID, '1.0'); }
  async bindAuth(creds) { await this.rpc.bindAuth(TSCH_UUID, '1.0', creds); }

  async registerTask(path, xml, flags = 2) {
    // SchRpcRegisterTask signature:
    //   [in, string] wchar_t* path           (LPWSTR — referent + wstr)
    //   [in, string] wchar_t* xml            (WSTR non-null, but marshalled
    //                                          the same as LPWSTR here)
    //   [in] DWORD flags
    //   [in, string] wchar_t* sddl           (LPWSTR nullable)
    //   [in] DWORD logonType
    //   [in, range(0,32)] DWORD cCreds
    //   [in, size_is(cCreds)] TASK_USER_CRED* pCreds  (nullable array pointer)
    const stub = concat([
      u32(0x00020000), ndrUString(path),  // path (LPWSTR): referent + wstr
      ndrUString(xml),                    // xml (WSTR, non-null): no referent
      u32(flags),
      u32(0),                              // sddl = NULL referent
      u32(0),                              // logonType = TASK_LOGON_NONE
      u32(0),                              // cCreds = 0
      u32(0),                              // pCreds = NULL
    ]);
    const out = await this.rpc.call(1, stub);
    // Response layout — MS-TSCH §3.2.5.4.2:
    //   [out] pActualPath          LPWSTR (referent u32 + wstring if non-null)
    //   [out] pErrorInfo           LPTASK_XML_ERROR_INFO (referent u32 + struct if non-null)
    //   return value               HRESULT (u32)
    const r = new NdrReader(out);
    const pathRef = r.u32();
    const actualPath = pathRef ? r.wstring() : '';
    const errRef = r.u32();
    if (errRef) {
      // TASK_XML_ERROR_INFO { u32 line, u32 col, [string] LPWSTR node, [string] LPWSTR desc }.
      // Skip past it — impacket does the same when it doesn't need the detail.
      r.u32(); r.u32();                        // line, col
      const nodeRef = r.u32(); if (nodeRef) r.wstring();
      const descRef = r.u32(); if (descRef) r.wstring();
    }
    const status = r.u32();
    if (status) throw new Error(`SchRpcRegisterTask 0x${status.toString(16)}${actualPath ? ` (path=${actualPath})` : ''}`);
    return actualPath || path;
  }

  // SchRpcRun (opnum 12) — MS-TSCH §3.2.5.4.13. Per impacket's SchRpcRun:
  //   [in, string] const wchar_t* path         WSTR  (no leading referent)
  //   [in] DWORD cArgs
  //   [in, unique, size_is(cArgs)] LPWSTR* pArgs   PWSTR_ARRAY (nullable ptr)
  //   [in] DWORD flags
  //   [in] DWORD sessionId
  //   [in, unique, string] const wchar_t* pszUser  LPWSTR (nullable)
  async run(path) {
    const stub = concat([
      ndrUString(path),   // WSTR: no referent
      u32(0),             // cArgs = 0
      u32(0),             // pArgs = NULL
      u32(0),             // flags = 0
      u32(0),             // sessionId = 0
      u32(0),             // pszUser = NULL
    ]);
    const out = await this.rpc.call(12, stub);
    const r = new NdrReader(out);
    const guid = r.bytes(16);
    const status = r.u32();
    if (status) throw new Error(`SchRpcRun 0x${status.toString(16)}`);
    return guid;
  }

  // SchRpcDelete (opnum 13 — NOT 7; opnum 7 is SchRpcEnumTasks, the old
  // code used the wrong opnum and got away with it only because the caller
  // wrapped delete() in try{} catch{}). Per impacket:
  //   [in, string] const wchar_t* path         WSTR (no referent)
  //   [in] DWORD flags
  async delete(path) {
    const stub = concat([
      ndrUString(path),   // WSTR: no referent
      u32(0),             // flags = 0
    ]);
    const out = await this.rpc.call(13, stub);
    const r = new NdrReader(out);
    const status = r.u32();
    if (status) throw new Error(`SchRpcDelete 0x${status.toString(16)}`);
  }
}

export { taskXml };
