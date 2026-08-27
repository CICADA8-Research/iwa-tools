// DCE-RPC over TCP with NTLM authentication (MS-RPCE).
// Reusable transport for DCOM, EPM, and direct RPC interface calls.

import { concat } from '../ldap/ber.js';
import { uuidBytes } from '../smb/dcerpc.js';
import { buildNegotiate, buildAuthenticate, NtlmSession } from '../ntlm/seal.js';
import { parseType2 } from '../ntlm/ntlm.js';

const PTYPE = {
  REQUEST: 0, RESPONSE: 2, FAULT: 3,
  BIND: 11, BIND_ACK: 12, BIND_NAK: 13,
  ALTER_CONTEXT: 14, ALTER_CONTEXT_RESP: 15,
  AUTH3: 16,
};
const PFC_FIRST = 0x01, PFC_LAST = 0x02;
const NDR_SYNTAX = '8a885d04-1ceb-11c9-9fe8-08002b104860';
const RPC_C_AUTHN_WINNT = 10;
const RPC_C_AUTHN_LEVEL_CONNECT = 2;
const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5;
export const RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;

function u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }

function hex(buf, max = 512) {
  if (!buf) return '(null)';
  const b = buf.length > max ? buf.subarray(0, max) : buf;
  let s = '';
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, '0');
    if ((i + 1) % 2 === 0) s += ' ';
    if ((i + 1) % 32 === 0) s += '\n  ';
  }
  return s + (buf.length > max ? `... (${buf.length} bytes total)` : ` (${buf.length}b)`);
}

export { PTYPE, uuidBytes };

export class DceRpcTcp {
  constructor(log = () => {}) {
    this._socket = null;
    this._reader = null;
    this._writer = null;
    this._buf = new Uint8Array(0);
    this._callId = 1;
    this._session = null;
    this._authLevel = RPC_C_AUTHN_LEVEL_CONNECT;
    this._log = log;
    this._maxFrag = 4280;
  }

  async connect(host, port, timeout = 10000) {
    this._socket = new TCPSocket(host, port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
  }

  async close() {
    try { this._reader?.releaseLock(); } catch {}
    try { this._writer?.releaseLock(); } catch {}
    try { await this._socket?.close(); } catch {}
  }

  async _readExact(n) {
    while (this._buf.length < n) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('DCE-RPC TCP: connection closed');
      this._buf = concat([this._buf, value]);
    }
    const result = new Uint8Array(this._buf.subarray(0, n));
    this._buf = this._buf.subarray(n);
    return result;
  }

  async _readPdu() {
    const hdr = await this._readExact(16);
    const dv = new DataView(hdr.buffer, hdr.byteOffset);
    const fragLen = dv.getUint16(8, true);
    if (fragLen <= 16) return hdr;
    const rest = await this._readExact(fragLen - 16);
    return concat([hdr, rest]);
  }

  async _send(data) {
    await this._writer.write(data);
  }

  _header(ptype, fragLen, authLen, callId) {
    return concat([
      Uint8Array.of(5, 0, ptype, PFC_FIRST | PFC_LAST),
      Uint8Array.of(0x10, 0, 0, 0),
      u16(fragLen), u16(authLen),
      u32(callId),
    ]);
  }

  _authVerifier(blob, padLen = 0) {
    return concat([
      Uint8Array.of(RPC_C_AUTHN_WINNT, this._authLevel, padLen, 0),
      u32(this._authCtxId || 0),
      blob,
    ]);
  }

  async bind(interfaceUuid, ver = '0.0') {
    const [maj, min] = ver.split('.').map(Number);
    const ctx = concat([
      u16(0), Uint8Array.of(1, 0),
      uuidBytes(interfaceUuid), u16(maj), u16(min),
      uuidBytes(NDR_SYNTAX), u16(2), u16(0),
    ]);
    const body = concat([
      u16(this._maxFrag), u16(this._maxFrag), u32(0),
      Uint8Array.of(1, 0, 0, 0),
      ctx,
    ]);
    const pdu = concat([this._header(PTYPE.BIND, 0, 0, this._callId), body]);
    new DataView(pdu.buffer).setUint16(8, pdu.length, true);
    await this._send(pdu);
    const resp = await this._readPdu();
    if (resp[2] === PTYPE.BIND_NAK) throw new Error('DCE-RPC bind rejected');
    if (resp[2] !== PTYPE.BIND_ACK) throw new Error(`expected BIND_ACK, got ptype ${resp[2]}`);
    const rdv = new DataView(resp.buffer, resp.byteOffset);
    this._maxFrag = Math.min(this._maxFrag, rdv.getUint16(16, true));
    this._callId++;
  }

  async bindAuth(interfaceUuid, ver, { user, domain, password, hash }, authLevel) {
    if (authLevel) this._authLevel = authLevel;
    this._authCtxId = 79231;
    const [maj, min] = (ver || '0.0').split('.').map(Number);

    // Step 1: BIND with NTLMSSP_NEGOTIATE
    const negotiate = buildNegotiate();
    const authVer1 = this._authVerifier(negotiate);
    const ctx = concat([
      u16(0), Uint8Array.of(1, 0),
      uuidBytes(interfaceUuid), u16(maj), u16(min),
      uuidBytes(NDR_SYNTAX), u16(2), u16(0),
    ]);
    const body = concat([
      u16(this._maxFrag), u16(this._maxFrag), u32(0),
      Uint8Array.of(1, 0, 0, 0),
      ctx,
    ]);
    const callId1 = this._callId++;
    const fragLen1 = 16 + body.length + authVer1.length;
    const pdu1 = concat([this._header(PTYPE.BIND, fragLen1, negotiate.length, callId1), body, authVer1]);
    new DataView(pdu1.buffer).setUint16(8, pdu1.length, true);
    await this._send(pdu1);

    // Step 2: Read BIND_ACK with NTLMSSP_CHALLENGE
    const ack = await this._readPdu();
    if (ack[2] !== PTYPE.BIND_ACK) throw new Error(`bind auth failed: ptype ${ack[2]}`);
    const ackDv = new DataView(ack.buffer, ack.byteOffset);
    const ackFragLen = ackDv.getUint16(8, true);
    const ackAuthLen = ackDv.getUint16(10, true);

    // Parse presentation_result_list to check if server accepted our context
    {
      let pos = 24; // after common header (16) + max_xmit(2) + max_recv(2) + assoc_group(4)
      const secAddrLen = ackDv.getUint16(pos, true); pos += 2;
      pos += secAddrLen;
      pos = (pos + 3) & ~3; // 4-align
      const nResults = ack[pos]; pos += 4;
      for (let i = 0; i < nResults; i++) {
        const result = ackDv.getUint16(pos, true); pos += 2;
        const reason = ackDv.getUint16(pos, true); pos += 2;
        pos += 20; // skip transfer syntax uuid + ver
        if (result !== 0) {
          const results = ['accept', 'user_rejection', 'provider_rejection'];
          throw new Error(`server rejected presentation context ${i}: ${results[result] || result} (reason=${reason})`);
        }
      }
    }

    if (ackAuthLen === 0) throw new Error('BIND_ACK missing auth data');
    const challengeBlob = ack.subarray(ackFragLen - ackAuthLen);
    const type2 = parseType2(challengeBlob);

    // Step 3: Build AUTHENTICATE (with MIC if server sent MsvAvTimestamp)
    const sessionKey = new Uint8Array(16);
    (globalThis.crypto || {}).getRandomValues?.(sessionKey);
    const { type3, exportedSessionKey, micUsed } = buildAuthenticate({
      user, domain, password, hash, type2, exportedSessionKey: sessionKey,
      negotiateMessage: negotiate,
      challengeMessage: challengeBlob,
    });
    this._session = new NtlmSession(exportedSessionKey, 'client');
    this._exportedSessionKey = exportedSessionKey;

    // Step 4: Send AUTH3 — MUST reuse BIND's call_id per MS-RPCE 2.2.2.4
    const authVer3 = this._authVerifier(type3);
    const pad3 = new Uint8Array(4);
    const fragLen3 = 16 + pad3.length + authVer3.length;
    const pdu3 = concat([this._header(PTYPE.AUTH3, fragLen3, type3.length, callId1), pad3, authVer3]);
    new DataView(pdu3.buffer).setUint16(8, pdu3.length, true);
    await this._send(pdu3);
    this._callId++;

    this._log(`RPC auth: bound to ${interfaceUuid} v${ver} with NTLM authLevel=${this._authLevel}`);
  }

  async call(opnum, stub, contextId = 0) {
    // Unauthenticated / CONNECT path — no signing, no sealing.
    if (!this._session || this._authLevel < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) {
      const body = concat([
        u32(stub.length), u16(contextId), u16(opnum),
        stub,
      ]);
      const callId = this._callId++;
      const fragLen = 16 + body.length;
      const pdu = concat([this._header(PTYPE.REQUEST, fragLen, 0, callId), body]);
      new DataView(pdu.buffer).setUint16(8, pdu.length, true);
      await this._send(pdu);
      return await this._readResponse();
    }

    // Authenticated PKT_INTEGRITY / PKT_PRIVACY path.
    //
    // Per impacket rpcrt.py `_transport_send()` with NEGOTIATE_EXTENDED_SESSIONSECURITY:
    //   sealedMessage, signature = ntlm.SEAL(
    //     flags, signKey, sealKey,
    //     rpc_packet.get_packet()[:-16],  # messageToSign = ENTIRE PDU minus 16-byte sig
    //     plain_data,                      # messageToEncrypt = plaintext stub+pad
    //     seq, handle)
    //
    // So we build the full PDU (header + body + stub_plaintext + preamble + zero_sig),
    // slice off the trailing 16-byte sig placeholder, HMAC over the rest, then insert
    // sealed(stub+pad) in place of plaintext and the computed sig at the end.
    const padLen = (4 - (stub.length % 4)) % 4;
    const padding = new Uint8Array(padLen);
    const paddedStub = padLen ? concat([stub, padding]) : stub;
    const preamble = concat([
      Uint8Array.of(RPC_C_AUTHN_WINNT, this._authLevel, padLen, 0),
      u32(this._authCtxId || 0),
    ]);
    const zeroSig = new Uint8Array(16);
    const callId = this._callId++;

    // First construct the full PDU with plaintext stub + zero signature.
    const bodyPlain = concat([
      u32(stub.length), u16(contextId), u16(opnum),
      paddedStub, preamble, zeroSig,
    ]);
    const fragLen = 16 + bodyPlain.length;
    const header = this._header(PTYPE.REQUEST, fragLen, 16, callId);
    const pduPlain = concat([header, bodyPlain]);
    new DataView(pduPlain.buffer).setUint16(8, pduPlain.length, true);

    // signInput = full PDU minus trailing 16-byte signature placeholder.
    const signInput = pduPlain.subarray(0, pduPlain.length - 16);


    // Per impacket: SEAL first (encrypts stub → consumes ks[0..N-1]), then MAC
    // (encrypts HMAC → consumes ks[N..N+7]). No macFirst flag = default SEAL-first.
    let sig, wireStub;
    if (this._authLevel >= RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
      const out = this._session.sealRpc(paddedStub, { signInput });
      sig = out.sig;
      wireStub = out.sealed;
    } else {
      // PKT_INTEGRITY: no encryption, just MAC over signInput.
      sig = this._session._mac(this._session._sendSeal, this._session._sendKey, this._session.sendSeq, signInput);
      this._session.sendSeq = (this._session.sendSeq + 1) >>> 0;
      wireStub = paddedStub;
    }

    // Reassemble final PDU: swap plaintext stub → wireStub, zero sig → real sig.
    const bodyFinal = concat([
      u32(stub.length), u16(contextId), u16(opnum),
      wireStub, preamble, sig,
    ]);
    const pdu = concat([header, bodyFinal]);
    await this._send(pdu);
    return await this._readResponse();
  }

  async _readResponse() {

    // Read response fragments
    let result = new Uint8Array(0);
    for (;;) {
      const resp = await this._readPdu();
      const ptype = resp[2], flags = resp[3];
      if (ptype === PTYPE.FAULT) {
        const faultDv = new DataView(resp.buffer, resp.byteOffset);
        const status = faultDv.getUint32(24, true);
        const flagsField = resp[3];
        const cancelCount = resp[26];
        throw new Error(`DCE-RPC fault: 0x${status.toString(16)}`);
      }
      if (ptype !== PTYPE.RESPONSE) throw new Error(`expected RESPONSE, got ptype ${ptype}`);
      const respDv = new DataView(resp.buffer, resp.byteOffset);
      const respAuthLen = respDv.getUint16(10, true);

      let stubData;
      if (this._session && respAuthLen > 0 && this._authLevel >= RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
        const authStart = resp.length - respAuthLen - 8;
        const authPadLen = resp[authStart + 2];
        const preamble = resp.subarray(authStart, authStart + 8);
        const wireSig = resp.subarray(authStart + 8, authStart + 8 + respAuthLen);
        const sealedStub = resp.subarray(24, authStart);
        // signInput = full PDU with sealed stub swapped for plaintext AND
        // trailing 16-byte signature stripped (impacket rpcrt.py convention).
        const respHeaderAndBodyHeader = resp.subarray(0, 24);
        const plaintext = this._session.unsealRpc(sealedStub, wireSig, {
          signInputBuilder: (pt) => concat([respHeaderAndBodyHeader, pt, preamble]),
        });
        stubData = authPadLen ? plaintext.subarray(0, plaintext.length - authPadLen) : plaintext;
      } else {
        const stubEnd = resp.length - (respAuthLen ? respAuthLen + 8 : 0);
        stubData = resp.subarray(24, stubEnd);
      }

      result = concat([result, stubData]);
      if (flags & PFC_LAST) break;
    }
    return result;
  }
}

// Endpoint Mapper (EPM) — resolve interface endpoints via port 135
const EPM_UUID = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa';

export async function epmLookup(host, interfaceUuid, ver = '0.0', log = () => {}) {
  const rpc = new DceRpcTcp(log);
  try {
    await rpc.connect(host, 135);
    await rpc.bind(EPM_UUID, '3.0');

    // ept_map (opnum 3) — find endpoint for an interface
    const [maj, min] = ver.split('.').map(Number);

    // Build tower: floor 1 = interface, floor 2 = NDR, floor 3 = RPC,
    //              floor 4 = TCP, floor 5 = IP
    const ifUuid = uuidBytes(interfaceUuid);
    const ndrUuid = uuidBytes(NDR_SYNTAX);

    // Floor 1: interface UUID
    const f1lhs = concat([Uint8Array.of(0x0d), ifUuid, u16(maj)]);
    const f1rhs = concat([u16(min)]);
    const floor1 = concat([u16(f1lhs.length), f1lhs, u16(f1rhs.length), f1rhs]);

    // Floor 2: NDR transfer syntax
    const f2lhs = concat([Uint8Array.of(0x0d), ndrUuid, u16(2)]);
    const f2rhs = concat([u16(0)]);
    const floor2 = concat([u16(f2lhs.length), f2lhs, u16(f2rhs.length), f2rhs]);

    // Floor 3: RPC connection-oriented
    const floor3 = concat([u16(1), Uint8Array.of(0x0b), u16(2), u16(0)]);

    // Floor 4: TCP (port placeholder)
    const floor4 = concat([u16(1), Uint8Array.of(0x07), u16(2), Uint8Array.of(0, 0)]);

    // Floor 5: IP (address placeholder)
    const floor5 = concat([u16(1), Uint8Array.of(0x09), u16(4), Uint8Array.of(0, 0, 0, 0)]);

    const towerData = concat([
      u16(5), // num floors
      floor1, floor2, floor3, floor4, floor5,
    ]);

    // ept_map input params per DCE 1.1 IDL:
    //   [in] uuid_p_t obj              — full pointer: referent(4) + [uuid(16)]
    //   [in] twr_p_t map_tower         — full pointer: referent(4) + twr_t
    //   [in,out] ept_lookup_handle_t   — context handle: attrs(4) + uuid(16)
    //   [in] unsigned32 max_towers     — u32
    // twr_t (conformant struct): max_count(4) + tower_length(4) + bytes[max_count]
    const padTower = (4 - (towerData.length % 4)) % 4;
    const stub = concat([
      u32(0),                        // obj referent = 0 (null pointer)
      u32(0x00020000),               // tower referent (non-null)
      u32(towerData.length),         // max_count for conformant array
      u32(towerData.length),         // tower_length field
      towerData,                     // tower octets
      new Uint8Array(padTower),      // align to 4
      new Uint8Array(20),            // entry_handle (null context handle)
      u32(4),                        // max_towers
    ]);

    const resp = await rpc.call(3, stub);
    // Parse ept_map response to find TCP port
    // Response: entry_handle(20) + num_towers(4) + tower_array...
    const rdv = new DataView(resp.buffer, resp.byteOffset);
    const numTowers = rdv.getUint32(20, true);
    if (numTowers === 0) throw new Error(`no EPM entry for ${interfaceUuid}`);

    // Scan for the TCP floor pattern inside any returned tower:
    //   lhs_len(2 LE)=1 | lhs(1)=0x07 (TCP) | rhs_len(2 LE)=2 | rhs(2 BE)=port
    // On wire that's exactly: 01 00 07 02 00 P1 P2.
    for (let i = 24; i < resp.length - 4; i++) {
      if (resp[i] === 0x07 && resp[i - 2] === 1 && resp[i - 1] === 0 &&
          resp[i + 1] === 2 && resp[i + 2] === 0) {
        const port = (resp[i + 3] << 8) | resp[i + 4]; // big-endian
        if (port > 0 && port < 65536) {
          log(`EPM: ${interfaceUuid} → port ${port}`);
          return port;
        }
      }
    }
    throw new Error(`EPM: could not find TCP port for ${interfaceUuid}`);
  } finally {
    await rpc.close();
  }
}

// Well-known interface UUIDs for display
const KNOWN_IFS = {
  '000001a0-0000-0000-c000-000000000046': 'IRemoteSCMActivator',
  '99fcfec4-5260-101b-bbcb-00aa0021347a': 'IOXIDResolver',
  '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57': 'IRemoteActivation',
  'd4781cd6-e5d3-44df-ad94-930efe48a887': 'IWbemLevel1Login',
  '9556dc99-828c-1054-9ded-00aa004bbb25': 'IWbemServices',
  '1c1c45ee-4395-11d2-b60b-00104b703efd': 'IWbemFetchSmartEnum',
  '423ec01e-2e35-11d2-b604-00104b703efd': 'IWbemWCOSmartEnum',
  '12345778-1234-abcd-ef00-0123456789ac': 'SAM (samr)',
  '12345778-1234-abcd-ef00-0123456789ab': 'LSA (lsarpc)',
  'e1af8308-5d1f-11c9-91a4-08002b14a0fa': 'EPM (epmp)',
  '338cd001-2244-31f1-aaaa-900038001003': 'WinReg',
  '367abb81-9844-35f1-ad32-98f038001003': 'svcctl',
  '86d35949-83c9-4044-b424-db363231fd0c': 'Task Scheduler (ITaskSchedulerService)',
  '378e52b0-c0a9-11cf-822d-00aa0051e40f': 'Task Scheduler (SASec)',
  '12345678-1234-abcd-ef00-0123456789ab': 'spoolss',
  'c681d488-d850-11d0-8c52-00c04fd90f7e': 'EfsRpc',
  'df1941c5-fe89-4e79-bf10-463657acf44d': 'EfsRpc (alt)',
  '76f03f96-cdfd-44fc-a22c-64950a001209': 'IRemoteWinspool',
  '894de0c0-0d55-11d3-a322-00c04fa321a1': 'WinStation (TSSRV)',
  '1ff70682-0a51-30e8-076d-740be8cee98b': 'atsvc (AT Scheduler)',
  '6bffd098-a112-3610-9833-46c3f87e345a': 'wkssvc',
  '4b324fc8-1670-01d3-1278-5a47bf6ee188': 'srvsvc',
  'e3514235-4b06-11d1-ab04-00c04fc2dcd2': 'drsuapi',
  '3dde7c30-165d-11d1-ab8f-00805f14db40': 'BackupKey',
  'ecec0d70-a603-11d0-96b1-00a0c91ece30': 'ICertPassage',
  'f5cc5a18-4264-101a-8c59-08002b2f8426': 'DHCP Server',
};

function parseUuid(data, off) {
  const b = data.subarray(off, off + 16);
  const p = (i) => b[i].toString(16).padStart(2, '0');
  return `${p(3)}${p(2)}${p(1)}${p(0)}-${p(5)}${p(4)}-${p(7)}${p(6)}-${p(8)}${p(9)}-${p(10)}${p(11)}${p(12)}${p(13)}${p(14)}${p(15)}`;
}

// Enumerate ALL RPC endpoints registered on port 135 (ept_lookup, opnum 2)
export async function epmEnum(host, log = () => {}) {
  const rpc = new DceRpcTcp(log);
  const endpoints = [];
  try {
    await rpc.connect(host, 135);
    await rpc.bind(EPM_UUID, '3.0');

    const handle = new Uint8Array(20); // null context handle
    let done = false;

    while (!done) {
      // ept_lookup (opnum 2): inquiry_type=0 (all), object=NULL, interface_id=NULL,
      //                       vers_option=1, entry_handle, max_ents=50
      const stub = concat([
        u32(0),                   // inquiry_type (RPC_C_EP_ALL_ELTS)
        u32(0),                   // object UUID pointer (NULL)
        u32(0),                   // interface_id pointer (NULL)
        u32(0),                   // vers_option
        handle,                   // entry_handle (context handle)
        u32(50),                  // max_ents
      ]);

      let resp;
      try {
        resp = await rpc.call(2, stub);
      } catch (e) {
        break;
      }
      const rdv = new DataView(resp.buffer, resp.byteOffset);

      // Parse response: entry_handle(20) + num_ents(4) + entries...
      const newHandle = resp.subarray(0, 20);
      handle.set(newHandle);
      const numEnts = rdv.getUint32(20, true);
      if (numEnts === 0) { done = true; break; }

      // Skip past the entry_handle(20) + num_ents(4) + max_count(4)
      let pos = 28;
      for (let i = 0; i < numEnts && pos + 4 < resp.length; i++) {
        // Each entry: object_uuid(16) + tower_pointer(4) + ...
        // The format is complex — scan for tower floors to extract interface UUID + port
        // Tower structure: tower_length(4) + num_floors(2) + floors...
        // Floor: lhs_len(2) + lhs_data + rhs_len(2) + rhs_data
        // Floor 1 LHS byte 0 = protocol_id: 0x0d = UUID

        // Find the next valid tower by scanning for the protocol ID pattern
        let found = false;
        for (let j = pos; j < resp.length - 30 && !found; j++) {
          // Look for tower start: 2-byte numFloors (3-6 typical) followed by a floor with protocol 0x0d
          if (resp[j] >= 3 && resp[j] <= 10 && resp[j + 1] === 0) {
            const nFloors = resp[j] | (resp[j + 1] << 8);
            if (nFloors >= 3 && nFloors <= 10) {
              let fpos = j + 2;
              const lhsLen = resp[fpos] | (resp[fpos + 1] << 8);
              if (lhsLen === 19 && resp[fpos + 2] === 0x0d && fpos + lhsLen + 2 < resp.length) {
                const ifUuid = parseUuid(resp, fpos + 3);
                const ifMajor = resp[fpos + 19] | (resp[fpos + 20] << 8);

                // Walk floors to find TCP port (protocol 0x07)
                let fp = fpos;
                let tcpPort = 0;
                let protocol = '';
                for (let f = 0; f < nFloors && fp < resp.length - 4; f++) {
                  const flhsLen = resp[fp] | (resp[fp + 1] << 8);
                  fp += 2;
                  const pid = resp[fp];
                  fp += flhsLen;
                  const frhsLen = resp[fp] | (resp[fp + 1] << 8);
                  fp += 2;
                  if (pid === 0x07 && frhsLen === 2) {
                    tcpPort = (resp[fp] << 8) | resp[fp + 1];
                    protocol = 'tcp';
                  }
                  if (pid === 0x08 && frhsLen === 2) {
                    protocol = protocol || 'udp';
                  }
                  if (pid === 0x0f) {
                    protocol = 'ncacn_np';
                  }
                  fp += frhsLen;
                }

                if (ifUuid !== '00000000-0000-0000-0000-000000000000') {
                  const name = KNOWN_IFS[ifUuid] || '';
                  endpoints.push({ uuid: ifUuid, version: ifMajor, port: tcpPort, protocol, name });
                  found = true;
                  pos = fp;
                }
              }
            }
          }
          if (found) break;
          pos = j + 1;
        }
        if (!found) break;
      }

      // Check status code at end of response
      const status = rdv.getUint32(resp.length - 4, true);
      if (status === 0x16c9a0d6) { done = true; } // RPC_X_NO_MORE_ENTRIES
      if (numEnts < 50) { done = true; }
    }
  } finally {
    await rpc.close();
  }

  // Deduplicate by UUID
  const seen = new Set();
  const deduped = [];
  for (const ep of endpoints) {
    const key = `${ep.uuid}:${ep.port}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(ep);
    }
  }
  return deduped;
}
