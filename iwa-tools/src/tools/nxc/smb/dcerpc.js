// Minimal DCE-RPC (MS-RPCE) over a named pipe: BIND to an interface, then issue
// REQUESTs and read RESPONSEs. The transport is a transceive(bytes)->bytes
// function (the SMB2 FSCTL_PIPE_TRANSCEIVE on an open pipe). Little-endian NDR.
//
// Two auth modes:
//   * NULL bind (default) — SMB session's authentication identity is used by
//     the target RPC server for all calls. Fine for interfaces that don't
//     enforce RPC-layer auth (samr, svcctl, drsuapi, wkssvc).
//   * NTLMSSP-authenticated bind — call `bindAuth(iface, ver, creds, level)`
//     instead of `bind()`. Currently only RPC_C_AUTHN_LEVEL_CONNECT (2) is
//     implemented: an NTLMSSP_NEGOTIATE/CHALLENGE/AUTHENTICATE exchange runs
//     on the BIND/BIND_ACK/AUTH3 PDUs, then subsequent REQUEST/RESPONSE PDUs
//     go plain (no per-PDU signing). This matches impacket's default and
//     satisfies interfaces that require the caller identity to be re-asserted
//     at RPC layer, e.g. TSCH `SchRpcRegisterTask` on hardened DCs.

import { concat } from '../ldap/ber.js';
import { buildNegotiate, buildAuthenticate, NtlmSession } from '../ntlm/seal.js';
import { parseType2 } from '../ntlm/ntlm.js';

const PTYPE = {
  REQUEST: 0, RESPONSE: 2, FAULT: 3,
  BIND: 11, BIND_ACK: 12, BIND_NAK: 13,
  ALTER_CONTEXT: 14, ALTER_CONTEXT_RESP: 15,
  AUTH3: 16,
};
const PFC_FIRST = 0x01, PFC_LAST = 0x02;
const NDR_SYNTAX = '8a885d04-1ceb-11c9-9fe8-08002b104860'; // NDR transfer syntax v2.0

const RPC_C_AUTHN_WINNT = 10;
export const RPC_C_AUTHN_LEVEL_CONNECT = 2;
export const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5;
export const RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;

const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

// "12345778-1234-abcd-ef00-0123456789ac" -> 16 DCE-RPC bytes (first 3 fields LE).
export function uuidBytes(uuid) {
  const h = uuid.replace(/-/g, '');
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  const out = new Uint8Array(16);
  out[0] = b[3]; out[1] = b[2]; out[2] = b[1]; out[3] = b[0]; // time-low LE
  out[4] = b[5]; out[5] = b[4];                               // time-mid LE
  out[6] = b[7]; out[7] = b[6];                               // time-hi LE
  out.set(b.subarray(8), 8);                                  // rest big-endian
  return out;
}

function header(ptype, fragLen, authLen, callId) {
  return concat([
    Uint8Array.of(5, 0, ptype, PFC_FIRST | PFC_LAST), // ver, minor, ptype, flags
    Uint8Array.of(0x10, 0, 0, 0),                     // drep: little-endian
    u16(fragLen), u16(authLen),                       // frag_length, auth_length
    u32(callId),
  ]);
}

export class DceRpc {
  // transceive(bytes) -> bytes           — send PDU, receive PDU (FSCTL_PIPE_TRANSCEIVE)
  // read()           -> bytes            — read additional response fragments
  // write(bytes)     -> void             — fire-and-forget send (SMB2 WRITE, no reply)
  //                                        needed for AUTH3, which the server never
  //                                        responds to per MS-RPCE §2.2.2.4
  constructor(transceive, read = null, write = null) {
    this._tx = transceive;
    this._read = read;
    this._write = write;
    this._callId = 1;
    this._session = null;
    this._authLevel = 0;
    this._authCtxId = 0;
  }

  // Unauthenticated bind — RPC identity is inherited from the SMB session.
  async bind(interfaceUuid, ver = '1.0') {
    const [maj, min] = ver.split('.').map(Number);
    const context = concat([
      u16(0), Uint8Array.of(1, 0),        // context_id=0, n_transfer_syn=1, reserved
      uuidBytes(interfaceUuid), u16(maj), u16(min),
      uuidBytes(NDR_SYNTAX), u16(2), u16(0),
    ]);
    const body = concat([
      u16(0x16d0), u16(0x16d0),           // max_xmit_frag, max_recv_frag
      u32(0),                             // assoc_group_id
      Uint8Array.of(1, 0, 0, 0),          // n_context_elem=1, reserved(3)
      context,
    ]);
    const pdu = concat([header(PTYPE.BIND, 0, 0, this._callId), body]);
    new DataView(pdu.buffer).setUint16(8, pdu.length, true);
    const resp = await this._tx(pdu);
    if (resp[2] === PTYPE.BIND_NAK) throw new Error('DCE-RPC bind rejected');
    if (resp[2] !== PTYPE.BIND_ACK) throw new Error(`DCE-RPC: expected BIND_ACK, got ptype ${resp[2]}`);
    this._callId++;
  }

  // NTLMSSP-authenticated bind at auth level `authLevel` (PKT_PRIVACY by
  // default — matches impacket's atexec.py, which explicitly raises to level 6
  // for the TSCH interface. Server 2019+ requires signed+sealed RPC PDUs to
  // call SchRpcRegisterTask; a plain CONNECT bind is accepted but every
  // subsequent REQUEST is rejected with nca_s_fault_access_denied (0x5)).
  async bindAuth(interfaceUuid, ver = '1.0', creds, authLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
    if (!this._write) throw new Error('DceRpc.bindAuth requires a write() callback (AUTH3 has no server response)');
    this._authLevel = authLevel;
    this._authCtxId = 79231;
    const [maj, min] = ver.split('.').map(Number);

    // Step 1: BIND with NTLMSSP_NEGOTIATE auth trailer.
    const negotiate = buildNegotiate();
    const authVer1 = concat([
      Uint8Array.of(RPC_C_AUTHN_WINNT, this._authLevel, 0, 0), // authType, authLevel, authPadLen, reserved
      u32(this._authCtxId),
      negotiate,
    ]);
    const context = concat([
      u16(0), Uint8Array.of(1, 0),
      uuidBytes(interfaceUuid), u16(maj), u16(min),
      uuidBytes(NDR_SYNTAX), u16(2), u16(0),
    ]);
    const body = concat([
      u16(0x16d0), u16(0x16d0), u32(0),
      Uint8Array.of(1, 0, 0, 0),
      context,
    ]);
    const callId1 = this._callId;
    const fragLen1 = 16 + body.length + authVer1.length;
    const pdu1 = concat([header(PTYPE.BIND, fragLen1, negotiate.length, callId1), body, authVer1]);
    new DataView(pdu1.buffer).setUint16(8, pdu1.length, true);

    const ack = await this._tx(pdu1);
    if (ack[2] === PTYPE.BIND_NAK) throw new Error('DCE-RPC bindAuth rejected');
    if (ack[2] !== PTYPE.BIND_ACK) throw new Error(`DCE-RPC: expected BIND_ACK, got ptype ${ack[2]}`);
    const ackDv = new DataView(ack.buffer, ack.byteOffset, ack.byteLength);
    const ackFragLen = ackDv.getUint16(8, true);
    const ackAuthLen = ackDv.getUint16(10, true);
    if (ackAuthLen === 0) throw new Error('DCE-RPC bindAuth: BIND_ACK missing NTLMSSP_CHALLENGE');
    // auth_value slice starts at fragLen - authLen (past 8-byte sec_trailer preamble).
    const challengeBlob = ack.subarray(ackFragLen - ackAuthLen, ackFragLen);
    const type2 = parseType2(challengeBlob);

    // Step 2: build NTLMSSP_AUTHENTICATE (Type3) with MIC when server sent MsvAvTimestamp.
    const exportedSessionKey = new Uint8Array(16);
    (globalThis.crypto || {}).getRandomValues?.(exportedSessionKey);
    const { type3, exportedSessionKey: expKey } = buildAuthenticate({
      user: creds.user, domain: creds.domain, password: creds.password, hash: creds.hash,
      type2, exportedSessionKey,
      negotiateMessage: negotiate,
      challengeMessage: challengeBlob,
    });
    this._session = new NtlmSession(expKey, 'client');

    // Step 3: AUTH3 fire-and-forget. Server never replies (MS-RPCE §2.2.2.4).
    // MUST reuse callId of the BIND. 4-byte pad between header and auth trailer.
    const pad3 = new Uint8Array(4);
    const authVer3 = concat([
      Uint8Array.of(RPC_C_AUTHN_WINNT, this._authLevel, 0, 0),
      u32(this._authCtxId),
      type3,
    ]);
    const fragLen3 = 16 + pad3.length + authVer3.length;
    const pdu3 = concat([header(PTYPE.AUTH3, fragLen3, type3.length, callId1), pad3, authVer3]);
    new DataView(pdu3.buffer).setUint16(8, pdu3.length, true);
    await this._write(pdu3);
    this._callId++;
  }

  // Issue a request and return the response stub (concatenated fragments).
  //  * No session (or CONNECT level)     → plain REQUEST, no per-PDU auth
  //  * PKT_INTEGRITY (5)                 → REQUEST + MAC-only auth trailer
  //  * PKT_PRIVACY   (6)                 → REQUEST with sealed stub + MAC
  //                                         (impacket's default for TSCH,
  //                                          DRSUAPI, WMI, WinReg on hardened
  //                                          hosts — Server 2019+ rejects the
  //                                          plain path with 0x5).
  async call(opnum, stub) {
    let pdu;
    if (!this._session || this._authLevel < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) {
      const body = concat([
        u32(stub.length),
        u16(0), u16(opnum),
        stub,
      ]);
      pdu = concat([header(PTYPE.REQUEST, 0, 0, this._callId), body]);
      new DataView(pdu.buffer).setUint16(8, pdu.length, true);
    } else {
      // Authenticated path — mirrors impacket rpcrt.py `_transport_send()`
      // for NEGOTIATE_EXTENDED_SESSIONSECURITY:
      //   sig = MAC(signKey, sendSeq, full_PDU_minus_16_byte_sig_placeholder)
      //   sealed_stub = SEAL(sealKey, plaintext_stub)
      // The full PDU is: [common header 16B] + [alloc_hint u32 + ctx u16 + opnum u16]
      //                 + [sealed_stub + pad] + [sec_trailer preamble 8B] + [sig 16B]
      // auth_length in the header = 16 (the sig only, not the preamble).
      const padLen = (4 - (stub.length % 4)) % 4;
      const padding = new Uint8Array(padLen);
      const paddedStub = padLen ? concat([stub, padding]) : stub;
      const preamble = new Uint8Array([RPC_C_AUTHN_WINNT, this._authLevel, padLen, 0, 0, 0, 0, 0]);
      new DataView(preamble.buffer).setUint32(4, this._authCtxId, true);
      const zeroSig = new Uint8Array(16);

      const bodyPlain = concat([
        u32(stub.length),
        u16(0), u16(opnum),
        paddedStub, preamble, zeroSig,
      ]);
      const fragLen = 16 + bodyPlain.length;
      const hdr = header(PTYPE.REQUEST, fragLen, 16, this._callId);
      const pduPlain = concat([hdr, bodyPlain]);
      new DataView(pduPlain.buffer).setUint16(8, pduPlain.length, true);

      // signInput = full PDU minus the trailing 16-byte signature placeholder.
      const signInput = pduPlain.subarray(0, pduPlain.length - 16);
      let sig, wireStub;
      if (this._authLevel >= RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
        const out = this._session.sealRpc(paddedStub, { signInput });
        sig = out.sig;
        wireStub = out.sealed;
      } else {
        // PKT_INTEGRITY: MAC over signInput only, stub stays plaintext.
        sig = this._session._mac(this._session._sendSeal, this._session._sendKey, this._session.sendSeq, signInput);
        this._session.sendSeq = (this._session.sendSeq + 1) >>> 0;
        wireStub = paddedStub;
      }
      const bodyFinal = concat([
        u32(stub.length),
        u16(0), u16(opnum),
        wireStub, preamble, sig,
      ]);
      pdu = concat([hdr, bodyFinal]);
    }
    this._callId++;

    let resp = await this._tx(pdu);
    let out = new Uint8Array(0);
    let pos = 0;
    let needMore = false;
    for (;;) {
      if (pos + 24 > resp.length) {
        if (needMore && this._read) {
          try { resp = await this._read(); pos = 0; needMore = false; continue; } catch { break; }
        }
        break;
      }
      const dv = new DataView(resp.buffer, resp.byteOffset + pos, resp.length - pos);
      const ptype = resp[pos + 2], flags = resp[pos + 3];
      const fragLen = dv.getUint16(8, true);
      if (ptype === PTYPE.FAULT) {
        const status = dv.getUint32(24, true);
        // Common nca_s_fault codes — surface the friendly name to save the user
        // a search when triaging.
        const name = {
          0x1c010002: 'nca_s_op_rng_error',
          0x1c010003: 'nca_s_unk_if',
          0x1c00001c: 'nca_s_fault_ndr',
          0x1c00001a: 'nca_s_fault_bad_stub_data',
          0x00000005: 'nca_s_fault_access_denied',
          0x000006f7: 'RPC_S_ENTRY_ALREADY_EXISTS / bad marshalling',
          0x8007000e: 'E_OUTOFMEMORY',
        }[status] || 'unknown';
        throw new Error(`DCE-RPC fault 0x${status.toString(16)} (${name})`);
      }
      if (ptype !== PTYPE.RESPONSE) throw new Error(`DCE-RPC: expected RESPONSE, got ptype ${ptype}`);
      const respAuthLen = dv.getUint16(10, true);
      let stubData;
      if (this._session && respAuthLen > 0 && this._authLevel >= RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
        // Layout inside the frag: [common header 16] [alloc_hint u32 + ctx u16 + opnum u16]
        //                         [sealed_stub + pad] [sec_trailer 8] [sig 16]
        const fragStart = pos;
        const authStart = fragStart + fragLen - respAuthLen - 8;
        const authPadLen = resp[authStart + 2];
        const preamble = resp.subarray(authStart, authStart + 8);
        const wireSig = resp.subarray(authStart + 8, authStart + 8 + respAuthLen);
        const sealedStub = resp.subarray(fragStart + 24, authStart);
        const headerAndBodyHeader = resp.subarray(fragStart, fragStart + 24);
        const plaintext = this._session.unsealRpc(sealedStub, wireSig, {
          signInputBuilder: (pt) => concat([headerAndBodyHeader, pt, preamble]),
        });
        stubData = authPadLen ? plaintext.subarray(0, plaintext.length - authPadLen) : plaintext;
      } else if (respAuthLen > 0) {
        // Auth trailer present but not sealed — strip it (8-byte preamble + auth).
        stubData = resp.subarray(pos + 24, pos + fragLen - respAuthLen - 8);
      } else {
        stubData = resp.subarray(pos + 24, pos + fragLen);
      }
      out = concat([out, stubData]);
      pos += fragLen;
      needMore = !(flags & PFC_LAST);
      if (!needMore) break;
    }
    if (out.length === 0) throw new Error(`DCE-RPC: empty response (opnum=${opnum}, respLen=${resp.length})`);
    return out;
  }
}
