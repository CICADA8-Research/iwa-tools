// Minimal DCE-RPC (MS-RPCE) over a named pipe: BIND to an interface, then issue
// REQUESTs and read RESPONSEs. The transport is a transceive(bytes)->bytes
// function (the SMB2 FSCTL_PIPE_TRANSCEIVE on an open pipe). Little-endian NDR.

import { concat } from '../ldap/ber.js';
import { buildNegotiate, buildAuthenticate, NtlmSession } from '../ntlm/seal.js';
import { parseType2 } from '../ntlm/ntlm.js';

const PTYPE = { REQUEST: 0, RESPONSE: 2, FAULT: 3, BIND: 11, BIND_ACK: 12, BIND_NAK: 13, AUTH3: 16 };
const PFC_FIRST = 0x01, PFC_LAST = 0x02;
const AUTH_NTLM = 0x0a, AUTH_CONNECT = 0x02, AUTH_PRIVACY = 0x06;
const NDR_SYNTAX = '8a885d04-1ceb-11c9-9fe8-08002b104860'; // NDR transfer syntax v2.0

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

function header(ptype, fragLen, callId) {
  return concat([
    Uint8Array.of(5, 0, ptype, PFC_FIRST | PFC_LAST), // ver, minor, ptype, flags
    Uint8Array.of(0x10, 0, 0, 0),                     // drep: little-endian
    u16(fragLen), u16(0),                             // frag_length, auth_length
    u32(callId),
  ]);
}

export class DceRpc {
  // opts.writeOnly(bytes) sends a one-way PDU (AUTH3) — required for authenticated binds.
  constructor(transceive, opts = {}) { this._tx = transceive; this._writeOnly = opts.writeOnly; this._callId = 1; }

  // Append an auth verifier (sec_trailer + auth value) and fix frag/auth lengths.
  _addTrailer(pdu, level, authValue) {
    const pad = (4 - (pdu.length % 4)) % 4;
    const trailer = concat([Uint8Array.of(AUTH_NTLM, level, pad, 0), u32(0), authValue]); // sec_trailer + value
    const full = concat([pdu, new Uint8Array(pad), trailer]);
    const dv = new DataView(full.buffer, full.byteOffset, full.byteLength);
    dv.setUint16(8, full.length, true);         // frag_length
    dv.setUint16(10, authValue.length, true);   // auth_length
    return full;
  }
  _extractTrailer(resp) {
    const dv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const frag = dv.getUint16(8, true);
    const authLen = dv.getUint16(10, true);
    if (!authLen) throw new Error('DCE-RPC: server returned no auth token (RPC authentication refused)');
    return resp.subarray(frag - authLen, frag);
  }

  // auth (optional): { user, domain, password, level? } → NTLM RPC authentication.
  async bind(interfaceUuid, ver = '1.0', auth = null) {
    const [maj, min] = ver.split('.').map(Number);
    const context = concat([
      u16(0), Uint8Array.of(1, 0),        // context_id=0, n_transfer_syn=1, reserved
      uuidBytes(interfaceUuid), u16(maj), u16(min),       // abstract syntax + version
      uuidBytes(NDR_SYNTAX), u16(2), u16(0),              // transfer syntax NDR v2.0
    ]);
    const body = concat([
      u16(0x16d0), u16(0x16d0),           // max_xmit_frag, max_recv_frag
      u32(0),                             // assoc_group_id
      Uint8Array.of(1, 0, 0, 0),          // n_context_elem=1, reserved(3)
      context,
    ]);
    const level = (auth && auth.level) || AUTH_CONNECT;
    let pdu = concat([header(PTYPE.BIND, 0, this._callId), body]);
    if (auth) pdu = this._addTrailer(pdu, level, buildNegotiate()); // NTLM type1
    else new DataView(pdu.buffer).setUint16(8, pdu.length, true);

    const resp = await this._tx(pdu);
    if (resp[2] === PTYPE.BIND_NAK) throw new Error('DCE-RPC bind rejected');
    if (resp[2] !== PTYPE.BIND_ACK) throw new Error(`DCE-RPC: expected BIND_ACK, got ptype ${resp[2]}`);

    if (auth) {
      if (!this._writeOnly) throw new Error('DceRpc: authenticated bind needs a writeOnly transport');
      const { type3, exportedSessionKey } = buildAuthenticate({ user: auth.user, domain: auth.domain, password: auth.password, type2: parseType2(this._extractTrailer(resp)) });
      const a3 = this._addTrailer(concat([header(PTYPE.AUTH3, 0, this._callId), u32(0)]), level, type3);
      await this._writeOnly(a3); // one-way — no response
      if (level >= AUTH_PRIVACY) { this._ntlm = new NtlmSession(exportedSessionKey, 'client'); this._level = level; }
    }
    this._callId++;
  }

  // Issue a request and return the response stub. With PKT_PRIVACY the stub is
  // NTLM-sealed and a signed sec_trailer is appended; the response is decrypted.
  async call(opnum, stub) {
    let pdu;
    if (this._ntlm) {
      const pad = (4 - (stub.length % 4)) % 4;
      const stubPad = concat([stub, new Uint8Array(pad).fill(0xbb)]);      // pad bytes = 0xBB (impacket)
      const reqBody = concat([u32(stubPad.length), u16(0), u16(opnum)]);   // alloc_hint, cont_id, opnum
      const secTrailer = concat([Uint8Array.of(AUTH_NTLM, this._level, pad, 0), u32(0)]); // 8-byte sec_trailer (no sig yet)
      const hdr = header(PTYPE.REQUEST, 0, this._callId);
      const hdv = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
      hdv.setUint16(8, 16 + reqBody.length + stubPad.length + secTrailer.length + 16, true); // frag_length
      hdv.setUint16(10, 16, true);                                          // auth_length
      const toSign = concat([hdr, reqBody, stubPad, secTrailer]);           // whole PDU minus signature
      const { sealed, signature } = this._ntlm.sealRpc(stubPad, toSign);
      pdu = concat([hdr, reqBody, sealed, secTrailer, signature]);
    } else {
      const body = concat([u32(stub.length), u16(0), u16(opnum), stub]);
      pdu = concat([header(PTYPE.REQUEST, 0, this._callId), body]);
      new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength).setUint16(8, pdu.length, true);
    }
    this._callId++;

    const resp = await this._tx(pdu); // full response (all fragments) from the pipe
    let out = new Uint8Array(0);
    let pos = 0;
    for (;;) {
      if (pos + 24 > resp.length) break;
      const dv = new DataView(resp.buffer, resp.byteOffset + pos, resp.length - pos);
      const ptype = resp[pos + 2], flags = resp[pos + 3];
      const fragLen = dv.getUint16(8, true);
      const aLen = dv.getUint16(10, true);
      if (ptype === PTYPE.FAULT) throw new Error(`DCE-RPC fault 0x${dv.getUint32(24, true).toString(16)}`);
      if (ptype !== PTYPE.RESPONSE) throw new Error(`DCE-RPC: expected RESPONSE, got ptype ${ptype}`);
      if (this._ntlm && aLen) {
        const padLen = resp[pos + fragLen - aLen - 8 + 2]; // sec_trailer auth_pad_length
        const sealed = resp.subarray(pos + 24, pos + fragLen - aLen - 8);
        const plain = this._ntlm.decryptRpc(sealed);       // decrypt stub (MAC not re-verified)
        out = concat([out, plain.subarray(0, plain.length - padLen)]);
      } else {
        out = concat([out, resp.subarray(pos + 24, pos + fragLen)]);
      }
      pos += fragLen;
      if (flags & PFC_LAST) break;
    }
    return out;
  }
}
