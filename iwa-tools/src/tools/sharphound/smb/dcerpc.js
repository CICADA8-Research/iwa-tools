// Minimal DCE-RPC (MS-RPCE) over a named pipe: BIND to an interface, then issue
// REQUESTs and read RESPONSEs. The transport is a transceive(bytes)->bytes
// function (the SMB2 FSCTL_PIPE_TRANSCEIVE on an open pipe). Little-endian NDR.

import { concat } from '../ldap/ber.js';

const PTYPE = { REQUEST: 0, RESPONSE: 2, FAULT: 3, BIND: 11, BIND_ACK: 12, BIND_NAK: 13 };
const PFC_FIRST = 0x01, PFC_LAST = 0x02;
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
  constructor(transceive, log = () => {}) { this._tx = transceive; this._callId = 1; }

  async bind(interfaceUuid, ver = '1.0') {
    const [maj, min] = ver.split('.').map(Number);
    // p_context_elem: n_context_elem(1)+reserved(1)+reserved2(2), then one context.
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
    const pdu = concat([header(PTYPE.BIND, 0, this._callId), body]);
    new DataView(pdu.buffer).setUint16(8, pdu.length, true); // frag_length
    const resp = await this._tx(pdu);
    if (resp[2] === PTYPE.BIND_NAK) throw new Error('DCE-RPC bind rejected');
    if (resp[2] !== PTYPE.BIND_ACK) throw new Error(`DCE-RPC: expected BIND_ACK, got ptype ${resp[2]}`);
    this._callId++;
  }

  // Issue a request and return the response stub (concatenated fragments).
  async call(opnum, stub) {
    const body = concat([
      u32(stub.length),                   // alloc_hint
      u16(0), u16(opnum),                 // p_cont_id, opnum
      stub,
    ]);
    const pdu = concat([header(PTYPE.REQUEST, 0, this._callId), body]);
    new DataView(pdu.buffer).setUint16(8, pdu.length, true);
    this._callId++;

    const resp = await this._tx(pdu); // full response (all fragments) from the pipe
    let out = new Uint8Array(0);
    let pos = 0;
    for (;;) {
      if (pos + 24 > resp.length) break;
      const dv = new DataView(resp.buffer, resp.byteOffset + pos, resp.length - pos);
      const ptype = resp[pos + 2], flags = resp[pos + 3];
      const fragLen = dv.getUint16(8, true);
      if (ptype === PTYPE.FAULT) throw new Error(`DCE-RPC fault 0x${dv.getUint32(24, true).toString(16)}`);
      if (ptype !== PTYPE.RESPONSE) throw new Error(`DCE-RPC: expected RESPONSE, got ptype ${ptype}`);
      out = concat([out, resp.subarray(pos + 24, pos + fragLen)]); // skip 24-byte response header
      pos += fragLen;
      if (flags & PFC_LAST) break;
    }
    return out;
  }
}
