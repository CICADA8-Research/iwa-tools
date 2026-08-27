// MS-NRPC (Netlogon Remote Protocol) client: establish a secure channel with a DC
// and validate NTLM authentication responses via NetrLogonSamLogonWithFlags.
// Uses DCE-RPC over TCP (ncacn_ip_tcp) with RPC_C_AUTHN_NETLOGON sealing.

import { Aes } from './certify/crypto/aes.js';
import { md4 } from './certify/crypto/md4.js';
import { Rc4 } from './certify/crypto/rc4.js';
import { concat } from './certify/ldap/ber.js';

const NRPC_UUID = '12345678-1234-abcd-ef00-01234567cffb';
const EPM_UUID  = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa';
const NRPC_IFACE = new Uint8Array([0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb]);
const NDR_SYNTAX = '8a885d04-1ceb-11c9-9fe8-08002b104860';

const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const hex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

function uuidBytes(uuid) {
  const h = uuid.replace(/-/g, '');
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  const out = new Uint8Array(16);
  out[0] = b[3]; out[1] = b[2]; out[2] = b[1]; out[3] = b[0];
  out[4] = b[5]; out[5] = b[4]; out[6] = b[7]; out[7] = b[6];
  out.set(b.subarray(8), 8);
  return out;
}

function utf16leZ(s) {
  const b = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  return b;
}

function ndrWStr(s) {
  const z = utf16leZ(s);
  const chars = z.length / 2;
  return concat([u32(chars), u32(0), u32(chars), z]);
}

function ndrRefWStr(s, ref) {
  return concat([u32(ref), ndrWStr(s)]);
}

// ---- AES-CFB8 ---------------------------------------------------------------
function aesCfb8Encrypt(key, iv, data) {
  const aes = new Aes(key);
  const reg = new Uint8Array(iv);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const block = aes.encryptBlock(reg);
    out[i] = data[i] ^ block[0];
    reg.copyWithin(0, 1);
    reg[15] = out[i];
  }
  return out;
}

function aesCfb8Decrypt(key, iv, data) {
  const aes = new Aes(key);
  const reg = new Uint8Array(iv);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const block = aes.encryptBlock(reg);
    out[i] = data[i] ^ block[0];
    reg.copyWithin(0, 1);
    reg[15] = data[i];
  }
  return out;
}

// ---- NRPC crypto ------------------------------------------------------------
async function hmacSha256(key, data) {
  const k = await globalThis.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, data));
}

async function computeSessionKey(ntHash, clientChallenge, serverChallenge) {
  const hmac = await hmacSha256(ntHash, concat([clientChallenge, serverChallenge]));
  return hmac.slice(0, 16);
}

function computeCredential(challenge, sessionKey) {
  return aesCfb8Encrypt(sessionKey, new Uint8Array(16), challenge);
}

function computeAuthenticator(credential, sessionKey) {
  const ts = Math.floor(Date.now() / 1000);
  const tsBytes = new Uint8Array(4);
  new DataView(tsBytes.buffer).setUint32(0, ts, true);
  const combined = new Uint8Array(8);
  for (let i = 0; i < 8; i++) combined[i] = (credential[i] + tsBytes[i % 4]) & 0xff;
  const newCred = aesCfb8Encrypt(sessionKey, new Uint8Array(16), combined);
  return { credential: newCred, timestamp: tsBytes };
}

// ---- TCP transport for DCE-RPC ----------------------------------------------
class TcpRpcTransport {
  constructor(host, port) { this._host = host; this._port = port; }

  async connect() {
    this._socket = new TCPSocket(this._host, this._port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
    this._buf = new Uint8Array(0);
  }

  async close() {
    try { this._reader?.releaseLock(); } catch {}
    try { this._writer?.releaseLock(); } catch {}
    try { await this._socket?.close(); } catch {}
  }

  async _fillBuf(need) {
    while (this._buf.length < need) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('TCP: connection closed');
      this._buf = concat([this._buf, new Uint8Array(value)]);
    }
  }

  async send(pdu) { await this._writer.write(pdu); }

  async recv() {
    await this._fillBuf(10);
    const fragLen = this._buf[8] | (this._buf[9] << 8);
    await this._fillBuf(fragLen);
    const result = this._buf.slice(0, fragLen);
    this._buf = this._buf.slice(fragLen);
    return result;
  }

  async transceive(pdu) {
    await this.send(pdu);
    return this.recv();
  }
}

// ---- Minimal DCE-RPC PDU builder --------------------------------------------
const PTYPE = { REQUEST: 0, RESPONSE: 2, FAULT: 3, BIND: 11, BIND_ACK: 12, ALTER_CTX: 14, ALTER_CTX_RESP: 15, AUTH3: 16 };
const PFC_FIRST = 0x01, PFC_LAST = 0x02;
const AUTH_NETLOGON = 0x44;
const AUTH_PRIVACY = 0x06;

function rpcHeader(ptype, fragLen, callId) {
  return concat([
    Uint8Array.of(5, 0, ptype, PFC_FIRST | PFC_LAST),
    Uint8Array.of(0x10, 0, 0, 0),
    u16(fragLen), u16(0),
    u32(callId),
  ]);
}

function ctxItem(ctxId, ifUuid, ifMaj, ifMin) {
  return concat([
    u16(ctxId), Uint8Array.of(1, 0),
    uuidBytes(ifUuid), u16(ifMaj), u16(ifMin),
    uuidBytes(NDR_SYNTAX), u16(2), u16(0),
  ]);
}

function nlAuthMessage(domainName, computerName, computerAccount) {
  const enc = new TextEncoder();
  return concat([
    u32(0),
    u32(0x403),
    enc.encode(domainName + '\0'),
    enc.encode(computerName + '\0'),
    enc.encode(computerAccount + '\0'),
  ]);
}

// ---- NL_AUTH_SHA2_SIGNATURE for request sealing (MS-NRPC §2.2.1.3.3) --------
async function nlSealRequest(sessionKey, seqNum, stub) {
  const sigHdr = new Uint8Array(8);
  new DataView(sigHdr.buffer).setUint16(0, 0x0013, true);
  new DataView(sigHdr.buffer).setUint16(2, 0x001a, true);
  sigHdr[4] = 0xff; sigHdr[5] = 0xff;
  sigHdr[6] = 0x00; sigHdr[7] = 0x00;

  const seqBytes = new Uint8Array(8);
  new DataView(seqBytes.buffer).setBigUint64(0, BigInt(seqNum), true);

  const confounder = globalThis.crypto.getRandomValues(new Uint8Array(8));

  const checksum = await hmacSha256(sessionKey, concat([sigHdr, seqBytes, confounder, stub]));

  const iv1 = new Uint8Array(16);
  iv1.set(seqBytes, 0);
  const sealedData = aesCfb8Encrypt(sessionKey, iv1, concat([confounder, stub]));

  const iv2 = new Uint8Array(16);
  iv2.set(checksum.slice(0, 8), 0);
  const encSeq = aesCfb8Encrypt(sessionKey, iv2, seqBytes);

  const sig = concat([sigHdr, encSeq, checksum.slice(0, 8), sealedData.slice(0, 8)]);
  return { sealed: sealedData.slice(8), signature: sig };
}

async function nlUnsealResponse(sessionKey, sig, sealedStub) {
  const encSeq = sig.subarray(8, 16);
  const checksum = sig.subarray(16, 24);
  const encConfounder = sig.subarray(24, 32);

  const iv2 = new Uint8Array(16);
  iv2.set(checksum.slice(0, 8), 0);
  const seqBytes = aesCfb8Decrypt(sessionKey, iv2, encSeq);

  const iv1 = new Uint8Array(16);
  iv1.set(seqBytes, 0);
  const plain = aesCfb8Decrypt(sessionKey, iv1, concat([encConfounder, sealedStub]));

  return plain.slice(8);
}

// ---- EPM endpoint mapper ----------------------------------------------------
async function epmLookup(host, ifUuid) {
  const t = new TcpRpcTransport(host, 135);
  await t.connect();
  try {
    const ctx = ctxItem(0, EPM_UUID, 3, 0);
    const bindBody = concat([u16(0x16d0), u16(0x16d0), u32(0), Uint8Array.of(1, 0, 0, 0), ctx]);
    let pdu = concat([rpcHeader(PTYPE.BIND, 0, 1), bindBody]);
    new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
    let resp = await t.transceive(pdu);
    if (resp[2] !== PTYPE.BIND_ACK) throw new Error('EPM bind failed');

    const ifBytes = uuidBytes(ifUuid);
    const tower = buildEpmTower(ifBytes, 1, 0);
    const stub = concat([
      u32(0),
      u32(0x00020000), u32(tower.length), u32(tower.length),
      tower,
      u32(0), u32(0), u32(0), u32(0),
      u32(4),
    ]);
    const reqBody = concat([u32(stub.length), u16(0), u16(3), stub]);
    pdu = concat([rpcHeader(PTYPE.REQUEST, 0, 2), reqBody]);
    new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
    resp = await t.transceive(pdu);
    if (resp[2] === PTYPE.FAULT) throw new Error('EPM ept_map fault');
    const respStub = resp.subarray(24);
    return parseEpmResponse(respStub);
  } finally { await t.close(); }
}

function buildEpmTower(ifBytes, ifMaj, ifMin) {
  const ndrBytes = uuidBytes(NDR_SYNTAX);
  const floors = [];
  const f1lhs = concat([Uint8Array.of(0x0d), ifBytes, u16(ifMaj)]);
  floors.push(concat([u16(f1lhs.length), f1lhs, u16(2), u16(ifMin)]));
  const f2lhs = concat([Uint8Array.of(0x0d), ndrBytes, u16(2)]);
  floors.push(concat([u16(f2lhs.length), f2lhs, u16(2), u16(0)]));
  floors.push(concat([u16(1), Uint8Array.of(0x0b), u16(2), u16(0)]));
  floors.push(concat([u16(1), Uint8Array.of(0x07), u16(2), u16(0)]));
  floors.push(concat([u16(1), Uint8Array.of(0x09), u16(4), u32(0)]));
  const body = concat([u16(5), ...floors]);
  return concat([u32(body.length), body]);
}

function parseEpmResponse(stub) {
  const dv = new DataView(stub.buffer, stub.byteOffset, stub.byteLength);
  let off = 20;
  const numTowers = dv.getUint32(off, true); off += 4;
  if (!numTowers) throw new Error('EPM: no endpoints found');
  off += 4;
  for (let t = 0; t < numTowers; t++) {
    const ref = dv.getUint32(off, true); off += 4;
    if (!ref) continue;
  }
  off = 28 + numTowers * 4;
  for (let t = 0; t < numTowers; t++) {
    const towerLen = dv.getUint32(off, true); off += 4;
    const towerEnd = off + towerLen;
    const paddedLen = (towerLen + 3) & ~3;
    const innerLen = dv.getUint32(off, true); off += 4;
    const numFloors = dv.getUint16(off, true); off += 2;
    for (let f = 0; f < numFloors; f++) {
      const lhsLen = dv.getUint16(off, true); off += 2;
      const proto = stub[off];
      off += lhsLen;
      const rhsLen = dv.getUint16(off, true); off += 2;
      if (proto === 0x07 && rhsLen === 2) {
        const port = (stub[off] << 8) | stub[off + 1];
        return port;
      }
      off += rhsLen;
    }
    off = towerEnd;
    off = (off + 3) & ~3;
  }
  throw new Error('EPM: no TCP endpoint in tower');
}

// ---- NRPC client over TCP DCE-RPC ------------------------------------------
export class NrpcClient {
  constructor(dcIp, computerName, computerHash, domain, log = () => {}) {
    this._dc = dcIp;
    this._name = computerName.replace(/\$$/, '');
    this._account = computerName.endsWith('$') ? computerName : computerName + '$';
    this._hash = typeof computerHash === 'string' ? Uint8Array.from(computerHash.match(/.{2}/g).map(h => parseInt(h, 16))) : computerHash;
    this._domain = domain;
    this._log = log;
    this._callId = 1;
    this._seqNum = 0;
    this._sessionKey = null;
    this._credential = null;
    this._transport = null;
  }

  async setup() {
    this._log(`NRPC: discovering endpoint on ${this._dc}`);
    let port;
    try { port = await epmLookup(this._dc, NRPC_UUID); } catch (e) {
      this._log(`EPM lookup failed (${e.message}), trying port 49664`);
      port = 49664;
    }
    this._log(`NRPC: connecting to ${this._dc}:${port}`);
    this._transport = new TcpRpcTransport(this._dc, port);
    await this._transport.connect();

    await this._bind(false);

    const clientChallenge = globalThis.crypto.getRandomValues(new Uint8Array(8));
    const serverChallenge = await this._reqChallenge(clientChallenge);
    this._log(`NRPC: challenges exchanged`);

    this._sessionKey = await computeSessionKey(this._hash, clientChallenge, serverChallenge);
    this._credential = computeCredential(clientChallenge, this._sessionKey);

    const { serverCred, negotiateFlags } = await this._authenticate3();
    this._log(`NRPC: authenticated (flags=0x${negotiateFlags.toString(16)})`);

    await this._bind(true);

    await this._getCapabilities();
    this._log(`NRPC: secure channel established`);
  }

  async _bind(withAuth) {
    const ctx = ctxItem(0, NRPC_UUID, 1, 0);
    const bindBody = concat([u16(0x16d0), u16(0x16d0), u32(0), Uint8Array.of(1, 0, 0, 0), ctx]);
    const ptype = withAuth ? PTYPE.ALTER_CTX : PTYPE.BIND;
    let pdu = concat([rpcHeader(ptype, 0, this._callId), bindBody]);

    if (withAuth) {
      const authMsg = nlAuthMessage(this._domain, this._name, this._account);
      const pad = (4 - (pdu.length % 4)) % 4;
      const trailer = concat([Uint8Array.of(AUTH_NETLOGON, AUTH_PRIVACY, pad, 0), u32(0), authMsg]);
      pdu = concat([pdu, new Uint8Array(pad), trailer]);
      const dv = new DataView(pdu.buffer, pdu.byteOffset);
      dv.setUint16(8, pdu.length, true);
      dv.setUint16(10, authMsg.length, true);
    } else {
      new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
    }

    const resp = await this._transport.transceive(pdu);
    const expectedResp = withAuth ? PTYPE.ALTER_CTX_RESP : PTYPE.BIND_ACK;
    if (resp[2] !== expectedResp) throw new Error(`NRPC bind: expected ptype ${expectedResp}, got ${resp[2]}`);
    this._callId++;
  }

  async _plainCall(opnum, stub) {
    const body = concat([u32(stub.length), u16(0), u16(opnum), stub]);
    const pdu = concat([rpcHeader(PTYPE.REQUEST, 0, this._callId), body]);
    new DataView(pdu.buffer, pdu.byteOffset).setUint16(8, pdu.length, true);
    this._callId++;
    const resp = await this._transport.transceive(pdu);
    if (resp[2] === PTYPE.FAULT) {
      const fc = new DataView(resp.buffer, resp.byteOffset).getUint32(24, true);
      throw new Error(`NRPC fault 0x${fc.toString(16)}`);
    }
    return resp.subarray(24);
  }

  async _sealedCall(opnum, stub) {
    const { sealed, signature } = await nlSealRequest(this._sessionKey, this._seqNum, stub);
    this._seqNum++;

    const pad = (4 - (sealed.length % 4)) % 4;
    const secTrailer = concat([Uint8Array.of(AUTH_NETLOGON, AUTH_PRIVACY, pad, 0), u32(0)]);
    const body = concat([u32(sealed.length + pad), u16(0), u16(opnum)]);
    const hdr = rpcHeader(PTYPE.REQUEST, 0, this._callId);
    const fragLen = 16 + body.length + sealed.length + pad + secTrailer.length + signature.length;
    const dv = new DataView(hdr.buffer, hdr.byteOffset);
    dv.setUint16(8, fragLen, true);
    dv.setUint16(10, signature.length, true);
    const pdu = concat([hdr, body, sealed, new Uint8Array(pad), secTrailer, signature]);
    this._callId++;

    const resp = await this._transport.transceive(pdu);
    if (resp[2] === PTYPE.FAULT) {
      const fc = new DataView(resp.buffer, resp.byteOffset).getUint32(24, true);
      throw new Error(`NRPC sealed fault 0x${fc.toString(16)}`);
    }

    const rdv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const rFragLen = rdv.getUint16(8, true);
    const rAuthLen = rdv.getUint16(10, true);
    if (rAuthLen) {
      const sigStart = rFragLen - rAuthLen;
      const trailStart = sigStart - 8;
      const rPadLen = resp[trailStart + 2];
      const rSig = resp.subarray(sigStart, sigStart + rAuthLen);
      const rSealed = resp.subarray(24, trailStart);
      const plain = await nlUnsealResponse(this._sessionKey, rSig, rSealed);
      return plain.subarray(0, plain.length - rPadLen);
    }
    return resp.subarray(24, rFragLen);
  }

  async _reqChallenge(clientChallenge) {
    const stub = concat([
      u32(0),
      ndrWStr(this._name + '\0'),
      clientChallenge,
    ]);
    const resp = await this._plainCall(4, stub);
    const serverChallenge = resp.slice(0, 8);
    const status = new DataView(resp.buffer, resp.byteOffset).getUint32(resp.length - 4, true);
    if (status) throw new Error(`NetrServerReqChallenge: 0x${status.toString(16)}`);
    return serverChallenge;
  }

  async _authenticate3() {
    const negotiateFlags = 0x600FFFFF;
    const stub = concat([
      u32(0),
      ndrWStr(this._account + '\0'),
      u16(2), u16(0),
      ndrWStr(this._name + '\0'),
      this._credential,
      u32(negotiateFlags),
    ]);
    const resp = await this._plainCall(26, stub);
    const rdv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const serverCred = resp.slice(0, 8);
    const negFlags = rdv.getUint32(8, true);
    const accountRid = rdv.getUint32(12, true);
    const status = rdv.getUint32(16, true);
    if (status) throw new Error(`NetrServerAuthenticate3: 0x${status.toString(16)}`);
    return { serverCred, negotiateFlags: negFlags, accountRid };
  }

  async _getCapabilities() {
    const auth = computeAuthenticator(this._credential, this._sessionKey);
    this._credential = auth.credential;
    const stub = concat([
      ndrRefWStr('\0', 0x20000),
      ndrRefWStr(this._name + '\0', 0x20004),
      auth.credential,
      auth.timestamp,
      new Uint8Array(8 + 4),
      u32(1),
    ]);
    const resp = await this._sealedCall(21, stub);
    const rdv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const status = rdv.getUint32(resp.length - 4, true);
    if (status) throw new Error(`NetrLogonGetCapabilities: 0x${status.toString(16)}`);
    this._updateAuth(resp.subarray(0, 12));
  }

  _updateAuth(authResp) {
    this._credential = authResp.slice(0, 8);
  }

  async validate(ntlmAuthBlob, challenge) {
    const auth = parseNtlmAuth(ntlmAuthBlob);
    const authenticator = computeAuthenticator(this._credential, this._sessionKey);
    this._credential = authenticator.credential;

    const logonInfo = buildNetworkLogonInfo(auth, challenge);
    const stub = concat([
      ndrRefWStr('\0', 0x20000),
      ndrRefWStr(this._name + '\0', 0x20004),
      authenticator.credential,
      authenticator.timestamp,
      new Uint8Array(8 + 4),
      u16(6), u16(0),
      u16(6), u16(0),
      u32(0x20008),
      logonInfo,
      u16(6), u16(0),
      u32(0),
    ]);
    const resp = await this._sealedCall(45, stub);
    const rdv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);

    this._updateAuth(resp.subarray(0, 12));
    const errorCode = rdv.getUint32(resp.length - 4, true);
    if (errorCode) return { sessionKey: null, errorCode, flags: 0 };

    const userSessionKey = extractSessionKeyFromValidation(resp.subarray(12));

    const encSessionKey = auth.encryptedRandomSessionKey;
    let sessionKey;
    if (encSessionKey && encSessionKey.length === 16 && userSessionKey) {
      const rc4 = new Rc4(userSessionKey);
      sessionKey = rc4.update(encSessionKey);
    } else {
      sessionKey = userSessionKey;
    }

    return { sessionKey, errorCode, flags: auth.flags };
  }

  async close() {
    try { await this._transport?.close(); } catch {}
  }
}

// ---- NTLMSSP_AUTH parser ----------------------------------------------------
function parseNtlmAuth(blob) {
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (dv.getUint32(8, true) !== 3) throw new Error('not NTLMSSP_AUTH');
  const field = (off) => {
    const len = dv.getUint16(off, true);
    const offset = dv.getUint32(off + 4, true);
    return blob.subarray(offset, offset + len);
  };
  const flags = dv.getUint32(60, true);
  return {
    lmResponse: field(12),
    ntResponse: field(20),
    domainName: decodeUtf16(field(28)),
    userName: decodeUtf16(field(36)),
    workstation: decodeUtf16(field(44)),
    encryptedRandomSessionKey: field(52),
    flags,
    lmRaw: field(12),
    ntRaw: field(20),
  };
}

function decodeUtf16(bytes) {
  let s = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const c = bytes[i] | (bytes[i + 1] << 8);
    if (c) s += String.fromCharCode(c);
  }
  return s;
}

function buildNetworkLogonInfo(auth, challenge) {
  const domainU16 = utf16leZ(auth.domainName).subarray(0, auth.domainName.length * 2);
  const userU16 = utf16leZ(auth.userName).subarray(0, auth.userName.length * 2);
  const wsU16 = new Uint8Array(0);

  const identity = concat([
    u16(domainU16.length), u16(domainU16.length), u32(0x20010),
    u32(0x820),
    u64(0),
    u16(userU16.length), u16(userU16.length), u32(0x20014),
    u16(0), u16(0), u32(0),
  ]);

  const ntResp = auth.ntRaw;
  const lmResp = auth.lmRaw;
  const networkPart = concat([
    challenge,
    u16(ntResp.length), u16(ntResp.length), u32(0x20018),
    u16(lmResp.length), u16(lmResp.length), u32(0x2001c),
  ]);

  const deferred = concat([
    ndrWStr(auth.domainName),
    ndrWStr(auth.userName),
    u32(ntResp.length), ntResp,
    new Uint8Array((4 - (ntResp.length % 4)) % 4),
    u32(lmResp.length), lmResp,
    new Uint8Array((4 - (lmResp.length % 4)) % 4),
  ]);

  return concat([identity, networkPart, deferred]);
}

function extractSessionKeyFromValidation(data) {
  if (data.length >= 128 + 16) {
    return data.slice(128, 144);
  }
  for (const tryOff of [120, 124, 128, 132, 136]) {
    if (tryOff + 16 <= data.length) {
      const candidate = data.slice(tryOff, tryOff + 16);
      if (candidate.some(b => b !== 0)) return candidate;
    }
  }
  return null;
}
