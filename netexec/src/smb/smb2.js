// A minimal SMB2 client (dialect 2.1) over the Direct Sockets API, just enough
// to carry DCE-RPC over named pipes on IPC$ (samr / lsarpc / srvsvc) for the
// host-based BloodHound collection. Reuses the project's NTLM for SPNEGO session
// setup; the resulting session key signs every request with HMAC-SHA256
// (mandatory against domain controllers).
//
// Framing: each PDU is a 4-byte big-endian length (Direct TCP) + SMB2 header
// (64 bytes) + a command body.

import { concat } from '../ldap/ber.js';
import { buildNegotiate, buildAuthenticate } from '../ntlm/seal.js';
import { parseType2 } from '../ntlm/ntlm.js';
import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from '../ntlm/spnego.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { buildGssApReq, gssInitToken, spnegoKrbInitToken } from '../kerberos/gss.js';
import { ETYPE } from '../kerberos/constants.js';

const CMD = { NEGOTIATE: 0, SESSION_SETUP: 1, LOGOFF: 2, TREE_CONNECT: 3, TREE_DISCONNECT: 4, CREATE: 5, CLOSE: 6, READ: 8, WRITE: 9, IOCTL: 0x0b, QUERY_DIRECTORY: 0x0e };
const ST = { SUCCESS: 0, PENDING: 0x00000103, MORE_PROCESSING: 0xc0000016, BUFFER_OVERFLOW: 0x80000005 };
const FLAGS_SIGNED = 0x08;
const FSCTL_PIPE_TRANSCEIVE = 0x0011c017;

const enc = new TextEncoder();
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const utf16le = (s) => { const b = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };

async function hmacSha256_16(key, data) {
  const k = await globalThis.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, data)).slice(0, 16);
}

export class Smb2Client {
  constructor(host, port = 445, log = () => {}) {
    this._host = host; this._port = port; this._log = log;
    this._buf = new Uint8Array(0);
    this._mid = 0; this._sessionId = 0n; this._signingKey = null; this._sign = false;
  }

  get sessionKey() { return this._signingKey; }

  async connect() {
    if (typeof TCPSocket === 'undefined') throw new Error('TCPSocket unavailable — run as an installed IWA.');
    this._socket = new TCPSocket(this._host, this._port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
  }
  async close() {
    try { this._reader?.releaseLock(); } catch { /* ignore */ }
    try { this._writer?.releaseLock(); } catch { /* ignore */ }
    try { await this._socket?.close(); } catch { /* ignore */ }
  }

  _header(command, { treeId = 0, creditCharge = 1 } = {}) {
    const h = new Uint8Array(64);
    h.set([0xfe, 0x53, 0x4d, 0x42], 0);          // ProtocolId "\xFESMB"
    const dv = new DataView(h.buffer);
    dv.setUint16(4, 64, true);                   // StructureSize
    dv.setUint16(6, creditCharge, true);
    dv.setUint16(12, command, true);
    dv.setUint16(14, 1, true);                   // CreditRequest
    dv.setBigUint64(24, BigInt(this._mid), true); // MessageId
    dv.setUint32(36, treeId, true);              // TreeId
    dv.setBigUint64(40, this._sessionId, true);  // SessionId
    return h;
  }

  async _call(command, body, opts = {}) {
    const header = this._header(command, opts);
    const dv = new DataView(header.buffer);
    if (this._sign && this._signingKey) {
      dv.setUint32(16, FLAGS_SIGNED, true);
      const msg = concat([header, body]);
      const sig = await hmacSha256_16(this._signingKey, msg);
      header.set(sig, 48);
    }
    const pdu = concat([header, body]);
    const framed = new Uint8Array(4 + pdu.length);
    new DataView(framed.buffer).setUint32(0, pdu.length, false); // 4-byte BE length
    framed.set(pdu, 4);
    await this._writer.write(framed);
    this._mid += opts.creditCharge || 1;
    return this._read();
  }

  async _read() {
    for (;;) {
      if (this._buf.length >= 4) {
        const len = new DataView(this._buf.buffer, this._buf.byteOffset, 4).getUint32(0, false);
        if (this._buf.length >= 4 + len) {
          const pdu = this._buf.slice(4, 4 + len);
          this._buf = this._buf.slice(4 + len);
          const dv = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength);
          const status = dv.getUint32(8, true);
          const sessionId = dv.getBigUint64(40, true);
          return { pdu, dv, status, sessionId, body: pdu.subarray(64) };
        }
      }
      const { value, done } = await this._reader.read();
      if (done) throw new Error('SMB: connection closed by server');
      this._buf = concat([this._buf, value]);
    }
  }

  async negotiate() {
    const body = concat([
      u16(36), u16(2),                 // StructureSize, DialectCount
      u16(1), u16(0),                  // SecurityMode=SIGNING_ENABLED, Reserved
      u32(0),                          // Capabilities
      ...[0, 0, 0, 0].map(() => u32(0)), // ClientGuid (16 bytes of 0)
      u64(0),                          // ClientStartTime
      u16(0x0202), u16(0x0210),        // Dialects: 2.0.2, 2.1
    ]);
    const r = await this._call(CMD.NEGOTIATE, body);
    if (r.status !== ST.SUCCESS) throw new Error(`SMB negotiate failed: 0x${r.status.toString(16)}`);
    // NEGOTIATE response body layout (MS-SMB2 §2.2.4):
    //   0: StructureSize u16, 2: SecurityMode u16, 4: DialectRevision u16,
    //   6: NegotiateContextCount u16, 8: ServerGuid[16], 24: Capabilities u32,
    //   28: MaxTransactSize u32, 32: MaxReadSize u32, 36: MaxWriteSize u32
    this._dialect = r.dv.getUint16(64 + 4, true);
    this._serverSecMode = r.dv.getUint16(64 + 2, true);
    this._capabilities = r.dv.getUint32(64 + 24, true);
    this._serverGuid = r.body.slice(8, 24);
    this._log(`SMB2 negotiated dialect 0x${this._dialect.toString(16)}.`);
  }

  get signingRequired() { return !!(this._serverSecMode & 0x02); }
  get signingEnabled() { return !!(this._serverSecMode & 0x01); }
  get dialect() { return this._dialect; }
  get capabilities() { return this._capabilities || 0; }
  get encryptionSupported() { return !!(this.capabilities & 0x40); }
  get serverGuid() {
    if (!this._serverGuid) return null;
    const g = this._serverGuid;
    const hex = Array.from(g, (b) => b.toString(16).padStart(2, '0'));
    // Windows-style GUID: {d1 (LE), d2 (LE), d3 (LE), d4 (BE), d5 (BE)}
    return `${hex[3]}${hex[2]}${hex[1]}${hex[0]}-${hex[5]}${hex[4]}-${hex[7]}${hex[6]}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
  }
  // NTLM CHALLENGE TargetInfo AV_PAIRS captured during login; keys are
  // impacket-style: nbComputerName, dnsComputerName, nbDomainName,
  // dnsDomainName, dnsTreeName, timestamp.
  get targetInfo() { return this._targetInfo || {}; }

  // SPNEGO + NTLM session setup; on success the session is signed.
  async login({ user, domain, password, hash, localAuth }) {
    const type1 = buildNegotiate();
    let r = await this._sessionSetup(spnegoNegTokenInit(type1));
    if (r.status !== ST.MORE_PROCESSING) throw new Error(`SMB session setup (1) unexpected status 0x${r.status.toString(16)}`);
    this._sessionId = r.sessionId;
    const type2raw = spnegoExtractToken(this._secBuf(r));
    if (!type2raw) throw new Error('SMB: no NTLM challenge in session setup response');
    const type2 = parseType2(type2raw);
    this._targetInfo = {
      nbComputerName: type2.nbComputerName,
      nbDomainName: type2.nbDomainName,
      dnsComputerName: type2.dnsComputerName,
      dnsDomainName: type2.dnsDomainName,
      dnsTreeName: type2.dnsTreeName,
      timestamp: type2.timestamp,
    };
    // --local-auth: substitute the target's NetBIOS name so auth validates against local SAM.
    const effectiveDomain = (localAuth && !domain && type2.nbComputerName) ? type2.nbComputerName : domain;
    const sessionKey = new Uint8Array(16);
    globalThis.crypto.getRandomValues(sessionKey);
    const { type3, exportedSessionKey } = buildAuthenticate({ user, domain: effectiveDomain, password, hash, type2, exportedSessionKey: sessionKey });
    this._signingKey = exportedSessionKey;
    r = await this._sessionSetup(spnegoNegTokenResp(type3));
    if (r.status !== ST.SUCCESS) throw new Error(`SMB authentication failed: 0x${r.status.toString(16)}`);
    this._sign = true;
    this._log(`SMB2 authenticated as ${effectiveDomain ? effectiveDomain + '\\' : ''}${user} (signed session).`);
  }

  async loginKerberos({ user, domain, password, hash, kdcHost }) {
    const realm = domain.toUpperCase();
    const kdc = kdcHost || this._host;
    const transport = new KdcSocketTransport(kdc, 88);
    await transport.connect();
    try {
      const krb = new KerberosClient(transport);
      const id = { username: user, realm };
      if (hash) {
        id.key = hash;
        id.etype = ETYPE.RC4_HMAC;
      } else {
        id.password = password;
      }
      const tgt = await krb.getTGT(id);
      const spn = `cifs/${this._host}`;
      const tgs = await krb.getTGS(tgt, { spn });
      const apReqBytes = buildGssApReq(tgs);
      const gssToken = gssInitToken(apReqBytes);
      const spnegoToken = spnegoKrbInitToken(gssToken);

      const r = await this._sessionSetup(spnegoToken);
      if (r.status !== ST.SUCCESS && r.status !== ST.MORE_PROCESSING) {
        throw new Error(`SMB Kerberos session setup failed: 0x${r.status.toString(16)}`);
      }
      this._sessionId = r.sessionId;
      this._signingKey = tgs.sessionKey.key;
      this._sign = true;
      this._log(`SMB2 Kerberos authenticated as ${user}@${realm} (signed session).`);
    } finally {
      await transport.close();
    }
  }

  async loginWithTicket(serviceTicket) {
    const apReqBytes = buildGssApReq(serviceTicket);
    const gssToken = gssInitToken(apReqBytes);
    const spnegoToken = spnegoKrbInitToken(gssToken);
    const r = await this._sessionSetup(spnegoToken);
    if (r.status !== ST.SUCCESS && r.status !== ST.MORE_PROCESSING) {
      throw new Error(`SMB ticket auth failed: 0x${r.status.toString(16)}`);
    }
    this._sessionId = r.sessionId;
    // MS-SMB2 §3.2.5.3 / MS-KILE §3.4.5.3: SMB2.x HMAC-SHA256 signing takes a
    // 16-byte SessionKey. Kerberos AES256 tickets carry a 32-byte session key;
    // take the first 16 bytes, matching what Windows / impacket do.
    const sk = serviceTicket.sessionKey.key;
    this._signingKey = sk.length >= 16 ? sk.subarray(0, 16) : (() => { const p = new Uint8Array(16); p.set(sk); return p; })();
    this._sign = true;
  }

  async _sessionSetup(securityBlob) {
    const body = concat([
      u16(25), Uint8Array.of(0, 1),    // StructureSize, Flags, SecurityMode=SIGNING_ENABLED
      u32(0), u32(0),                  // Capabilities, Channel
      u16(0x58), u16(securityBlob.length), // SecurityBufferOffset, Length
      u64(0),                          // PreviousSessionId
      securityBlob,
    ]);
    return this._call(CMD.SESSION_SETUP, body);
  }
  _secBuf(r) {
    const off = r.dv.getUint16(64 + 4, true);    // SecurityBufferOffset (from SMB2 header start)
    const len = r.dv.getUint16(64 + 6, true);
    return r.pdu.subarray(off, off + len);
  }

  async treeConnect(share) {
    const path = utf16le(`\\\\${this._host}\\${share}`);
    const body = concat([u16(9), u16(0), u16(0x48), u16(path.length), path]);
    const r = await this._call(CMD.TREE_CONNECT, body);
    if (r.status !== ST.SUCCESS) throw new Error(`SMB tree connect \\${share} failed: 0x${r.status.toString(16)}`);
    return r.dv.getUint32(36, true); // TreeId
  }

  // Open a named pipe (relative name, e.g. "samr") on the connected tree.
  async createPipe(treeId, name) {
    const nameB = utf16le(name);
    const body = concat([
      u16(57), Uint8Array.of(0, 0),    // StructureSize, SecurityFlags, RequestedOplockLevel
      u32(2),                          // ImpersonationLevel = Impersonation
      u64(0), u64(0),                  // SmbCreateFlags, Reserved
      u32(0x0012019f),                 // DesiredAccess (read/write + control)
      u32(0),                          // FileAttributes
      u32(7),                          // ShareAccess = R|W|D
      u32(1),                          // CreateDisposition = FILE_OPEN
      u32(0),                          // CreateOptions
      u16(0x78), u16(nameB.length),    // NameOffset, NameLength
      u32(0), u32(0),                  // CreateContextsOffset, Length
      nameB,
    ]);
    const r = await this._call(CMD.CREATE, body, { treeId });
    if (r.status !== ST.SUCCESS) throw new Error(`SMB open pipe ${name} failed: 0x${r.status.toString(16)}`);
    return r.pdu.slice(64 + 64, 64 + 64 + 16); // FileId (16 bytes) at offset 0x40 in CREATE response
  }

  // FSCTL_PIPE_TRANSCEIVE: write a DCE-RPC request, read the response. Follows
  // BUFFER_OVERFLOW with READs to collect a large reply.
  async transceive(treeId, fileId, input) {
    const body = concat([
      u16(57), u16(0),                 // StructureSize, Reserved
      u32(FSCTL_PIPE_TRANSCEIVE),
      fileId,                          // 16 bytes
      u32(0x78), u32(input.length),    // InputOffset (header+fixed body), InputCount
      u32(0),                          // MaxInputResponse
      u32(0), u32(0),                  // OutputOffset, OutputCount (request)
      u32(65535),                      // MaxOutputResponse
      u32(1),                          // Flags = IOCTL_IS_FSCTL
      u32(0),                          // Reserved2
      input,
    ]);
    let r = await this._call(CMD.IOCTL, body, { treeId });
    // MS-SMB2 §3.3.4.2: STATUS_PENDING = the server accepted the async
    // command but hasn't finished. Read follow-up PDUs (up to ~15 s) until
    // we see the completion.
    if (r.status === ST.PENDING) {
      const deadline = Date.now() + 15000;
      while (r.status === ST.PENDING && Date.now() < deadline) r = await this._read();
    }
    if (r.status !== ST.SUCCESS && r.status !== ST.BUFFER_OVERFLOW) throw new Error(`SMB ioctl failed: 0x${r.status.toString(16)}`);
    let out = this._ioctlOut(r);
    let overflow = r.status === ST.BUFFER_OVERFLOW;
    while (overflow) { const rd = await this._readPipe(treeId, fileId); out = concat([out, rd.bytes]); overflow = rd.overflow; }
    return out;
  }
  _ioctlOut(r) {
    const off = r.dv.getUint32(64 + 32, true);   // OutputOffset
    const cnt = r.dv.getUint32(64 + 36, true);   // OutputCount
    return r.pdu.subarray(off, off + cnt);
  }

  async readPipe(treeId, fileId) {
    const rd = await this._readPipe(treeId, fileId);
    let out = rd.bytes, overflow = rd.overflow;
    while (overflow) { const rd2 = await this._readPipe(treeId, fileId); out = concat([out, rd2.bytes]); overflow = rd2.overflow; }
    return out;
  }

  async _readPipe(treeId, fileId) {
    const body = concat([
      u16(49), Uint8Array.of(0, 0),    // StructureSize, Padding, Flags
      u32(65535),                      // Length
      u64(0),                          // Offset
      fileId,                          // 16
      u32(0),                          // MinimumCount
      u32(0),                          // Channel
      u32(0),                          // RemainingBytes
      u16(0), u16(0),                  // ReadChannelInfoOffset, Length
      Uint8Array.of(0),                // Buffer (1 byte)
    ]);
    const r = await this._call(CMD.READ, body, { treeId });
    if (r.status !== ST.SUCCESS && r.status !== ST.BUFFER_OVERFLOW) throw new Error(`SMB read failed: 0x${r.status.toString(16)}`);
    const off = r.dv.getUint16(64 + 2, true);    // DataOffset
    const len = r.dv.getUint32(64 + 4, true);    // DataLength
    return { bytes: r.pdu.subarray(off, off + len), overflow: r.status === ST.BUFFER_OVERFLOW };
  }

  async createFile(treeId, name, { access = 0x0012019f, disposition = 1, options = 0, attrs = 0 } = {}) {
    const nameB = utf16le(name);
    // StructureSize=57 = 56 fixed bytes + at least 1 byte of Buffer. When
    // name is empty (opening the tree root) we still need to send a padding
    // byte so the total body length is 57, not 56.
    const buf = nameB.length ? nameB : new Uint8Array(1);
    const body = concat([
      u16(57), Uint8Array.of(0, 0),
      u32(2),
      u64(0), u64(0),
      u32(access),
      u32(attrs),
      u32(7),
      u32(disposition),
      u32(options),
      u16(0x78), u16(nameB.length),
      u32(0), u32(0),
      buf,
    ]);
    const r = await this._call(CMD.CREATE, body, { treeId });
    if (r.status !== ST.SUCCESS) throw new Error(`SMB create ${name} failed: 0x${r.status.toString(16)}`);
    return r.pdu.slice(64 + 64, 64 + 64 + 16);
  }

  async readFile(treeId, fileId, offset = 0, length = 65535) {
    const body = concat([
      u16(49), Uint8Array.of(0, 0),
      u32(length),
      u64(offset),
      fileId,
      u32(0), u32(0), u32(0),
      u16(0), u16(0),
      Uint8Array.of(0),
    ]);
    const r = await this._call(CMD.READ, body, { treeId });
    if (r.status !== ST.SUCCESS && r.status !== ST.BUFFER_OVERFLOW)
      throw new Error(`SMB read failed: 0x${r.status.toString(16)}`);
    const off = r.dv.getUint16(64 + 2, true);
    const len = r.dv.getUint32(64 + 4, true);
    return r.pdu.subarray(off, off + len);
  }

  async readFileAll(treeId, fileId) {
    const chunks = [];
    let offset = 0;
    for (;;) {
      try {
        const data = await this.readFile(treeId, fileId, offset, 65535);
        if (data.length === 0) break;
        chunks.push(data);
        offset += data.length;
        if (data.length < 65535) break;
      } catch { break; }
    }
    return concat(chunks);
  }

  async writeFile(treeId, fileId, data, offset = 0) {
    const body = concat([
      u16(49), u16(0x70), u32(data.length),
      u64(offset),
      fileId,
      u32(0), u32(0), u32(0), u32(0),
      data,
    ]);
    const r = await this._call(CMD.WRITE, body, { treeId });
    if (r.status !== ST.SUCCESS) throw new Error(`SMB write failed: 0x${r.status.toString(16)}`);
    return r.dv.getUint32(64 + 4, true);
  }

  async deleteFile(treeId, path) {
    try {
      const fid = await this.createFile(treeId, path, {
        access: 0x00010000, disposition: 1, options: 0x00001000,
      });
      await this.closeFile(treeId, fid);
    } catch {}
  }

  // MS-SMB2 §2.2.33 QUERY_DIRECTORY request:
  //   StructureSize u16 = 33
  //   FileInformationClass u8
  //   Flags u8 (0x01 = SL_RESTART_SCAN)
  //   FileIndex u32 (0 = start)
  //   FileId[16]
  //   FileNameOffset u16 (SMB2_HDR_SIZE + 32 = 96)
  //   FileNameLength u16
  //   OutputBufferLength u32
  //   Buffer (search pattern in UTF-16LE)
  // The reply pages: SUCCESS on each batch, STATUS_NO_MORE_FILES when done.
  async queryDirectory(treeId, fileId, pattern = '*', infoClass = 37) {
    const patB = utf16le(pattern);
    const entries = [];
    let flags = 0x01; // SL_RESTART_SCAN on first call
    for (;;) {
      const body = concat([
        u16(33), Uint8Array.of(infoClass, flags),
        u32(0),                          // FileIndex
        fileId,
        u16(96), u16(patB.length),       // FileNameOffset, FileNameLength
        u32(0x10000),                    // OutputBufferLength = 64 KiB
        patB,
      ]);
      const r = await this._call(CMD.QUERY_DIRECTORY, body, { treeId });
      if (r.status === 0x80000006 /* STATUS_NO_MORE_FILES */) break;
      if (r.status !== ST.SUCCESS) {
        if (entries.length) break; // partial success is fine
        throw new Error(`SMB queryDirectory failed: 0x${r.status.toString(16)}`);
      }
      const bufOff = r.dv.getUint16(64 + 2, true);
      const bufLen = r.dv.getUint32(64 + 4, true);
      const buf = r.pdu.subarray(bufOff, bufOff + bufLen);
      let pos = 0;
      while (pos < buf.length) {
        const dv2 = new DataView(buf.buffer, buf.byteOffset + pos, buf.length - pos);
        const nextOff = dv2.getUint32(0, true);
        const nameLen = dv2.getUint32(60, true);
        let name = '';
        for (let i = 0; i < nameLen / 2; i++) {
          name += String.fromCharCode(dv2.getUint16(104 + i * 2, true));
        }
        const size = Number(dv2.getBigUint64(40, true));
        entries.push({ name, size });
        if (nextOff === 0) break;
        pos += nextOff;
      }
      flags = 0; // subsequent pages continue
    }
    return entries;
  }

  async closeFile(treeId, fileId) {
    const body = concat([u16(24), u16(0), u32(0), fileId]);
    try { await this._call(CMD.CLOSE, body, { treeId }); } catch { /* ignore */ }
  }
}
