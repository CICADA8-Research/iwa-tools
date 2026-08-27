// Kerberos AS/TGS client flow (RFC 4120), modelled on impacket's
// getKerberosTGT / getKerberosTGS. A KerberosClient drives the message
// exchange over a pluggable transport so the logic is testable without a
// socket; KdcSocketTransport is the Direct Sockets TCP implementation used in
// the IWA.

import { concat } from '../ldap/ber.js';
import {
  MSG_TYPE, NAME_TYPE, PADATA, KEY_USAGE, KRB_ERR, KRB_ERR_NAME,
  KDC_OPTIONS, AP_OPTIONS, ETYPE, ETYPE_PREFERENCE,
} from './constants.js';
import {
  kdcReq, kdcReqBody, paData, paEncTsEnc, encryptedData, authenticator, apReq,
  parseKdcRep, parseEncKdcRepPart, parseKrbError, parseMethodData, parseEtypeInfo2,
  parseKerberosTime,
} from './asn1.js';
import { encrypt, decrypt, stringToKey, defaultSalt } from './crypto.js';

// A KDC reply is framed as a single ASN.1 element; its leading application tag
// tells AS-REP (0x6b) / TGS-REP (0x6d) apart from KRB-ERROR (0x7e).
const TAG_AS_REP = 0x6b;
const TAG_TGS_REP = 0x6d;
const TAG_KRB_ERROR = 0x7e;

const FAR_FUTURE = new Date(Date.UTC(2037, 8, 13, 2, 48, 5)); // canonical "till"

function randomNonce() {
  const b = new Uint8Array(4);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return ((b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0) & 0x7fffffff;
}

export class KerberosError extends Error {
  constructor(code, context) {
    const name = KRB_ERR_NAME[code] || `error code ${code}`;
    super(`Kerberos ${context}: ${name}`);
    this.name = 'KerberosError';
    this.code = code;
  }
}

export class KerberosClient {
  // `transport` exposes async request(reqBytes) -> replyBytes (one round-trip).
  constructor(transport, log = () => {}) {
    this._t = transport;
    this._log = log;
    this._clockOffsetMs = 0; // (KDC clock − local clock), learned from stime
  }

  // Current time adjusted to the KDC's clock, so timestamps in PA-ENC-TIMESTAMP
  // / authenticators don't trip KRB_AP_ERR_SKEW when the local clock/timezone
  // is off. Calibrated from the KDC's stime during getTGT.
  _now() { return new Date(Date.now() + this._clockOffsetMs); }

  // Acquire a TGT. Identity is { username, realm } plus either { password } or
  // a pre-computed { key: Uint8Array, etype }. Returns the raw TGT plus the
  // session key for the TGS exchange.
  async getTGT({ username, realm, password = null, key = null, etype = null }) {
    realm = realm.toUpperCase();
    const sname = ['krbtgt', realm];
    const kdcOptions = KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.PROXIABLE | KDC_OPTIONS.RENEWABLE;

    const buildReq = (padatas) => kdcReq(MSG_TYPE.AS_REQ, kdcReqBody({
      kdcOptions, cname: [username], cnameType: NAME_TYPE.PRINCIPAL, realm,
      sname, snameType: NAME_TYPE.SRV_INST, till: FAR_FUTURE,
      nonce: randomNonce(), etypes: ETYPE_PREFERENCE,
    }), padatas);

    // First leg: optimistic AS-REQ with no pre-auth.
    this._log('AS-REQ (no pre-auth) …');
    let reply = await this._t.request(buildReq([]));

    if (reply[0] === TAG_KRB_ERROR) {
      const err = parseKrbError(reply);
      if (err.errorCode !== KRB_ERR.PREAUTH_REQUIRED) throw new KerberosError(err.errorCode, 'AS-REQ');

      // Pick the key/etype/salt the KDC wants from ETYPE-INFO2.
      const sel = this._selectPreauth(err, { key, etype, password, username, realm });
      // Calibrate our clock to the KDC's (from the error's stime) so a skewed
      // local clock/timezone doesn't trigger KRB_AP_ERR_SKEW here or in the
      // later TGS/AP-REQ authenticators.
      if (err.stime) this._clockOffsetMs = parseKerberosTime(err.stime).getTime() - Date.now();
      this._log(`Pre-auth required; using etype ${sel.etype}, KDC time ${err.stime || '(local)'}. Re-sending with PA-ENC-TIMESTAMP …`);
      const tsCipher = encrypt(sel.etype, sel.key, KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, paEncTsEnc(this._now(), err.susec || 0));
      const pa = paData(PADATA.ENC_TIMESTAMP, encryptedData(sel.etype, tsCipher));
      reply = await this._t.request(buildReq([pa]));
      if (reply[0] === TAG_KRB_ERROR) throw new KerberosError(parseKrbError(reply).errorCode, 'AS-REQ (pre-auth)');
      return this._finishAsRep(reply, sel.etype, sel.key, username, realm);
    }

    if (reply[0] === TAG_AS_REP) {
      // No pre-auth needed (AS-REP roastable). Derive the user key for the
      // returned etype with the default salt to open the enc-part.
      const rep = parseKdcRep(reply);
      const ut = rep.encPart.etype;
      const ukey = key && etype === ut ? key
        : stringToKey(ut, password, defaultSalt(realm, username));
      return this._finishAsRep(reply, ut, ukey, username, realm);
    }

    throw new Error(`unexpected AS reply tag 0x${reply[0].toString(16)}`);
  }

  _selectPreauth(err, { key, etype, password, username, realm }) {
    let entries = [];
    if (err.eData) {
      for (const pa of parseMethodData(err.eData)) {
        if (pa.type === PADATA.ETYPE_INFO2) entries = parseEtypeInfo2(pa.value);
      }
    }
    // Honour our own algorithm preference among what the KDC offered.
    for (const want of ETYPE_PREFERENCE) {
      const e = entries.find((x) => x.etype === want);
      if (!e) continue;
      if (key && etype === want) return { etype: want, key };
      if (password == null) continue;
      const salt = e.salt || defaultSalt(realm, username);
      return { etype: want, key: stringToKey(want, password, salt) };
    }
    // Fall back to a supplied key, or a password-derived AES256 key.
    if (key && etype != null) return { etype, key };
    if (password != null) {
      return { etype: ETYPE.AES256_CTS_HMAC_SHA1_96, key: stringToKey(ETYPE.AES256_CTS_HMAC_SHA1_96, password, defaultSalt(realm, username)) };
    }
    throw new Error('no usable etype/credential for pre-authentication');
  }

  _finishAsRep(reply, userEtype, userKey, username, realm) {
    const rep = parseKdcRep(reply);
    const encPart = decrypt(userEtype, userKey, KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher);
    const dec = parseEncKdcRepPart(encPart);
    this._log(`Got TGT for ${username}@${realm} (session key etype ${dec.key.etype}).`);
    return {
      ticket: rep.ticket,
      sessionKey: { etype: dec.key.etype, key: dec.key.keyvalue },
      crealm: rep.crealm,
      cname: [username],
      username,
      realm,
      clockOffsetMs: this._clockOffsetMs,
    };
  }

  // Learn the KDC clock offset without authenticating: an AS-REQ with no
  // pre-auth draws a KRB error whose `stime` reveals the KDC clock. Sets and
  // returns the offset (ms). Best-effort — returns the current offset (0) if the
  // KDC does not answer with a time. Used to make imported tickets (ccache/kirbi,
  // which carry no offset) tolerate an operator clock that isn't synced to the DC.
  async calibrateClock(username, realm) {
    try {
      const reply = await this._t.request(kdcReq(MSG_TYPE.AS_REQ, kdcReqBody({
        kdcOptions: KDC_OPTIONS.FORWARDABLE, cname: [username || 'x'], cnameType: NAME_TYPE.PRINCIPAL,
        realm: realm.toUpperCase(), sname: ['krbtgt', realm.toUpperCase()], snameType: NAME_TYPE.SRV_INST,
        till: FAR_FUTURE, nonce: randomNonce(), etypes: ETYPE_PREFERENCE,
      }), []));
      if (reply[0] === TAG_KRB_ERROR) {
        const err = parseKrbError(reply);
        if (err.stime) {
          this._clockOffsetMs = parseKerberosTime(err.stime).getTime() - Date.now();
          this._log(`Calibrated clock to KDC (offset ${Math.round(this._clockOffsetMs / 1000)}s).`);
        }
      }
    } catch { /* best-effort */ }
    return this._clockOffsetMs;
  }

  // Exchange a TGT for a service ticket. `spn` is "service/host" (e.g.
  // "ldap/dc01.example.com"); pass `spnComponents` to override the split.
  async getTGS(tgt, { spn, spnComponents = null, snameType = NAME_TYPE.SRV_INST, serverRealm = null, etypes = null }) {
    const realm = (serverRealm || tgt.realm).toUpperCase();
    const sname = spnComponents || spn.split('/');
    const nonce = randomNonce();
    // Inherit the KDC clock offset learned during getTGT (the TGT carries it).
    if (!this._clockOffsetMs && tgt.clockOffsetMs) this._clockOffsetMs = tgt.clockOffsetMs;

    // PA-TGS-REQ: an AP-REQ over the TGT, authenticator keyed with the TGT
    // session key at usage 7.
    const auth = authenticator({
      crealm: tgt.crealm, cname: tgt.cname, ctime: this._now(), cusec: 0,
    });
    const sk = tgt.sessionKey;
    const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.TGS_REQ_AUTH, auth));
    const ap = apReq({ apOptions: 0, ticket: tgt.ticket, encAuthenticator: encAuth });
    const pa = paData(PADATA.TGS_REQ, ap);

    const body = kdcReqBody({
      kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.RENEWABLE | KDC_OPTIONS.CANONICALIZE,
      cname: null, realm, sname, snameType, till: FAR_FUTURE,
      nonce, etypes: etypes || ETYPE_PREFERENCE,
    });
    this._log(`TGS-REQ for ${sname.join('/')} …`);
    const reply = await this._t.request(kdcReq(MSG_TYPE.TGS_REQ, body, [pa]));

    if (reply[0] === TAG_KRB_ERROR) throw new KerberosError(parseKrbError(reply).errorCode, 'TGS-REQ');
    if (reply[0] !== TAG_TGS_REP) throw new Error(`unexpected TGS reply tag 0x${reply[0].toString(16)}`);

    const rep = parseKdcRep(reply);
    // TGS-REP enc-part is keyed with the TGT session key at usage 8.
    const encPart = decrypt(sk.etype, sk.key, KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher);
    const dec = parseEncKdcRepPart(encPart);
    this._log(`Got service ticket for ${sname.join('/')} (session key etype ${dec.key.etype}).`);
    return {
      ticket: rep.ticket,
      sessionKey: { etype: dec.key.etype, key: dec.key.keyvalue },
      crealm: tgt.crealm,
      cname: tgt.cname,
      realm,
      spn: sname.join('/'),
      clockOffsetMs: this._clockOffsetMs,
    };
  }
}

// ---- Direct Sockets transport ---------------------------------------------
// Kerberos over TCP frames each PDU with a 4-byte big-endian length prefix
// (RFC 4120 §7.2.2). One request/response per call.

export class KdcSocketTransport {
  constructor(host, port = 88, log = () => {}) {
    this._host = host; this._port = port; this._log = log;
    this._socket = null; this._reader = null; this._writer = null;
    this._buf = new Uint8Array(0);
  }

  async connect() {
    if (typeof TCPSocket === 'undefined') {
      throw new Error('TCPSocket is unavailable — open this app as an installed Isolated Web App.');
    }
    this._log(`Connecting to KDC ${this._host}:${this._port} …`);
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

  async request(reqBytes) {
    const framed = new Uint8Array(4 + reqBytes.length);
    new DataView(framed.buffer).setUint32(0, reqBytes.length, false);
    framed.set(reqBytes, 4);
    await this._writer.write(framed);

    // Read until we have the 4-byte length and that many payload bytes.
    for (;;) {
      if (this._buf.length >= 4) {
        const len = new DataView(this._buf.buffer, this._buf.byteOffset, 4).getUint32(0, false);
        if (this._buf.length >= 4 + len) {
          const msg = this._buf.slice(4, 4 + len);
          this._buf = this._buf.slice(4 + len);
          return msg;
        }
      }
      const { value, done } = await this._reader.read();
      if (done) throw new Error('KDC closed the connection');
      this._buf = concat([this._buf, value]);
    }
  }
}
