// WinRM client: NTLM/Negotiate authentication over HTTP, then encrypted SOAP
// exchange. NTLM over HTTP is connection-oriented, so we reuse one keep-alive
// HTTP connection. The type-3 (AUTHENTICATE) request carries the first sealed
// SOAP body, after which the connection stays authenticated.

import { HttpClient } from '../http/client.js';
import { buildNegotiate, buildAuthenticate, NtlmSession } from '../ntlm/seal.js';
import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from '../ntlm/spnego.js';
import { parseType2 } from '../ntlm/ntlm.js';
import { wrapEncrypted, unwrapEncrypted } from './crypt.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { gssSealInit, gssSealEstablish, buildGssApReq, gssInitToken, spnegoKrbInitToken } from '../kerberos/gss.js';
import { ETYPE } from '../kerberos/constants.js';
import { loadTls } from '../tls/index.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = (bytes) => (typeof btoa === 'function'
  ? btoa(String.fromCharCode(...bytes))
  : Buffer.from(bytes).toString('base64'));
const b64decode = (s) => (typeof atob === 'function'
  ? Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
  : Uint8Array.from(Buffer.from(s, 'base64')));

// "aad3b...:31d6c..." (LM:NT) or a bare 32-hex NT hash -> 16 NT-hash bytes.
function hexToBytes(hex) {
  let h = hex.trim();
  if (h.includes(':')) h = h.split(':').pop(); // drop LM half of an LM:NT pair
  if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new Error('NTLM hash must be 32 hex chars (the NT hash).');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function parseIdentity(identity, domainHint = '') {
  identity = (identity || '').trim();
  let user = identity, domain = (domainHint || '').trim();
  if (identity.includes('\\')) { const [d, u] = identity.split('\\'); if (!domain) domain = d; user = u; }
  else if (identity.includes('@')) { const [u, d] = identity.split('@'); user = u; if (!domain) domain = d; }
  return { user, domain };
}

export class WinRMClient {
  constructor(log = () => {}) {
    this.http = new HttpClient(log);
    this._log = log;
    this.session = null;
    this._pendingAuth = null;
    this.endpoint = null;
    this.path = '/wsman';
  }

  async connect(host, port, creds, { http } = {}) {
    // Over TLS (HTTPS/5986) the channel is already encrypted, so SOAP rides in
    // cleartext (no NTLM/GSS message wrapping) and authentication carries a
    // tls-server-end-point channel binding. Over plain HTTP/5985 we fall back to
    // SSP message encryption.
    const tls = !!creds.tls;
    this._sealed = !tls;
    const realPort = port || (tls ? 5986 : 5985);
    // `http` lets a test harness inject a pre-connected HttpClient.
    if (http) this.http = http;
    else await this.http.connect(host, realPort, tls ? { tls: { TlsSession: loadTls(), sni: creds.sni || host } } : {});
    this.endpoint = `${tls ? 'https' : 'http'}://${host}:${realPort}${this.path}`;

    const { user, domain } = parseIdentity(creds.user || creds.bindDN, creds.domain);
    if (!user) throw new Error('A username is required (user@domain or DOMAIN\\user).');

    let cb = null;
    if (tls) {
      const c = await this.http.channelBinding();
      cb = c && c.applicationData;
      this._log(`TLS up — channel binding ${c ? c.hashName : 'none'}.`);
    }

    if (creds.authMethod === 'kerberos') return this._connectKerberos(host, creds, user, domain, cb);

    // Leg 1: type 1 -> 401 with the NTLM challenge.
    this._log('WinRM: sending NTLM NEGOTIATE …');
    const r1 = await this.http.send('POST', this.path, {
      Authorization: 'Negotiate ' + b64(spnegoNegTokenInit(buildNegotiate())),
      'Content-Type': 'application/soap+xml;charset=UTF-8',
    });
    if (r1.status !== 401) throw new Error(`WinRM: expected 401 Negotiate challenge, got HTTP ${r1.status}`);
    const www = (r1.rawHeaders.find(([n]) => n.toLowerCase() === 'www-authenticate') || [])[1] || '';
    const tok = /Negotiate ([A-Za-z0-9+/=]+)/.exec(www);
    if (!tok) throw new Error(`WinRM: server did not offer Negotiate auth (${www || 'no WWW-Authenticate'})`);

    const type2 = parseType2(spnegoExtractToken(b64decode(tok[1])));
    const sessionKey = new Uint8Array(16);
    (globalThis.crypto || {}).getRandomValues?.(sessionKey);
    const ntHash = creds.hash ? hexToBytes(creds.hash) : null; // pass-the-hash
    const { type3, exportedSessionKey } = buildAuthenticate({ user, domain, password: creds.password, ntHash, type2, exportedSessionKey: sessionKey, channelBinding: cb });
    this.session = new NtlmSession(exportedSessionKey);
    // Attached to the first request, which completes auth.
    this._pendingAuth = 'Negotiate ' + b64(spnegoNegTokenResp(type3));
    this._log(`WinRM: NTLMv2 handshake prepared for ${domain ? domain + '\\' : ''}${user}${cb ? ' (+channel binding)' : ''}.`);
  }

  // Kerberos: acquire an HTTP/<host> service ticket, then a single Negotiate
  // leg (mutual auth) whose WWW-Authenticate response carries the AP-REP, which
  // finishes the GSS context. Subsequent traffic is sealed like NTLM.
  async _connectKerberos(host, creds, user, domain, cb) {
    let st = creds.serviceTicket; // a harness may supply this directly
    if (!st) {
      const transport = new KdcSocketTransport(creds.kdc || host, 88, this._log);
      await transport.connect();
      try {
        const krb = new KerberosClient(transport, this._log);
        const id = { username: user, realm: domain };
        if (creds.hash) { id.key = hexToBytes(creds.hash); id.etype = ETYPE.RC4_HMAC; } else id.password = creds.password;
        const tgt = await krb.getTGT(id);
        st = await krb.getTGS(tgt, { spn: creds.spn || `HTTP/${host}` });
      } finally {
        await transport.close();
      }
    }

    if (this._sealed) {
      // Plain HTTP: establish a GSS sign+seal context (messages are wrapped).
      const { token, state } = gssSealInit(st);
      this._log(`WinRM: sending Kerberos AP-REQ (Negotiate) for ${user}@${domain} …`);
      const r = await this.http.send('POST', this.path, {
        Authorization: 'Negotiate ' + b64(token), 'Content-Type': 'application/soap+xml;charset=UTF-8',
      });
      if (r.status === 401) throw new Error('WinRM: Kerberos authentication rejected (401).');
      const www = (r.rawHeaders.find(([n]) => n.toLowerCase() === 'www-authenticate') || [])[1] || '';
      const m = /Negotiate ([A-Za-z0-9+/=]+)/.exec(www);
      this.session = gssSealEstablish(m ? b64decode(m[1]) : null, state);
      this._log('WinRM: Kerberos context established (sealed channel ready).');
    } else {
      // HTTPS: auth-only AP-REQ with channel binding; TLS provides confidentiality.
      const token = spnegoKrbInitToken(gssInitToken(buildGssApReq(st, { mutual: true, channelBinding: cb })));
      this._log(`WinRM: sending Kerberos AP-REQ over HTTPS for ${user}@${domain}${cb ? ' (+channel binding)' : ''} …`);
      const r = await this.http.send('POST', this.path, {
        Authorization: 'Negotiate ' + b64(token), 'Content-Type': 'application/soap+xml;charset=UTF-8',
      });
      if (r.status === 401) throw new Error('WinRM: Kerberos authentication rejected (401).');
      this._log('WinRM: Kerberos (HTTPS) authenticated.');
    }
  }

  // Send one SOAP message and return the SOAP response. Over HTTP the body is
  // SSP-encrypted (multipart/encrypted); over HTTPS it is plain (TLS protects it).
  async exchange(soapXml) {
    const headers = {};
    let body;
    if (this._sealed) {
      const wrapped = wrapEncrypted(this.session, soapXml);
      headers['Content-Type'] = wrapped.contentType;
      body = wrapped.body;
    } else {
      headers['Content-Type'] = 'application/soap+xml;charset=UTF-8';
      body = enc.encode(soapXml);
    }
    if (this._pendingAuth) { headers.Authorization = this._pendingAuth; this._pendingAuth = null; }
    const r = await this.http.send('POST', this.path, headers, body);
    if (r.status === 401) throw new Error('WinRM: authentication failed (401) — check credentials.');
    if (r.status !== 200 && r.status !== 500) {
      throw new Error(`WinRM: HTTP ${r.status} ${r.statusText} — ${dec.decode(r.body).slice(0, 200)}`);
    }
    return this._sealed ? unwrapEncrypted(this.session, r.body) : dec.decode(r.body);
  }

  async close() { await this.http.close(); }
}
