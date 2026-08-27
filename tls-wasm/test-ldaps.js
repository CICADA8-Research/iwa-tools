// Full live chain: WASM-TLS (rustls) to the DC's LDAPS:636, tls-server-end-point
// channel binding, then a Kerberos GSS-SPNEGO LDAP bind carrying that binding,
// then a rootDSE read — all over the encrypted channel. Uses the real adidns
// LdapClient + kerberos modules; the only test-shim is the Node net socket in
// place of the IWA's Direct Sockets.
//
//   node test-ldaps.js --kdc 100.100.10.100 --realm pk.lab --user user01 \
//       --pass 'P@ssw0rd' --host lab01-dc01.pk.lab
import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { TlsSocket } from './tls-socket.js';
import { KerberosClient } from '../adidns/src/kerberos/client.js';
import { kerberosSpnegoProducer } from '../adidns/src/kerberos/gss.js';
import { ETYPE } from '../adidns/src/kerberos/constants.js';
import { LdapClient, SCOPE, filter } from '../adidns/src/ldap/client.js';
const { TlsSession } = createRequire(import.meta.url)('./pkg/tls_wasm.js');

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function parseArgs(argv) { const a = {}; for (let i = 2; i < argv.length; i++) { if (!argv[i].startsWith('--')) continue; const k = argv[i].slice(2); const n = argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; }
function netStreams(sock) {
  const chunks = []; let waiting = null, ended = false, error = null;
  sock.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
  sock.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
  sock.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
  return {
    reader: { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); } },
    writer: { write: (b) => new Promise((res, rej) => sock.write(Buffer.from(b), (e) => (e ? rej(e) : res()))) },
  };
}
class NetKdc {
  constructor(h, p = 88) { this._h = h; this._p = p; }
  connect() { return new Promise((res, rej) => { this._b = Buffer.alloc(0); this._s = net.connect(this._p, this._h, res); this._s.on('data', (c) => { this._b = Buffer.concat([this._b, c]); this._t(); }); this._s.on('error', rej); }); }
  _t() { if (!this._pe || this._b.length < 4) return; const l = this._b.readUInt32BE(0); if (this._b.length < 4 + l) return; const m = Uint8Array.from(this._b.subarray(4, 4 + l)); this._b = this._b.subarray(4 + l); const p = this._pe; this._pe = null; p.resolve(m); }
  request(r) { return new Promise((res, rej) => { this._pe = { resolve: res, reject: rej }; const f = Buffer.alloc(4 + r.length); f.writeUInt32BE(r.length, 0); f.set(r, 4); this._s.write(f); this._t(); }); }
  close() { try { this._s.destroy(); } catch { /* ignore */ } }
}
const log = (m) => console.log('  ·', m);

async function main() {
  const a = parseArgs(process.argv);
  const host = a.host, realm = a.realm;

  // 1. Kerberos service ticket for ldap/<dc>.
  const kt = new NetKdc(a.kdc, 88); await kt.connect();
  console.log(`[*] Kerberos: TGT for ${a.user}@${realm}, then ldap/${host}`);
  const krb = new KerberosClient(kt, log);
  const id = { username: a.user, realm };
  if (a.rc4) { id.key = Uint8Array.from(Buffer.from(a.rc4, 'hex')); id.etype = ETYPE.RC4_HMAC; } else id.password = a.pass;
  const tgt = await krb.getTGT(id);
  const st = await krb.getTGS(tgt, { spn: `ldap/${host}` });
  kt.close();
  console.log(`[+] service ticket: etype ${st.sessionKey.etype}`);

  // 2. WASM-TLS to LDAPS:636 + channel binding.
  const sock = net.connect(636, a.kdc);
  await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
  const { reader, writer } = netStreams(sock);
  const tls = new TlsSocket(TlsSession, reader, writer, host);
  console.log('[*] WASM-TLS handshake to LDAPS:636 …');
  await tls.handshake();
  const cb = await tls.channelBinding();
  console.log(`[+] TLS up; channel binding ${cb.hashName}, ${cb.applicationData.length}B app-data`);

  // 3. LDAP GSS-SPNEGO bind over TLS, carrying the channel binding.
  const ldap = new LdapClient(log);
  ldap._reader = tls._reader; ldap._writer = tls._writer;
  console.log('[*] Kerberos LDAP bind over LDAPS (with channel binding) …');
  const cbData = a.nocbt ? null : cb.applicationData;
  if (a.nocbt) console.log('[*] (negative test: binding WITHOUT channel binding)');
  await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket: st, channelBinding: cbData, log }));

  // 4. Prove the bound, TLS-protected session works.
  for await (const e of ldap.search({ baseDN: '', scope: SCOPE.BASE, filter: filter.present('objectClass'), attributes: ['defaultNamingContext'], pageSize: 1 })) {
    const v = e.attributes.defaultNamingContext;
    console.log('[+] Bound over LDAPS+CBT. rootDSE defaultNamingContext =', v ? new TextDecoder().decode(v[0]) : '(none)');
  }
  sock.destroy();
  console.log('\n[+] OK — Kerberos over LDAPS with tls-server-end-point channel binding works.');
}
main().then(() => process.exit(0)).catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
