// Validate adidns's production TLS path end to end in Node: a TCPSocket polyfill
// over `net` lets the real LdapClient run unchanged, so this exercises the
// embedded WASM-TLS loader, LdapClient's LDAPS transport, channel binding, and
// the Kerberos/NTLM binds with CBT — exactly what the IWA runs in the browser.
//
//   node scripts/tls-live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab \
//       --realm pk.lab --user user01 --pass 'P@ssw0rd' [--auth kerberos|ntlm]
import net from 'node:net';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

// ---- TCPSocket polyfill (Direct Sockets shape) over Node net ---------------
globalThis.TCPSocket = class {
  constructor(host, port) {
    const chunks = []; let waiting = null, ended = false, error = null;
    const s = net.connect(port, host);
    this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
    s.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
    s.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
    const reader = { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); }, releaseLock() {} };
    const writer = { write: (b) => new Promise((res, rej) => s.write(Buffer.from(b), (e) => (e ? rej(e) : res()))), releaseLock() {} };
    this.opened = new Promise((resolve, reject) => {
      s.once('connect', () => resolve({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => reader }, writable: { getWriter: () => writer } }));
      s.once('error', reject);
    });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { LdapClient, SCOPE, filter } = await import('../src/ldap/client.js');
const { loadTls } = await import('../src/tls/index.js');
const { kerberosSpnegoBind } = await import('../src/kerberos/ldap-bind.js');
const { ntlmSpnegoProducer } = await import('../src/ntlm/sasl.js');

function parseArgs(argv) { const a = {}; for (let i = 2; i < argv.length; i++) { if (!argv[i].startsWith('--')) continue; const k = argv[i].slice(2); const n = argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; }
const log = (m) => console.log('  ·', m);

async function main() {
  const a = parseArgs(process.argv);
  const auth = a.auth || 'kerberos';
  const client = new LdapClient(log);

  // LDAPS over the embedded WASM-TLS engine (connect by IP, SNI = FQDN).
  console.log(`[*] adidns LdapClient → LDAPS ${a.ip}:636 (SNI ${a.fqdn}), WASM-TLS`);
  await client.connect(a.ip, 636, { tls: { TlsSession: loadTls(), sni: a.fqdn } });
  const cb = await client.channelBinding();
  console.log(`[+] TLS up; channel binding ${cb.hashName}, ${cb.applicationData.length}B`);

  if (auth === 'kerberos') {
    console.log(`[*] Kerberos bind (ldap/${a.fqdn}) over LDAPS + CBT`);
    await kerberosSpnegoBind(client, { host: a.fqdn, kdc: a.ip, realm: a.realm, user: a.user, password: a.pass, channelBinding: cb.applicationData, log });
  } else {
    console.log('[*] NTLMv2 bind over LDAPS + CBT');
    await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({ user: a.user, domain: a.realm, password: a.pass, channelBinding: cb.applicationData, log }));
  }

  for await (const e of client.search({ baseDN: '', scope: SCOPE.BASE, filter: filter.present('objectClass'), attributes: ['defaultNamingContext'], pageSize: 1 })) {
    const v = e.attributes.defaultNamingContext;
    console.log(`[+] Bound (${auth}) over LDAPS+CBT. rootDSE = ${v ? new TextDecoder().decode(v[0]) : '(none)'}`);
  }
  await client.close();
  console.log(`\n[+] OK — adidns ${auth} over WASM-TLS LDAPS with channel binding.`);
}
main().then(() => process.exit(0)).catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
