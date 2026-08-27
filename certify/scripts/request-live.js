// Live check of Certify `request` via MS-ICPR against the lab CA.
//   node scripts/request-live.js --ip 100.100.10.101 --cahost lab01-mssql01.pk.lab --ca pk-ROOT-CA --template User --user administrator --domain pk.lab --pass 'P@ssw0rd' [--altupn administrator@pk.lab]
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.__ICPR_DEBUG = true;
const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [A.cahost.toLowerCase()]: A.ip };
globalThis.TCPSocket = class { constructor(host, port) { const ch = []; let w = null, en = false, er = null; const s = net.connect(port, HOSTS[String(host).toLowerCase()] || host); this._s = s; s.on('data', (d) => { const u = Uint8Array.from(d); if (w) { const x = w; w = null; x.resolve({ value: u, done: false }); } else ch.push(u); }); s.on('end', () => { en = true; if (w) { const x = w; w = null; x.resolve({ done: true }); } }); s.on('error', (e) => { er = e; if (w) { const x = w; w = null; x.reject(e); } }); const rd = { read() { if (ch.length) return Promise.resolve({ value: ch.shift(), done: false }); if (er) return Promise.reject(er); if (en) return Promise.resolve({ done: true }); return new Promise((re, rj) => { w = { resolve: re, reject: rj }; }); }, releaseLock() {} }; const wr = { write: (b) => new Promise((re, rj) => s.write(Buffer.from(b), (e) => (e ? rj(e) : re()))), releaseLock() {} }; this.opened = new Promise((re, rj) => { s.once('connect', () => re({ readable: { getReader: () => rd }, writable: { getWriter: () => wr } })); s.once('error', rj); }); } async close() { try { this._s.destroy(); } catch {} } };

const { requestCert } = await import('../src/certify.js');
const res = await requestCert({
  caHost: A.cahost, caName: A.ca, template: A.template,
  subject: A.subject || 'CN=User', altUpn: A.altupn || null,
  user: A.user, domain: A.domain, password: A.pass,
}, { log: (m) => console.log('  ·', m) });

console.log(`\n[+] disposition = ${res.dispositionText} (${res.disposition}), requestId=${res.requestId}`);
if (res.certPem) {
  const { writeFileSync } = await import('node:fs');
  if (A.out) { writeFileSync(A.out + '.crt', res.certPem); writeFileSync(A.out + '.key', res.keyPem); console.log('[+] wrote ' + A.out + '.crt / .key'); }
  console.log('[+] issued certificate:\n' + res.certPem);
} else {
  console.log('[!] no certificate issued. message:', res.message);
}
process.exit(0);
