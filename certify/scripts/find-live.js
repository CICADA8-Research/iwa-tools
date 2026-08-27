// Live check of Certify `find` against the lab AD CS.
//   node scripts/find-live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab --realm pk.lab --user administrator --pass 'P@ssw0rd'
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [A.fqdn.toLowerCase()]: A.ip };

globalThis.TCPSocket = class {
  constructor(host, port) {
    const ch = []; let w = null, en = false, er = null;
    const s = net.connect(port, HOSTS[String(host).toLowerCase()] || host); this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (w) { const x = w; w = null; x.resolve({ value: u, done: false }); } else ch.push(u); });
    s.on('end', () => { en = true; if (w) { const x = w; w = null; x.resolve({ done: true }); } });
    s.on('error', (e) => { er = e; if (w) { const x = w; w = null; x.reject(e); } });
    const rd = { read() { if (ch.length) return Promise.resolve({ value: ch.shift(), done: false }); if (er) return Promise.reject(er); if (en) return Promise.resolve({ done: true }); return new Promise((re, rj) => { w = { resolve: re, reject: rj }; }); }, releaseLock() {} };
    const wr = { write: (b) => new Promise((re, rj) => s.write(Buffer.from(b), (e) => (e ? rj(e) : re()))), releaseLock() {} };
    this.opened = new Promise((re, rj) => { s.once('connect', () => re({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => rd }, writable: { getWriter: () => wr } })); s.once('error', rj); });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { run } = await import('../src/certify.js');
const res = await run({
  host: A.fqdn, kdc: A.ip, port: 636, tls: true, authMethod: 'kerberos',
  bindDN: A.user, user: A.user, domain: A.realm, password: A.pass, mode: 'find',
}, { log: (m) => console.log('  ·', m) });

console.log('\n[+] CAs:');
for (const c of res.caRows) console.log(`    ${c.name}  (${c.dns})  templates=${c.templates}  webEnroll=${c.webEnroll}  ${c.escs.join(',') || '-'}`);
console.log('\n[+] Templates (client-auth / enrollee-supplies-subject shown):');
for (const t of res.templateRows.filter((t) => t.clientAuth || t.escs.length))
  console.log(`    ${t.name}  schema=v${t.schema}  supplySubj=${t.suppliesSubject}  approval=${t.managerApproval}  ESC=[${t.escs.join(',')}]  enrollees=${t.enrollees.join('|')}`);
console.log('\n[!] FINDINGS:');
for (const f of res.findings) console.log(`    ${f.risk.padEnd(8)} ${f.id.padEnd(6)} ${f.scope}:${f.object}\n             ${f.detail}\n             principals: ${(f.principalNames || []).join(', ') || '(n/a)'}`);
console.log(`\n[+] summary: ${JSON.stringify(res.summary)}`);
process.exit(0);
