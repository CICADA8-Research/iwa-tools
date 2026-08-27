// Live check of host-based collection: run sharphound bhdump with --collect-local
// and confirm the DC computer node's LocalAdmins is populated over SMB/SAMR.
//   node scripts/hostcollect-live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab --realm pk.lab --user administrator --pass 'P@ssw0rd'
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

const { run } = await import('../src/sharphound.js');

const res = await run({
  host: A.fqdn, kdc: A.ip, port: 636, tls: true, authMethod: 'kerberos',
  bindDN: A.user, user: A.user, domain: A.realm, password: A.pass,
  mode: 'bhdump', collectLocal: true,
}, { log: (m) => console.log('  ·', m), onRow: () => {} });

const computers = res.files.find((f) => f.name === 'computers.json').content.data;
const dc = computers.find((c) => new RegExp(A.fqdn, 'i').test(c.Properties.name));
console.log('\n[+] DC computer:', dc.Properties.name);
console.log('[+] LocalAdmins.Collected =', dc.LocalAdmins.Collected);
console.log('[+] LocalAdmins.Results =', JSON.stringify(dc.LocalAdmins.Results, null, 0));
console.log('[+] RemoteDesktopUsers.Collected =', dc.RemoteDesktopUsers.Collected, '| Results', dc.RemoteDesktopUsers.Results.length);
console.log('[+] Sessions.Collected =', dc.Sessions.Collected, '| n =', dc.Sessions.Results.length);
console.log('[+] PrivilegedSessions.Collected =', dc.PrivilegedSessions.Collected, '| n =', dc.PrivilegedSessions.Results.length);
console.log('[+] RegistrySessions.Collected =', dc.RegistrySessions.Collected, '| Results =', JSON.stringify(dc.RegistrySessions.Results));
process.exit(0);
