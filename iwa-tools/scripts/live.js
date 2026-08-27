// Live check of the combined console in Node: TCPSocket polyfill (FQDN->IP)
// drives the real IwaConsole through portscan + an interactive ldap-shell.
//   node scripts/live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab --realm pk.lab --user administrator --pass 'P@ssw0rd'
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [A.fqdn]: A.ip };

globalThis.TCPSocket = class {
  constructor(host, port) {
    const ch = []; let w = null, en = false, er = null;
    const s = net.connect(port, HOSTS[host] || host); this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (w) { const x = w; w = null; x.resolve({ value: u, done: false }); } else ch.push(u); });
    s.on('end', () => { en = true; if (w) { const x = w; w = null; x.resolve({ done: true }); } });
    s.on('error', (e) => { er = e; if (w) { const x = w; w = null; x.reject(e); } });
    const rd = { read() { if (ch.length) return Promise.resolve({ value: ch.shift(), done: false }); if (er) return Promise.reject(er); if (en) return Promise.resolve({ done: true }); return new Promise((re, rj) => { w = { resolve: re, reject: rj }; }); }, releaseLock() {} };
    const wr = { write: (b) => new Promise((re, rj) => s.write(Buffer.from(b), (e) => (e ? rj(e) : re()))), releaseLock() {} };
    this.opened = new Promise((re, rj) => { s.once('connect', () => re({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => rd }, writable: { getWriter: () => wr } })); s.once('error', rj); });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { IwaConsole } = await import('../src/console.js');

let prompt = 'iwa#';
const io = { print: (t) => console.log(t), setPrompt: (s) => { prompt = s; }, clear() {}, download() {} };
const con = new IwaConsole(io);
const submit = async (line) => { console.log(`\n${prompt} ${line}`); await con.submit(line); };

await submit(`portscan ${A.ip} 88,389,445,636,5985`);
await submit(`ldap-shell --host ${A.fqdn} --kdc ${A.ip} --user ${A.user} --domain ${A.realm} --password ${A.pass} --tls`);
await submit('whoami');
await submit('get_user_groups administrator');
await submit('exit');
console.log('\n[+] done');
process.exit(0);
