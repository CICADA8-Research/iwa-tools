// Validate evil-winrm's production WinRM-HTTPS + channel-binding path in Node:
// a TCPSocket polyfill (FQDN->IP map so SPN/SNI stay the FQDN while TCP uses the
// IP) drives the real WinRMClient.connect() over TLS, then opens a shell.
//   node scripts/tls-live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab \
//       --realm pk.lab --user administrator --pass 'P@ssw0rd' [--auth kerberos|ntlm] [--cmd whoami]
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const ARG = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [ARG.fqdn]: ARG.ip };

globalThis.TCPSocket = class {
  constructor(host, port) {
    const chunks = []; let waiting = null, ended = false, error = null;
    const s = net.connect(port, HOSTS[host] || host);
    this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
    s.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
    s.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
    const reader = { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); }, releaseLock() {} };
    const writer = { write: (b) => new Promise((res, rej) => s.write(Buffer.from(b), (e) => (e ? rej(e) : res()))), releaseLock() {} };
    this.opened = new Promise((resolve, reject) => { s.once('connect', () => resolve({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => reader }, writable: { getWriter: () => writer } })); s.once('error', reject); });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { WinRMClient } = await import('../src/winrm/client.js');
const { Shell } = await import('../src/winrm/shell.js');

async function main() {
  const auth = ARG.auth || 'kerberos';
  const client = new WinRMClient((m) => console.log('  ·', m));
  console.log(`[*] evil-winrm WinRMClient → HTTPS ${ARG.fqdn}:5986 (${auth}, WASM-TLS + CBT)`);
  await client.connect(ARG.fqdn, 5986, {
    authMethod: auth, user: ARG.user, domain: ARG.realm,
    kdc: ARG.ip, tls: true, sni: ARG.fqdn, password: ARG.pass, hash: ARG.rc4 || null,
  });
  const shell = new Shell(client, (m) => console.log('  ·', m));
  await shell.open();
  const cmd = ARG.cmd || 'whoami';
  console.log(`[*] Running: ${cmd}`);
  let out = '';
  const r = await shell.run(cmd, { onStdout: (t) => { out += t; }, onStderr: (t) => { out += t; } });
  console.log('[+] Output:', out.trim());
  await shell.close();
  await client.close();
  console.log(`\n[+] OK — evil-winrm ${auth} over WASM-TLS HTTPS with channel binding (exit ${r.exitCode}).`);
}
main().then(() => process.exit(0)).catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
