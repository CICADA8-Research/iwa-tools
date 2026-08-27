// Live exercise of the LDAP shell against a DC over LDAPS (Kerberos), through
// the production connect() + LdapShell. TCPSocket polyfill maps the FQDN to the
// IP so SPN/SNI stay the FQDN. Creates throwaway objects and deletes them.
//   node scripts/live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab \
//       --realm pk.lab --user administrator --pass 'P@ssw0rd'
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [A.fqdn]: A.ip };

globalThis.TCPSocket = class {
  constructor(host, port) {
    const chunks = []; let waiting = null, ended = false, error = null;
    const s = net.connect(port, HOSTS[host] || host); this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
    s.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
    s.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
    const reader = { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); }, releaseLock() {} };
    const writer = { write: (b) => new Promise((res, rej) => s.write(Buffer.from(b), (e) => (e ? rej(e) : res()))), releaseLock() {} };
    this.opened = new Promise((resolve, reject) => { s.once('connect', () => resolve({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => reader }, writable: { getWriter: () => writer } })); s.once('error', reject); });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { connect } = await import('../src/connect.js');
const { LdapShell } = await import('../src/shell.js');

async function main() {
  const ctx = await connect({
    host: A.fqdn, kdc: A.ip, port: 636, tls: true,
    authMethod: 'kerberos', bindDN: A.user, domain: A.realm, password: A.pass,
  }, () => {});
  const shell = new LdapShell(ctx.client, { baseDN: ctx.baseDN, domain: ctx.domain, tls: ctx.tls });
  const run = async (line) => { console.log(`\n# ${line}`); try { console.log(await shell.run(line)); } catch (e) { console.log(`[!] ${e.message}`); } };

  await run('whoami');
  await run('get_user_groups administrator');
  await run('search (sAMAccountName=krbtgt) distinguishedName,objectSid');
  await run('add_user lsdemo Sup3rSecret!23');
  await run('get_object lsdemo');
  await run('set_dontreqpreauth lsdemo true');
  await run('set_spn lsdemo HTTP/lsdemo.pk.lab');
  await run('change_password lsdemo N3wPass!2024');
  await run('add_computer lsdemo01 Sup3rSecret!23');
  await run('set_rbcd lsdemo01 lsdemo');
  await run('clear_rbcd lsdemo01');
  console.log('\n--- cleanup ---');
  await run('del lsdemo');
  await run('del lsdemo01');

  await ctx.client.close();
  console.log('\n[+] done');
}
main().then(() => process.exit(0)).catch((e) => { console.error('[!]', e.stack || e.message); process.exit(1); });
