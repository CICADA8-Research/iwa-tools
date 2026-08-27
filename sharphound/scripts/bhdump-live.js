// Live check of the extended bhdump: set up an RBCD relationship via the LDAP
// shell, run the BloodHound collection, and confirm the new fields populate.
//   node scripts/bhdump-live.js --ip 100.100.10.100 --fqdn lab01-dc01.pk.lab --realm pk.lab --user administrator --pass 'P@ssw0rd'
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

const { connect } = await import('../../ldap-shell/src/connect.js');
const { LdapShell } = await import('../../ldap-shell/src/shell.js');
const { run } = await import('../src/sharphound.js');

const cfg = { host: A.fqdn, kdc: A.ip, port: 636, tls: true, authMethod: 'kerberos', bindDN: A.user, user: A.user, domain: A.realm, password: A.pass };

async function main() {
  // 1. set up: a user + computer with RBCD (user can act on the computer).
  const ctx = await connect(cfg, () => {});
  const shell = new LdapShell(ctx.client, { baseDN: ctx.baseDN, domain: ctx.domain, tls: true });
  for (const c of ['del bhuser', 'del bhcomp']) { try { await shell.run(c); } catch { /* fresh */ } } // idempotent
  console.log('[*] setup:', (await shell.run('add_user bhuser Sup3r!23')).split('\n')[0]);
  console.log('[*] setup:', (await shell.run('add_computer bhcomp Sup3r!23')).split('\n')[0]);
  console.log('[*] setup:', await shell.run('set_rbcd bhcomp bhuser'));
  const userSid = (await shell.run('search (sAMAccountName=bhuser) objectSid')).match(/S-1-5-\S+/)?.[0];
  await ctx.client.close();

  // 2. collect with the extended bhdump.
  console.log('[*] running sharphound bhdump …');
  const res = await run({ ...cfg, mode: 'bhdump' }, { log: () => {}, onRow: () => {} });
  const get = (name) => res.files.find((f) => f.name === name).content.data;
  const comp = get('computers.json').find((c) => /BHCOMP/.test(c.Properties.name));
  const sampleUser = get('users.json').find((u) => u.Properties.samaccountname === 'krbtgt') || get('users.json')[0];
  const domain = get('domains.json')[0];

  // 3. assertions / sample output.
  console.log('\n[+] computer BHCOMP.AllowedToAct =', JSON.stringify(comp?.AllowedToAct));
  console.log('    contains bhuser SID?', !!comp?.AllowedToAct?.some((x) => x.ObjectIdentifier === userSid), '(', userSid, ')');
  console.log('    BHCOMP.IsACLProtected =', comp?.IsACLProtected, '| haslaps =', comp?.Properties.haslaps);
  console.log('[+] sample user new props:', JSON.stringify({
    enabled: sampleUser.Properties.enabled, pwdneverexpires: sampleUser.Properties.pwdneverexpires,
    sensitive: sampleUser.Properties.sensitive, dontreqpreauth: sampleUser.Properties.dontreqpreauth,
    sidhistory: sampleUser.Properties.sidhistory, IsACLProtected: sampleUser.IsACLProtected,
    AllowedToDelegate: sampleUser.AllowedToDelegate, HasSIDHistory: sampleUser.HasSIDHistory,
  }));
  console.log('[+] domain:', JSON.stringify({ name: domain.Properties.name, machineaccountquota: domain.Properties.machineaccountquota, functionallevel: domain.Properties.functionallevel, trusts: domain.Trusts.length, IsACLProtected: domain.IsACLProtected }));
  console.log('[+] summary:', JSON.stringify(res.summary));

  // 4. cleanup.
  const ctx2 = await connect(cfg, () => {});
  const sh2 = new LdapShell(ctx2.client, { baseDN: ctx2.baseDN, domain: ctx2.domain, tls: true });
  await sh2.run('del bhuser'); await sh2.run('del bhcomp');
  await ctx2.client.close();
  console.log('\n[+] cleaned up. done.');
}
main().then(() => process.exit(0)).catch((e) => { console.error('[!]', e.stack || e.message); process.exit(1); });
