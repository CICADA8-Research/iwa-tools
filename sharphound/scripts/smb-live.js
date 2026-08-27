// Live check of the SMB2 foundation: connect, negotiate, NTLM session setup
// (signed), tree-connect IPC$, open the \samr pipe.
//   node scripts/smb-live.js --ip 100.100.10.100 --user administrator --domain pk.lab --pass 'P@ssw0rd'
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();

globalThis.TCPSocket = class {
  constructor(host, port) {
    const ch = []; let w = null, en = false, er = null;
    const s = net.connect(port, host); this._s = s;
    s.on('data', (d) => { const u = Uint8Array.from(d); if (w) { const x = w; w = null; x.resolve({ value: u, done: false }); } else ch.push(u); });
    s.on('end', () => { en = true; if (w) { const x = w; w = null; x.resolve({ done: true }); } });
    s.on('error', (e) => { er = e; if (w) { const x = w; w = null; x.reject(e); } });
    const rd = { read() { if (ch.length) return Promise.resolve({ value: ch.shift(), done: false }); if (er) return Promise.reject(er); if (en) return Promise.resolve({ done: true }); return new Promise((re, rj) => { w = { resolve: re, reject: rj }; }); }, releaseLock() {} };
    const wr = { write: (b) => new Promise((re, rj) => s.write(Buffer.from(b), (e) => (e ? rj(e) : re()))), releaseLock() {} };
    this.opened = new Promise((re, rj) => { s.once('connect', () => re({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: { getReader: () => rd }, writable: { getWriter: () => wr } })); s.once('error', rj); });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { Smb2Client } = await import('../src/smb/smb2.js');
const { Samr } = await import('../src/smb/samr.js');
const { Lsat } = await import('../src/smb/lsat.js');
const { Srvsvc } = await import('../src/smb/srvsvc.js');
const { Wkssvc } = await import('../src/smb/wkssvc.js');
const { Winreg } = await import('../src/smb/winreg.js');

async function main() {
  const c = new Smb2Client(A.ip, 445, (m) => console.log('  ·', m));
  console.log('[*] connect', A.ip + ':445');
  await c.connect();
  await c.negotiate();
  await c.login({ user: A.user, domain: A.domain, password: A.pass });
  const tid = await c.treeConnect('IPC$');
  console.log('[+] tree-connect IPC$ ok (treeId', tid + ')');
  const fid = await c.createPipe(tid, 'samr');
  console.log('[+] opened \\samr pipe');

  const samr = new Samr((bytes) => c.transceive(tid, fid, bytes), (m) => console.log('  ·', m));
  const groups = await samr.collectLocalGroups(A.ip);
  console.log('\n[+] local group members (SIDs):');
  for (const [edge, sids] of Object.entries(groups)) console.log(`    ${edge}: ${sids.length ? sids.join(', ') : '(none)'}`);

  await c.closeFile(tid, fid);

  // LSAT: resolve the LocalAdmins SIDs to names.
  const lfid = await c.createPipe(tid, 'lsarpc');
  console.log('\n[+] opened \\lsarpc pipe');
  const lsat = new Lsat((bytes) => c.transceive(tid, lfid, bytes));
  await lsat.bind();
  const policy = await lsat.openPolicy();
  const names = await lsat.lookupSids(policy, groups.LocalAdmins);
  console.log('[+] LSAT lookupSids:');
  for (const n of names) console.log(`    ${n.sid} -> ${n.domain ? n.domain + '\\' : ''}${n.name} (${n.type})`);
  await lsat.close(policy);
  await c.closeFile(tid, lfid);

  // SRVSVC: NetrSessionEnum (sessions on the host).
  const sfid = await c.createPipe(tid, 'srvsvc');
  console.log('\n[+] opened \\srvsvc pipe');
  const srvsvc = new Srvsvc((bytes) => c.transceive(tid, sfid, bytes));
  await srvsvc.bind();
  const sessions = await srvsvc.sessionEnum(A.ip);
  console.log(`[+] NetrSessionEnum: ${sessions.length} session(s)`);
  for (const s of sessions) console.log(`    user=${s.user}  from=${s.cname}`);
  await c.closeFile(tid, sfid);

  // WKSSVC: NetrWkstaUserEnum (logged-on users).
  const wfid = await c.createPipe(tid, 'wkssvc');
  console.log('\n[+] opened \\wkssvc pipe');
  const wkssvc = new Wkssvc((bytes) => c.transceive(tid, wfid, bytes));
  await wkssvc.bind();
  const loggedOn = await wkssvc.userEnum();
  console.log(`[+] NetrWkstaUserEnum: ${loggedOn.length} logon(s)`);
  for (const u of loggedOn) console.log(`    ${u.domain}\\${u.user}`);
  await c.closeFile(tid, wfid);

  // WINREG: enumerate HKU subkeys (loaded user hives). Remote Registry may need a
  // moment to trigger-start, so retry opening the pipe.
  let rfid;
  for (let i = 0; i < 5; i++) {
    try { rfid = await c.createPipe(tid, 'winreg'); break; }
    catch (e) { if (i === 4) throw e; console.log(`  · winreg pipe not ready (${e.message}), retrying…`); await new Promise((r) => setTimeout(r, 800)); }
  }
  console.log('\n[+] opened \\winreg pipe');
  const winreg = new Winreg((bytes) => c.transceive(tid, rfid, bytes));
  const regSids = await winreg.registrySessions();
  console.log(`[+] RegistrySessions (HKU user hives): ${regSids.length}`);
  for (const s of regSids) console.log(`    ${s}`);
  await c.closeFile(tid, rfid);

  await c.close();
  console.log('\n[+] SMB2 + SAMR + LSAT + SRVSVC + WKSSVC + WINREG OK');
}
main().then(() => process.exit(0)).catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
