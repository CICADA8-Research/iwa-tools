// Smoke test for the combined console: the dispatcher loads every bundled tool,
// lists them, prints usage, and routes unknown commands to an error. Also covers
// the pseudo file storage (store commands, @-expansion, results→store) and the
// Kerberos ticket parser.
// Run with: node scripts/test.js
import assert from 'node:assert';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { IwaConsole, TOOLS } from '../src/console.js';
import { Store, toBytes } from '../src/store.js';
import { parseTicketFile } from '../src/tickets.js';

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }
async function okAsync(name, fn) { await fn(); console.log(`  ok  ${name}`); pass++; }

function fakeIo() {
  const out = [], downloads = [], picks = [];
  return {
    out, downloads, picks,
    print: (t) => out.push(String(t)), setPrompt() {}, clear() {},
    download: (name, content) => downloads.push({ name, content }),
    pickFiles: async () => picks.shift() || [],
  };
}

ok('all tools are registered', () => {
  assert.deepStrictEqual([...TOOLS].sort(), ['adidns', 'certify', 'evil-winrm', 'ldap-shell', 'nxc', 'portscan', 'sharphound', 'soaphound'].sort());
});

await okAsync('help lists every tool', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('help');
  const text = io.out.join('\n');
  for (const t of TOOLS) assert.ok(text.includes(t), `help mentions ${t}`);
});

await okAsync('a tool with no args prints its usage', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('portscan');
  assert.ok(io.out.join('\n').toLowerCase().includes('usage'));
});

await okAsync('unknown command is rejected', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('nope --x 1');
  assert.ok(io.out.join('\n').includes('unknown command'));
});

await okAsync('quoted args tokenize correctly', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('adidns --domain "pk lab" --user a');
  assert.ok(io.out.join('\n').toLowerCase().includes('usage'));
});

ok('Tab completion offers matching tool + storage names', () => {
  const con = new IwaConsole(fakeIo());
  assert.deepStrictEqual(con.complete('s').sort(), ['sharphound', 'soaphound', 'store']);
  assert.deepStrictEqual(con.complete('ld'), ['ldap-shell']);
  assert.ok(con.complete('').includes('help') && con.complete('').includes('portscan'));
  assert.ok(con.complete('up').includes('upload') && con.complete('down').includes('download'));
});

await okAsync('help <tool> shows usage + a concrete example', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('help portscan');
  const text = io.out.join('\n');
  assert.ok(text.includes('portscan -p'));
  assert.ok(text.includes('example:') && text.includes('10.0.0.0/24'));
});

// ---- store ----------------------------------------------------------------

ok('Store put/get/getText/list/rm/mv round-trip', () => {
  const s = new Store();
  s.put('scope/net.txt', '10.0.0.0/24');
  assert.strictEqual(s.getText('scope/net.txt'), '10.0.0.0/24');
  assert.strictEqual(s.get('/scope/net.txt').length, 11); // leading slash normalised
  s.put('loot/data.json', { a: 1 });
  assert.ok(s.getText('loot/data.json').includes('"a": 1')); // objects → pretty JSON
  const paths = s.list().map((r) => r.path);
  assert.deepStrictEqual(paths, ['loot/data.json', 'scope/net.txt']);
  assert.deepStrictEqual(s.list('scope/').map((r) => r.path), ['scope/net.txt']);
  s.rename('scope/net.txt', 'scope/renamed.txt');
  assert.ok(s.has('scope/renamed.txt') && !s.has('scope/net.txt'));
  assert.strictEqual(s.remove('loot/data.json'), true);
  assert.strictEqual(s.get('loot/data.json'), null);
});

ok('toBytes normalises Uint8Array / string / object', () => {
  const u = new Uint8Array([1, 2, 3]);
  assert.strictEqual(toBytes(u), u);
  assert.deepStrictEqual([...toBytes('AB')], [65, 66]);
  assert.ok(new TextDecoder().decode(toBytes({ x: 1 })).includes('"x": 1'));
});

await okAsync('store commands: put, ls, cat, rm', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  await con.submit('put scope/net.txt 10.0.0.0/24');
  await con.submit('ls');
  await con.submit('cat scope/net.txt');
  await con.submit('rm scope/net.txt');
  const text = io.out.join('\n');
  assert.ok(text.includes('scope/net.txt'), 'ls shows the file');
  assert.ok(text.includes('10.0.0.0/24'), 'cat prints the content');
  assert.ok(text.includes('removed scope/net.txt'));
  assert.ok(!con.store.has('scope/net.txt'));
});

await okAsync('upload imports picked files into the store', async () => {
  const io = fakeIo();
  io.picks.push([{ name: 'adm.ccache', bytes: new Uint8Array([5, 4, 0, 0]) }]);
  const con = new IwaConsole(io);
  await con.submit('upload tickets/');
  assert.ok(con.store.has('tickets/adm.ccache'));
  assert.deepStrictEqual([...con.store.get('tickets/adm.ccache')], [5, 4, 0, 0]);
});

await okAsync('download exports a stored file via io.download', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  con.store.put('loot/Users.json', '{"data":[]}');
  await con.submit('download loot/Users.json');
  assert.strictEqual(io.downloads.length, 1);
  assert.strictEqual(io.downloads[0].name, 'Users.json');
});

await okAsync('@path expands a stored text file into a tool argument', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  con.store.put('scope/net.txt', '10.0.0.1');
  // portscan needs -p and a target; @scope/net.txt supplies the target text.
  // With no TCPSocket the scan yields 0 open, but arg expansion must have run
  // (the probe count reflects the expanded target, not the literal "@…").
  await con.submit('portscan -p 80 @scope/net.txt');
  const text = io.out.join('\n');
  assert.ok(text.includes('scanning 10.0.0.1'), `expected expanded target, got:\n${text}`);
});

await okAsync('@path errors clearly when the file is missing', async () => {
  const io = fakeIo();
  await new IwaConsole(io).submit('portscan -p 80 @nope.txt');
  assert.ok(io.out.join('\n').includes('no such file in store: nope.txt'));
});

// ---- ticket parser --------------------------------------------------------

// Minimal big-endian ccache (v0x0504) builder for one service + one TGT.
function buildCcache() {
  const a = [];
  const u16 = (v) => a.push((v >> 8) & 0xff, v & 0xff);
  const u32 = (v) => a.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  const raw = (bytes) => { for (const b of bytes) a.push(b); };
  const counted = (bytes) => { u32(bytes.length); raw(bytes); };
  const str = (s) => counted([...Buffer.from(s, 'utf8')]);
  const principal = (nt, realm, comps) => { u32(nt); u32(comps.length); str(realm); comps.forEach(str); };
  const cred = (server, etype, keylen, ticket) => {
    principal(1, 'CORP.LOCAL', ['user']);      // client
    principal(2, 'CORP.LOCAL', server);         // server
    u16(etype); u16(keylen); raw(new Array(keylen).fill(0xab)); // keyblock (no dup etype for 0504)
    u32(0); u32(0); u32(0); u32(0);             // times
    a.push(0);                                   // is_skey
    u32(0);                                       // tktflags
    u32(0);                                       // addresses
    u32(0);                                       // authdata
    counted(ticket); counted([]);               // ticket + second_ticket
  };
  u16(0x0504); u16(0);                           // version + empty header
  principal(1, 'CORP.LOCAL', ['user']);          // default principal
  cred(['ldap', 'dc01.corp.local'], 18, 32, [0x61, 0x05, 0x01, 0x02, 0x03]);
  cred(['krbtgt', 'CORP.LOCAL'], 23, 16, [0x61, 0xaa, 0xbb]);
  return new Uint8Array(a);
}

ok('parseTicketFile splits ccache TGT vs service ticket', () => {
  const r = parseTicketFile(buildCcache());
  assert.strictEqual(r.serviceTickets.length, 1);
  assert.strictEqual(r.tgts.length, 1);
  const svc = r.serviceTickets[0];
  assert.strictEqual(svc.spn, 'ldap/dc01.corp.local');
  assert.strictEqual(svc.sessionKey.etype, 18);
  assert.strictEqual(svc.sessionKey.key.length, 32);
  assert.strictEqual(svc.ticket[0], 0x61);       // raw [APPLICATION 1] Ticket
  assert.strictEqual(svc.crealm, 'CORP.LOCAL');
  assert.deepStrictEqual(svc.cname, ['user']);
  assert.strictEqual(r.tgts[0].spn, 'krbtgt/CORP.LOCAL');
});

ok('parseTicketFile accepts base64 text', () => {
  const b64 = Buffer.from(buildCcache()).toString('base64');
  const r = parseTicketFile(b64);
  assert.strictEqual(r.serviceTickets[0].spn, 'ldap/dc01.corp.local');
});

ok('ldapConfig imports --ticket from the store and forces kerberos', () => {
  const con = new IwaConsole(fakeIo());
  con.store.put('tickets/adm.ccache', buildCcache());
  const cfg = con.ldapConfig({ host: 'dc01', domain: 'corp.local', auth: 'ntlm', ticket: 'tickets/adm.ccache' });
  assert.strictEqual(cfg.authMethod, 'kerberos');                       // ticket overrides --auth
  assert.strictEqual(cfg.ticket.serviceTickets[0].spn, 'ldap/dc01.corp.local');
  assert.throws(() => con.ldapConfig({ host: 'dc01', ticket: 'tickets/missing' }), /no such file in store/);
});

await okAsync('klist inspects an uploaded ticket without binding', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  con.store.put('tickets/adm.ccache', buildCcache());
  await con.submit('klist tickets/adm.ccache');
  const text = io.out.join('\n');
  assert.ok(text.includes('1 TGT, 1 service ticket'));
  assert.ok(text.includes('ldap/dc01.corp.local'));
  assert.ok(text.includes('aes256-cts-hmac-sha1 (18)'));   // etype resolved to a name
  assert.ok(text.includes('user@CORP.LOCAL'));
});

await okAsync('nxc --ticket forces kerberos, skips the -u requirement, and dispatches (smb)', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  con.store.put('tickets/adm.ccache', buildCcache());
  // No -u: with a ticket this must not error out, and the store path must not
  // leak into the target list. (No TCPSocket in Node, so the SMB connect fails
  // — but only after the ticket plumbing dispatched to the smb handler.)
  await con.submit('nxc smb 10.0.0.1 --ticket tickets/adm.ccache');
  const text = io.out.join('\n');
  assert.ok(!text.includes('No user specified'), 'ticket satisfies the auth requirement');
  assert.ok(text.includes('SMB 10.0.0.1'), 'dispatched to the smb handler for the real target');
});

await okAsync('nxc winrm --ticket reaches the Kerberos stage (wiring fixed)', async () => {
  const io = fakeIo();
  const con = new IwaConsole(io);
  con.store.put('tickets/adm.ccache', buildCcache());
  // The old protocol→client wiring threw a TypeError at connect (mismatched
  // signature) before any auth. With the fix it dispatches through the real
  // client + Shell to _connectKerberos, which (no TCPSocket in Node) fails at
  // the KDC socket — proving it got past the broken wiring.
  await con.submit('nxc winrm 10.0.0.1 -u admin --ticket tickets/adm.ccache');
  const text = io.out.join('\n');
  assert.ok(text.includes('WINRM 10.0.0.1'), 'dispatched to the winrm handler');
  assert.ok(text.includes('TCPSocket'), `reached the Kerberos KDC socket stage, got:\n${text}`);
});

ok('completeArgs offers store paths for @, --ticket and path commands', () => {
  const con = new IwaConsole(fakeIo());
  con.store.put('scope/net.txt', '10.0.0.0/24');
  con.store.put('tickets/adm.ccache', new Uint8Array([5, 4]));
  assert.deepStrictEqual(con.completeArgs(['portscan', '-p', '80', '@sc']), ['@scope/net.txt']);
  assert.deepStrictEqual(con.completeArgs(['ldap-shell', '--ticket', 'tic']), ['tickets/adm.ccache']);
  assert.deepStrictEqual(con.completeArgs(['cat', 'scope/']), ['scope/net.txt']);
  assert.deepStrictEqual(con.completeArgs(['portscan', '-p', '80']), []); // no @/path context
});

console.log(`\n${pass} tests passed.`);
