// Offline unit tests for the pure protocol/parsing logic (no browser APIs).
// Run with: node scripts/test.js
import assert from 'node:assert';
import { NtlmSession } from '../src/ntlm/seal.js';
import { wrapEncrypted, unwrapEncrypted, ENCRYPTED_CONTENT_TYPE } from '../src/winrm/crypt.js';
import {
  createShell, runCommand, receive, signal, deleteShell,
  getShellId, getCommandId, parseReceiveResponse, getFault, escapeXml,
} from '../src/winrm/messages.js';
import { HttpClient } from '../src/http/client.js';
import { wrapPowerShell, splitCwd } from '../src/winrm/shell.js';
import { nthash, computeNtlmv2Response, ntowfv2 } from '../src/ntlm/ntlm.js';
import { b64encode, b64decode, download, upload } from '../src/winrm/transfer.js';

const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => new TextDecoder().decode(u);

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }
async function okAsync(name, fn) { return fn().then(() => { console.log(`  ok  ${name}`); pass++; }); }

// ---- WinRM message encryption (uses the NTLM seal, peer modelled by a mirror session) ----
ok('wrapEncrypted -> unwrapEncrypted round-trips a SOAP body', () => {
  const sk = Uint8Array.from({ length: 16 }, (_, i) => (i * 11) & 0xff);
  const client = new NtlmSession(sk, 'client');
  const server = new NtlmSession(sk, 'server');
  const soap = '<s:Envelope><s:Body>hello winrm</s:Body></s:Envelope>';
  const { contentType, body } = wrapEncrypted(client, soap);
  assert.strictEqual(contentType, ENCRYPTED_CONTENT_TYPE);
  // OriginalContent advertises the plaintext length.
  assert.ok(dec(body).includes(`Length=${enc(soap).length}`));
  assert.strictEqual(unwrapEncrypted(server, body), soap);
});

ok('a tampered encrypted body fails the NTLM signature check', () => {
  const sk = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const client = new NtlmSession(sk, 'client');
  const server = new NtlmSession(sk, 'server');
  const { body } = wrapEncrypted(client, '<x/>');
  body[body.length - 6] ^= 0xff; // flip a ciphertext byte
  assert.throws(() => unwrapEncrypted(server, body), /signature verification failed/);
});

// ---- WS-Man message construction ----
ok('createShell targets the cmd resource with the Create action', () => {
  const x = createShell('http://h:5985/wsman');
  assert.ok(x.includes('http://schemas.xmlsoap.org/ws/2004/09/transfer/Create'));
  assert.ok(x.includes('windows/shell/cmd'));
  assert.ok(x.includes('<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>'));
});
ok('runCommand carries the ShellId selector + command, escaped', () => {
  const x = runCommand('http://h:5985/wsman', 'SID-1', 'whoami & echo <hi>');
  assert.ok(x.includes('<w:Selector Name="ShellId">SID-1</w:Selector>'));
  assert.ok(x.includes('windows/shell/Command'));
  assert.ok(x.includes('whoami &amp; echo &lt;hi&gt;'));
});
ok('receive / signal / deleteShell use the right actions', () => {
  assert.ok(receive('to', 'S', 'C').includes('windows/shell/Receive'));
  assert.ok(signal('to', 'S', 'C').includes('signal/terminate'));
  assert.ok(deleteShell('to', 'S').includes('2004/09/transfer/Delete'));
  assert.strictEqual(escapeXml('a&b<c>'), 'a&amp;b&lt;c&gt;');
});

// ---- response extractors ----
ok('getShellId / getCommandId pull ids from responses', () => {
  assert.strictEqual(getShellId('<x><w:Selector Name="ShellId">ABC-123</w:Selector></x>'), 'ABC-123');
  assert.strictEqual(getShellId('<rsp:ShellId>Z9</rsp:ShellId>'), 'Z9');
  assert.strictEqual(getCommandId('<rsp:CommandId>CMD-7</rsp:CommandId>'), 'CMD-7');
});
ok('parseReceiveResponse decodes streams, state and exit code', () => {
  const xml = '<rsp:ReceiveResponse>' +
    '<rsp:Stream Name="stdout" CommandId="c">aGVsbG8K</rsp:Stream>' +     // "hello\n"
    '<rsp:Stream Name="stderr" CommandId="c">b29wcw==</rsp:Stream>' +     // "oops"
    '<rsp:CommandState CommandId="c" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">' +
    '<rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>';
  const r = parseReceiveResponse(xml);
  assert.strictEqual(dec(r.stdout), 'hello\n');
  assert.strictEqual(dec(r.stderr), 'oops');
  assert.strictEqual(r.done, true);
  assert.strictEqual(r.exitCode, 1);
});
ok('getFault detects a WSMan fault + timeout code', () => {
  const xml = '<s:Fault><s:Reason><s:Text>boom</s:Text></s:Reason>' +
    '<f:WSManFault xmlns:f="x" Code="2150858793"/></s:Fault>';
  const f = getFault(xml);
  assert.strictEqual(f.code, 2150858793);
  assert.match(f.message, /boom/);
  assert.strictEqual(getFault('<ok/>'), null);
});

// ---- HTTP response parsing (canned bytes through the client) ----
await okAsync('HttpClient parses status, headers and a Content-Length body', async () => {
  const c = new HttpClient();
  c._writer = { write: async () => {} };
  c._reader = { read: async () => ({ done: true }) };
  c.host = 'h'; c.port = 5985;
  c._buf = enc('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhELLO');
  const r = await c.send('POST', '/wsman', {}, new Uint8Array(0));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.headers['content-type'], 'text/plain');
  assert.strictEqual(dec(r.body), 'hELLO');
});
await okAsync('HttpClient de-chunks a Transfer-Encoding: chunked body', async () => {
  const c = new HttpClient();
  c._writer = { write: async () => {} };
  c._reader = { read: async () => ({ done: true }) };
  c.host = 'h'; c.port = 5985;
  c._buf = enc('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n');
  const r = await c.send('POST', '/wsman', {}, new Uint8Array(0));
  assert.strictEqual(dec(r.body), 'Wikipedia');
});

// ---- PowerShell command wrapping + working-directory tracking ----
ok('wrapPowerShell runs the command via powershell -EncodedCommand with cd + marker', () => {
  const cmd = wrapPowerShell('ls', 'C:\\Users\\Administrator');
  const m = /-EncodedCommand (\S+)/.exec(cmd);
  assert.ok(cmd.startsWith('powershell -NoProfile -NonInteractive'));
  const script = new TextDecoder('utf-16le').decode(Uint8Array.from(Buffer.from(m[1], 'base64')));
  assert.ok(script.includes("Set-Location -LiteralPath 'C:\\Users\\Administrator'"));
  assert.ok(script.includes('try { ls }'));
  assert.ok(script.includes("@@CWD@@:' + (Get-Location).Path"));
});
ok('wrapPowerShell substitutes $null for an empty command (prompt priming)', () => {
  const script = new TextDecoder('utf-16le').decode(Uint8Array.from(Buffer.from(/-EncodedCommand (\S+)/.exec(wrapPowerShell('', null))[1], 'base64')));
  assert.ok(script.includes('try { $null }'));
  assert.ok(!script.includes('Set-Location')); // no pwd yet
});
ok('splitCwd extracts the trailing CWD marker and strips it from output', () => {
  const { text, cwd } = splitCwd('line1\r\nline2\r\n@@CWD@@:C:\\Users\\Administrator\\Desktop');
  assert.strictEqual(text, 'line1\r\nline2');
  assert.strictEqual(cwd, 'C:\\Users\\Administrator\\Desktop');
  assert.strictEqual(splitCwd('no marker here').cwd, null);
});

// ---- Pass-the-Hash: hash path == password path (MS-NLMP 4.2.4 vector) ----
ok('computeNtlmv2Response with an NT hash matches the password path', () => {
  const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
  const args = [fromHex('0123456789abcdef'), fromHex('aaaaaaaaaaaaaaaa'), fromHex('0000000000000000'),
    fromHex('02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000')];
  const ntHash = nthash('Password');
  const byHash = computeNtlmv2Response('User', 'Domain', ntHash, ...args);
  const byPass = computeNtlmv2Response('User', 'Domain', 'Password', ...args);
  assert.strictEqual(Buffer.from(byHash.ntProofStr).toString('hex'), '68cd0ab851e51c96aabc927bebef6a1c');
  assert.strictEqual(Buffer.from(byHash.ntProofStr).toString('hex'), Buffer.from(byPass.ntProofStr).toString('hex'));
  // sanity: ntowfv2 is the keyed step over the NT hash
  assert.strictEqual(Buffer.from(ntowfv2('User', 'Domain', 'Password')).toString('hex'), '0c868a403bfd7a93a3001ef22ef02e3f');
});

// ---- preamble + transfer ----
ok('wrapPowerShell injects the preamble before the command', () => {
  const enc16 = (cmd) => new TextDecoder('utf-16le').decode(Uint8Array.from(Buffer.from(/-EncodedCommand (\S+)/.exec(cmd)[1], 'base64')));
  const script = enc16(wrapPowerShell('Invoke-Foo', 'C:\\', 'function Invoke-Foo {1}'));
  assert.ok(script.includes('function Invoke-Foo {1}'));
  assert.ok(script.indexOf('function Invoke-Foo {1}') < script.indexOf('try { Invoke-Foo }'));
});

ok('base64 transfer helpers round-trip arbitrary bytes', () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => (i * 7) & 0xff);
  assert.strictEqual(Buffer.from(b64decode(b64encode(bytes))).toString('hex'), Buffer.from(bytes).toString('hex'));
});

await okAsync('download decodes base64 stdout; upload chunks (overwrite then append)', async () => {
  const payload = Uint8Array.from({ length: 4000 }, (_, i) => i & 0xff);
  // Fake shell: download returns the file as base64; upload records commands.
  const dlShell = { pwd: null, async run() { return { stdout: b64encode(payload), stderr: '', exitCode: 0 }; } };
  const got = await download(dlShell, 'C:\\x.bin');
  assert.strictEqual(Buffer.from(got).toString('hex'), Buffer.from(payload).toString('hex'));

  const cmds = [];
  const upShell = { pwd: null, async run(c) { cmds.push(c); return { stdout: '', stderr: '', exitCode: 0 }; } };
  await upload(upShell, 'C:\\out.bin', payload);
  assert.strictEqual(cmds.length, Math.ceil(4000 / 1500)); // 3 chunks
  assert.ok(cmds[0].includes('WriteAllBytes'));
  assert.ok(cmds[1].includes('FileMode]::Append'));
});

console.log(`\n${pass} tests passed.`);
