// Live Kerberos WinRM check from the command line: acquires an HTTP/<host>
// service ticket, then drives the real WinRMClient (Negotiate Kerberos auth +
// GSS-sealed multipart/encrypted SOAP) over a Node net socket injected in place
// of the Direct Sockets TCPSocket.
//
//   node scripts/krb-winrm-live.js --kdc 100.100.10.100 --realm pk.lab \
//       --user administrator --pass 'P@ssw0rd' --host lab01-dc01.pk.lab [--cmd whoami]

import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { KerberosClient } from '../src/kerberos/client.js';
import { ETYPE } from '../src/kerberos/constants.js';
import { HttpClient } from '../src/http/client.js';
import { WinRMClient } from '../src/winrm/client.js';
import { Shell } from '../src/winrm/shell.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2); const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) a[k] = true; else { a[k] = next; i++; }
  }
  return a;
}

function netStreams(sock) {
  const chunks = []; let waiting = null, ended = false, error = null;
  sock.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
  sock.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
  sock.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
  return {
    _reader: { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); }, releaseLock() {} },
    _writer: { write: (b) => new Promise((res, rej) => sock.write(Buffer.from(b), (e) => (e ? rej(e) : res()))), releaseLock() {} },
  };
}

class NetKdcTransport {
  constructor(host, port = 88) { this._host = host; this._port = port; }
  connect() { return new Promise((res, rej) => { this._buf = Buffer.alloc(0); this._sock = net.connect(this._port, this._host, res); this._sock.on('data', (c) => { this._buf = Buffer.concat([this._buf, c]); this._try(); }); this._sock.on('error', rej); }); }
  _try() { if (!this._pending || this._buf.length < 4) return; const len = this._buf.readUInt32BE(0); if (this._buf.length < 4 + len) return; const msg = Uint8Array.from(this._buf.subarray(4, 4 + len)); this._buf = this._buf.subarray(4 + len); const p = this._pending; this._pending = null; p.resolve(msg); }
  request(req) { return new Promise((resolve, reject) => { this._pending = { resolve, reject }; const f = Buffer.alloc(4 + req.length); f.writeUInt32BE(req.length, 0); f.set(req, 4); this._sock.write(f); this._try(); }); }
  close() { try { this._sock.destroy(); } catch { /* ignore */ } }
}

async function main() {
  const a = parseArgs(process.argv);
  if (!a.kdc || !a.realm || !a.user || (!a.pass && !a.rc4) || !a.host) {
    console.error('usage: node scripts/krb-winrm-live.js --kdc <ip> --realm <realm> --user <name> (--pass <pw> | --rc4 <nthash>) --host <fqdn> [--port 5985] [--cmd whoami]');
    process.exit(2);
  }
  const log = (m) => console.log('  ·', m);
  const port = Number(a.port) || 5985;

  // 1. HTTP/<host> service ticket via a Node KDC socket.
  const kt = new NetKdcTransport(a.kdc, 88);
  await kt.connect();
  console.log(`[*] Kerberos: TGT for ${a.user}@${a.realm}, then HTTP/${a.host}`);
  const krb = new KerberosClient(kt, log);
  const id = { username: a.user, realm: a.realm };
  if (a.rc4) { id.key = Uint8Array.from(Buffer.from(a.rc4, 'hex')); id.etype = ETYPE.RC4_HMAC; } else id.password = a.pass;
  const tgt = await krb.getTGT(id);
  const st = await krb.getTGS(tgt, { spn: a.spn || `HTTP/${a.host}` });
  kt.close();
  console.log(`[+] Service ticket: etype ${st.sessionKey.etype}, ${st.ticket.length} bytes`);

  // 2. WinRM over a Node net socket, injecting the ticket + http transport.
  const sock = net.connect(port, a.kdc);
  await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
  const http = new HttpClient(log);
  Object.assign(http, netStreams(sock));
  http.host = a.host; http.port = port;

  const client = new WinRMClient(log);
  console.log('[*] WinRM Kerberos Negotiate auth + sealed channel …');
  await client.connect(a.host, port, { authMethod: 'kerberos', user: a.user, domain: a.realm, serviceTicket: st }, { http });

  // 3. Open a shell and run a command — proves the sealed SOAP round-trips.
  const shell = new Shell(client, log);
  await shell.open();
  const cmd = a.cmd || 'whoami';
  console.log(`[*] Running: ${cmd}`);
  let out = '';
  const r = await shell.run(cmd, { onStdout: (t) => { out += t; }, onStderr: (t) => { out += t; } });
  console.log('[+] Output:', out.trim());
  await shell.close();
  await client.close();
  sock.destroy();
  console.log(`\n[+] OK — sealed WinRM channel works (exit ${r.exitCode}).`);
}

main().catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
