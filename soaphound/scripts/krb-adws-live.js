// Live Kerberos ADWS check from the command line: acquires a service ticket,
// then drives the real AdwsClient (NMF preamble + NNS Kerberos handshake +
// GSS-sealed WS-Enumeration) over Node net sockets injected in place of the
// Direct Sockets TCPSocket the IWA uses.
//
//   node scripts/krb-adws-live.js --kdc 100.100.10.100 --realm pk.lab \
//       --user user01 --pass 'P@ssw0rd' --fqdn lab01-dc01.pk.lab [--spn HOST/lab01-dc01.pk.lab]

import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { KerberosClient } from '../src/kerberos/client.js';
import { ETYPE } from '../src/kerberos/constants.js';
import { Connection } from '../src/net/socket.js';
import { AdwsClient, domainToBaseDN } from '../src/adws/client.js';

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

// Node net socket -> the {_reader,_writer} shape both transports use.
function netStreams(sock) {
  const chunks = []; let waiting = null, ended = false, error = null;
  sock.on('data', (d) => {
    const u = Uint8Array.from(d);
    if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u);
  });
  sock.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
  sock.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
  return {
    _reader: {
      read() {
        if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false });
        if (error) return Promise.reject(error);
        if (ended) return Promise.resolve({ done: true });
        return new Promise((resolve, reject) => { waiting = { resolve, reject }; });
      },
      releaseLock() {},
    },
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
  if (!a.kdc || !a.realm || !a.user || (!a.pass && !a.rc4)) {
    console.error('usage: node scripts/krb-adws-live.js --kdc <ip> --realm <realm> --user <name> (--pass <pw> | --rc4 <nthash>) --fqdn <dc-fqdn> [--spn HOST/<fqdn>] [--port 9389]');
    process.exit(2);
  }
  const fqdn = a.fqdn || a.kdc;
  const spn = a.spn || `HOST/${fqdn}`;
  const log = (m) => console.log('  ·', m);

  // 1. Service ticket for the ADWS host SPN.
  const kt = new NetKdcTransport(a.kdc, 88);
  await kt.connect();
  console.log(`[*] Kerberos: TGT for ${a.user}@${a.realm}, then ${spn}`);
  const krb = new KerberosClient(kt, log);
  const id = { username: a.user, realm: a.realm };
  if (a.rc4) { id.key = Uint8Array.from(Buffer.from(a.rc4, 'hex')); id.etype = ETYPE.RC4_HMAC; } else id.password = a.pass;
  const tgt = await krb.getTGT(id);
  const st = await krb.getTGS(tgt, { spn });
  kt.close();
  console.log(`[+] Service ticket: etype ${st.sessionKey.etype}, ${st.ticket.length} bytes`);

  // 2. ADWS over a Node net socket, injecting the ticket + connection.
  const sock = net.connect(Number(a.port) || 9389, a.kdc);
  await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
  const conn = new Connection(log);
  Object.assign(conn, netStreams(sock));

  const client = new AdwsClient(log);
  console.log(`[*] ADWS NMF/NNS Kerberos handshake + sealed channel …`);
  await client.connect(a.kdc, Number(a.port) || 9389,
    { authMethod: 'kerberos', user: a.user, domain: a.realm, serviceTicket: st },
    { fqdn, connection: conn });

  // 3. Prove the sealed channel: a tiny base query for the domain object.
  const baseDN = domainToBaseDN(a.realm);
  console.log(`[*] Sealed WS-Enumeration query on ${baseDN} …`);
  let n = 0;
  for await (const o of client.query({ baseDN, filter: '(objectClass=domain)', attributes: ['distinguishedName', 'objectSid'] })) {
    n++;
    console.log(`[+] ${o.className}  ${o.dn}`);
    if (n >= 1) break;
  }
  await client.close();
  sock.destroy();
  console.log(`\n[+] OK — sealed ADWS channel works (${n} object).`);
}

main().catch((e) => { console.error('\n[!]', e.stack || e.message); process.exit(1); });
