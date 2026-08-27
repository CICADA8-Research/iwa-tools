// Validate the TlsSocket adapter + channel binding end to end over a real TLS
// server: handshake, compute tls-server-end-point, cross-check the hash against
// Node's crypto, and round-trip an HTTP request over the WASM-TLS app-data path.
import net from 'node:net';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { TlsSocket } from './tls-socket.js';
const { TlsSession } = createRequire(import.meta.url)('./pkg/tls_wasm.js');

const host = process.argv[2] || 'cloudflare.com';
const port = Number(process.argv[3]) || 443;

function netStreams(sock) {
  const chunks = []; let waiting = null, ended = false, error = null;
  sock.on('data', (d) => { const u = Uint8Array.from(d); if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); } else chunks.push(u); });
  sock.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
  sock.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
  return {
    reader: { read() { if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false }); if (error) return Promise.reject(error); if (ended) return Promise.resolve({ done: true }); return new Promise((res, rej) => { waiting = { resolve: res, reject: rej }; }); } },
    writer: { write: (b) => new Promise((res, rej) => sock.write(Buffer.from(b), (e) => (e ? rej(e) : res()))) },
  };
}

const hex = (u) => Buffer.from(u).toString('hex');

async function main() {
  const sock = net.connect(port, host);
  await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
  const { reader, writer } = netStreams(sock);
  const tls = new TlsSocket(TlsSession, reader, writer, host);

  console.log(`[*] TLS handshake to ${host}:${port} via WASM engine + TlsSocket adapter`);
  await tls.handshake();
  console.log('[+] handshake complete');

  const cb = await tls.channelBinding();
  console.log(`[+] channel binding: ${cb.hashName}, certHash ${cb.certHash.length}B = ${hex(cb.certHash).slice(0, 24)}…`);
  // Cross-check the cert hash against Node's own crypto over the same DER.
  const ref = new Uint8Array(crypto.createHash(cb.hashName.replace('-', '').toLowerCase()).update(tls._peerCert).digest());
  console.log(`[${hex(ref) === hex(cb.certHash) ? '+' : '!'}] cert hash matches Node crypto: ${hex(ref) === hex(cb.certHash)}`);
  console.log(`[+] GSS application_data = "${Buffer.from(cb.applicationData.slice(0, 21))}" + hash`);

  // Round-trip an HTTP request over the encrypted app-data channel.
  await tls._writer.write(new TextEncoder().encode(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
  const { value } = await tls._reader.read();
  const head = new TextDecoder().decode(value).split('\r\n')[0];
  console.log(`[+] app-data over TLS works — server replied: ${head}`);
  sock.destroy();
}

main().then(() => process.exit(0)).catch((e) => { console.error('[!]', e.stack || e.message); process.exit(1); });
