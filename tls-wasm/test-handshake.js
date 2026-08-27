// Validate the WASM-TLS engine against a live server: drive the rustls-in-wasm
// session over a Node net socket and complete a TLS handshake, then report the
// negotiated peer certificate (used for channel binding).
//   node test-handshake.js <host> <port> [sni]
const net = require('net');
const { TlsSession } = require('./pkg/tls_wasm.js');

const host = process.argv[2] || '100.100.10.100';
const port = Number(process.argv[3]) || 636;
const sni = process.argv[4] || 'lab01-dc01.pk.lab';

const sock = net.connect(port, host);
const tls = new TlsSession(sni);
const flush = () => { let o; while ((o = tls.take_outgoing())) sock.write(Buffer.from(o)); };

sock.on('connect', () => { console.log(`[*] TCP ${host}:${port} connected; starting TLS (SNI ${sni})`); flush(); });
sock.on('data', (d) => {
  try { tls.recv(Uint8Array.from(d)); } catch (e) { console.error('[!] TLS error:', e.message); process.exit(1); }
  flush();
  if (!tls.is_handshaking()) {
    const cert = tls.peer_cert();
    console.log('[+] TLS handshake complete.');
    console.log(`[+] peer certificate: ${cert ? cert.length : 0} bytes (DER)`);
    process.exit(0);
  }
});
sock.on('error', (e) => { console.error('[!] socket:', e.message); process.exit(1); });
sock.on('close', () => { if (tls.is_handshaking()) { console.error('[!] closed mid-handshake'); process.exit(1); } });
setTimeout(() => { console.error('[!] timeout; still handshaking =', tls.is_handshaking()); process.exit(1); }, 12000);
