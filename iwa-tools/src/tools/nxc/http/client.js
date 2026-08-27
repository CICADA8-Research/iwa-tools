// Minimal HTTP/1.1 client over a Direct Sockets TCPSocket. WinRM speaks SOAP
// over HTTP on 5985; NTLM authentication is connection-oriented, so a single
// keep-alive TCP connection is reused for the whole session. Bodies are binary
// (multipart/encrypted), so the response body is returned as raw bytes.

import { TlsSocket } from '../tls/tls-socket.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0); o.set(b, a.length);
  return o;
}
function indexOfSeq(buf, seq, from = 0) {
  outer: for (let i = from; i <= buf.length - seq.length; i++) {
    for (let j = 0; j < seq.length; j++) if (buf[i + j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}
const CRLFCRLF = enc.encode('\r\n\r\n');

export class HttpClient {
  constructor(log = () => {}) {
    this._log = log;
    this._buf = new Uint8Array(0);
    this._reader = null; this._writer = null; this._socket = null;
    this.host = null; this.port = 5985;
  }

  // `opts.tls = { TlsSession, sni }` wraps the connection in TLS (WinRM HTTPS).
  async connect(host, port, opts = {}) {
    if (typeof TCPSocket === 'undefined') {
      throw new Error('TCPSocket is unavailable — open this app as an installed Isolated Web App.');
    }
    this.host = host; this.port = port;
    this._log(`Connecting to ${host}:${port} …`);
    this._socket = new TCPSocket(host, port);
    const info = await this._socket.opened;
    const rawReader = info.readable.getReader();
    const rawWriter = info.writable.getWriter();
    this._log(`TCP connected (${info.remoteAddress}:${info.remotePort}).`);

    if (opts.tls) {
      this._log('Starting TLS (HTTPS) …');
      this._tls = new TlsSocket(opts.tls.TlsSession, rawReader, rawWriter, opts.tls.sni || host);
      await this._tls.handshake();
      this._reader = this._tls._reader;
      this._writer = this._tls._writer;
      this._log('TLS established.');
    } else {
      this._reader = rawReader;
      this._writer = rawWriter;
    }
  }

  // tls-server-end-point channel binding for the HTTPS connection (or null).
  async channelBinding() { return this._tls ? this._tls.channelBinding() : null; }

  async _fill() {
    const { value, done } = await this._reader.read();
    if (done) throw new Error('connection closed by server');
    this._buf = concat(this._buf, value);
  }
  async _readUntil(seq) {
    for (;;) {
      const i = indexOfSeq(this._buf, seq);
      if (i >= 0) { const head = this._buf.subarray(0, i); this._buf = this._buf.subarray(i + seq.length); return head; }
      await this._fill();
    }
  }
  async _readExact(n) {
    while (this._buf.length < n) await this._fill();
    const out = this._buf.subarray(0, n); this._buf = this._buf.subarray(n); return out;
  }
  async _readLine() { return dec.decode(await this._readUntil(enc.encode('\r\n'))); }

  // Send one request and read the full response. headers is an object;
  // Content-Length is set automatically from body (Uint8Array, may be empty).
  async send(method, path, headers, body = new Uint8Array(0)) {
    const lines = [`${method} ${path} HTTP/1.1`];
    const h = { Host: `${this.host}:${this.port}`, Connection: 'Keep-Alive', 'Content-Length': String(body.length), ...headers };
    for (const [k, v] of Object.entries(h)) if (v != null) lines.push(`${k}: ${v}`);
    const head = enc.encode(lines.join('\r\n') + '\r\n\r\n');
    await this._writer.write(body.length ? concat(head, body) : head);

    // Status line + headers.
    const headBytes = await this._readUntil(CRLFCRLF);
    const headText = dec.decode(headBytes);
    const [statusLine, ...headerLines] = headText.split('\r\n');
    const m = /^HTTP\/1\.\d\s+(\d+)\s*(.*)$/.exec(statusLine);
    if (!m) throw new Error(`bad HTTP status line: ${statusLine}`);
    const status = Number(m[1]);
    const respHeaders = {};
    const rawHeaders = [];
    for (const line of headerLines) {
      const c = line.indexOf(':');
      if (c < 0) continue;
      const name = line.slice(0, c).trim();
      const value = line.slice(c + 1).trim();
      rawHeaders.push([name, value]);
      respHeaders[name.toLowerCase()] = value;
    }

    // Body: chunked or Content-Length.
    let respBody = new Uint8Array(0);
    if ((respHeaders['transfer-encoding'] || '').toLowerCase().includes('chunked')) {
      respBody = await this._readChunked();
    } else if (respHeaders['content-length'] !== undefined) {
      respBody = await this._readExact(Number(respHeaders['content-length']));
    }
    return { status, statusText: m[2], headers: respHeaders, rawHeaders, body: respBody };
  }

  async _readChunked() {
    let out = new Uint8Array(0);
    for (;;) {
      const sizeLine = await this._readLine();
      const size = parseInt(sizeLine.split(';')[0].trim(), 16);
      if (!size) { await this._readUntil(enc.encode('\r\n')); break; } // trailer
      out = concat(out, await this._readExact(size));
      await this._readExact(2); // CRLF after chunk
    }
    return out;
  }

  async close() {
    try { this._reader?.releaseLock(); } catch { /* ignore */ }
    try { this._writer?.releaseLock(); } catch { /* ignore */ }
    try { await this._socket?.close(); } catch { /* ignore */ }
  }
}

export { concat, indexOfSeq };
