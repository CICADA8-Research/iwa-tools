// Buffered byte-stream over a Direct Sockets TCPSocket. ADWS framing (MC-NMF /
// MS-NNS) is length-prefixed binary, so unlike the LDAP client we read exact
// byte counts rather than self-delimiting TLVs. readExact() accumulates chunks
// until it can satisfy the request.

export class Connection {
  constructor(log = () => {}) {
    this._log = log;
    this._buf = new Uint8Array(0);
    this._reader = null;
    this._writer = null;
    this._socket = null;
  }

  async connect(host, port) {
    if (typeof TCPSocket === 'undefined') {
      throw new Error('TCPSocket is unavailable — open this app as an installed Isolated Web App.');
    }
    this._log(`Connecting to ${host}:${port} …`);
    this._socket = new TCPSocket(host, port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
    this._log(`TCP connected (${info.remoteAddress}:${info.remotePort}).`);
  }

  async write(bytes) {
    await this._writer.write(bytes);
  }

  // Read exactly n bytes (or throw if the connection closes first).
  async readExact(n) {
    while (this._buf.length < n) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('connection closed by server');
      this._buf = concat(this._buf, value);
    }
    const out = this._buf.subarray(0, n);
    this._buf = this._buf.subarray(n);
    return out;
  }

  async close() {
    try { this._reader?.releaseLock(); } catch { /* ignore */ }
    try { this._writer?.releaseLock(); } catch { /* ignore */ }
    try { await this._socket?.close(); } catch { /* ignore */ }
  }
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
