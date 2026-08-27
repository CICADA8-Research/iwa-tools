// TLS transport adapter: bridges a raw byte stream (a Direct Sockets TCPSocket
// in the IWA, or a Node net socket in tests) to the rustls-in-wasm engine, and
// exposes the same { _reader, _writer } shape the LDAP/HTTP/NNS clients already
// use — except the bytes flowing through are now TLS-protected. Drop a TlsSocket
// in where a plaintext socket went to get LDAPS / WinRM-HTTPS.
//
// `TlsSession` is the wasm-bindgen class from the tls_wasm pkg, passed in so this
// file is independent of how the wasm module is loaded (node vs web target).

import { tlsServerEndPoint } from './channel-binding.js';

export class TlsSocket {
  // rawReader/rawWriter speak ciphertext: rawReader.read() -> {value,done};
  // rawWriter.write(bytes) -> Promise. `sni` is the server name for the SNI/cert.
  constructor(TlsSession, rawReader, rawWriter, sni) {
    this._tls = new TlsSession(sni);
    this._raw = rawReader;
    this._rawW = rawWriter;
    this._plain = new Uint8Array(0); // decrypted, not yet consumed
    this._peerCert = null;
  }

  async _flushOutgoing() {
    let out;
    while ((out = this._tls.take_outgoing())) await this._rawW.write(out);
  }

  // Run the TLS handshake to completion.
  async handshake() {
    await this._flushOutgoing(); // ClientHello
    while (this._tls.is_handshaking()) {
      const { value, done } = await this._raw.read();
      if (done) throw new Error('connection closed during TLS handshake');
      this._tls.recv(value);
      await this._flushOutgoing();
      this._drainPlain();
    }
    this._peerCert = this._tls.peer_cert() || null;
  }

  _drainPlain() {
    let p;
    while ((p = this._tls.read())) this._plain = concat(this._plain, p);
  }

  // The tls-server-end-point channel binding (RFC 5929) for this connection:
  // { certHash, applicationData } — applicationData goes into the GSS bindings.
  async channelBinding() {
    if (!this._peerCert) throw new Error('no peer certificate (handshake not complete)');
    return tlsServerEndPoint(this._peerCert);
  }

  // ---- the {_reader,_writer} interface the clients consume (plaintext) ------
  get _reader() {
    return {
      read: async () => {
        if (this._plain.length) { const v = this._plain; this._plain = new Uint8Array(0); return { value: v, done: false }; }
        for (;;) {
          const { value, done } = await this._raw.read();
          if (done) return { done: true };
          // Feed ciphertext in small chunks, draining decrypted plaintext between
          // each, so the engine's bounded receive buffer never overflows on a
          // large response (e.g. a full LDAP page of thousands of objects).
          for (let off = 0; off < value.length; off += 8192) {
            this._tls.recv(value.subarray(off, off + 8192));
            await this._flushOutgoing(); // e.g. TLS 1.3 post-handshake / key update
            this._drainPlain();
          }
          if (this._plain.length) { const v = this._plain; this._plain = new Uint8Array(0); return { value: v, done: false }; }
        }
      },
      releaseLock() {},
    };
  }

  get _writer() {
    return {
      write: async (bytes) => { this._tls.send(bytes); await this._flushOutgoing(); },
      releaseLock() {},
    };
  }
}

function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0); o.set(b, a.length);
  return o;
}
