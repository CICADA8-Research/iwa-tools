// TLS for the IWA: a rustls (TLS 1.2/1.3) engine compiled to wasm, plus the
// socket adapter and tls-server-end-point channel binding. The wasm is
// initialised synchronously from the base64-embedded bytes (no fetch), so this
// works the same whether bundled in the .swbn or loaded under Node.

import { initSync, TlsSession } from './tls_wasm.js';
import { wasmBytes } from './wasm-bytes.js';

let inited = false;

// Initialise the wasm module once and return the TlsSession class.
export function loadTls() {
  if (!inited) { initSync({ module: wasmBytes() }); inited = true; }
  return TlsSession;
}

export { TlsSocket } from './tls-socket.js';
export { tlsServerEndPoint } from './channel-binding.js';
