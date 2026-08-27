# tls-wasm

[rustls](https://github.com/rustls/rustls) (TLS 1.2/1.3) compiled to `wasm32`,
so the IWA tools can speak **LDAPS/636** and **WinRM-HTTPS/5986** over the
plaintext-only Direct Sockets `TCPSocket`, and derive **tls-server-end-point**
channel bindings for hardened (channel-binding-enforcing) DCs.

## Why wasm

The Direct Sockets API gives raw TCP but no TLS, and there is no browser API to
run TLS over an arbitrary socket. Pure-JS TLS (e.g. node-forge) is limited to TLS
1.2 + RSA/CBC and fails modern/hardened servers. rustls gives TLS 1.3 + modern
ciphers; compiling it to wasm is the way to run it in the IWA.

## How it builds for `wasm32-unknown-unknown`

The browser wasm sandbox has no OS RNG and no system clock, and rustls's default
providers (`aws-lc-rs`/`ring`) need C/asm. So:

* **Crypto provider:** [`rustls-rustcrypto`](https://crates.io/crates/rustls-rustcrypto)
  — pure-Rust (RustCrypto), compiles to wasm.
* **Randomness:** `getrandom` `js` feature → Web Crypto `getRandomValues`.
* **Clock:** `rustls-pki-types` `web` feature → the JS clock (`web-time`).
* **Bindings:** `wasm-bindgen`; built with `wasm-pack`.
* **Cert verification:** disabled (a `ServerCertVerifier` that accepts all) —
  this is pentest tooling; the peer cert is still captured for channel binding.

[`src/lib.rs`](./src/lib.rs) exposes a small feed/drain API (`TlsSession`):
`recv(ciphertext)`, `take_outgoing()`, `send(plaintext)`, `read()`,
`is_handshaking()`, `peer_cert()` — the explicit model that fits a non-blocking
socket pump.

## JS side (copied into each tool's `src/tls/`)

| File | Role |
|------|------|
| `tls_wasm.js` + `tls_wasm_bg.wasm` | wasm-bindgen glue + the engine (from `pkg-web/`) |
| `wasm-bytes.js` | the wasm **base64-embedded** (so rollup bundles it; `initSync`) |
| `tls-socket.js` | `TlsSocket` — wraps a `TCPSocket`, exposes `{ _reader, _writer }` carrying plaintext; `channelBinding()` |
| `channel-binding.js` | `tls-server-end-point` (RFC 5929): hash the server cert DER, build the GSS application data |
| `index.js` | `loadTls()` (init once → `TlsSession`), re-exports `TlsSocket` |

## Build / regenerate

```bash
wasm-pack build --target web  --out-dir pkg-web --release   # for the IWA bundle
wasm-pack build --target nodejs                  --release  # for the Node tests below
node gen-embed.js                                           # -> ../adidns/src/tls/wasm-bytes.js
```

## Tests (Node, against a live server)

```bash
node test-handshake.js cloudflare.com 443           # engine: TLS 1.3 handshake + peer cert
node test-cbt.js       cloudflare.com 443           # adapter + channel-binding hash (cross-checked vs node crypto)
node test-ldaps.js --kdc <ip> --realm <r> --user <u> --pass <p> --host <dc-fqdn>   # full Kerberos-over-LDAPS + CBT
```

Note: `wasm32-unknown-unknown` is a browser target. The Node tests run the same
`.wasm` and JS (WebAssembly + `initSync` are identical), validating the engine,
adapter and channel binding; the final in-browser run uses the same artifacts via
Direct Sockets.
