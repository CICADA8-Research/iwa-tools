// Deduplicated: the embedded TLS wasm lives once in the adidns tool copy; this
// re-exports it so the combined bundle carries the ~883 KB base64 only once.
export { WASM_B64, wasmBytes } from '../../adidns/tls/wasm-bytes.js';
