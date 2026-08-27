// Generate adidns/src/tls/wasm-bytes.js — the TLS engine wasm, base64-embedded
// so rollup bundles it into the .swbn (no separate asset to fetch in the IWA).
const fs = require('fs');
const wasm = fs.readFileSync('pkg-web/tls_wasm_bg.wasm');
const b64 = wasm.toString('base64');
const out = [
  '// AUTO-GENERATED from tls-wasm/pkg-web/tls_wasm_bg.wasm. Do not edit by hand.',
  '// The rustls TLS engine (wasm32), base64-embedded so rollup bundles it into',
  '// the .swbn — no separate asset to fetch at runtime.',
  `export const WASM_B64 = ${JSON.stringify(b64)};`,
  '',
  'export function wasmBytes() {',
  '  const bin = typeof atob === "function" ? atob(WASM_B64) : Buffer.from(WASM_B64, "base64").toString("binary");',
  '  const out = new Uint8Array(bin.length);',
  '  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);',
  '  return out;',
  '}',
  '',
].join('\n');
fs.writeFileSync('../adidns/src/tls/wasm-bytes.js', out);
console.log(`wrote adidns/src/tls/wasm-bytes.js (${wasm.length} B wasm -> ${b64.length} B base64)`);
