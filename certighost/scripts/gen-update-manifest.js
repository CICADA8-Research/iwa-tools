import { readFileSync, writeFileSync } from 'node:fs';
import { parsePemKey, WebBundleId } from 'wbn-sign';

const here = (p) => new URL(p, import.meta.url);
const pkg = JSON.parse(readFileSync(here('../package.json'), 'utf8'));
const version = pkg.version;
const src = process.argv[2] || 'certighost.swbn';

const id = new WebBundleId(parsePemKey(readFileSync(here('../signing.key')))).serialize();

const manifest = { versions: [{ version, src }] };
const outPath = here('../dist/update.json');
writeFileSync(outPath, JSON.stringify(manifest, null, 2) + '\n');

console.log('Wrote dist/update.json:\n');
console.log(JSON.stringify(manifest, null, 2));
console.log('\nWeb Bundle ID :', id);
console.log('\nHost dist/update.json and dist/certighost.swbn on an HTTPS server, then:');
console.log('  chrome://web-app-internals -> "Install IWA via Update Manifest"');
console.log('  -> paste  https://YOUR_HOST/update.json');
