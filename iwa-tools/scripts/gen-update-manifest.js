// Generates the IWA Update Manifest (dist/update.json) that lets Chrome install
// the app over the network from a URL instead of a local .swbn file. Reads the
// version from package.json and derives the Web Bundle ID from signing.key.
//
//   node scripts/gen-update-manifest.js [bundleSrc]
//
// bundleSrc is what goes in the manifest's "src" — a path relative to the manifest
// URL (default "iwa-tools.swbn") or an absolute https:// URL to the bundle.

import { readFileSync, writeFileSync } from 'node:fs';
import { parsePemKey, WebBundleId } from 'wbn-sign';

const here = (p) => new URL(p, import.meta.url);
const pkg = JSON.parse(readFileSync(here('../package.json'), 'utf8'));
const version = pkg.version;
const src = process.argv[2] || 'iwa-tools.swbn';

const id = new WebBundleId(parsePemKey(readFileSync(here('../signing.key')))).serialize();

const manifest = { versions: [{ version, src }] };
const outPath = here('../dist/update.json');
writeFileSync(outPath, JSON.stringify(manifest, null, 2) + '\n');

console.log('Wrote dist/update.json:\n');
console.log(JSON.stringify(manifest, null, 2));
console.log('\nWeb Bundle ID :', id);
console.log('\nHost dist/update.json and dist/iwa-tools.swbn on an HTTPS server, then:');
console.log('  • Dev:  chrome://web-app-internals → "Install IWA via Update Manifest"');
console.log('          → paste  https://YOUR_HOST/update.json');
console.log('  • Prod: set the IsolatedWebAppInstallForceList enterprise policy:');
console.log(JSON.stringify([{ update_manifest_url: 'https://YOUR_HOST/update.json', web_bundle_id: id }], null, 2));
