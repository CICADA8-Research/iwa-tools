import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, existsSync } from 'node:fs';
import { WebBundleId } from 'wbn-sign';

const OUT = new URL('../signing.key', import.meta.url);

if (existsSync(OUT) && !process.argv.includes('--force')) {
  console.error('signing.key already exists. Re-run with --force to overwrite (this CHANGES the app origin).');
  process.exit(1);
}

const { privateKey } = generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
writeFileSync(OUT, pem);

const id = new WebBundleId(privateKey);
console.log('Wrote signing.key');
console.log('Web Bundle ID :', id.serialize());
console.log('App origin    :', id.serializeWithIsolatedWebAppOrigin());
