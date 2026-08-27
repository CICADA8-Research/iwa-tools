// Prints the Web Bundle ID / isolated-app:// origin derived from signing.key.
import { readFileSync } from 'node:fs';
import { parsePemKey, WebBundleId } from 'wbn-sign';

const key = parsePemKey(readFileSync(new URL('../signing.key', import.meta.url)));
const id = new WebBundleId(key);
console.log('Web Bundle ID :', id.serialize());
console.log('App origin    :', id.serializeWithIsolatedWebAppOrigin());
