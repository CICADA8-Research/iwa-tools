// Builds the app into a signed Web Bundle (.swbn) installable as an Isolated
// Web App. `src/main.js` is bundled to /app.js; everything under public/ (the
// HTML shell, manifest and icons) is added verbatim. The webbundle plugin adds
// the mandatory IWA security headers (CSP, COOP/COEP/CORP) and signs the
// integrity block with the Ed25519 key in signing.key.
import { readFileSync, existsSync } from 'node:fs';
import webbundle from 'rollup-plugin-webbundle';
import { parsePemKey, WebBundleId } from 'wbn-sign';

const KEY_PATH = new URL('./signing.key', import.meta.url);
if (!existsSync(KEY_PATH)) {
  throw new Error('signing.key not found — run `npm run keygen` first.');
}
const key = parsePemKey(readFileSync(KEY_PATH));
const baseURL = new WebBundleId(key).serializeWithIsolatedWebAppOrigin();

export default {
  input: 'src/main.js',
  output: { dir: 'dist', format: 'esm', entryFileNames: 'app.js' },
  plugins: [
    webbundle({
      baseURL,
      static: { dir: 'public', baseURL },
      output: 'soaphound-iwa.swbn',
      integrityBlockSign: { key, isIwa: true },
    }),
  ],
};
