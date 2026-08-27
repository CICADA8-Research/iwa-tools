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
      output: 'netexec-iwa.swbn',
      integrityBlockSign: { key, isIwa: true },
    }),
  ],
};
