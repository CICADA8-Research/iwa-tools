import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import webbundle from 'rollup-plugin-webbundle';
import { parsePemKey, WebBundleId } from 'wbn-sign';

const __dirname = dirname(fileURLToPath(import.meta.url));

const KEY_PATH = new URL('./signing.key', import.meta.url);
if (!existsSync(KEY_PATH)) {
  throw new Error('signing.key not found — run `npm run keygen` first.');
}
const key = parsePemKey(readFileSync(KEY_PATH));
const baseURL = new WebBundleId(key).serializeWithIsolatedWebAppOrigin();

const certifyRoot = resolve(__dirname, '../iwa-tools/src/tools/certify');

function certifyAlias() {
  return {
    name: 'certify-alias',
    resolveId(source, importer) {
      if (!importer) return null;
      if (source.startsWith('./certify/') || source.startsWith('../certify/')) {
        const rel = source.replace(/^\.\.?\/certify\//, '');
        return resolve(certifyRoot, rel);
      }
      return null;
    },
  };
}

export default {
  input: 'src/main.js',
  output: { dir: 'dist', format: 'esm', entryFileNames: 'app.js' },
  plugins: [
    certifyAlias(),
    webbundle({
      baseURL,
      static: { dir: 'public', baseURL },
      output: 'certighost.swbn',
      integrityBlockSign: { key, isIwa: true },
    }),
  ],
};
