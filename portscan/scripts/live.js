// Live check of the scan engine in Node: a TCPSocket polyfill over `net` lets
// the production scanner run unchanged.
//   node scripts/live.js <targets> <ports>
import net from 'node:net';

globalThis.TCPSocket = class {
  constructor(host, port) {
    const s = net.connect(port, host);
    this._s = s;
    s.on('error', () => {}); // prevent unhandled 'error'
    this.opened = new Promise((res, rej) => {
      s.once('connect', () => res({ remoteAddress: s.remoteAddress, remotePort: s.remotePort, readable: {}, writable: {} }));
      s.once('error', rej);
    });
  }
  async close() { try { this._s.destroy(); } catch { /* ignore */ } }
};

const { scan } = await import('../src/scanner.js');

const targets = process.argv[2] || '100.100.10.100';
const ports = process.argv[3] || '22,23,88,135,389,445,636,3389,5985,8080,9389';

console.log(`[*] scanning ${targets} ports ${ports}`);
const t0 = Date.now();
const { open, scanned } = await scan({
  targets, ports, timeout: 1200, concurrency: 64,
  onOpen: (hp) => console.log(`    OPEN  ${hp}`),
});
console.log(`[+] ${open} open / ${scanned} probed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
process.exit(0);
