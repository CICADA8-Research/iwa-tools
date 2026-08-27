// A TCP connect scanner over the Direct Sockets API. For each ip:port it opens
// a TCPSocket and races the connection against a timeout:
//   opened resolves  -> OPEN
//   opened rejects    -> closed/refused  (skipped)
//   timeout wins      -> filtered/no-route (skipped)
// A fixed-size worker pool bounds the number of in-flight sockets; an
// AbortSignal stops the scan promptly.

import { ipsFromSpec, expandPorts } from './targets.js';

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function probe(ip, port, timeout) {
  let sock;
  try {
    sock = new TCPSocket(ip, port);
    const verdict = await Promise.race([
      sock.opened.then(() => 'open', () => 'closed'),
      delay(timeout).then(() => 'timeout'),
    ]);
    return verdict === 'open';
  } catch {
    return false; // constructor / immediate failure
  } finally {
    try { await sock?.close(); } catch { /* ignore */ }
  }
}

// Drives the scan. Calls onOpen(`ip:port`, ip, port) for each open port and
// onProgress(done, total) as work completes. Returns { open, scanned }.
export async function scan({
  targets, ports, timeout = 1500, concurrency = 100,
  onOpen = () => {}, onProgress = () => {}, signal,
} = {}) {
  if (typeof TCPSocket === 'undefined') {
    throw new Error('TCPSocket is unavailable — open this app as an installed Isolated Web App.');
  }
  const portList = expandPorts(ports);

  // Lazy task stream so a /16 × many ports never builds a giant array.
  function* tasks() {
    for (const ip of ipsFromSpec(targets)) {
      for (const p of portList) yield [ip, p];
    }
  }
  const it = tasks();

  let scanned = 0, open = 0;
  async function worker() {
    for (;;) {
      if (signal && signal.aborted) return;
      const next = it.next();
      if (next.done) return;
      const [ip, port] = next.value;
      if (await probe(ip, port, timeout)) { open++; onOpen(`${ip}:${port}`, ip, port); }
      scanned++;
      onProgress(scanned);
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, worker));
  return { open, scanned };
}
