// UI controller for the port scanner: reads the form, runs the connect scan,
// and streams open ip:port results into a live list.
import { scan } from './scanner.js';
import { countHosts, expandPorts } from './targets.js';

const $ = (id) => document.getElementById(id);
const els = {
  targets: $('targets'), ports: $('ports'), timeout: $('timeout'), concurrency: $('concurrency'),
  btnScan: $('btn-scan'), btnStop: $('btn-stop'), btnClear: $('btn-clear'), btnCsv: $('btn-csv'),
  status: $('status'), progress: $('progress'), count: $('count'), results: $('results'), log: $('log'),
};

let abort = null;
const open = [];

function log(msg, cls = '') {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = msg;
  els.log.appendChild(line);
  els.log.scrollTop = els.log.scrollHeight;
}

function addOpen(hostport) {
  open.push(hostport);
  const li = document.createElement('div');
  li.className = 'hit';
  li.textContent = hostport;
  els.results.appendChild(li);
  els.count.textContent = `${open.length} open`;
  els.btnCsv.disabled = open.length === 0;
}

function clearResults() {
  open.length = 0;
  els.results.replaceChildren();
  els.log.replaceChildren();
  els.count.textContent = '';
  els.progress.textContent = '';
  els.btnCsv.disabled = true;
}

function setRunning(on) {
  els.btnScan.disabled = on;
  els.btnStop.disabled = !on;
  for (const f of ['targets', 'ports', 'timeout', 'concurrency']) els[f].disabled = on;
}

async function start() {
  clearResults();
  const targets = els.targets.value.trim();
  if (!targets) { els.status.textContent = 'Enter at least one target.'; return; }

  let total;
  try {
    const hosts = countHosts(targets);
    const portsN = expandPorts(els.ports.value).length;
    total = hosts * portsN;
    log(`Targets: ${hosts} host(s) × ${portsN} port(s) = ${total} probes.`);
    if (total > 500000) { log('That is a very large scan; consider narrowing it.', 'warn'); }
  } catch (e) {
    els.status.textContent = e.message; log(`ERROR: ${e.message}`, 'err'); return;
  }

  abort = new AbortController();
  setRunning(true);
  els.status.textContent = 'Scanning…';
  const t0 = Date.now();
  try {
    const { scanned } = await scan({
      targets,
      ports: els.ports.value,
      timeout: parseInt(els.timeout.value, 10) || 1500,
      concurrency: parseInt(els.concurrency.value, 10) || 100,
      onOpen: (hp) => addOpen(hp),
      onProgress: (done) => { if (done % 25 === 0 || done === total) els.progress.textContent = `${done}/${total}`; },
      signal: abort.signal,
    });
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    const stopped = abort.signal.aborted;
    els.progress.textContent = `${scanned}/${total}`;
    log(`${stopped ? 'Stopped' : 'Done'}: ${scanned} probed, ${open.length} open, ${secs}s.`, stopped ? 'warn' : 'ok');
    els.status.textContent = stopped ? 'Stopped.' : `Done — ${open.length} open port(s).`;
  } catch (e) {
    log(`ERROR: ${e.message}`, 'err');
    els.status.textContent = `Error: ${e.message}`;
  } finally {
    setRunning(false);
    abort = null;
  }
}

els.btnScan.onclick = start;
els.btnStop.onclick = () => { abort?.abort(); els.status.textContent = 'Stopping…'; };
els.btnClear.onclick = clearResults;
els.btnCsv.onclick = () => {
  const csv = ['ip,port', ...open.map((hp) => hp.replace(':', ','))].join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'portscan.csv';
  a.click();
  URL.revokeObjectURL(a.href);
};

if (typeof TCPSocket === 'undefined') {
  els.status.textContent = 'Direct Sockets unavailable.';
  log('TCPSocket API not available. Install and launch as an Isolated Web App with the direct-sockets permission.', 'err');
} else {
  els.status.textContent = 'Ready.';
  log('Direct Sockets available. Enter targets and scan.', 'ok');
}
