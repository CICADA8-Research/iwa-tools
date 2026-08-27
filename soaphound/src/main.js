// UI controller: reads the form, runs the chosen ADWS collection mode, streams
// a live log, renders tabular results (query/dnsdump) or a summary + downloads
// (buildcache/bhdump/certdump).
import { run } from './soaphound.js';
import { makeZip } from './zip.js';

const $ = (id) => document.getElementById(id);
const els = {
  host: $('host'), port: $('port'), fqdn: $('fqdn'),
  user: $('user'), domain: $('domain'), password: $('password'),
  mode: $('mode'), basedn: $('basedn'), queryOpts: $('query-opts'),
  filter: $('filter'), attributes: $('attributes'),
  btnRun: $('btn-run'), btnClear: $('btn-clear'),
  status: $('status'), summary: $('summary'), downloads: $('downloads'),
  count: $('count'), thead: $('thead'), rows: $('rows'), log: $('log'),
};

let busy = false;
let rowCount = 0;

function syncModeUI() {
  els.queryOpts.classList.toggle('hide', els.mode.value !== 'query');
}
els.mode.addEventListener('change', syncModeUI);
syncModeUI();

function log(msg, cls = '') {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = msg;
  els.log.appendChild(line);
  els.log.scrollTop = els.log.scrollHeight;
}

function setBusy(state, label) {
  busy = state;
  els.btnRun.disabled = state;
  if (label) els.status.textContent = label;
}

function clearResults() {
  rowCount = 0;
  els.summary.replaceChildren();
  els.downloads.replaceChildren();
  els.count.textContent = '';
  els.thead.replaceChildren();
  els.rows.replaceChildren();
  els.log.replaceChildren();
}

function setTableHead(cols) {
  const tr = document.createElement('tr');
  for (const c of cols) { const th = document.createElement('th'); th.textContent = c; tr.appendChild(th); }
  els.thead.replaceChildren(tr);
}

function addCells(cells) {
  const tr = document.createElement('tr');
  for (const [txt, cls] of cells) { const td = document.createElement('td'); if (cls) td.className = cls; td.textContent = txt; tr.appendChild(td); }
  els.rows.appendChild(tr);
  rowCount++;
  els.count.textContent = `${rowCount} row(s)`;
}

function download(name, bytes, mime = 'application/octet-stream') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bytes], { type: mime }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadButton(label, fn) {
  const b = document.createElement('button');
  b.textContent = label;
  b.style.flex = '0 0 auto';
  b.onclick = fn;
  els.downloads.appendChild(b);
}

function renderDownloads(files) {
  const enc = new TextEncoder();
  for (const f of files) {
    downloadButton(`⬇ ${f.name}`, () => download(f.name, enc.encode(JSON.stringify(f.content, null, 2)), 'application/json'));
  }
  if (files.length > 1) {
    downloadButton('⬇ all (.zip)', () => {
      const zipFiles = files.map((f) => ({ name: f.name, bytes: enc.encode(JSON.stringify(f.content, null, 2)) }));
      download('soaphound.zip', makeZip(zipFiles), 'application/zip');
    });
  }
}

function renderSummary(summary) {
  els.summary.replaceChildren();
  for (const [k, v] of Object.entries(summary || {})) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = `${k}: ${v}`;
    els.summary.appendChild(chip);
  }
}

function readConfig() {
  const host = els.host.value.trim();
  if (!host) throw new Error('Domain Controller host is required.');
  return {
    host,
    port: parseInt(els.port.value, 10) || 9389,
    fqdn: els.fqdn.value.trim() || null,
    user: els.user.value.trim(),
    domain: els.domain.value.trim(),
    password: els.password.value,
    mode: els.mode.value,
    baseDN: els.basedn.value.trim() || null,
    filter: els.filter.value.trim() || '(objectClass=*)',
    attributes: els.attributes.value.trim(),
  };
}

async function execute() {
  if (busy) return;
  clearResults();
  let config;
  try { config = readConfig(); }
  catch (e) { log(e.message, 'log-err'); els.status.textContent = e.message; return; }

  // Set up live table for streaming modes.
  if (config.mode === 'dnsdump') setTableHead(['Name', 'Type', 'TTL', 'Value']);
  else if (config.mode === 'query') setTableHead(['DN', 'Class', 'Attributes']);

  setBusy(true, 'Running…');
  try {
    const onRow = (row) => {
      if (config.mode === 'dnsdump') addCells([[row.fqdn], [row.type, 'type'], [row.ttl === '' ? '' : String(row.ttl)], [row.value, 'val']]);
      else if (config.mode === 'query') addCells([[row.dn || '', 'val'], [row.className, 'type'], [summarizeAttrs(row.attributes), 'val']]);
    };
    const result = await run(config, { log, onRow });
    if (result.summary) renderSummary(result.summary);
    if (result.files) renderDownloads(result.files);
    if (result.rows && !result.files) els.count.textContent = `${result.rows.length} row(s)`;
    log('Done.', 'log-ok');
    els.status.textContent = 'Done.';
  } catch (e) {
    console.error(e);
    log(`ERROR: ${e.message}`, 'log-err');
    els.status.textContent = `Error: ${e.message}`;
  } finally {
    setBusy(false);
  }
}

function summarizeAttrs(attrs) {
  return Object.entries(attrs || {})
    .filter(([k]) => k !== 'distinguishedName' && k !== 'objectReferenceProperty')
    .map(([k, v]) => `${k}=${(v || []).join('|')}`)
    .join('  ');
}

els.btnRun.onclick = execute;
els.btnClear.onclick = clearResults;

if (typeof TCPSocket === 'undefined') {
  log('TCPSocket API not available. This app must be installed and launched as an Isolated Web App with the direct-sockets permission.', 'log-err');
  els.status.textContent = 'Direct Sockets unavailable.';
} else {
  log('Direct Sockets available. Ready.', 'log-ok');
  els.status.textContent = 'Ready.';
}
