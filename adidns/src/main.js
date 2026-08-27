// UI controller: reads the form, drives the ADIDNS dump, and renders results
// and a live log.
import { run } from './adidnsdump.js';

const $ = (id) => document.getElementById(id);
const els = {
  host: $('host'), port: $('port'), pagesize: $('pagesize'),
  auth: $('auth'), bind: $('bind'), domain: $('domain'), domainRow: $('domain-row'),
  kdc: $('kdc'), kdcRow: $('kdc-row'), tls: $('tls'),
  password: $('password'), basedn: $('basedn'), zone: $('zone'),
  forest: $('forest'), tomb: $('tomb'), resolve: $('resolve'),
  btnZones: $('btn-zones'), btnDump: $('btn-dump'), btnCsv: $('btn-csv'), btnClear: $('btn-clear'),
  status: $('status'), zones: $('zones'), count: $('count'), rows: $('rows'), log: $('log'),
};

// Domain/realm applies to NTLM and Kerberos; the KDC field is Kerberos-only;
// simple bind takes a full DN/UPN and neither.
function syncAuthUI() {
  const v = els.auth.value;
  const showDomain = v === 'ntlm' || v === 'kerberos';
  els.domain.style.display = showDomain ? '' : 'none';
  els.domainRow.style.display = showDomain ? '' : 'none';
  els.kdc.style.display = v === 'kerberos' ? '' : 'none';
  els.kdcRow.style.display = v === 'kerberos' ? '' : 'none';
}
els.auth.addEventListener('change', syncAuthUI);
syncAuthUI();

// Flip the default port between LDAP (389) and LDAPS (636) with the TLS toggle.
els.tls.addEventListener('change', () => {
  const v = els.port.value.trim();
  if (els.tls.checked && (v === '' || v === '389')) els.port.value = '636';
  else if (!els.tls.checked && v === '636') els.port.value = '389';
});

let collected = [];
let busy = false;

function log(msg, cls = '') {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = msg;
  els.log.appendChild(line);
  els.log.scrollTop = els.log.scrollHeight;
}

function setBusy(state, label) {
  busy = state;
  els.btnZones.disabled = state;
  els.btnDump.disabled = state;
  els.status.textContent = label;
}

function addRow(row) {
  collected.push(row);
  const tr = document.createElement('tr');
  if (row.tombstoned) tr.className = 'tomb';
  const td = (txt, cls) => { const c = document.createElement('td'); if (cls) c.className = cls; c.textContent = txt; return c; };
  tr.append(td(row.fqdn), td(row.type, 'type'), td(row.ttl === '' ? '' : String(row.ttl)), td(row.value, 'val'));
  els.rows.appendChild(tr);
  els.count.textContent = `${collected.length} record(s)`;
  els.btnCsv.disabled = collected.length === 0;
}

function renderZones(zones) {
  els.zones.replaceChildren();
  for (const z of zones) {
    const chip = document.createElement('span');
    chip.className = 'zone';
    chip.textContent = z;
    chip.title = 'Click to dump this zone';
    chip.onclick = () => { els.zone.value = z; startDump(); };
    els.zones.appendChild(chip);
  }
}

function clearResults() {
  collected = [];
  els.rows.replaceChildren();
  els.zones.replaceChildren();
  els.count.textContent = '';
  els.log.replaceChildren();
  els.btnCsv.disabled = true;
}

function readConfig() {
  const host = els.host.value.trim();
  if (!host) { throw new Error('Domain Controller host is required.'); }
  return {
    host,
    port: parseInt(els.port.value, 10) || 389,
    authMethod: els.auth.value,
    bindDN: els.bind.value.trim(),
    domain: els.domain.value.trim(),
    kdc: els.kdc.value.trim(),
    tls: els.tls.checked,
    password: els.password.value,
    baseDN: els.basedn.value.trim() || null,
    zone: els.zone.value.trim() || null,
    forest: els.forest.checked,
    includeTombstoned: els.tomb.checked,
    resolve: els.resolve.checked,
  };
}

async function execute(extra) {
  if (busy) return;
  clearResults();
  let config;
  try { config = { ...readConfig(), ...extra }; }
  catch (e) { log(e.message, 'log-err'); els.status.textContent = e.message; return; }

  setBusy(true, 'Running…');
  try {
    const { zones, rows } = await run(config, { log, onRow: addRow });
    if (zones && zones.length) renderZones(zones);
    log(`Done. ${rows.length} record(s) across ${zones ? zones.length : 0} zone(s).`, 'log-ok');
    els.status.textContent = `Done — ${rows.length} record(s).`;
  } catch (e) {
    console.error(e);
    log(`ERROR: ${e.message}`, 'log-err');
    els.status.textContent = `Error: ${e.message}`;
  } finally {
    setBusy(false, els.status.textContent);
  }
}

function startDump() { execute({ listOnly: false }); }

els.btnZones.onclick = () => execute({ listOnly: true });
els.btnDump.onclick = startDump;
els.btnClear.onclick = clearResults;
els.btnCsv.onclick = () => {
  const esc = (s) => `"${String(s).replace(/"/g, '""')}"`;
  const csv = ['name,type,ttl,value',
    ...collected.map((r) => [r.fqdn, r.type, r.ttl, r.value].map(esc).join(','))].join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'adidnsdump.csv';
  a.click();
  URL.revokeObjectURL(a.href);
};

// Surface socket capability up front.
if (typeof TCPSocket === 'undefined') {
  log('TCPSocket API not available. This app must be installed and launched as an Isolated Web App with the direct-sockets permission.', 'log-err');
  els.status.textContent = 'Direct Sockets unavailable.';
} else {
  log('Direct Sockets available. Ready.', 'log-ok');
}
