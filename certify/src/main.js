// UI controller for Certify: reads the form, runs the AD CS enumeration + ESC
// analysis, streams a log and renders findings / templates / CAs tables.
import { run, requestCert, authenticate } from './certify.js';

const $ = (id) => document.getElementById(id);
const els = {
  host: $('host'), port: $('port'), auth: $('auth'), bind: $('bind'),
  domain: $('domain'), domainRow: $('domain-row'), kdc: $('kdc'), kdcRow: $('kdc-row'),
  tls: $('tls'), password: $('password'), mode: $('mode'), enabledOnly: $('enabled-only'), reqOpts: $('req-opts'),
  reqCahost: $('req-cahost'), reqCa: $('req-ca'), reqTemplate: $('req-template'),
  reqSubject: $('req-subject'), reqAltname: $('req-altname'),
  btnRun: $('btn-run'), btnClear: $('btn-clear'),
  status: $('status'), summary: $('summary'), tables: $('tables'), log: $('log'),
};

let busy = false;

function syncUI() {
  const v = els.auth.value;
  const showDomain = v === 'ntlm' || v === 'kerberos';
  els.domain.style.display = els.domainRow.style.display = showDomain ? '' : 'none';
  els.kdc.style.display = els.kdcRow.style.display = (v === 'kerberos' || els.mode.value === 'auth') ? '' : 'none';
  els.reqOpts.classList.toggle('hide', els.mode.value !== 'request' && els.mode.value !== 'auth');
}
els.auth.addEventListener('change', syncUI);
els.mode.addEventListener('change', syncUI);
els.tls.addEventListener('change', () => {
  const v = els.port.value.trim();
  if (els.tls.checked && (v === '' || v === '389')) els.port.value = '636';
  else if (!els.tls.checked && v === '636') els.port.value = '389';
});
syncUI();

function log(msg, cls = '') {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = msg;
  els.log.appendChild(line);
  els.log.scrollTop = els.log.scrollHeight;
}
function setBusy(state, label) { busy = state; els.btnRun.disabled = state; if (label) els.status.textContent = label; }
function clear() { els.summary.replaceChildren(); els.tables.replaceChildren(); els.log.replaceChildren(); els.status.textContent = 'Ready.'; }

function readConfig() {
  const host = els.host.value.trim();
  if (!host) throw new Error('Domain Controller host is required.');
  return {
    host, port: parseInt(els.port.value, 10) || (els.tls.checked ? 636 : 389),
    authMethod: els.auth.value, bindDN: els.bind.value.trim(), user: els.bind.value.trim(),
    domain: els.domain.value.trim(), kdc: els.kdc.value.trim(), tls: els.tls.checked,
    password: els.password.value, mode: els.mode.value, enabled: els.enabledOnly.checked,
  };
}

function chip(t) { const c = document.createElement('span'); c.className = 'chip'; c.textContent = t; return c; }

function table(title, cols, rows) {
  const wrap = document.createElement('div'); wrap.className = 'tablewrap';
  const h = document.createElement('h3'); h.textContent = title; wrap.appendChild(h);
  const t = document.createElement('table');
  const thr = document.createElement('tr');
  for (const c of cols) { const th = document.createElement('th'); th.textContent = c.label; thr.appendChild(th); }
  const thead = document.createElement('thead'); thead.appendChild(thr); t.appendChild(thead);
  const tb = document.createElement('tbody');
  for (const r of rows) {
    const tr = document.createElement('tr');
    for (const c of cols) { const td = document.createElement('td'); c.render(td, r); tr.appendChild(td); }
    tb.appendChild(tr);
  }
  t.appendChild(tb); wrap.appendChild(t);
  if (!rows.length) { const e = document.createElement('div'); e.style.cssText = 'padding:10px;color:var(--muted);font-size:12px'; e.textContent = 'none'; wrap.appendChild(e); }
  return wrap;
}
const text = (v) => (td, r) => { td.textContent = typeof v === 'function' ? v(r) : r[v]; };
const boolCell = (key, yes = 'yes', no = 'no') => (td, r) => { td.textContent = r[key] ? yes : no; td.className = r[key] ? 'yes' : 'no'; };

function renderFindings(findings) {
  return table(`Findings (${findings.length})`, [
    { label: 'Risk', render: (td, f) => { td.textContent = f.risk; td.className = `risk ${f.risk}`; } },
    { label: 'ESC', render: (td, f) => { td.textContent = f.id; td.className = 'esc'; } },
    { label: 'Object', render: (td, f) => { td.textContent = `${f.scope}: ${f.object}`; td.className = 'val'; } },
    { label: 'Principals', render: (td, f) => { td.textContent = (f.principalNames || []).join(', ') || '—'; td.className = 'val'; } },
    { label: 'Detail', render: text((f) => f.detail) },
  ], findings);
}
function renderTemplates(rows) {
  return table(`Certificate templates (${rows.length})`, [
    { label: 'Template', render: text('name') },
    { label: 'Enabled', render: boolCell('enabled', 'yes', 'no') },
    { label: 'Schema', render: (td, r) => { td.textContent = 'v' + r.schema; td.className = 'mono'; } },
    { label: 'ClientAuth', render: boolCell('clientAuth') },
    { label: 'SupplySubj', render: boolCell('suppliesSubject') },
    { label: 'Approval', render: boolCell('managerApproval') },
    { label: 'ESC', render: (td, r) => { td.textContent = r.escs.join(', ') || '—'; td.className = 'esc'; } },
    { label: 'Enrollees', render: (td, r) => { td.textContent = r.enrollees.join(', '); td.className = 'val'; } },
    { label: 'EKUs', render: (td, r) => { td.textContent = r.ekus.join(', ') || '(any)'; td.className = 'val'; } },
  ], rows);
}
function renderCAs(rows) {
  return table(`Certification Authorities (${rows.length})`, [
    { label: 'CA', render: text('name') },
    { label: 'Host', render: (td, r) => { td.textContent = r.dns || ''; td.className = 'val'; } },
    { label: 'Templates', render: (td, r) => { td.textContent = r.templates; td.className = 'mono'; } },
    { label: 'Web enroll', render: boolCell('webEnroll') },
    { label: 'ESC', render: (td, r) => { td.textContent = r.escs.join(', ') || '—'; td.className = 'esc'; } },
  ], rows);
}

async function execute() {
  if (busy) return;
  clear();
  let config;
  try { config = readConfig(); } catch (e) { log(e.message, 'log-err'); els.status.textContent = e.message; return; }
  setBusy(true, 'Running…');
  try {
    if (config.mode === 'request') { await doRequest(config); return; }
    if (config.mode === 'auth') { await doAuth(config); return; }
    const res = await run(config, { log });
    for (const [k, v] of Object.entries(res.summary)) els.summary.appendChild(chip(`${k}: ${v}`));
    els.summary.appendChild(chip(res.configNC));
    const mode = config.mode;
    if (mode === 'find' || mode === 'vulnerable') els.tables.appendChild(renderFindings(res.findings));
    if (mode === 'find' || mode === 'cas') els.tables.appendChild(renderCAs(res.caRows));
    if (mode === 'find' || mode === 'templates') els.tables.appendChild(renderTemplates(res.templateRows));
    log('Done.', 'log-ok');
    els.status.textContent = `Done — ${res.summary.findings} finding(s).`;
  } catch (e) {
    console.error(e);
    log(`ERROR: ${e.message}`, 'log-err');
    els.status.textContent = `Error: ${e.message}`;
  } finally {
    setBusy(false);
  }
}

function download(name, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

async function doRequest(config) {
  const res = await requestCert({
    ...config, caHost: els.reqCahost.value.trim() || config.host, caName: els.reqCa.value.trim(),
    template: els.reqTemplate.value.trim(), subject: els.reqSubject.value.trim() || 'CN=User',
    altUpn: els.reqAltname.value.trim() || null,
  }, { log });
  els.summary.appendChild(chip(`disposition: ${res.dispositionText}`));
  els.summary.appendChild(chip(`requestId: ${res.requestId}`));
  if (res.message) els.summary.appendChild(chip(res.message));
  if (res.certPem) {
    const b = (label, fn) => { const x = document.createElement('button'); x.textContent = label; x.style.flex = '0 0 auto'; x.onclick = fn; els.tables.appendChild(x); };
    b('⬇ cert.crt', () => download('cert.crt', res.certPem));
    b('⬇ cert.key', () => download('cert.key', res.keyPem));
    const pre = document.createElement('pre'); pre.className = 'val'; pre.style.cssText = 'white-space:pre-wrap;margin-top:12px'; pre.textContent = res.certPem; els.tables.appendChild(pre);
    log('Certificate issued.', 'log-ok');
    els.status.textContent = 'Certificate issued.';
  } else {
    els.status.textContent = `Not issued: ${res.dispositionText}`;
  }
}

async function doAuth(config) {
  const res = await authenticate({
    ...config, kdc: config.kdc || config.host, caHost: els.reqCahost.value.trim() || config.host,
    caName: els.reqCa.value.trim(), template: els.reqTemplate.value.trim() || 'User', subject: `CN=${config.user}`,
  }, { log });
  els.summary.appendChild(chip(`PKINIT: ${res.ok ? 'ok' : 'failed'}`));
  els.summary.appendChild(chip(`${res.username}@${res.realm}`));
  els.summary.appendChild(chip(`session etype ${res.sessionKeyEtype}`));
  if (res.ntHash) {
    const pre = document.createElement('pre'); pre.className = 'val'; pre.style.cssText = 'margin-top:12px;font-size:14px';
    pre.textContent = `${res.username} NT hash:\n${res.ntHash}`;
    els.tables.appendChild(pre);
    els.status.textContent = 'NT hash recovered.';
  } else {
    els.status.textContent = 'PKINIT TGT obtained.';
  }
  log('Done.', 'log-ok');
}

els.btnRun.onclick = execute;
els.btnClear.onclick = clear;

if (typeof TCPSocket === 'undefined') {
  log('TCPSocket API not available. Install and launch as an Isolated Web App with the direct-sockets permission.', 'log-err');
  els.status.textContent = 'Direct Sockets unavailable.';
} else {
  log('Direct Sockets available. Ready.', 'log-ok');
  els.status.textContent = 'Ready.';
}
