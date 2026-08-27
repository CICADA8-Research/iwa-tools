// UI controller: a connection form + an interactive LDAP shell terminal.
import { connect } from './connect.js';
import { LdapShell } from './shell.js';

const $ = (id) => document.getElementById(id);
const els = {
  host: $('host'), port: $('port'), auth: $('auth'), bind: $('bind'),
  domain: $('domain'), domainRow: $('domain-row'), kdc: $('kdc'), kdcRow: $('kdc-row'),
  tls: $('tls'), password: $('password'), hash: $('hash'), basedn: $('basedn'),
  btnConn: $('btn-conn'), btnDisc: $('btn-disc'), status: $('status'),
  term: $('term'), cmd: $('cmd'), ps: $('ps'),
};

let shell = null, client = null, busy = false;
const history = []; let histIdx = 0;

function write(text, cls) {
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = text.endsWith('\n') ? text : text + '\n';
  els.term.appendChild(span);
  els.term.scrollTop = els.term.scrollHeight;
}
const log = (m) => write(`[*] ${m}`, 'ok');

function syncAuthUI() {
  const v = els.auth.value;
  const showDomain = v === 'ntlm' || v === 'kerberos';
  els.domainRow.style.display = els.domain.style.display = showDomain ? '' : 'none';
  els.kdcRow.style.display = els.kdc.style.display = v === 'kerberos' ? '' : 'none';
}
els.auth.addEventListener('change', syncAuthUI);
syncAuthUI();
els.tls.addEventListener('change', () => {
  const v = els.port.value.trim();
  if (els.tls.checked && (v === '' || v === '389')) els.port.value = '636';
  else if (!els.tls.checked && v === '636') els.port.value = '389';
});

function setConnected(on) {
  els.btnConn.disabled = on; els.btnDisc.disabled = !on; els.cmd.disabled = !on;
  for (const f of ['host', 'port', 'auth', 'bind', 'domain', 'kdc', 'tls', 'password', 'hash', 'basedn']) els[f].disabled = on;
  if (on) els.cmd.focus();
}

async function doConnect() {
  els.term.replaceChildren();
  els.btnConn.disabled = true;
  els.status.textContent = 'Connecting…';
  const config = {
    host: els.host.value.trim(),
    port: parseInt(els.port.value, 10) || null,
    authMethod: els.auth.value,
    bindDN: els.bind.value.trim(),
    domain: els.domain.value.trim(),
    kdc: els.kdc.value.trim() || null,
    tls: els.tls.checked,
    password: els.password.value,
    hash: els.hash.value.trim() || null,
    baseDN: els.basedn.value.trim() || null,
  };
  if (!config.host) { els.status.textContent = 'Host is required.'; els.btnConn.disabled = false; return; }
  try {
    const ctx = await connect(config, log);
    client = ctx.client;
    shell = new LdapShell(client, { baseDN: ctx.baseDN, domain: ctx.domain, tls: ctx.tls, log });
    els.ps.textContent = `${ctx.domain}#`;
    write(`Connected. Base DN: ${ctx.baseDN}. Type "help" for commands.`, 'ok');
    els.status.textContent = `Connected to ${config.host}.`;
    setConnected(true);
  } catch (e) {
    write(`[!] ${e.message}`, 'err');
    els.status.textContent = `Error: ${e.message}`;
    try { await client?.close(); } catch { /* ignore */ }
    client = shell = null;
    setConnected(false);
  }
}

async function disconnect() {
  setConnected(false);
  try { await client?.close(); } catch { /* ignore */ }
  client = shell = null;
  els.status.textContent = 'Disconnected.';
  els.ps.textContent = '#';
}

async function runLine(line) {
  if (!shell || busy) return;
  write(`${els.ps.textContent} ${line}`, 'cmd');
  if (line.trim().toLowerCase() === 'exit') { await disconnect(); return; }
  busy = true; els.cmd.disabled = true;
  try {
    const out = await shell.run(line);
    if (out) write(out);
  } catch (e) {
    write(`[!] ${e.message}`, 'err');
  } finally {
    busy = false;
    if (shell) { els.cmd.disabled = false; els.cmd.focus(); }
  }
}

els.cmd.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const c = els.cmd.value; els.cmd.value = '';
    if (c.trim()) { history.push(c); histIdx = history.length; runLine(c); }
  } else if (e.key === 'ArrowUp') { if (histIdx > 0) els.cmd.value = history[--histIdx]; e.preventDefault(); }
  else if (e.key === 'ArrowDown') { if (histIdx < history.length - 1) els.cmd.value = history[++histIdx]; else { histIdx = history.length; els.cmd.value = ''; } e.preventDefault(); }
});

els.btnConn.onclick = doConnect;
els.btnDisc.onclick = disconnect;

if (typeof TCPSocket === 'undefined') {
  els.status.textContent = 'Direct Sockets unavailable.';
  write('[!] TCPSocket API not available. Install and launch as an Isolated Web App with the direct-sockets permission.', 'err');
} else {
  els.status.textContent = 'Ready.';
  write('[*] Direct Sockets available. Fill in the target and connect.', 'ok');
}
