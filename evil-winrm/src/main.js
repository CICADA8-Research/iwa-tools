// UI controller: a small terminal. Connect opens a WinRM PowerShell shell; each
// entered line runs as a command with live-streamed output. Supports
// pass-the-hash, command history, Ctrl+C, file download/upload, in-memory script
// loading (preamble) and in-memory .NET execution (Invoke-Binary).
import { WinRMClient } from './winrm/client.js';
import { Shell } from './winrm/shell.js';
import { download, upload, invokeBinary } from './winrm/transfer.js';

const $ = (id) => document.getElementById(id);
const els = {
  host: $('host'), port: $('port'), user: $('user'), domain: $('domain'),
  auth: $('auth'), kdc: $('kdc'), kdcRow: $('kdc-row'), tls: $('tls'),
  password: $('password'), hash: $('hash'),
  btnConn: $('btn-conn'), btnDisc: $('btn-disc'), status: $('status'),
  term: $('term'), cmd: $('cmd'), ps: $('ps'),
  btnUpload: $('btn-upload'), btnLoadPs: $('btn-loadps'), btnInvoke: $('btn-invoke'),
  fileUpload: $('file-upload'), filePs: $('file-ps'), fileBin: $('file-bin'),
};

let client = null, shell = null, busy = false;
const history = [];
let histIdx = 0;

// The KDC field is only relevant for Kerberos.
function syncAuthUI() {
  const kerb = els.auth.value === 'kerberos';
  els.kdc.style.display = kerb ? '' : 'none';
  els.kdcRow.style.display = kerb ? '' : 'none';
}
els.auth.addEventListener('change', syncAuthUI);
syncAuthUI();

// Flip the default port between HTTP (5985) and HTTPS (5986) with the TLS toggle.
els.tls.addEventListener('change', () => {
  const v = els.port.value.trim();
  if (els.tls.checked && (v === '' || v === '5985')) els.port.value = '5986';
  else if (!els.tls.checked && v === '5986') els.port.value = '5985';
});

function write(text, cls) {
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = text;
  els.term.appendChild(span);
  els.term.scrollTop = els.term.scrollHeight;
}
const log = (m) => write(`[*] ${m}\n`, 'ok');
function updatePrompt() { els.ps.textContent = shell && shell.pwd ? `PS ${shell.pwd}>` : 'PS>'; }
const basename = (p) => p.split(/[\\/]/).pop() || 'download.bin';

function setConnected(on) {
  els.btnConn.disabled = on;
  els.btnDisc.disabled = !on;
  els.cmd.disabled = !on;
  for (const b of [els.btnUpload, els.btnLoadPs, els.btnInvoke]) b.disabled = !on;
  for (const f of ['host', 'port', 'user', 'domain', 'auth', 'kdc', 'password', 'hash']) els[f].disabled = on;
  els.cmd.placeholder = on ? 'type a command and press Enter (Ctrl+C to interrupt)' : 'connect to run commands…';
  if (on) els.cmd.focus();
}

async function connect() {
  const host = els.host.value.trim();
  if (!host) { els.status.textContent = 'Host is required.'; return; }
  els.term.replaceChildren();
  els.btnConn.disabled = true;
  els.status.textContent = 'Connecting…';
  client = new WinRMClient(log);
  try {
    await client.connect(host, parseInt(els.port.value, 10) || (els.tls.checked ? 5986 : 5985), {
      authMethod: els.auth.value,
      user: els.user.value.trim(), domain: els.domain.value.trim(),
      kdc: els.kdc.value.trim() || null,
      tls: els.tls.checked, sni: host,
      password: els.password.value, hash: els.hash.value.trim() || null,
    });
    shell = new Shell(client, log);
    await shell.open();
    els.status.textContent = `Connected to ${host}.`;
    updatePrompt();
    setConnected(true);
  } catch (e) {
    write(`[!] ${e.message}\n`, 'err');
    els.status.textContent = `Error: ${e.message}`;
    try { await client.close(); } catch { /* ignore */ }
    client = null; shell = null;
    setConnected(false);
  }
}

async function disconnect() {
  setConnected(false);
  els.status.textContent = 'Disconnecting…';
  try { await shell?.close(); } catch { /* ignore */ }
  try { await client?.close(); } catch { /* ignore */ }
  shell = null; client = null;
  els.status.textContent = 'Disconnected.';
}

// Run a command with live output. Returns when complete.
async function runCommand(command) {
  if (!shell || busy) return;
  busy = true; els.cmd.disabled = true;
  write(`${els.ps.textContent} ${command}\n`, 'cmd');
  let any = false;
  try {
    const r = await shell.run(command, {
      onStdout: (t) => { any = true; write(t); },
      onStderr: (t) => { any = true; write(t, 'err'); },
    });
    if (!any) write('(no output)\n', 'ok');
    if (r.exitCode) write(`[exit ${r.exitCode}]\n`, 'err');
    updatePrompt();
  } catch (e) {
    write(`[!] ${e.message}\n`, 'err');
  } finally {
    busy = false;
    if (shell) { els.cmd.disabled = false; els.cmd.focus(); }
  }
}

// `download <remote path>` — pull a file and save it in the browser.
async function doDownload(remote) {
  if (!shell || busy) return;
  busy = true; els.cmd.disabled = true;
  write(`${els.ps.textContent} download ${remote}\n`, 'cmd');
  try {
    const bytes = await download(shell, remote);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    a.download = basename(remote);
    a.click();
    URL.revokeObjectURL(a.href);
    write(`[*] downloaded ${bytes.length} bytes -> ${a.download}\n`, 'ok');
  } catch (e) {
    write(`[!] download failed: ${e.message}\n`, 'err');
  } finally {
    busy = false; if (shell) { els.cmd.disabled = false; els.cmd.focus(); }
  }
}

function submit(line) {
  const t = line.trim();
  if (!t) return;
  history.push(t); histIdx = history.length;
  const dl = /^download\s+(.+)$/i.exec(t);
  if (dl) doDownload(dl[1].trim()); else runCommand(t);
}

// ---- file-backed actions ----
const readBytes = (file) => file.arrayBuffer().then((b) => new Uint8Array(b));

async function withBusy(fn) {
  if (!shell || busy) return;
  busy = true; els.cmd.disabled = true;
  try { await fn(); } finally { busy = false; if (shell) { els.cmd.disabled = false; els.cmd.focus(); } }
}

els.btnUpload.onclick = () => els.fileUpload.click();
els.fileUpload.onchange = async () => {
  const file = els.fileUpload.files[0]; els.fileUpload.value = '';
  if (!file) return;
  const remote = prompt('Remote destination path:', `${shell.pwd || '.'}\\${file.name}`);
  if (!remote) return;
  await withBusy(async () => {
    write(`[*] uploading ${file.name} (${file.size} bytes) -> ${remote}\n`, 'ok');
    const bytes = await readBytes(file);
    try {
      await upload(shell, remote, bytes, (done, total) => { els.status.textContent = `Uploading ${done}/${total}…`; });
      write(`[*] uploaded ${bytes.length} bytes.\n`, 'ok');
    } catch (e) { write(`[!] upload failed: ${e.message}\n`, 'err'); }
    els.status.textContent = 'Connected.';
  });
};

els.btnLoadPs.onclick = () => els.filePs.click();
els.filePs.onchange = async () => {
  const file = els.filePs.files[0]; els.filePs.value = '';
  if (!file) return;
  const text = await file.text();
  shell.addPreamble(text);
  write(`[*] loaded ${file.name} into the session (${file.size} bytes). Its functions are now available.\n`, 'ok');
};

els.btnInvoke.onclick = () => els.fileBin.click();
els.fileBin.onchange = async () => {
  const file = els.fileBin.files[0]; els.fileBin.value = '';
  if (!file) return;
  const argStr = prompt(`Arguments for ${file.name} (space-separated):`, '') || '';
  const args = argStr.match(/(?:[^\s"]+|"[^"]*")+/g)?.map((s) => s.replace(/^"|"$/g, '')) || [];
  await withBusy(async () => {
    write(`[*] Invoke-Binary ${file.name} ${argStr}\n`, 'cmd');
    const bytes = await readBytes(file);
    try {
      const r = await invokeBinary(shell, bytes, args, (stream, t) => write(t, stream === 'stderr' ? 'err' : ''));
      if (r.exitCode) write(`[exit ${r.exitCode}]\n`, 'err');
    } catch (e) { write(`[!] Invoke-Binary failed: ${e.message}\n`, 'err'); }
    updatePrompt();
  });
};

// ---- terminal input: history + Ctrl+C ----
els.cmd.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const c = els.cmd.value; els.cmd.value = '';
    if (c.trim()) submit(c);
  } else if (e.key === 'ArrowUp') {
    if (histIdx > 0) { histIdx--; els.cmd.value = history[histIdx]; }
    e.preventDefault();
  } else if (e.key === 'ArrowDown') {
    if (histIdx < history.length - 1) { histIdx++; els.cmd.value = history[histIdx]; }
    else { histIdx = history.length; els.cmd.value = ''; }
    e.preventDefault();
  } else if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) {
    if (busy && shell) { shell.interrupt(); write('^C\n', 'err'); }
  }
});

els.btnConn.onclick = connect;
els.btnDisc.onclick = disconnect;

if (typeof TCPSocket === 'undefined') {
  els.status.textContent = 'Direct Sockets unavailable.';
  write('[!] TCPSocket API not available. Install and launch as an Isolated Web App with the direct-sockets permission.\n', 'err');
} else {
  els.status.textContent = 'Ready.';
  write('[*] Direct Sockets available. Enter target + credentials and Connect.\n', 'ok');
}
