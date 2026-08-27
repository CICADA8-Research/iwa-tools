// TUI controller: a single full-width pseudo-console for the bundled utilities.
import { IwaConsole, TOOLS } from './console.js';
import { toBytes } from './store.js';
import { parseTicketFile } from './tickets.js';

const $ = (id) => document.getElementById(id);
const term = $('term'), cmd = $('cmd'), ps = $('ps');

let busy = false;
const history = []; let histIdx = 0;

function print(text, cls = '') {
  for (const line of String(text).split('\n')) {
    const el = document.createElement('div');
    if (cls) el.className = cls;
    el.textContent = line;
    term.appendChild(el);
  }
  term.scrollTop = term.scrollHeight;
}

const io = {
  print,
  setPrompt: (s) => { ps.textContent = s; },
  clear: () => term.replaceChildren(),
  download: (name, content) => {
    const bytes = toBytes(content);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    a.download = name; a.click(); URL.revokeObjectURL(a.href);
  },
  // Import file(s) from disk: opens the OS file picker and resolves to
  // [{ name, bytes:Uint8Array }] for the store `upload` command.
  pickFiles: () => new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file'; input.multiple = true; input.style.display = 'none';
    document.body.appendChild(input);
    let settled = false;
    const done = (val) => { if (settled) return; settled = true; input.remove(); resolve(val); };
    input.addEventListener('change', async () => {
      const files = await Promise.all([...input.files].map(async (f) => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) })));
      done(files);
    });
    // If the dialog is cancelled there is no reliable event; resolve empty on the
    // next focus so the command doesn't hang forever.
    window.addEventListener('focus', () => setTimeout(() => done([]), 300), { once: true });
    input.click();
  }),
};

const con = new IwaConsole(io);

async function submit(line) {
  if (busy) return;
  print(`${ps.textContent} ${line}`, 'cmd');
  busy = true; cmd.disabled = true;
  try { await con.submit(line); }
  catch (e) { print(`[!] ${e.message}`, 'err'); }
  finally { busy = false; cmd.disabled = false; cmd.focus(); refreshFilesBadge(); }
}

function commonPrefix(words) {
  if (!words.length) return '';
  let p = words[0];
  for (const w of words) { while (!w.startsWith(p)) p = p.slice(0, -1); }
  return p;
}

cmd.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const c = cmd.value; cmd.value = '';
    if (c.trim()) { history.push(c); histIdx = history.length; submit(c); }
  } else if (e.key === 'Tab') {
    e.preventDefault();
    const val = cmd.value;
    if (!val.includes(' ')) { // complete the command/tool name (first word)
      const matches = con.complete(val);
      if (matches.length === 1) cmd.value = matches[0] + ' ';
      else if (matches.length > 1) {
        const cp = commonPrefix(matches);
        if (cp.length > val.length) cmd.value = cp;
        print(matches.join('   '), 'muted');
      }
    } else { // complete a store path for the last argument (@path, --ticket, cat/…)
      const argv = val.replace(/\s+/g, ' ').split(' ');
      const matches = con.completeArgs(argv);
      if (!matches.length) return;
      const head = argv.slice(0, -1).join(' ');
      const last = argv[argv.length - 1];
      if (matches.length === 1) cmd.value = `${head} ${matches[0]} `;
      else {
        const cp = commonPrefix(matches);
        if (cp.length > last.length) cmd.value = `${head} ${cp}`;
        print(matches.join('   '), 'muted');
      }
    }
  } else if (e.key === 'ArrowUp') { if (histIdx > 0) cmd.value = history[--histIdx]; e.preventDefault(); }
  else if (e.key === 'ArrowDown') { if (histIdx < history.length - 1) cmd.value = history[++histIdx]; else { histIdx = history.length; cmd.value = ''; } e.preventDefault(); }
});

// ---- Files tab: a visual view over the console's in-memory store -----------

const store = con.store;
const humanSize = (n) => n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1024 * 1024)).toFixed(1)} MB`;
function ageOf(mtime) {
  const s = Math.max(0, Math.round((Date.now() - mtime) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
const basename = (p) => p.split('/').pop();

// If a stored file is a Kerberos ccache/kirbi, return a short "client@REALM · spn"
// label to flag it in the list; null otherwise. Cheap (store is in-memory).
function ticketInfo(path) {
  const bytes = store.get(path);
  if (!bytes || !(bytes[0] === 0x05 || bytes[0] === 0x76 || /\.(ccache|kirbi)$/i.test(path))) return null;
  try {
    const { tgts, serviceTickets } = parseTicketFile(bytes);
    const t = tgts[0] || serviceTickets[0];
    if (!t) return null;
    const client = `${(t.cname || []).join('/')}@${t.crealm || ''}`;
    return `${client} · ${tgts.length ? 'TGT' : t.spn}`;
  } catch { return null; }
}

const filerows = $('filerows'), filesEmpty = $('files-empty'), filesCount = $('files-count');

function renderFiles() {
  const rows = store.list();
  filesCount.textContent = rows.length ? ` ${rows.length}` : '';
  filesEmpty.hidden = rows.length > 0;
  filerows.replaceChildren();
  for (const r of rows) {
    const tr = document.createElement('tr');

    const path = document.createElement('td'); path.className = 'path'; path.textContent = r.path;
    const tkt = ticketInfo(r.path);
    if (tkt) { const b = document.createElement('span'); b.className = 'tag'; b.textContent = `🎫 ${tkt}`; b.title = 'Kerberos ticket — use with --ticket ' + r.path; path.append(' ', b); }
    const size = document.createElement('td'); size.className = 'num'; size.textContent = humanSize(r.size);
    const age = document.createElement('td'); age.className = 'age'; age.textContent = ageOf(r.mtime);

    const actions = document.createElement('td'); actions.className = 'actions';
    const dl = document.createElement('button'); dl.className = 'btn'; dl.textContent = 'Download';
    dl.addEventListener('click', () => { const b = store.get(r.path); if (b) io.download(basename(r.path), b); });
    const del = document.createElement('button'); del.className = 'btn danger'; del.textContent = 'Delete';
    del.addEventListener('click', () => { store.remove(r.path); renderFiles(); });
    actions.append(dl, del);

    tr.append(path, size, age, actions);
    filerows.appendChild(tr);
  }
}

// Keep the tab badge current after console commands; re-render if the tab is up.
function refreshFilesBadge() {
  const n = store.list().length;
  filesCount.textContent = n ? ` ${n}` : '';
  if (!views.files.hidden) renderFiles();
}

// Store uploaded File objects under an optional folder prefix.
async function storeFiles(fileList) {
  const dirRaw = $('upload-dir').value.trim();
  const dir = dirRaw ? dirRaw.replace(/^\/+/, '').replace(/\/*$/, '/') : '';
  let n = 0;
  for (const f of fileList) {
    const bytes = new Uint8Array(await f.arrayBuffer());
    store.put(dir + f.name, bytes);
    n++;
  }
  if (n) { renderFiles(); print(`[+] stored ${n} file(s) into the store${dir ? ' under ' + dir : ''}.`, 'ok'); }
}

$('btn-upload').addEventListener('click', () => {
  const input = document.createElement('input');
  input.type = 'file'; input.multiple = true; input.style.display = 'none';
  document.body.appendChild(input);
  input.addEventListener('change', async () => { await storeFiles(input.files); input.remove(); });
  input.click();
});

// Drag & drop onto the file list.
const filewrap = $('filewrap');
for (const ev of ['dragenter', 'dragover']) filewrap.addEventListener(ev, (e) => { e.preventDefault(); filewrap.classList.add('drag'); });
for (const ev of ['dragleave', 'drop']) filewrap.addEventListener(ev, (e) => { e.preventDefault(); if (ev === 'dragleave' && filewrap.contains(e.relatedTarget)) return; filewrap.classList.remove('drag'); });
filewrap.addEventListener('drop', (e) => { if (e.dataTransfer?.files?.length) storeFiles(e.dataTransfer.files); });

// ---- tab switching ---------------------------------------------------------

const views = { console: $('view-console'), files: $('view-files') };
function switchTab(name) {
  for (const btn of document.querySelectorAll('#tabs button')) btn.classList.toggle('active', btn.dataset.tab === name);
  for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
  if (name === 'files') renderFiles();
  if (name === 'console') cmd.focus();
}
for (const btn of document.querySelectorAll('#tabs button')) btn.addEventListener('click', () => switchTab(btn.dataset.tab));

print('iwa-tools — unified console for the Direct Sockets utilities.', 'ok');
print(`Tools: ${TOOLS.join(', ')}.  Type "help" or "help <tool>".`);
print('Files tab: upload/download files, or store tool results (loot/). In the console: ls, cat, put, @path, --ticket.', 'muted');
if (typeof TCPSocket === 'undefined') {
  print('[!] TCPSocket unavailable — install and launch as an Isolated Web App with the direct-sockets permission.', 'err');
} else {
  print('Direct Sockets available.', 'ok');
}
ps.textContent = 'iwa#';
cmd.focus();
