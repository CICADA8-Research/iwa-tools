// A Windows Remote Shell over a WinRMClient: open a cmd shell, run commands and
// stream their stdout/stderr, then clean up. Mirrors WinRS / Evil-WinRM.

import {
  createShell, runCommand, receive, signal, deleteShell,
  getShellId, getCommandId, parseReceiveResponse, getFault,
} from './messages.js';
import { utf16le } from '../ntlm/ntlm.js';

// WSMan "operation timed out" fault — benign, just means no output yet; retry.
const TIMEOUT_FAULT = 2150858793;

// The WinRM "cmd" shell runs cmd.exe, so each command is dispatched through
// PowerShell to give a real PS session (where `ls`, `Get-ChildItem`, … work).
// Because each powershell.exe invocation is stateless, we carry the working
// directory ourselves: cd into the tracked path, run the command, then emit a
// marker line with the resulting path so we can update it.
const CWD_MARK = '@@CWD@@:';
const b64 = (bytes) => (typeof btoa === 'function'
  ? btoa(String.fromCharCode(...bytes))
  : Buffer.from(bytes).toString('base64'));

export function wrapPowerShell(command, pwd, preamble = '') {
  const body = (command && command.trim()) || '$null';
  const setLoc = pwd ? `Set-Location -LiteralPath ${psQuote(pwd)}; ` : '';
  const pre = preamble ? preamble + '\n' : '';
  const script =
    '[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference=\'SilentlyContinue\'; ' +
    `${pre}${setLoc}try { ${body} } finally { Write-Output ('${CWD_MARK}' + (Get-Location).Path) }`;
  return `powershell -NoProfile -NonInteractive -EncodedCommand ${b64(utf16le(script))}`;
}

function psQuote(s) { return `'${String(s).replace(/'/g, "''")}'`; }

// Pull the trailing CWD marker out of stdout text -> { text, cwd }.
export function splitCwd(text) {
  const lines = text.split(/\r?\n/);
  let cwd = null;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].startsWith(CWD_MARK)) { cwd = lines[i].slice(CWD_MARK.length).trim(); lines.splice(i, 1); break; }
  }
  return { text: lines.join('\r\n'), cwd };
}

export class Shell {
  constructor(client, log = () => {}) {
    this.client = client;
    this._log = log;
    this.shellId = null;
    this.to = client.endpoint;
    this.pwd = null;        // tracked PowerShell working directory
    this.preamble = '';     // script/functions re-applied to every command
    this._activeCommandId = null;
    this._interrupt = false;
  }

  // Load PowerShell into the session preamble so its functions/variables are
  // available to every subsequent command (works around the stateless shell).
  addPreamble(text) { this.preamble += (this.preamble ? '\n' : '') + text; }
  clearPreamble() { this.preamble = ''; }

  // Request termination of the currently running command (Ctrl+C). Takes effect
  // at the next receive boundary.
  interrupt() { if (this._activeCommandId) this._interrupt = true; }

  async open() {
    const xml = await this.client.exchange(createShell(this.to));
    const fault = getFault(xml);
    if (fault) throw new Error(`WinRM open shell failed: ${fault.message}`);
    this.shellId = getShellId(xml);
    if (!this.shellId) throw new Error('WinRM: no ShellId in Create response');
    this._log(`Shell opened (${this.shellId}).`);
    // Prime the working directory so the prompt is correct from the start.
    try { await this.run(''); } catch { /* ignore */ }
  }

  // Run a command (through PowerShell) to completion. If opts.onStdout/onStderr
  // are given, output streams to them line-by-line as it arrives (the trailing
  // working-directory marker is held back). Always returns the full
  // { stdout, stderr, exitCode } as strings, with the working directory tracked.
  async run(command, opts = {}) {
    const onStdout = opts.onStdout, onStderr = opts.onStderr;
    const wrapped = wrapPowerShell(command, this.pwd, this.preamble);
    const cmdXml = await this.client.exchange(runCommand(this.to, this.shellId, wrapped));
    const fault = getFault(cmdXml);
    if (fault) throw new Error(`WinRM command failed: ${fault.message}`);
    const commandId = getCommandId(cmdXml);
    if (!commandId) throw new Error('WinRM: no CommandId in Command response');
    this._activeCommandId = commandId;
    this._interrupt = false;

    const odec = new TextDecoder('utf-8'), edec = new TextDecoder('utf-8');
    let pendingOut = '', fullOut = '', fullErr = '', exitCode = null;

    // Flush complete lines from pendingOut, capturing the CWD marker and
    // streaming the rest.
    const flushLines = (final) => {
      let nl;
      while ((nl = pendingOut.indexOf('\n')) >= 0) {
        const line = pendingOut.slice(0, nl + 1);
        pendingOut = pendingOut.slice(nl + 1);
        emitLine(line);
      }
      if (final && pendingOut) { emitLine(pendingOut); pendingOut = ''; }
    };
    const emitLine = (line) => {
      if (line.startsWith(CWD_MARK)) { this.pwd = line.slice(CWD_MARK.length).trim() || this.pwd; return; }
      fullOut += line;
      if (onStdout) onStdout(line);
    };

    try {
      for (;;) {
        if (this._interrupt) {
          try { await this.client.exchange(signal(this.to, this.shellId, commandId)); } catch { /* ignore */ }
          this._interrupt = false;
        }
        const xml = await this.client.exchange(receive(this.to, this.shellId, commandId));
        const f = getFault(xml);
        if (f) {
          if (f.code === TIMEOUT_FAULT) continue; // no output within the window — retry
          throw new Error(`WinRM receive failed: ${f.message}`);
        }
        const r = parseReceiveResponse(xml);
        if (r.stdout.length) { pendingOut += odec.decode(r.stdout, { stream: true }); flushLines(false); }
        if (r.stderr.length) { const t = edec.decode(r.stderr, { stream: true }); fullErr += t; if (onStderr) onStderr(t); }
        if (r.done) { exitCode = r.exitCode; break; }
      }
    } finally {
      this._activeCommandId = null;
    }
    pendingOut += odec.decode(); // flush decoder
    flushLines(true);
    try { await this.client.exchange(signal(this.to, this.shellId, commandId)); } catch { /* best effort */ }
    return { stdout: fullOut, stderr: fullErr, exitCode };
  }

  async close() {
    if (!this.shellId) return;
    try { await this.client.exchange(deleteShell(this.to, this.shellId)); } catch { /* best effort */ }
    this.shellId = null;
  }
}

function concatBytes(list) {
  let t = 0; for (const a of list) t += a.length;
  const o = new Uint8Array(t); let off = 0;
  for (const a of list) { o.set(a, off); off += a.length; }
  return o;
}
