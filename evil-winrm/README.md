# Evil-WinRM IWA

A minimalist browser port of **Evil-WinRM**, built as a Chrome **Isolated Web App
(IWA)** that opens a **WinRM (WS-Management) shell** to a Windows host over the
**Direct Sockets API** (`TCPSocket`) and runs commands — all from the browser.

It speaks WinRM over **HTTP on 5985** with **NTLM/Negotiate** authentication and
**NTLM message encryption** (`multipart/encrypted`), so it works against a default
WinRM configuration (which requires encryption on HTTP).

> ⚠️ **Authorised use only.** This is a remote-administration / offensive-security
> tool. Use it only against hosts you own or are explicitly authorised to test.

## What it does

A small PowerShell terminal: connect with host + credentials and it opens a shell
on the target via WS-Management; each line runs through PowerShell with its
stdout/stderr **streamed live**, and the working directory is tracked so the
prompt and `cd` behave like a real session. Features:

- **Pass-the-Hash** — authenticate with an NT hash (`32 hex`, or `LM:NT`) instead
  of a password.
- **File download / upload** — `download <remote path>` saves the file in the
  browser; the **Upload…** button pushes a local file to the target (chunked
  base64 over the shell).
- **In-memory script loading** — the **Load .ps1…** button adds a script to the
  session *preamble* that is re-applied to every command, so its functions stay
  available across commands (working around the stateless shell).
- **Invoke .NET (in memory)** — the **Invoke .NET…** button runs a C# assembly
  (e.g. Rubeus, SharpHound) via `[Reflection.Assembly]::Load(...).EntryPoint`.
- **Ctrl+C** interrupts a running command; **↑/↓** browse command history.

Disconnect cleanly deletes the remote shell.

## How it works

WinRM is WS-Management (MS-WSMV) SOAP over HTTP. The flow:

1. **HTTP/1.1 client over `TCPSocket`** (`src/http/client.js`) — one keep-alive
   connection (NTLM auth is connection-bound), Content-Length + chunked bodies,
   binary response bodies.
2. **NTLM/Negotiate over HTTP** (`src/winrm/client.js`) — `Authorization:
   Negotiate <type1>` → `401` with the `WWW-Authenticate` challenge → compute the
   type-3 response and the session key. The type-3 request carries the first
   sealed SOAP body and completes auth on the connection.
3. **Message encryption** (`src/winrm/crypt.js`) — every SOAP body is wrapped as
   `multipart/encrypted` whose octet-stream is
   `<4-byte sig length><signature(16)><sealed SOAP>`. That is exactly the NTLM
   `GSS_WrapEx` output produced by `NtlmSession.seal()` — the **same sign+seal
   implementation built for the soaphound tool** (verified byte-for-byte against
   impacket). Using encryption unconditionally works against both default
   (`AllowUnencrypted=false`) and relaxed WinRM.
4. **WS-Man shell messages** (`src/winrm/messages.js`, `src/winrm/shell.js`) —
   `Create` (open cmd shell) → `Command` → `Receive` loop (streaming base64
   stdout/stderr + `CommandState`/`ExitCode`) → `Signal` (terminate) →
   `Delete` (close).

All of this runs in-browser; the password never leaves the machine (an NTLMv2
response is computed locally).

## Reuse

The cryptographic core is shared with the other tools in this repo (copied, so
each tool stays self-contained):

- `src/ntlm/seal.js` — NTLM sign+seal (key exchange, SIGNKEY/SEALKEY,
  `GSS_WrapEx`), `src/ntlm/ntlm.js`, `src/ntlm/spnego.js` — from `soaphound`.
- `src/crypto/{md4,md5,rc4}.js`, `src/ldap/ber.js` — shared primitives.

## Build

```bash
npm install
npm run keygen     # one-time: generate the Ed25519 signing key (fixes the app origin)
npm test           # offline tests: encryption round-trip, WS-Man messages, HTTP parsing
npm run build      # produces dist/evil-winrm-iwa.swbn
```

## Install in Chrome

Enable **Isolated Web Apps**, **IWA Developer Mode** and disable **Local Network
Access check** at `chrome://flags`, then install `dist/evil-winrm-iwa.swbn` via
`chrome://web-app-internals/`. The manifest grants `direct-sockets`,
`direct-sockets-private` and `cross-origin-isolated`.

## Usage

1. **Host / IP** + **WinRM port** (5985).
2. **Credentials** — `user`, `user@domain` or `DOMAIN\user`, plus optional Domain,
   and password.
3. **Connect** — opens the shell. Type commands at the prompt; output streams in.
   **Disconnect** closes the shell.

## Limitations / security notes

- **HTTP (5985) only — no HTTPS (5986).** `TCPSocket` has no TLS, so the 5986
  HTTPS listener is not reachable. Confidentiality on 5985 comes from NTLM message
  encryption (always on here), which is what default WinRM mandates anyway.
- **NTLM only** (no Kerberos), consistent with the other tools. Local and domain
  accounts both work (`user`, `DOMAIN\user`, `user@domain`).
- **No persistent runspace.** Each command is a fresh `powershell` invocation
  (true session state needs the MS-PSRP binary protocol). Working directory and
  loaded scripts are re-applied client-side (cwd tracking + preamble), but
  arbitrary variable state does not persist between commands.
- **Invoke .NET stages via a temp file.** The assembly is uploaded to `%TEMP%`,
  loaded into the CLR with `Assembly.Load([byte[]])` (executed in-process, not as
  a child process) and the temp file is deleted afterwards — so it touches disk
  briefly, unlike full Evil-WinRM's pure-memory load over a persistent runspace.
- **Ctrl+C latency** is up to the operation timeout (~30 s) for a command that is
  producing no output, since the interrupt is sent at the next receive boundary.
- One command at a time (no interactive PTY / stdin streaming).
- Output is decoded as UTF-8 (the PowerShell wrapper forces UTF-8 console output).

## Project layout

```
src/
  http/client.js     HTTP/1.1 over TCPSocket (keep-alive, chunked)
  ntlm/seal.js       NTLM sign+seal (GSS_WrapEx)            [shared with soaphound]
  ntlm/ntlm.js,spnego.js   NTLMv2 + SPNEGO                  [shared]
  crypto/, ldap/ber.js     MD4/MD5/RC4, BER concat helper   [shared]
  winrm/client.js    NTLM-over-HTTP auth + encrypted exchange
  winrm/crypt.js     multipart/encrypted wrap/unwrap (NTLM seal)
  winrm/messages.js  WS-Man SOAP builders + response extractors
  winrm/shell.js     open / run (streamed) / interrupt / preamble / close
  winrm/transfer.js  download / upload (chunked) / invoke-binary (in-memory .NET)
  main.js            terminal UI (history, Ctrl+C, transfer buttons)
public/              UI shell + IWA manifest
scripts/             keygen, icon generation, tests
rollup.config.js     bundles + signs the .swbn
```
