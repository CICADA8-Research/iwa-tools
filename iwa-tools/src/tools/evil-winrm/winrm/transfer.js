// File transfer and in-memory .NET execution over the WinRM shell, built on top
// of the (stateless) PowerShell command runner. Bytes move as base64 through
// command output (download) and command input (upload, chunked to stay under
// the command-line length limit).

const enc = new TextEncoder();

function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return typeof btoa === 'function' ? btoa(s) : Buffer.from(s, 'binary').toString('base64');
}
function b64decode(s) {
  const clean = s.replace(/\s+/g, '');
  return typeof atob === 'function'
    ? Uint8Array.from(atob(clean), (c) => c.charCodeAt(0))
    : Uint8Array.from(Buffer.from(clean, 'base64'));
}
// PowerShell single-quoted literal.
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;

// Download a remote file -> Uint8Array. Reads it as one base64 blob.
export async function download(shell, remotePath) {
  const ps = `[Convert]::ToBase64String([IO.File]::ReadAllBytes(${q(remotePath)}))`;
  const r = await shell.run(ps);
  if (r.stderr && r.stderr.trim()) throw new Error(r.stderr.trim().split('\n')[0]);
  const data = (r.stdout || '').trim();
  if (!data) throw new Error('empty response (file missing or unreadable?)');
  return b64decode(data);
}

// Upload bytes to a remote path, chunked. Each chunk is a separate command so
// the wrapped `powershell -EncodedCommand <b64>` line stays well under cmd's
// ~8KB limit (1500 raw bytes -> ~2KB base64 -> ~ fits comfortably).
export async function upload(shell, remotePath, bytes, onProgress = () => {}) {
  const CHUNK = 1500;
  if (bytes.length === 0) {
    await shell.run(`[IO.File]::WriteAllBytes(${q(remotePath)}, New-Object byte[] 0)`);
    return 0;
  }
  for (let off = 0; off < bytes.length; off += CHUNK) {
    const piece = b64encode(bytes.subarray(off, off + CHUNK));
    let ps;
    if (off === 0) {
      ps = `[IO.File]::WriteAllBytes(${q(remotePath)}, [Convert]::FromBase64String('${piece}'))`;
    } else {
      ps = `$f=[IO.File]::Open(${q(remotePath)}, [IO.FileMode]::Append); ` +
        `$b=[Convert]::FromBase64String('${piece}'); $f.Write($b,0,$b.Length); $f.Close()`;
    }
    const r = await shell.run(ps);
    if (r.stderr && r.stderr.trim()) throw new Error(r.stderr.trim().split('\n')[0]);
    onProgress(Math.min(off + CHUNK, bytes.length), bytes.length);
  }
  return bytes.length;
}

// Run a .NET assembly in memory. The assembly is staged to %TEMP% (via chunked
// upload), then Assembly.Load([byte[]]) loads it into the CLR and its EntryPoint
// is invoked in-process; the temp file is removed afterwards. Console output is
// captured via the normal command stdout. onData streams output live.
export async function invokeBinary(shell, bytes, args = [], onData = () => {}) {
  const name = `wr_${randHex(8)}.bin`;
  // Resolve a concrete temp path on the target.
  const tmp = (await shell.run(`Write-Output (Join-Path $env:TEMP ${q(name)})`)).stdout.trim().split(/\r?\n/)[0];
  if (!tmp) throw new Error('could not resolve %TEMP% on the target');
  await upload(shell, tmp, bytes);
  // Load the assembly into the CLR and invoke its entry point, then delete.
  const argArr = '[string[]]@(' + args.map((a) => `'${String(a).replace(/'/g, "''")}'`).join(',') + ')';
  const ps =
    'try { ' +
    `$a=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes(${q(tmp)})); ` +
    '$ep=$a.EntryPoint; ' +
    `if ($ep.GetParameters().Length -eq 1) { [void]$ep.Invoke($null, @(,${argArr})) } else { [void]$ep.Invoke($null, $null) } ` +
    `} finally { Remove-Item -Force ${q(tmp)} -ErrorAction SilentlyContinue }`;
  return shell.run(ps, { onStdout: (t) => onData('stdout', t), onStderr: (t) => onData('stderr', t) });
}

function randHex(n) {
  const b = new Uint8Array(n);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export { b64encode, b64decode };
