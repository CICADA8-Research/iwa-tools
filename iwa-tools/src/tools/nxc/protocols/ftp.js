import { concat } from '../ldap/ber.js';
import { loadTls, TlsSocket } from '../tls/index.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

class FtpClient {
  constructor(host, port = 21) {
    this._host = host;
    this._port = port;
    this._buf = new Uint8Array(0);
  }

  async connect() {
    this._socket = new TCPSocket(this._host, this._port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
    return this._readResponse();
  }

  async close() {
    try { await this._send('QUIT'); } catch {}
    try { this._reader?.releaseLock(); } catch {}
    try { this._writer?.releaseLock(); } catch {}
    try { await this._socket?.close(); } catch {}
  }

  async _send(cmd) {
    await this._writer.write(enc.encode(cmd + '\r\n'));
    return this._readResponse();
  }

  async _readResponse() {
    for (;;) {
      const text = dec.decode(this._buf);
      const match = text.match(/^(\d{3})[ ][^\r\n]*\r\n/m);
      if (match) {
        const end = text.indexOf(match[0]) + match[0].length;
        const full = text.slice(0, end);
        this._buf = enc.encode(text.slice(end));
        return { code: parseInt(match[1]), text: full.trim() };
      }
      const { value, done } = await this._reader.read();
      if (done) throw new Error('FTP: connection closed');
      this._buf = concat([this._buf, value]);
    }
  }

  async authTls() {
    const r = await this._send('AUTH TLS');
    if (r.code !== 234) throw new Error(`AUTH TLS: ${r.text}`);
    this._buf = new Uint8Array(0);
    const TlsSes = loadTls();
    const tls = new TlsSocket(TlsSes, this._reader, this._writer, this._host);
    await tls.handshake();
    this._reader = tls._reader;
    this._writer = tls._writer;
    this._isTls = true;
    await this._send('PBSZ 0');
    await this._send('PROT P');
  }

  async login(user, password) {
    let r = await this._send(`USER ${user}`);
    if (r.code === 331) r = await this._send(`PASS ${password}`);
    if (r.code !== 230) throw new Error(`FTP login failed: ${r.text}`);
    return r;
  }

  async pwd() { return this._send('PWD'); }
  async syst() { return this._send('SYST'); }

  async _pasv() {
    const r = await this._send('PASV');
    if (r.code !== 227) throw new Error(`PASV failed: ${r.text}`);
    const m = r.text.match(/(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/);
    if (!m) throw new Error('PASV: cannot parse address');
    const host = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
    const port = parseInt(m[5]) * 256 + parseInt(m[6]);
    return { host, port };
  }

  async _dataTransfer(cmd) {
    const { host, port } = await this._pasv();
    const dataSock = new TCPSocket(host, port);
    const info = await dataSock.opened;
    let dataReader = info.readable.getReader();
    let dataWriter = info.writable.getWriter();
    if (this._isTls) {
      const TlsSes = loadTls();
      const dtls = new TlsSocket(TlsSes, dataReader, dataWriter, this._host);
      await dtls.handshake();
      dataReader = dtls._reader;
      dataWriter = dtls._writer;
    }
    const ctrlResp = this._send(cmd);
    // First control reply after RETR/LIST/etc: 1xx (150 Opening data connection)
    // if the transfer will happen; 4xx/5xx (e.g. 550 Failed to open file) if
    // the server rejects the command outright. In the rejection case the data
    // socket never sees any bytes — if we naively drain it to EOF we'd hang
    // until server-side timeout (impacket's default is 30 s). Check the
    // control response first and abort early on any non-1xx.
    const firstReply = await ctrlResp;
    if (firstReply.code >= 400) {
      try { dataReader.releaseLock(); } catch {}
      try { dataWriter.releaseLock(); } catch {}
      try { await dataSock.close(); } catch {}
      throw new Error(`FTP ${cmd.split(' ')[0]} failed: ${firstReply.text}`);
    }
    // 1xx = intermediate "opening" reply. Drain data now.
    const chunks = [];
    for (;;) {
      const { value, done } = await dataReader.read();
      if (done) break;
      chunks.push(value);
    }
    try { dataReader.releaseLock(); } catch {}
    try { dataWriter.releaseLock(); } catch {}
    try { await dataSock.close(); } catch {}
    // Final 2xx (226 Transfer complete).
    const done = await this._readResponse();
    return { data: concat(chunks), resp: done };
  }

  async list(path = '') {
    const cmd = path ? `LIST ${path}` : 'LIST';
    const { data } = await this._dataTransfer(cmd);
    return dec.decode(data);
  }

  async retr(path) {
    const { data } = await this._dataTransfer(`RETR ${path}`);
    return data;
  }

  async stor(path, content) {
    const { host, port } = await this._pasv();
    const dataSock = new TCPSocket(host, port);
    const info = await dataSock.opened;
    let dataReader = info.readable.getReader();
    let dataWriter = info.writable.getWriter();
    if (this._isTls) {
      const TlsSes = loadTls();
      const dtls = new TlsSocket(TlsSes, dataReader, dataWriter, this._host);
      await dtls.handshake();
      dataWriter = dtls._writer;
    }
    const ctrlResp = this._send(`STOR ${path}`);
    // Same guard as _dataTransfer — server may reject STOR outright (5xx),
    // in which case writing to the data socket races the server-side close.
    const firstReply = await ctrlResp;
    if (firstReply.code >= 400) {
      try { dataReader.releaseLock(); } catch {}
      try { dataWriter.releaseLock(); } catch {}
      try { await dataSock.close(); } catch {}
      throw new Error(`FTP STOR failed: ${firstReply.text}`);
    }
    const payload = typeof content === 'string' ? enc.encode(content) : content;
    await dataWriter.write(payload);
    try { dataReader.releaseLock(); } catch {}
    try { dataWriter.releaseLock(); } catch {}
    try { await dataSock.close(); } catch {}
    return await this._readResponse();
  }
}

export async function ftpAuth(host, creds, opts, log) {
  const client = new FtpClient(host, opts.port || 21);
  try {
    const banner = await client.connect();
    log('info', 'ftp', host, 'banner', banner.text);
    if (opts.tls) {
      await client.authTls();
      log('ok', 'ftp', host, 'tls', 'AUTH TLS OK');
    }
    await client.login(creds.user, creds.password);
    log('ok', 'ftp', host, `${creds.user}`, `login OK${opts.tls ? ' (FTPS)' : ''}`);
    await client.close();
    return true;
  } catch (e) {
    log('err', 'ftp', host, `${creds.user}`, e.message);
    try { await client.close(); } catch {}
    return false;
  }
}

export async function ftpAnon(host, _creds, opts, log) {
  const client = new FtpClient(host, opts.port || 21);
  try {
    const banner = await client.connect();
    log('info', 'ftp', host, 'banner', banner.text);
    await client.login('anonymous', 'anonymous@');
    log('ok', 'ftp', host, 'anonymous', 'anonymous login OK');
    const syst = await client.syst();
    log('ok', 'ftp', host, 'system', syst.text);
    await client.close();
    return true;
  } catch (e) {
    log('err', 'ftp', host, 'anonymous', 'anonymous login failed');
    try { await client.close(); } catch {}
    return false;
  }
}

export async function ftpLs(host, creds, opts, log, path) {
  const client = new FtpClient(host, opts.port || 21);
  try {
    await client.connect();
    if (opts.tls) await client.authTls();
    await client.login(creds.user, creds.password);
    const listing = await client.list(path || '');
    for (const line of listing.split('\n')) {
      const trimmed = line.trim();
      if (trimmed) log('ok', 'ftp', host, '', trimmed);
    }
    await client.close();
    return listing;
  } catch (e) {
    log('err', 'ftp', host, 'ls', e.message);
    try { await client.close(); } catch {}
    return null;
  }
}

export async function ftpGet(host, creds, opts, log, path) {
  if (!path) { log('err', 'ftp', host, 'get', 'no path specified'); return null; }
  const client = new FtpClient(host, opts.port || 21);
  try {
    await client.connect();
    if (opts.tls) await client.authTls();
    await client.login(creds.user, creds.password);
    const data = await client.retr(path);
    log('ok', 'ftp', host, path, `${data.length} bytes downloaded`);
    await client.close();
    return data;
  } catch (e) {
    log('err', 'ftp', host, 'get', e.message);
    try { await client.close(); } catch {}
    return null;
  }
}

export async function ftpPut(host, creds, opts, log, args) {
  if (!args) { log('err', 'ftp', host, 'put', 'usage: path data'); return null; }
  const idx = args.indexOf(' ');
  const path = idx > 0 ? args.slice(0, idx) : args;
  const data = idx > 0 ? args.slice(idx + 1) : '';
  const client = new FtpClient(host, opts.port || 21);
  try {
    await client.connect();
    if (opts.tls) await client.authTls();
    await client.login(creds.user, creds.password);
    await client.stor(path, data);
    log('ok', 'ftp', host, path, `${data.length} bytes uploaded`);
    await client.close();
    return true;
  } catch (e) {
    log('err', 'ftp', host, 'put', e.message);
    try { await client.close(); } catch {}
    return null;
  }
}

export async function ftpBrute(host, creds, opts, log) {
  const passwords = ['', 'admin', 'password', 'pass', '123456', 'ftp', 'guest', 'root', 'test',
    'admin123', 'password123', '1234', '12345', '123456789', 'admin1', 'letmein',
    creds.user, creds.password].filter(Boolean);
  const users = [creds.user, 'admin', 'ftp', 'anonymous', 'root', 'test', 'guest', 'user'].filter((v, i, a) => a.indexOf(v) === i);
  let found = 0;
  for (const user of users) {
    for (const pass of passwords) {
      const client = new FtpClient(host, opts.port || 21);
      try {
        await client.connect();
        if (opts.tls) await client.authTls();
        await client.login(user, pass);
        log('ok', 'ftp', host, `${user}:${pass}`, 'LOGIN SUCCESS');
        found++;
        await client.close();
      } catch {
        try { await client.close(); } catch {}
      }
    }
  }
  if (found === 0) log('info', 'ftp', host, 'brute', 'no valid credentials found');
  else log('ok', 'ftp', host, 'brute', `${found} valid credential(s) found`);
  return found;
}

export async function ftpBanner(host, creds, opts, log) {
  const client = new FtpClient(host, opts.port || 21);
  try {
    const resp = await client.connect();
    log('ok', 'ftp', host, 'banner', resp);
    await client.close();
    return resp;
  } catch (e) {
    log('err', 'ftp', host, 'banner', e.message);
    try { await client.close(); } catch {}
    return null;
  }
}

export async function ftpSpider(host, creds, opts, log) {
  try {
    const client = new FtpClient(host, opts.port || 21);
    await client.connect();
    if (creds.user) {
      await client.login(creds.user, creds.password);
    } else {
      await client.login('anonymous', 'anonymous@');
    }

    const visited = new Set();
    const maxDepth = opts.depth || 3;
    const interesting = [];
    const patterns = [/\.txt$/i, /\.cfg$/i, /\.conf$/i, /\.ini$/i, /\.bak$/i, /\.sql$/i, /\.log$/i,
      /\.env$/i, /\.key$/i, /\.pem$/i, /\.cer$/i, /\.pfx$/i, /\.xml$/i, /\.json$/i,
      /password/i, /cred/i, /secret/i, /backup/i, /dump/i];

    async function crawl(dir, depth) {
      if (depth > maxDepth || visited.has(dir)) return;
      visited.add(dir);
      try {
        const listing = await client.list(dir);
        for (const entry of listing) {
          const fullPath = `${dir}/${entry.name}`.replace(/\/+/g, '/');
          if (entry.type === 'd') {
            log('ok', 'ftp', host, 'dir', fullPath);
            await crawl(fullPath, depth + 1);
          } else {
            const isInteresting = patterns.some(p => p.test(entry.name));
            if (isInteresting) {
              log('warn', 'ftp', host, 'INTERESTING', `${fullPath} (${entry.size || '?'} bytes)`);
              interesting.push(fullPath);
            } else {
              log('ok', 'ftp', host, 'file', `${fullPath} (${entry.size || '?'} bytes)`);
            }
          }
        }
      } catch {}
    }

    await crawl('/', 0);
    log('ok', 'ftp', host, 'spider', `${visited.size} dir(s), ${interesting.length} interesting file(s)`);
    await client.close();
    return interesting;
  } catch (e) {
    log('err', 'ftp', host, 'spider', e.message);
    return null;
  }
}

export async function ftpWrite(host, creds, opts, log) {
  try {
    const client = new FtpClient(host, opts.port || 21);
    await client.connect();
    if (creds.user) {
      await client.login(creds.user, creds.password);
    } else {
      await client.login('anonymous', 'anonymous@');
    }

    const testFile = `.nxc_write_test_${Date.now()}`;
    try {
      const data = new TextEncoder().encode('nxc write test\n');
      await client.stor(testFile, data);
      log('warn', 'ftp', host, 'writable', 'FTP server allows file upload!');
      try { await client.dele(testFile); } catch {}
      await client.close();
      return true;
    } catch {
      log('ok', 'ftp', host, 'write-check', 'server does not allow writes');
      await client.close();
      return false;
    }
  } catch (e) {
    log('err', 'ftp', host, 'write-check', e.message);
    return null;
  }
}
