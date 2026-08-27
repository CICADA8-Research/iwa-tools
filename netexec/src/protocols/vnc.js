import { concat } from '../ldap/ber.js';
import { desEncrypt } from '../crypto/des.js';

export async function vncScreen(host, _creds, opts, log) {
  const port = opts.port || 5900;
  try {
    const socket = new TCPSocket(host, port);
    const info = await socket.opened;
    const reader = info.readable.getReader();
    const writer = info.writable.getWriter();
    const { value } = await Promise.race([
      reader.read(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
    ]);
    if (value) {
      const banner = new TextDecoder().decode(value).trim();
      log('ok', 'vnc', host, 'VNC', banner);
      const noAuth = value.length > 12;
      if (banner.startsWith('RFB')) {
        await writer.write(value.slice(0, 12));
        try {
          const { value: secTypes } = await Promise.race([
            reader.read(),
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000)),
          ]);
          if (secTypes && secTypes.length > 0) {
            const numTypes = secTypes[0];
            const types = Array.from(secTypes.slice(1, 1 + numTypes));
            const names = { 1: 'None', 2: 'VNC', 30: 'Apple', 16: 'Tight' };
            log('ok', 'vnc', host, 'auth-types', types.map(t => names[t] || `type-${t}`).join(', '));
            if (types.includes(1)) log('warn', 'vnc', host, 'NO AUTH', 'VNC allows unauthenticated access');
          }
        } catch {}
      }
    }
    try { reader.releaseLock(); } catch {}
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
    return true;
  } catch (e) {
    log('err', 'vnc', host, 'VNC', e.message);
    return false;
  }
}

export async function vncBrute(host, creds, opts, log) {
  const port = opts.port || 5900;
  const pwd = creds.password || '';
  if (!pwd) { log('err', 'vnc', host, 'brute', 'no password specified (-p)'); return null; }
  try {
    const socket = new TCPSocket(host, port);
    const info = await socket.opened;
    const reader = info.readable.getReader();
    const writer = info.writable.getWriter();
    const cleanup = () => {
      try { reader.releaseLock(); } catch {}
      try { writer.releaseLock(); } catch {}
      try { socket.close(); } catch {}
    };
    const readTO = (ms) => Promise.race([
      reader.read(),
      new Promise((_, r) => setTimeout(() => r(new Error('timeout')), ms)),
    ]);
    const { value: verBuf } = await readTO(opts.timeout || 5000);
    if (!verBuf || verBuf.length < 12) { log('err', 'vnc', host, 'brute', 'no version'); cleanup(); return null; }
    await writer.write(verBuf.slice(0, 12));
    const { value: secBuf } = await readTO(3000);
    if (!secBuf || secBuf.length < 2) { log('err', 'vnc', host, 'brute', 'no security types'); cleanup(); return null; }
    const numTypes = secBuf[0];
    const types = Array.from(secBuf.slice(1, 1 + numTypes));
    if (!types.includes(2)) {
      if (types.includes(1)) log('warn', 'vnc', host, 'brute', 'no auth required (type 1)');
      else log('info', 'vnc', host, 'brute', `VNC auth (type 2) not available: ${types}`);
      cleanup(); return { success: types.includes(1), noAuth: types.includes(1) };
    }
    await writer.write(Uint8Array.of(2));
    const { value: challenge } = await readTO(3000);
    if (!challenge || challenge.length < 16) { log('err', 'vnc', host, 'brute', 'no challenge'); cleanup(); return null; }
    const keyBytes = new Uint8Array(8);
    for (let i = 0; i < 8 && i < pwd.length; i++) {
      let b = pwd.charCodeAt(i);
      b = ((b & 0x55) << 1) | ((b & 0xAA) >> 1);
      b = ((b & 0x33) << 2) | ((b & 0xCC) >> 2);
      b = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4);
      keyBytes[i] = b;
    }
    const resp = new Uint8Array(16);
    resp.set(desEncrypt(keyBytes, challenge.slice(0, 8)), 0);
    resp.set(desEncrypt(keyBytes, challenge.slice(8, 16)), 8);
    await writer.write(resp);
    const { value: result } = await readTO(3000);
    cleanup();
    if (result && result.length >= 4) {
      const status = new DataView(result.buffer, result.byteOffset).getUint32(0, false);
      if (status === 0) {
        log('ok', 'vnc', host, `${pwd}`, 'VNC auth SUCCESS');
        return { success: true, password: pwd };
      }
    }
    log('err', 'vnc', host, `${pwd}`, 'VNC auth failed');
    return { success: false };
  } catch (e) {
    log('err', 'vnc', host, 'brute', e.message);
    return null;
  }
}

export async function vncAuth(host, creds, opts, log) {
  return vncBrute(host, creds, opts, log);
}

export async function vncBanner(host, _creds, opts, log) {
  const port = opts.port || 5900;
  try {
    const socket = new TCPSocket(host, port);
    const info = await socket.opened;
    const reader = info.readable.getReader();
    const { value } = await Promise.race([
      reader.read(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
    ]);
    let banner = '';
    if (value) {
      banner = new TextDecoder().decode(value).trim();
      log('ok', 'vnc', host, 'banner', banner);
    }
    try { reader.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
    return banner;
  } catch (e) {
    log('err', 'vnc', host, 'banner', e.message);
    return null;
  }
}
