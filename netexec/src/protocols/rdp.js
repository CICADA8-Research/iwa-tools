import { concat } from '../ldap/ber.js';

export async function rdpScreen(host, _creds, opts, log) {
  const port = opts.port || 3389;
  try {
    const socket = new TCPSocket(host, port);
    const info = await socket.opened;
    const reader = info.readable.getReader();
    const writer = info.writable.getWriter();
    const connReq = buildX224ConnReq();
    await writer.write(connReq);
    const { value } = await Promise.race([
      reader.read(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
    ]);
    if (value && value.length > 0) {
      const nla = value.length > 19 && value[19] !== 0;
      log('ok', 'rdp', host, 'RDP', nla ? 'NLA required' : 'NLA not required');
    } else {
      log('ok', 'rdp', host, 'RDP', 'port open');
    }
    try { reader.releaseLock(); } catch {}
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
    return true;
  } catch (e) {
    log('err', 'rdp', host, 'RDP', e.message);
    return false;
  }
}

function buildX224ConnReq(requestedProtocols = 0x03) {
  const cookie = new TextEncoder().encode('Cookie: mstshash=nxc\r\n');
  const rdpNegReq = new Uint8Array(8);
  rdpNegReq[0] = 0x01; rdpNegReq[2] = 0x08;
  new DataView(rdpNegReq.buffer).setUint32(4, requestedProtocols, true);
  // X.224 CR TPDU (ISO 8073 §13.3): LI (1) + Code (1) + DST-REF (2) +
  // SRC-REF (2) + Class (1) = 7 fixed bytes, followed by the variable part
  // (cookie + RDP Negotiation Request). LI counts every byte after itself.
  const x224Len = 7 + cookie.length + rdpNegReq.length;
  const tpktLen = 4 + x224Len;
  const pkt = new Uint8Array(tpktLen);
  pkt[0] = 0x03; pkt[1] = 0x00;
  new DataView(pkt.buffer).setUint16(2, tpktLen, false);
  pkt[4] = x224Len - 1;
  pkt[5] = 0xe0;
  pkt[6] = 0x00; pkt[7] = 0x00;
  pkt[8] = 0x00; pkt[9] = 0x00;
  pkt[10] = 0x00;
  pkt.set(cookie, 11);
  pkt.set(rdpNegReq, 11 + cookie.length);
  return pkt;
}

function berLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  return Uint8Array.of(0x82, (n >> 8) & 0xFF, n & 0xFF);
}

function buildBlueKeepMcsCI() {
  const csCore = new Uint8Array(216);
  csCore[0] = 0x01; csCore[1] = 0xC0;
  csCore[2] = 0xD8; csCore[3] = 0x00;
  csCore[4] = 0x04; csCore[5] = 0x00; csCore[6] = 0x08; csCore[7] = 0x00;
  csCore[8] = 0x00; csCore[9] = 0x04;
  csCore[10] = 0x00; csCore[11] = 0x03;
  csCore[12] = 0x01; csCore[13] = 0xCA;
  csCore[14] = 0x03; csCore[15] = 0xAA;
  csCore[16] = 0x09; csCore[17] = 0x04;
  csCore[20] = 0xCE; csCore[21] = 0x0E;
  csCore[56] = 0x04;
  csCore[64] = 0x0C;
  csCore[132] = 0x01; csCore[133] = 0xCA;
  csCore[134] = 0x01;
  csCore[140] = 0x18;
  csCore[142] = 0x07;
  csCore[144] = 0x01;

  const csNet = new Uint8Array(20);
  csNet[0] = 0x03; csNet[1] = 0xC0;
  csNet[2] = 0x14; csNet[3] = 0x00;
  csNet[4] = 0x01;
  const enc = new TextEncoder();
  csNet.set(enc.encode('MS_T120'), 8);
  csNet[19] = 0x80;

  const clientData = concat([csCore, csNet]);
  const gccInner = concat([
    new Uint8Array([0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
                    0x44, 0x75, 0x63, 0x61]),
    berLen(clientData.length), clientData,
  ]);
  const gccData = concat([
    new Uint8Array([0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01]),
    berLen(gccInner.length), gccInner,
  ]);

  const domainParams = new Uint8Array([
    0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
    0x02, 0x02, 0xFF, 0xFF, 0x02, 0x01, 0x02,
  ]);
  const minParams = new Uint8Array([
    0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
    0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
    0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02,
  ]);
  const maxParams = new Uint8Array([
    0x30, 0x1C, 0x02, 0x02, 0xFF, 0xFF, 0x02, 0x02, 0xFC, 0x17,
    0x02, 0x02, 0xFF, 0xFF, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x01, 0x02, 0x02, 0xFF, 0xFF, 0x02, 0x01, 0x02,
  ]);

  const userData = concat([Uint8Array.of(0x04), berLen(gccData.length), gccData]);
  const mcsBody = concat([
    Uint8Array.of(0x04, 0x01, 0x01),
    Uint8Array.of(0x04, 0x01, 0x01),
    Uint8Array.of(0x01, 0x01, 0xFF),
    domainParams, minParams, maxParams, userData,
  ]);
  const mcsCI = concat([Uint8Array.of(0x7F, 0x65), berLen(mcsBody.length), mcsBody]);
  const x224Data = Uint8Array.of(0x02, 0xF0, 0x80);
  const totalLen = 4 + x224Data.length + mcsCI.length;
  const tpkt = new Uint8Array(4);
  tpkt[0] = 0x03; tpkt[1] = 0x00;
  new DataView(tpkt.buffer).setUint16(2, totalLen, false);
  return concat([tpkt, x224Data, mcsCI]);
}

export async function rdpBlueKeep(host, _creds, opts, log) {
  const port = opts.port || 3389;
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
      new Promise(r => setTimeout(() => r({ value: null, done: true }), ms)),
    ]);
    await writer.write(buildX224ConnReq(0x00));
    const { value: ccResp } = await readTO(opts.timeout || 5000);
    if (!ccResp || ccResp.length < 11) {
      log('info', 'rdp', host, 'bluekeep', 'no RDP response'); cleanup(); return null;
    }
    if (ccResp[5] !== 0xD0) {
      log('info', 'rdp', host, 'bluekeep', 'unexpected X224 response'); cleanup(); return null;
    }
    if (ccResp.length > 11 && ccResp[11] === 0x03) {
      log('ok', 'rdp', host, 'bluekeep', 'NLA required — not vulnerable to CVE-2019-0708');
      cleanup(); return { vulnerable: false };
    }
    await writer.write(buildBlueKeepMcsCI());
    const { value: mcsResp, done } = await readTO(4000);
    if (done || !mcsResp || mcsResp.length === 0) {
      log('ok', 'rdp', host, 'bluekeep', 'not vulnerable (connection dropped after MS_T120)');
      cleanup(); return { vulnerable: false };
    }
    if (mcsResp[0] === 0x03 && mcsResp.length > 7) {
      log('warn', 'rdp', host, 'bluekeep', 'VULNERABLE — CVE-2019-0708 (server accepted MS_T120 channel)');
      cleanup(); return { vulnerable: true };
    }
    log('info', 'rdp', host, 'bluekeep', 'inconclusive'); cleanup(); return { vulnerable: null };
  } catch (e) {
    log('err', 'rdp', host, 'bluekeep', e.message);
    return null;
  }
}

export async function rdpNla(host, _creds, opts, log) {
  const port = opts.port || 3389;
  try {
    const socket = new TCPSocket(host, port);
    const info = await socket.opened;
    const reader = info.readable.getReader();
    const writer = info.writable.getWriter();

    await writer.write(buildX224ConnReq(0x03));
    const { value } = await Promise.race([
      reader.read(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
    ]);

    if (value && value.length > 11) {
      if (value[11] === 0x02) {
        const selectedProtocol = value.length > 15 ? new DataView(value.buffer, value.byteOffset).getUint32(12, true) : 0;
        const protocols = [];
        if (selectedProtocol & 0x01) protocols.push('TLS');
        if (selectedProtocol & 0x02) protocols.push('CredSSP/NLA');
        if (selectedProtocol === 0) protocols.push('Standard RDP');
        log('ok', 'rdp', host, 'nla', `selected: ${protocols.join('+') || 'standard'}`);
      } else if (value[11] === 0x03) {
        log('warn', 'rdp', host, 'nla', 'negotiation failure — NLA required but not offered');
      } else {
        log('ok', 'rdp', host, 'nla', 'unknown negotiation response');
      }
    }

    try { reader.releaseLock(); } catch {}
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
    return true;
  } catch (e) {
    log('err', 'rdp', host, 'nla', e.message);
    return null;
  }
}

export async function rdpBanner(host, _creds, opts, log) {
  return rdpScreen(host, _creds, opts, log);
}
