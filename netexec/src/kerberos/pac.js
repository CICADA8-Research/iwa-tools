import { concat } from '../ldap/ber.js';
import { md5, hmacMd5 } from '../crypto/md5.js';
import { checksum as krbChecksum, checksumType } from './crypto.js';
import { ETYPE } from './constants.js';

// ---- SID utilities ----------------------------------------------------------

export function parseSidString(s) {
  const parts = s.split('-');
  return {
    revision: parseInt(parts[1], 10),
    identifierAuthority: parseInt(parts[2], 10),
    subAuthorities: parts.slice(3).map(x => parseInt(x, 10) >>> 0),
  };
}

export function encodeSid(sid) {
  const n = sid.subAuthorities.length;
  const buf = new Uint8Array(8 + n * 4);
  buf[0] = sid.revision; buf[1] = n;
  buf[7] = sid.identifierAuthority & 0xFF;
  buf[6] = (sid.identifierAuthority >> 8) & 0xFF;
  buf[5] = (sid.identifierAuthority >> 16) & 0xFF;
  const dv = new DataView(buf.buffer);
  for (let i = 0; i < n; i++) dv.setUint32(8 + i * 4, sid.subAuthorities[i], true);
  return buf;
}

// ---- FILETIME ---------------------------------------------------------------

const EPOCH_DIFF = 116444736000000000n;

function dateToFiletime(date) {
  const buf = new Uint8Array(8);
  const ft = BigInt(date.getTime()) * 10000n + EPOCH_DIFF;
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, Number(ft & 0xFFFFFFFFn), true);
  dv.setUint32(4, Number((ft >> 32n) & 0xFFFFFFFFn), true);
  return buf;
}

const NEVER = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);

// ---- UTF-16LE ---------------------------------------------------------------

function toUtf16(str) {
  const buf = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    buf[i * 2] = str.charCodeAt(i) & 0xFF;
    buf[i * 2 + 1] = (str.charCodeAt(i) >> 8) & 0xFF;
  }
  return buf;
}

// ---- NDR helpers ------------------------------------------------------------

function u32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return b; }
function u16(v) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v & 0xFFFF, true); return b; }
function i32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v, true); return b; }

// ---- PAC Checksum -----------------------------------------------------------

const KERB_NON_KERB_CKSUM_SALT = 17;

function pacChecksumHmacMd5(key, usage, data) {
  const ksign = hmacMd5(key, i32(usage));
  return hmacMd5(ksign, md5(data));
}

function pacChecksum(etype, key, data) {
  if (etype === ETYPE.RC4_HMAC) return pacChecksumHmacMd5(key, KERB_NON_KERB_CKSUM_SALT, data);
  return krbChecksum(etype, key, KERB_NON_KERB_CKSUM_SALT, data);
}

function pacCksumType(etype) {
  if (etype === ETYPE.RC4_HMAC) return -138;
  return checksumType(etype);
}

function pacCksumSize(etype) {
  return etype === ETYPE.RC4_HMAC ? 16 : 12;
}

// ---- KERB_VALIDATION_INFO (NDR) --------------------------------------------

const GROUP_ATTRS = 7; // SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED

function buildValidationInfo({
  username, fullName = '', domain, domainSid,
  userId = 500, primaryGroupId = 513,
  groupIds = [513, 512, 520, 518, 519],
  logonTime,
}) {
  const now = logonTime || new Date();
  const sid = typeof domainSid === 'string' ? parseSidString(domainSid) : domainSid;
  const shortDomain = domain.split('.')[0].toUpperCase();

  let nextRef = 0x00020000;
  const fixed = [];
  const deferred = [];

  const addStr = (str) => {
    const utf = toUtf16(str);
    const len = utf.length;
    fixed.push(u16(len), u16(len));
    if (len > 0) {
      fixed.push(u32(nextRef++));
      const chars = len / 2;
      const pad = (chars % 2) ? 2 : 0;
      deferred.push(concat([u32(chars), u32(0), u32(chars), utf, new Uint8Array(pad)]));
    } else {
      fixed.push(u32(0));
    }
  };

  // Type serialization v1 header (16 bytes, objectBufferLength filled later)
  const hdr = new Uint8Array(16);
  hdr[0] = 1; hdr[1] = 0x10;
  new DataView(hdr.buffer).setUint16(2, 8, true);
  hdr[4] = 0xCC; hdr[5] = 0xCC; hdr[6] = 0xCC; hdr[7] = 0xCC;

  // Top-level unique pointer referent
  fixed.push(u32(nextRef++));

  // FILETIMEs
  fixed.push(dateToFiletime(now)); // LogonTime
  fixed.push(NEVER);               // LogoffTime
  fixed.push(NEVER);               // KickOffTime
  fixed.push(dateToFiletime(now)); // PasswordLastSet
  fixed.push(dateToFiletime(now)); // PasswordCanChange
  fixed.push(NEVER);               // PasswordMustChange

  // RPC_UNICODE_STRING fields
  addStr(username);     // EffectiveName
  addStr(fullName);     // FullName
  addStr('');           // LogonScript
  addStr('');           // ProfilePath
  addStr('');           // HomeDirectory
  addStr('');           // HomeDirectoryDrive

  fixed.push(u16(0), u16(0)); // LogonCount, BadPasswordCount
  fixed.push(u32(userId));
  fixed.push(u32(primaryGroupId));

  // GroupIds
  fixed.push(u32(groupIds.length));
  fixed.push(u32(nextRef++));
  const grpBuf = [u32(groupIds.length)];
  for (const g of groupIds) { grpBuf.push(u32(g), u32(GROUP_ATTRS)); }
  deferred.push(concat(grpBuf));

  fixed.push(u32(0));           // UserFlags
  fixed.push(new Uint8Array(16)); // UserSessionKey

  addStr(shortDomain); // LogonServer
  addStr(shortDomain); // LogonDomainName

  // LogonDomainId SID pointer
  fixed.push(u32(nextRef++));
  const sidBin = encodeSid(sid);
  deferred.push(concat([u32(sid.subAuthorities.length), sidBin]));

  fixed.push(new Uint8Array(8)); // Reserved1[2]
  fixed.push(u32(0x10));         // UserAccountControl = UF_NORMAL_ACCOUNT
  fixed.push(u32(0));            // SubAuthStatus
  fixed.push(new Uint8Array(8)); // LastSuccessfulILogon
  fixed.push(new Uint8Array(8)); // LastFailedILogon
  fixed.push(u32(0));            // FailedILogonCount
  fixed.push(u32(0));            // Reserved3
  fixed.push(u32(0));            // SidCount
  fixed.push(u32(0));            // ExtraSids (NULL)
  fixed.push(u32(0));            // ResourceGroupDomainSid (NULL)
  fixed.push(u32(0));            // ResourceGroupCount
  fixed.push(u32(0));            // ResourceGroupIds (NULL)

  const ndrData = concat([...fixed, ...deferred]);
  new DataView(hdr.buffer).setUint32(8, ndrData.length, true);
  return concat([hdr, ndrData]);
}

// ---- PAC_CLIENT_INFO (type 10) -----------------------------------------------

function buildClientInfo(username, logonTime) {
  const utf = toUtf16(username);
  const buf = new Uint8Array(10 + utf.length);
  buf.set(dateToFiletime(logonTime), 0);
  new DataView(buf.buffer).setUint16(8, utf.length, true);
  buf.set(utf, 10);
  return buf;
}

// ---- PAC_UPN_DNS_INFO (type 12) -----------------------------------------------

function buildUpnDnsInfo(username, domain) {
  const upn = toUtf16(`${username}@${domain}`);
  const dns = toUtf16(domain.toUpperCase());
  const H = 16;
  const buf = new Uint8Array(H + upn.length + dns.length);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, upn.length, true);
  dv.setUint16(2, H, true);
  dv.setUint16(4, dns.length, true);
  dv.setUint16(6, H + upn.length, true);
  buf.set(upn, H);
  buf.set(dns, H + upn.length);
  return buf;
}

// ---- PAC Assembly -----------------------------------------------------------

function pad8(n) { return (8 - (n % 8)) % 8; }

export function buildPac({
  username, fullName = '', domain, domainSid,
  userId = 500, primaryGroupId = 513,
  groupIds = [513, 512, 520, 518, 519],
  key, etype, logonTime = null,
}) {
  const now = logonTime || new Date();
  const csz = pacCksumSize(etype);
  const ctype = pacCksumType(etype);

  const logonInfo = buildValidationInfo({ username, fullName, domain, domainSid, userId, primaryGroupId, groupIds, logonTime: now });
  const clientInfo = buildClientInfo(username, now);
  const upnDns = buildUpnDnsInfo(username, domain);

  const mkSig = () => {
    const b = new Uint8Array(4 + csz + 2);
    new DataView(b.buffer).setInt32(0, ctype, true);
    return b;
  };
  const srvSig = mkSig();
  const kdcSig = mkSig();

  const bufs = [
    { type: 1, data: logonInfo },
    { type: 10, data: clientInfo },
    { type: 12, data: upnDns },
    { type: 6, data: srvSig },
    { type: 7, data: kdcSig },
  ];

  const N = bufs.length;
  const hdrSz = 8 + N * 16;
  let off = hdrSz;
  const offsets = [];
  for (const b of bufs) {
    offsets.push(off);
    off += b.data.length + pad8(b.data.length);
  }

  const pac = new Uint8Array(off);
  const pdv = new DataView(pac.buffer);
  pdv.setUint32(0, N, true);
  pdv.setUint32(4, 0, true);
  for (let i = 0; i < N; i++) {
    const base = 8 + i * 16;
    pdv.setUint32(base, bufs[i].type, true);
    pdv.setUint32(base + 4, bufs[i].data.length, true);
    pdv.setUint32(base + 8, offsets[i], true);
    pdv.setUint32(base + 12, 0, true);
    pac.set(bufs[i].data, offsets[i]);
  }

  const srvOff = offsets[bufs.findIndex(b => b.type === 6)] + 4;
  const kdcOff = offsets[bufs.findIndex(b => b.type === 7)] + 4;

  const srvCk = pacChecksum(etype, key, pac);
  pac.set(srvCk.subarray(0, csz), srvOff);
  const kdcCk = pacChecksum(etype, key, srvCk.subarray(0, csz));
  pac.set(kdcCk.subarray(0, csz), kdcOff);

  return pac;
}
