// LDAP data source for the BloodHound processors. SharpHound collects directory
// data over LDAP (389/636); this adapts the hand-rolled LDAP client to the same
// `query()` shape the shared bhdump/buildcache processors expect (the ones the
// soaphound tool drives over ADWS): each row is { dn, className, attributes },
// attributes are arrays of strings, and binary attributes (objectSid,
// objectGUID, nTSecurityDescriptor, …) are base64 — exactly what security/sid.js
// and security/sddl.js decode.
//
// Large multi-valued attributes use LDAP range retrieval (member;range=0-1499)
// and are completed here transparently, mirroring SharpHound.

import { LdapClient, SCOPE, filter as F } from './client.js';
import { tlv, octetString, concat as berConcat } from './ber.js';
import { ntlmSpnegoProducer, parseIdentity } from '../ntlm/sasl.js';
import { kerberosSpnegoBind } from '../kerberos/ldap-bind.js';
import { loadTls } from '../tls/index.js';

const dec = new TextDecoder();
const enc = new TextEncoder();

// Attributes whose raw bytes must survive as base64 (not UTF-8 text).
const BINARY = new Set([
  'objectsid', 'objectguid', 'ntsecuritydescriptor', 'sidhistory',
  'msds-allowedtoactonbehalfofotheridentity', 'securityidentifier', 'cacertificate',
]);

// Canonical casing for the attributes the processors read by exact name.
const CANON = {};
for (const n of [
  'distinguishedName', 'objectClass', 'objectSid', 'objectGUID', 'sAMAccountName',
  'sAMAccountType', 'name', 'ou', 'displayName', 'description', 'userAccountControl',
  'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'lastLogon', 'whenCreated',
  'servicePrincipalName', 'member', 'memberOf', 'primaryGroupID', 'gPLink',
  'gPCFileSysPath', 'nTSecurityDescriptor', 'dNSHostName', 'operatingSystem',
  'msDS-Behavior-Version', 'msDS-AllowedToDelegateTo',
  'msDS-AllowedToActOnBehalfOfOtherIdentity', 'trustDirection', 'trustType',
  'trustAttributes', 'securityIdentifier', 'objectCategory', 'sIDHistory',
]) CANON[n.toLowerCase()] = n;

function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return typeof btoa === 'function' ? btoa(s) : Buffer.from(s, 'binary').toString('base64');
}
const decodeValue = (name, u8) => (BINARY.has(name.toLowerCase()) ? b64(u8) : dec.decode(u8));

export class LdapBhClient {
  constructor(log = () => {}) {
    this.ldap = new LdapClient(log);
    this._log = log;
    this.pageSize = 1000;
  }

  async connect(host, port, creds) {
    await this.ldap.connect(host, port, creds.tls ? { tls: { TlsSession: loadTls(), sni: creds.sni || host } } : {});
    let channelBinding = null;
    if (creds.tls) {
      const cb = await this.ldap.channelBinding();
      channelBinding = cb && cb.applicationData;
      this._log(`TLS up — channel binding ${cb ? cb.hashName : 'none'}.`);
    }
    if (creds.authMethod === 'simple') {
      await this.ldap.bind(creds.bindDN, creds.password);
    } else if (creds.authMethod === 'kerberos') {
      const { user, domain } = parseIdentity(creds.user || creds.bindDN, creds.domain);
      const realm = creds.domain || domain;
      this._log(`Kerberos bind as ${user}@${realm} (ldap/${host}) …`);
      await kerberosSpnegoBind(this.ldap, {
        host, kdc: creds.kdc || null, realm, user,
        password: creds.password, hash: creds.hash || null, channelBinding, log: this._log,
      });
    } else {
      const { user, domain } = parseIdentity(creds.user || creds.bindDN, creds.domain);
      this._log(`NTLMv2 bind as ${domain ? domain + '\\' : ''}${user} …`);
      await this.ldap.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({ user, domain, password: creds.password, channelBinding, log: this._log }));
    }
  }

  async *query({ baseDN, filter = '(objectClass=*)', attributes = [] }) {
    const filt = parseFilter(filter);
    const needSD = attributes.some((a) => a.toLowerCase() === 'ntsecuritydescriptor');
    for await (const entry of this.ldap.search({
      baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes, pageSize: this.pageSize, sdFlags: needSD,
    })) {
      yield await this._normalize(entry);
    }
  }

  // Normalize one LDAP entry, completing any range-limited attributes.
  async _normalize(entry) {
    const attrs = {};
    const ranged = [];
    for (const [name, vals] of Object.entries(entry.attributes)) {
      const semi = name.indexOf(';range=');
      if (semi >= 0) {
        const base = name.slice(0, semi);
        const high = name.slice(semi + 7).split('-')[1];
        put(attrs, base, vals);
        if (high !== '*') ranged.push({ base, nextLow: Number(name.slice(semi + 7).split('-')[1]) + 1 });
      } else {
        put(attrs, name, vals);
      }
    }
    for (const r of ranged) await this._expandRange(entry.dn, r.base, r.nextLow, attrs);

    const dnKey = CANON.distinguishedname;
    if (!attrs[dnKey]) attrs[dnKey] = [entry.dn];
    const oc = attrs[CANON.objectclass] || [];
    return { dn: entry.dn, className: oc.length ? oc[oc.length - 1] : '', attributes: attrs };
  }

  // Pull remaining values of a ranged attribute via base-scoped reads.
  async _expandRange(dn, base, fromLow, attrs) {
    let low = fromLow;
    for (let guard = 0; guard < 100000; guard++) {
      let got = 0, done = false;
      for await (const entry of this.ldap.search({
        baseDN: dn, scope: SCOPE.BASE, filter: F.present('objectClass'),
        attributes: [`${base};range=${low}-*`], pageSize: 1,
      })) {
        for (const [name, vals] of Object.entries(entry.attributes)) {
          const semi = name.indexOf(';range=');
          if (semi < 0) continue;
          put(attrs, base, vals);
          got += vals.length;
          const high = name.slice(semi + 7).split('-')[1];
          if (high === '*') done = true; else low = Number(high) + 1;
        }
      }
      if (got === 0 || done) break;
    }
    this._log(`Range-retrieved ${base} for ${dn}: ${(attrs[CANON[base.toLowerCase()] || base] || []).length} value(s).`);
  }

  async close() { await this.ldap.close(); }
}

function put(attrs, name, vals) {
  const key = CANON[name.toLowerCase()] || name;
  const decoded = vals.map((v) => decodeValue(name, v));
  attrs[key] = attrs[key] ? attrs[key].concat(decoded) : decoded;
}

// ---- Minimal RFC 4515 filter string -> BER ---------------------------------
export function parseFilter(str) {
  let i = 0;
  const peek = () => str[i];
  const eat = (c) => { if (str[i] !== c) throw new Error(`bad filter at ${i}: expected ${c}`); i++; };

  function parse() {
    eat('(');
    let node;
    const c = peek();
    if (c === '&') { i++; node = F.and(...list()); }
    else if (c === '|') { i++; node = F.or(...list()); }
    else if (c === '!') { i++; node = tlv(0xa2, parse()); }
    else node = item();
    eat(')');
    return node;
  }
  function list() { const subs = []; while (peek() === '(') subs.push(parse()); return subs; }
  function item() {
    let attr = '';
    while (i < str.length && str[i] !== '=' && str[i] !== ')') attr += str[i++];
    eat('=');
    let val = '';
    while (i < str.length && str[i] !== ')') val += str[i++];
    if (val === '*') return F.present(attr);
    if (val.includes('*')) return substrings(attr, val);
    return F.equal(attr, unescapeLdap(val));
  }
  const f = parse();
  return f;
}

function substrings(attr, pattern) {
  const parts = pattern.split('*');
  const choices = [];
  if (parts[0]) choices.push(tlv(0x80, enc.encode(unescapeLdap(parts[0]))));        // initial
  for (let k = 1; k < parts.length - 1; k++) {
    if (parts[k]) choices.push(tlv(0x81, enc.encode(unescapeLdap(parts[k]))));       // any
  }
  const last = parts[parts.length - 1];
  if (last) choices.push(tlv(0x82, enc.encode(unescapeLdap(last))));                  // final
  return tlv(0xa4, berConcat([octetString(attr), tlv(0x30, berConcat(choices))]));
}

function unescapeLdap(s) {
  return s.replace(/\\([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
