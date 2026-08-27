// AD CS enumeration over LDAP: the Enrollment Services (CAs) and Certificate
// Templates live under the Configuration naming context. We read the template
// flags, EKUs and security descriptors that the ESC checks reason about.

import { SCOPE, filter as F } from '../ldap/client.js';

const dec = new TextDecoder();

// Case-insensitive attribute access on a normalized query() row.
export function first(attrs, name) { const k = Object.keys(attrs).find((x) => x.toLowerCase() === name.toLowerCase()); return k ? attrs[k][0] : undefined; }
export function all(attrs, name) { const k = Object.keys(attrs).find((x) => x.toLowerCase() === name.toLowerCase()); return k ? attrs[k] : []; }

export async function discoverConfigNC(client) {
  for await (const e of client.ldap.search({ baseDN: '', scope: SCOPE.BASE, filter: F.present('objectClass'), attributes: ['configurationNamingContext'], pageSize: 1 })) {
    const v = e.attributes.configurationNamingContext || e.attributes.configurationnamingcontext;
    if (v && v.length) return dec.decode(v[0]);
  }
  return null;
}

const CA_ATTRS = ['cn', 'name', 'displayName', 'dNSHostName', 'cACertificate', 'certificateTemplates', 'nTSecurityDescriptor', 'msPKI-Enrollment-Servers', 'flags'];
const TPL_ATTRS = ['cn', 'name', 'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
  'msPKI-RA-Signature', 'msPKI-Minimal-Key-Size', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy',
  'msPKI-Template-Schema-Version', 'msPKI-Certificate-Policy', 'nTSecurityDescriptor'];

export async function enumerateCAs(client, configNC) {
  const base = `CN=Enrollment Services,CN=Public Key Services,CN=Services,${configNC}`;
  const out = [];
  for await (const o of client.query({ baseDN: base, filter: '(objectClass=pKIEnrollmentService)', attributes: CA_ATTRS })) out.push(o);
  return out;
}

export async function enumerateTemplates(client, configNC) {
  const base = `CN=Certificate Templates,CN=Public Key Services,CN=Services,${configNC}`;
  const out = [];
  for await (const o of client.query({ baseDN: base, filter: '(objectClass=pKICertificateTemplate)', attributes: TPL_ATTRS })) out.push(o);
  return out;
}

// Resolve a SID to a readable name: well-known table first, else an AD SID-bind
// (<SID=…>) base search. Cached on the client.
export async function resolveSid(client, sid, wellKnownName) {
  const wk = wellKnownName(sid);
  if (wk) return wk;
  client._sidCache = client._sidCache || new Map();
  if (client._sidCache.has(sid)) return client._sidCache.get(sid);
  let name = sid;
  try {
    for await (const e of client.ldap.search({ baseDN: `<SID=${sid}>`, scope: SCOPE.BASE, filter: F.present('objectClass'), attributes: ['sAMAccountName', 'name'], pageSize: 1 })) {
      const v = e.attributes.sAMAccountName || e.attributes.samaccountname || e.attributes.name;
      if (v && v.length) { name = dec.decode(v[0]); break; }
    }
  } catch { /* unresolved — keep the SID */ }
  client._sidCache.set(sid, name);
  return name;
}
