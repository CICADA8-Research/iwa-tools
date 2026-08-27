// --buildcache: enumerate every object and record a compact map of
//   ValueToIdCache: DN (uppercased) -> object identifier (SID, or GUID when the
//                   object has no SID, e.g. OUs / containers / GPOs)
//   IdToTypeCache:  identifier -> BloodHound label
// This cache is what bhdump/certdump use to resolve ACE/membership targets and
// trust relationships. Mirrors SOAPHound's cache.txt structure.

import { sidFromB64, guidFromB64 } from '../security/sid.js';

const CACHE_ATTRS = ['distinguishedName', 'objectClass', 'objectSid', 'objectGUID', 'sAMAccountType'];

// Derive a BloodHound label from an object's classes / SAM account type.
export function labelFor(classes, samType) {
  const c = new Set(classes.map((x) => x.toLowerCase()));
  if (c.has('domaindns') || c.has('domain')) return 'Domain';
  if (c.has('computer') || c.has('msds-groupmanagedserviceaccount')) return 'Computer';
  if (c.has('group')) return 'Group';
  if (c.has('foreignsecurityprincipal')) return 'Base';
  if (c.has('user') || c.has('inetorgperson') || c.has('msds-managedserviceaccount')) return 'User';
  if (c.has('grouppolicycontainer')) return 'GPO';
  if (c.has('organizationalunit')) return 'OU';
  if (c.has('pkicertificatetemplate')) return 'CertTemplate';
  if (c.has('pkienrollmentservice')) return 'EnterpriseCA';
  if (c.has('container') || c.has('builtindomain')) return 'Container';
  return 'Base';
}

export function identifierFor(attrs) {
  if (attrs.objectSid && attrs.objectSid[0]) return sidFromB64(attrs.objectSid[0]);
  if (attrs.objectGUID && attrs.objectGUID[0]) return guidFromB64(attrs.objectGUID[0]);
  return null;
}

export async function buildCache(client, baseDN, hooks = {}) {
  const log = hooks.log || (() => {});
  const onProgress = hooks.onProgress || (() => {});
  const cache = { ValueToIdCache: {}, IdToTypeCache: {} };
  let n = 0;
  log(`Building cache from ${baseDN} …`);
  for await (const obj of client.query({ baseDN, filter: '(objectClass=*)', attributes: CACHE_ATTRS })) {
    const id = identifierFor(obj.attributes);
    if (!id || !obj.dn) continue;
    const label = labelFor(obj.attributes.objectClass || [], obj.attributes.sAMAccountType?.[0]);
    cache.ValueToIdCache[obj.dn.toUpperCase()] = id;
    cache.IdToTypeCache[id] = label;
    n++;
    if (n % 250 === 0) onProgress(n);
  }
  log(`Cache built: ${n} objects.`);
  return { cache, count: n };
}
