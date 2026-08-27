// --bhdump: collect the directory and emit BloodHound Community Edition JSON
// (users/groups/computers/domains/gpos/ous/containers).
//
// Memory note: a large domain can hold hundreds of thousands of objects, each
// with a multi-KB nTSecurityDescriptor. To keep peak memory bounded we DO NOT
// retain the raw objects. Pass 1 streams the enumeration and, for each object,
// builds its output node, parses ACE principals (then drops the descriptor),
// and records only the lean cache (DN/SID/type) + parent->children map; the raw
// object is then garbage-collected. Pass 2 walks the (already-kept) output
// arrays and resolves the edges that need the *complete* cache — ACE principal
// types, group members, primary-group SIDs and child objects.

import { sidFromB64, guidFromB64 } from '../security/sid.js';
import { acesFromDescriptor } from '../security/sddl.js';
import { labelFor } from './buildcache.js';

const BH_ATTRS = [
  'distinguishedName', 'objectClass', 'objectSid', 'objectGUID', 'sAMAccountName',
  'sAMAccountType', 'name', 'displayName', 'description', 'userAccountControl',
  'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'servicePrincipalName',
  'member', 'primaryGroupID', 'gPLink', 'gPCFileSysPath', 'nTSecurityDescriptor',
  'dNSHostName', 'operatingSystem', 'msDS-Behavior-Version', 'msDS-AllowedToDelegateTo',
  'trustDirection', 'trustType', 'trustAttributes', 'securityIdentifier', 'objectCategory',
];

const WELLKNOWN_TYPE = {
  'S-1-5-11': 'Group', 'S-1-5-9': 'Group', 'S-1-1-0': 'Group', 'S-1-5-18': 'User',
  'S-1-5-32-544': 'Group', 'S-1-5-32-545': 'Group', 'S-1-5-32-546': 'Group',
};

const first = (a) => (a && a.length ? a[0] : undefined);
const num = (v) => (v === undefined ? undefined : Number(v));
const bool = (v) => !!v;

// AD timestamp helpers -> epoch seconds (BloodHound convention; -1 = never).
function fileTimeToEpoch(v) {
  if (v === undefined) return -1;
  const n = Number(v);
  if (!n || n === 0 || n === 9223372036854775807) return -1;
  return Math.floor(n / 10000000 - 11644473600);
}
function genTimeToEpoch(v) {
  if (!v) return -1;
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(v);
  if (!m) return -1;
  return Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000);
}

export async function bhDump(client, baseDN, domain, hooks = {}) {
  const log = hooks.log || (() => {});
  const DOMAIN = domain.toUpperCase();
  const cache = { IdToTypeCache: {}, ValueToIdCache: {} };
  const childrenByParent = new Map(); // parent DN (upper) -> [{ObjectIdentifier, ObjectType}]
  const out = { users: [], groups: [], computers: [], domains: [], gpos: [], ous: [], containers: [] };
  let domainSid = null;
  let n = 0;

  // ---- Pass 1: stream, build nodes, drop raw objects --------------------
  log('Collecting directory objects …');
  for await (const o of client.query({ baseDN, filter: '(objectClass=*)', attributes: BH_ATTRS })) {
    const a = o.attributes;
    const sid = a.objectSid ? sidFromB64(first(a.objectSid)) : null;
    const guid = a.objectGUID ? guidFromB64(first(a.objectGUID)) : null;
    const id = sid || guid;
    const label = labelFor(a.objectClass || [], first(a.sAMAccountType));
    if (id && o.dn) {
      cache.IdToTypeCache[id] = label;
      cache.ValueToIdCache[o.dn.toUpperCase()] = id;
      const parent = o.dn.slice(o.dn.indexOf(',') + 1).toUpperCase();
      if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
      childrenByParent.get(parent).push({ ObjectIdentifier: id, ObjectType: label });
    }
    if (label === 'Domain') domainSid = sid;

    // Parse ACE principals now (type filled in pass 2); the descriptor is freed
    // with `o` after this iteration.
    const aces = acesFromDescriptor(first(a.nTSecurityDescriptor), () => null);
    const node = buildNode(label, o, a, sid, guid, DOMAIN, aces);
    if (node) out[node.bucket].push(node.node);
    n++;
  }
  log(`Collected ${n} objects.`);

  // ---- Pass 2: resolve cache-dependent edges over the output arrays ------
  const typeOf = (s) => cache.IdToTypeCache[s] || WELLKNOWN_TYPE[s] || 'Base';
  const childObjectsOf = (dn) => childrenByParent.get((dn || '').toUpperCase()) || [];
  for (const bucket of Object.keys(out)) {
    for (const node of out[bucket]) {
      if (node.Properties) node.Properties.domainsid = domainSid;
      for (const ace of node.Aces || []) ace.PrincipalType = typeOf(ace.PrincipalSID);
      if (node._memberDNs) {
        node.Members = node._memberDNs.map((dn) => {
          const mid = cache.ValueToIdCache[dn.toUpperCase()];
          return mid ? { ObjectIdentifier: mid, ObjectType: typeOf(mid) } : null;
        }).filter(Boolean);
      }
      if (node._pgRID !== undefined) {
        node.PrimaryGroupSID = domainSid && node._pgRID ? `${domainSid}-${node._pgRID}` : null;
      }
      if (node._dn && 'ChildObjects' in node) node.ChildObjects = childObjectsOf(node._dn);
      delete node._memberDNs; delete node._pgRID; delete node._dn;
    }
  }

  const files = Object.entries(out).map(([type, data]) => ({
    name: `${type}.json`,
    content: { data, meta: { methods: 0, type, count: data.length, version: 6 } },
  }));
  const summary = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.length]));
  log(`BloodHound data: ${Object.entries(summary).map(([k, v]) => `${v} ${k}`).join(', ')}.`);
  return { files, summary, cache };
}

// Build a node with edges left in a "pending" form (temp _-prefixed fields that
// pass 2 resolves and deletes). No cache lookups here — only the object itself.
function buildNode(label, o, a, sid, guid, DOMAIN, aces) {
  const baseProps = {
    domain: DOMAIN, domainsid: null, distinguishedname: o.dn,
    name: undefined, description: first(a.description),
    whencreated: genTimeToEpoch(first(a.whenCreated)),
  };
  switch (label) {
    case 'User': {
      const sam = first(a.sAMAccountName) || '';
      const uac = num(first(a.userAccountControl)) || 0;
      return { bucket: 'users', node: {
        ObjectIdentifier: sid,
        Properties: {
          ...baseProps, name: `${sam}@${DOMAIN}`.toUpperCase(), samaccountname: sam,
          objectid: sid, enabled: !(uac & 0x2), pwdlastset: fileTimeToEpoch(first(a.pwdLastSet)),
          lastlogontimestamp: fileTimeToEpoch(first(a.lastLogonTimestamp)),
          admincount: bool(first(a.adminCount)), displayname: first(a.displayName),
          serviceprincipalnames: a.servicePrincipalName || [],
          hasspn: !!(a.servicePrincipalName && a.servicePrincipalName.length),
          unconstraineddelegation: !!(uac & 0x80000), trustedtoauth: !!(uac & 0x1000000),
          dontreqpreauth: !!(uac & 0x400000), passwordnotreqd: !!(uac & 0x20),
        },
        PrimaryGroupSID: null, _pgRID: first(a.primaryGroupID),
        Aces: aces, SPNTargets: [], HasSIDHistory: [], AllowedToDelegate: [],
        IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'Computer': {
      const sam = (first(a.sAMAccountName) || '').replace(/\$$/, '');
      const uac = num(first(a.userAccountControl)) || 0;
      return { bucket: 'computers', node: {
        ObjectIdentifier: sid,
        Properties: {
          ...baseProps, name: (first(a.dNSHostName) || `${sam}.${DOMAIN}`).toUpperCase(),
          samaccountname: first(a.sAMAccountName), objectid: sid, enabled: !(uac & 0x2),
          operatingsystem: first(a.operatingSystem), unconstraineddelegation: !!(uac & 0x80000),
          trustedtoauth: !!(uac & 0x1000000), serviceprincipalnames: a.servicePrincipalName || [],
          lastlogontimestamp: fileTimeToEpoch(first(a.lastLogonTimestamp)), pwdlastset: fileTimeToEpoch(first(a.pwdLastSet)),
        },
        PrimaryGroupSID: null, _pgRID: first(a.primaryGroupID),
        Aces: aces, AllowedToDelegate: [], AllowedToAct: [], HasSIDHistory: [],
        Sessions: empty(), PrivilegedSessions: empty(), RegistrySessions: empty(),
        DcomUsers: empty(), PSRemoteUsers: empty(), LocalAdmins: empty(), RemoteDesktopUsers: empty(),
        Status: null, IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'Group': {
      const sam = first(a.sAMAccountName) || first(a.name) || '';
      return { bucket: 'groups', node: {
        ObjectIdentifier: sid,
        Properties: { ...baseProps, name: `${sam}@${DOMAIN}`.toUpperCase(), samaccountname: sam, objectid: sid, admincount: bool(first(a.adminCount)) },
        Members: [], _memberDNs: a.member || [], Aces: aces, IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'Domain': {
      return { bucket: 'domains', node: {
        ObjectIdentifier: sid,
        Properties: { ...baseProps, name: DOMAIN, objectid: sid, functionallevel: funcLevel(first(a['msDS-Behavior-Version'])) },
        ChildObjects: [], _dn: o.dn, Links: parseGpLinks(a.gPLink),
        Trusts: [], Aces: aces, GPOChanges: gpoChanges(), IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'OU': {
      const oid = (guid || '').toUpperCase();
      return { bucket: 'ous', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.name) || first(a.ou)}@${DOMAIN}`.toUpperCase(), objectid: oid, blocksinheritance: false },
        ChildObjects: [], _dn: o.dn, Links: parseGpLinks(a.gPLink),
        Aces: aces, GPOChanges: gpoChanges(), IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'GPO': {
      const oid = (guid || '').toUpperCase();
      return { bucket: 'gpos', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.displayName) || first(a.name)}@${DOMAIN}`.toUpperCase(), objectid: oid, gpcpath: first(a.gPCFileSysPath) },
        Aces: aces, IsDeleted: false, IsACLProtected: false,
      } };
    }
    case 'Container': {
      const oid = (guid || sid || '').toUpperCase();
      return { bucket: 'containers', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.name)}@${DOMAIN}`.toUpperCase(), objectid: oid },
        ChildObjects: [], _dn: o.dn, Aces: aces, IsDeleted: false, IsACLProtected: false,
      } };
    }
    default: return null;
  }
}

const empty = () => ({ Collected: false, FailureReason: null, Results: [] });
const gpoChanges = () => ({ LocalAdmins: [], RemoteDesktopUsers: [], DcomUsers: [], PSRemoteUsers: [], AffectedComputers: [] });
function funcLevel(v) {
  const map = { 0: '2000', 1: '2003 Interim', 2: '2003', 3: '2008', 4: '2008 R2', 5: '2012', 6: '2012 R2', 7: '2016' };
  return map[v] || 'Unknown';
}

// gPLink "[LDAP://cn={GUID},...;flag]..." -> [{IsEnforced, GUID}]
function parseGpLinks(gPLink) {
  const val = first(gPLink);
  if (!val) return [];
  const links = [];
  const re = /\[LDAP:\/\/(?:cn=)?\{?([0-9A-Fa-f-]{36})\}?[^;]*;(\d)\]/g;
  let m;
  while ((m = re.exec(val))) {
    const flag = Number(m[2]);
    if (flag & 1) continue; // link disabled
    links.push({ IsEnforced: !!(flag & 2), GUID: m[1].toUpperCase() });
  }
  return links;
}
