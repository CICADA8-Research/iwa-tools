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
import { acesFromDescriptor, descriptorIsProtected, daclPrincipals } from '../security/sddl.js';
import { labelFor } from './buildcache.js';
import { collectHostLocalGroups } from '../smb/hostcollect.js';

const METHOD_BITS = {
  Group: 1, LocalAdmin: 2, GPOLocalGroup: 4, Session: 8, LoggedOn: 16,
  Trusts: 32, ACL: 64, Container: 128, RDP: 256, ObjectProps: 512,
  DCOM: 8192, PSRemote: 16384, SPNTargets: 32768, CertServices: 65536,
};

function methodsBitmask(methods) {
  let mask = 0;
  for (const m of methods) mask |= (METHOD_BITS[m] || 0);
  return mask;
}

const BH_ATTRS = [
  'distinguishedName', 'objectClass', 'objectSid', 'objectGUID', 'sAMAccountName',
  'sAMAccountType', 'name', 'displayName', 'description', 'userAccountControl',
  'adminCount', 'pwdLastSet', 'lastLogon', 'lastLogonTimestamp', 'whenCreated', 'servicePrincipalName',
  'member', 'primaryGroupID', 'gPLink', 'gPCFileSysPath', 'nTSecurityDescriptor',
  'dNSHostName', 'operatingSystem', 'msDS-Behavior-Version', 'msDS-AllowedToDelegateTo',
  'msDS-AllowedToActOnBehalfOfOtherIdentity', 'sIDHistory', 'mail', 'title', 'homeDirectory',
  'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime', 'ms-DS-MachineAccountQuota',
  'trustDirection', 'trustType', 'trustAttributes', 'securityIdentifier', 'trustPartner', 'objectCategory',
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
  const hostCollect = hooks.hostCollect || null;
  const methods = hooks.methods || new Set(['Group', 'LocalAdmin', 'Session', 'Trusts', 'ACL', 'ObjectProps', 'Container', 'SPNTargets', 'RDP', 'DCOM', 'PSRemote']);
  const has = (m) => methods.has(m);
  const DOMAIN = domain.toUpperCase();
  const cache = { IdToTypeCache: {}, ValueToIdCache: {} };
  const childrenByParent = new Map(); // parent DN (upper) -> [{ObjectIdentifier, ObjectType}]
  const out = { users: [], groups: [], computers: [], domains: [], gpos: [], ous: [], containers: [] };
  const spnHostToSid = new Map(); // UPPER host / sam -> computer SID (for delegation edges)
  const trusts = [];              // domain trust relationships
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

    // Side maps that later edges need: computer host -> SID (for AllowedToDelegate)
    // and the domain's trust objects (class trustedDomain, not a BloodHound node).
    const classes = (a.objectClass || []).map((c) => String(c).toLowerCase());
    if (classes.includes('computer') && sid) {
      const dns = first(a.dNSHostName);
      const csam = (first(a.sAMAccountName) || '').replace(/\$$/, '');
      if (dns) spnHostToSid.set(dns.toUpperCase(), sid);
      if (csam) spnHostToSid.set(csam.toUpperCase(), sid);
    }
    if (has('Trusts') && classes.includes('trusteddomain')) trusts.push(buildTrust(a));

    const aces = has('ACL') ? acesFromDescriptor(first(a.nTSecurityDescriptor), () => null) : [];
    const node = buildNode(label, o, a, sid, guid, DOMAIN, aces, methods);
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
      if (has('ACL')) for (const ace of node.Aces || []) ace.PrincipalType = typeOf(ace.PrincipalSID);
      if (node._memberDNs && has('Group')) {
        node.Members = node._memberDNs.map((dn) => {
          const mid = cache.ValueToIdCache[dn.toUpperCase()];
          return mid ? { ObjectIdentifier: mid, ObjectType: typeOf(mid) } : null;
        }).filter(Boolean);
      } else if (node._memberDNs) {
        node.Members = [];
      }
      if (node._pgRID !== undefined) {
        node.PrimaryGroupSID = domainSid && node._pgRID ? `${domainSid}-${node._pgRID}` : null;
      }
      if (node._dn && 'ChildObjects' in node) node.ChildObjects = has('Container') ? childObjectsOf(node._dn) : [];
      if (node._sidHistory) node.HasSIDHistory = node._sidHistory.map((s) => ({ ObjectIdentifier: s, ObjectType: typeOf(s) }));
      if (node._delegateSPNs) node.AllowedToDelegate = has('SPNTargets') ? resolveDelegate(node._delegateSPNs, spnHostToSid) : [];
      if (node._rbcdSids) node.AllowedToAct = node._rbcdSids.map((s) => ({ ObjectIdentifier: s, ObjectType: typeOf(s) }));
      if ('Trusts' in node) node.Trusts = has('Trusts') ? trusts : [];
      delete node._memberDNs; delete node._pgRID; delete node._dn;
      delete node._sidHistory; delete node._delegateSPNs; delete node._rbcdSids;
    }
  }

  // ---- Optional host-based pass: per-computer local groups over SMB/SAMR ----
  if (hostCollect && hostCollect.enabled && hostCollect.creds) {
    const hm = hostCollect.methods || methods;
    const userByName = new Map();
    for (const u of out.users) { const n = (u.Properties.samaccountname || '').toLowerCase(); if (n) userByName.set(n, u.ObjectIdentifier); }
    const compByName = new Map();
    for (const cn of out.computers) {
      const sid = cn.ObjectIdentifier;
      const dns = (cn.Properties.name || '').toLowerCase();
      if (dns) { compByName.set(dns, sid); compByName.set(dns.split('.')[0], sid); }
      const sam = (cn.Properties.samaccountname || '').replace(/\$$/, '').toLowerCase();
      if (sam) compByName.set(sam, sid);
    }
    const resolveUser = (name) => userByName.get(String(name).toLowerCase()) || null;
    const resolveComputer = (name) => { const n = String(name).replace(/^\\\\/, '').toLowerCase(); return compByName.get(n) || compByName.get(n.split('.')[0]) || null; };

    let targets = out.computers.filter((n) => n.Properties.enabled);
    if (hostCollect.excludeDCs) {
      const dcSids = new Set(out.computers.filter((n) => (n.Properties.unconstraineddelegation && (n.Properties.operatingsystem || '').toLowerCase().includes('server'))).map((n) => n.ObjectIdentifier));
      targets = targets.filter((n) => !dcSids.has(n.ObjectIdentifier));
    }
    if (hostCollect.stealth) targets = targets.slice(0, 1);
    const methodList = [...hm].filter((m) => ['LocalAdmin', 'RDP', 'DCOM', 'PSRemote', 'Session', 'LoggedOn'].includes(m));
    log(`Host-based collection [${methodList.join(',')}] on ${targets.length} computer(s) …`);
    for (const node of targets) {
      const host = node.Properties.name;
      const lg = await collectHostLocalGroups(host, hostCollect.creds, { typeOf, resolveUser, resolveComputer, computerSid: node.ObjectIdentifier, methods: hm }, { log });
      Object.assign(node, lg);
    }
  }

  const mask = methodsBitmask(methods);
  const files = Object.entries(out).map(([type, data]) => ({
    name: `${type}.json`,
    content: { data, meta: { methods: mask, type, count: data.length, version: 6 } },
  }));
  const summary = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.length]));
  log(`BloodHound data: ${Object.entries(summary).map(([k, v]) => `${v} ${k}`).join(', ')}.`);
  return { files, summary, cache };
}

// Build a node with edges left in a "pending" form (temp _-prefixed fields that
// pass 2 resolves and deletes). No cache lookups here — only the object itself.
function buildNode(label, o, a, sid, guid, DOMAIN, aces, methods) {
  const uac = num(first(a.userAccountControl)) || 0;
  const aclProtected = methods.has('ACL') ? descriptorIsProtected(first(a.nTSecurityDescriptor)) : false;
  const sidHistory = (a.sIDHistory || []).map((v) => sidFromB64(v)).filter(Boolean);
  const objProps = methods.has('ObjectProps');
  const baseProps = {
    domain: DOMAIN, domainsid: null, distinguishedname: o.dn,
    name: undefined, description: objProps ? first(a.description) : undefined,
    whencreated: objProps ? genTimeToEpoch(first(a.whenCreated)) : undefined,
  };
  switch (label) {
    case 'User': {
      const sam = first(a.sAMAccountName) || '';
      const props = { ...baseProps, name: `${sam}@${DOMAIN}`.toUpperCase(), samaccountname: sam, objectid: sid, enabled: !(uac & 0x2) };
      if (objProps) Object.assign(props, {
        pwdlastset: fileTimeToEpoch(first(a.pwdLastSet)),
        lastlogon: fileTimeToEpoch(first(a.lastLogon)), lastlogontimestamp: fileTimeToEpoch(first(a.lastLogonTimestamp)),
        admincount: bool(first(a.adminCount)), displayname: first(a.displayName),
        email: first(a.mail), title: first(a.title), homedirectory: first(a.homeDirectory),
        serviceprincipalnames: a.servicePrincipalName || [],
        hasspn: !!(a.servicePrincipalName && a.servicePrincipalName.length),
        unconstraineddelegation: !!(uac & 0x80000), trustedtoauth: !!(uac & 0x1000000),
        dontreqpreauth: !!(uac & 0x400000), passwordnotreqd: !!(uac & 0x20),
        pwdneverexpires: !!(uac & 0x10000), sensitive: !!(uac & 0x100000), sidhistory: sidHistory,
      });
      return { bucket: 'users', node: {
        ObjectIdentifier: sid, Properties: props,
        PrimaryGroupSID: null, _pgRID: first(a.primaryGroupID),
        Aces: aces, SPNTargets: [], HasSIDHistory: [], _sidHistory: sidHistory,
        AllowedToDelegate: [], _delegateSPNs: a['msDS-AllowedToDelegateTo'] || [],
        IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'Computer': {
      const sam = (first(a.sAMAccountName) || '').replace(/\$$/, '');
      const props = { ...baseProps, name: (first(a.dNSHostName) || `${sam}.${DOMAIN}`).toUpperCase(),
        samaccountname: first(a.sAMAccountName), objectid: sid, enabled: !(uac & 0x2) };
      if (objProps) Object.assign(props, {
        operatingsystem: first(a.operatingSystem), unconstraineddelegation: !!(uac & 0x80000),
        trustedtoauth: !!(uac & 0x1000000), serviceprincipalnames: a.servicePrincipalName || [],
        lastlogon: fileTimeToEpoch(first(a.lastLogon)), lastlogontimestamp: fileTimeToEpoch(first(a.lastLogonTimestamp)),
        pwdlastset: fileTimeToEpoch(first(a.pwdLastSet)), email: first(a.mail),
        haslaps: !!(first(a['ms-Mcs-AdmPwdExpirationTime']) || first(a['msLAPS-PasswordExpirationTime'])),
        sidhistory: sidHistory,
      });
      return { bucket: 'computers', node: {
        ObjectIdentifier: sid, Properties: props,
        PrimaryGroupSID: null, _pgRID: first(a.primaryGroupID),
        Aces: aces, HasSIDHistory: [], _sidHistory: sidHistory,
        AllowedToDelegate: [], _delegateSPNs: a['msDS-AllowedToDelegateTo'] || [],
        AllowedToAct: [], _rbcdSids: daclPrincipals(first(a['msDS-AllowedToActOnBehalfOfOtherIdentity'])),
        Sessions: empty(), PrivilegedSessions: empty(), RegistrySessions: empty(),
        DcomUsers: empty(), PSRemoteUsers: empty(), LocalAdmins: empty(), RemoteDesktopUsers: empty(),
        Status: null, IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'Group': {
      const sam = first(a.sAMAccountName) || first(a.name) || '';
      return { bucket: 'groups', node: {
        ObjectIdentifier: sid,
        Properties: { ...baseProps, name: `${sam}@${DOMAIN}`.toUpperCase(), samaccountname: sam, objectid: sid, admincount: bool(first(a.adminCount)) },
        Members: [], _memberDNs: a.member || [], Aces: aces, IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'Domain': {
      return { bucket: 'domains', node: {
        ObjectIdentifier: sid,
        Properties: { ...baseProps, name: DOMAIN, objectid: sid, functionallevel: funcLevel(first(a['msDS-Behavior-Version'])), machineaccountquota: num(first(a['ms-DS-MachineAccountQuota'])) },
        ChildObjects: [], _dn: o.dn, Links: parseGpLinks(a.gPLink),
        Trusts: [], Aces: aces, GPOChanges: gpoChanges(), IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'OU': {
      const oid = (guid || '').toUpperCase();
      return { bucket: 'ous', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.name) || first(a.ou)}@${DOMAIN}`.toUpperCase(), objectid: oid, blocksinheritance: false },
        ChildObjects: [], _dn: o.dn, Links: parseGpLinks(a.gPLink),
        Aces: aces, GPOChanges: gpoChanges(), IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'GPO': {
      const oid = (guid || '').toUpperCase();
      return { bucket: 'gpos', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.displayName) || first(a.name)}@${DOMAIN}`.toUpperCase(), objectid: oid, gpcpath: first(a.gPCFileSysPath) },
        Aces: aces, IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    case 'Container': {
      const oid = (guid || sid || '').toUpperCase();
      return { bucket: 'containers', node: {
        ObjectIdentifier: oid,
        Properties: { ...baseProps, name: `${first(a.name)}@${DOMAIN}`.toUpperCase(), objectid: oid },
        ChildObjects: [], _dn: o.dn, Aces: aces, IsDeleted: false, IsACLProtected: aclProtected,
      } };
    }
    default: return null;
  }
}

// SPN "service/host[:port][/…]" -> host.
function spnHost(spn) { const p = String(spn).split('/'); return p.length > 1 ? p[1].split(':')[0] : ''; }

// Resolve msDS-AllowedToDelegateTo SPNs to target computer SIDs (AllowedToDelegate).
function resolveDelegate(spns, map) {
  const seen = new Set(); const out = [];
  for (const spn of spns) {
    const sid = map.get(spnHost(spn).toUpperCase());
    if (sid && !seen.has(sid)) { seen.add(sid); out.push({ ObjectIdentifier: sid, ObjectType: 'Computer' }); }
  }
  return out;
}

// A trustedDomain object -> a BloodHound domain Trust entry.
function buildTrust(a) {
  const attr = num(first(a.trustAttributes)) || 0;
  const dir = num(first(a.trustDirection)) || 0;
  const type = num(first(a.trustType)) || 0;
  const DIR = { 0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional' };
  const trustType = (attr & 0x8) ? 'Forest' : (attr & 0x40) ? 'ParentChild' : type === 2 ? 'External' : 'Unknown';
  return {
    TargetDomainSid: a.securityIdentifier ? sidFromB64(first(a.securityIdentifier)) : null,
    TargetDomainName: (first(a.trustPartner) || first(a.name) || '').toUpperCase(),
    IsTransitive: !(attr & 0x1),
    SidFilteringEnabled: !!(attr & 0x4),
    TrustDirection: DIR[dir] || 'Unknown',
    TrustType: trustType,
  };
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
