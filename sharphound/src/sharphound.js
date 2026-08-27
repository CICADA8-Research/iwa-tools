// Top-level driver: binds to a DC over LDAP and dispatches collection using
// SharpHound-style collection methods (Default, All, DCOnly, etc.), reusing the
// BloodHound processors (bhdump/buildcache) that the soaphound tool drives over
// ADWS. Supports both LDAP-based and host-based (SMB/RPC) collection.

import { LdapBhClient } from './ldap/source.js';
import { SCOPE, filter as F } from './ldap/client.js';
import { bhDump } from './modes/bhdump.js';
import { buildCache } from './modes/buildcache.js';

const dec = new TextDecoder();

function domainToBaseDN(domain) {
  return domain.split('.').map((p) => `DC=${p}`).join(',');
}
function baseDNToDomain(dn) {
  return dn.split(',').filter((p) => /^DC=/i.test(p)).map((p) => p.slice(3)).join('.');
}

// Read defaultNamingContext from RootDSE (SharpHound auto-discovers the NC).
async function readBaseDN(client) {
  for await (const e of client.ldap.search({
    baseDN: '', scope: SCOPE.BASE, filter: F.present('objectClass'),
    attributes: ['defaultNamingContext'], pageSize: 1,
  })) {
    const v = e.attributes.defaultNamingContext;
    if (v && v.length) return dec.decode(v[0]);
  }
  return null;
}

export async function run(config, hooks = {}) {
  const log = hooks.log || (() => {});
  const onRow = hooks.onRow || (() => {});

  const client = new LdapBhClient(log);
  await client.connect(config.host, config.port || (config.tls ? 636 : 389), {
    authMethod: config.authMethod || 'ntlm',
    bindDN: config.bindDN,
    user: config.user || config.bindDN,
    domain: config.domain,
    kdc: config.kdc,
    hash: config.hash,
    tls: config.tls,
    sni: config.host,
    password: config.password,
  });

  try {
    let baseDN = config.baseDN || await readBaseDN(client);
    if (!baseDN && config.domain) baseDN = domainToBaseDN(config.domain);
    if (!baseDN) throw new Error('Could not determine the base DN (set it manually).');
    const domain = config.domain || baseDNToDomain(baseDN);
    log(`Base DN: ${baseDN} (domain ${domain})`);

    switch (config.mode) {
      case 'query': {
        const rows = [];
        const attributes = (config.attributes || 'distinguishedName,objectClass,sAMAccountName,objectSid')
          .split(',').map((s) => s.trim()).filter(Boolean);
        for await (const o of client.query({ baseDN, filter: config.filter || '(objectClass=*)', attributes })) {
          const row = { dn: o.dn, className: o.className, attributes: o.attributes };
          rows.push(row); onRow(row);
        }
        return { mode: 'query', rows };
      }
      case 'buildcache': {
        const { cache, count } = await buildCache(client, baseDN, { log, onProgress: (n) => onRow({ progress: n }) });
        return { mode: 'buildcache', summary: { objects: count }, files: [{ name: 'cache.json', content: cache }] };
      }
      case 'collect': {
        const methods = config.collectionMethods || new Set();
        const HOST_METHODS = ['LocalAdmin', 'RDP', 'DCOM', 'PSRemote', 'Session', 'LoggedOn', 'GPOLocalGroup'];
        const needsHost = HOST_METHODS.some((m) => methods.has(m));
        const hostCollect = needsHost
          ? { enabled: true, methods, stealth: config.stealth, excludeDCs: config.excludeDCs,
              creds: { user: config.user || config.bindDN, domain: config.domain || domain, password: config.password } }
          : null;
        const { files, summary } = await bhDump(client, baseDN, domain, { log, hostCollect, methods });
        return { mode: 'collect', summary, files };
      }
      default:
        throw new Error(`Unknown mode: ${config.mode}`);
    }
  } finally {
    await client.close();
    log('Connection closed.');
  }
}
