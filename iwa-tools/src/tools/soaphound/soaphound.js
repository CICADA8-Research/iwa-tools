// Top-level driver: connects an ADWS session and dispatches the chosen
// collection mode. Mirrors the shape of the adidns tool's run() so the UI layer
// stays thin. Modes return a uniform { mode, rows?, files?, summary? }.

import { AdwsClient, domainToBaseDN } from './adws/client.js';
import { buildCache } from './modes/buildcache.js';
import { dnsDump } from './modes/dnsdump.js';
import { bhDump } from './modes/bhdump.js';
import { certDump } from './modes/certdump.js';

// "DOMAIN\\user" / "user@domain" / plain "user" (+ separate domain) -> parts.
export function parseIdentity(identity, domainHint = '') {
  identity = (identity || '').trim();
  let user = identity;
  let domain = (domainHint || '').trim();
  if (identity.includes('\\')) { const [d, u] = identity.split('\\'); if (!domain) domain = d; user = u; }
  else if (identity.includes('@')) { const [u, d] = identity.split('@'); user = u; if (!domain) domain = d; }
  return { user, domain };
}

export async function run(config, hooks = {}) {
  const log = hooks.log || (() => {});
  const onRow = hooks.onRow || (() => {});
  const { user, domain } = parseIdentity(config.user, config.domain);
  if (!user) throw new Error('A username is required (user@domain or DOMAIN\\user).');
  if (!domain) throw new Error('A domain is required (e.g. corp.local).');

  const client = new AdwsClient(log);
  await client.connect(config.host, config.port || 9389, {
    authMethod: config.authMethod || 'ntlm',
    user, domain, password: config.password,
    kdc: config.kdc, hash: config.hash, spn: config.spn, ticket: config.ticket || null,
  }, { fqdn: config.fqdn || config.host });

  const baseDN = config.baseDN || domainToBaseDN(domain);
  log(`Domain naming context: ${baseDN}`);

  try {
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
      case 'dnsdump': {
        const rows = await dnsDump(client, baseDN, { log, onRow });
        return { mode: 'dnsdump', rows };
      }
      case 'buildcache': {
        const { cache, count } = await buildCache(client, baseDN, { log, onProgress: (n) => onRow({ progress: n }) });
        return { mode: 'buildcache', summary: { objects: count }, files: [{ name: 'cache.json', content: cache }] };
      }
      case 'bhdump': {
        const { files, summary } = await bhDump(client, baseDN, domain, { log });
        return { mode: 'bhdump', summary, files };
      }
      case 'certdump': {
        const { cache } = await buildCache(client, baseDN, { log });
        const { files, summary } = await certDump(client, baseDN, cache, { log });
        return { mode: 'certdump', summary, files };
      }
      default:
        throw new Error(`Unknown mode: ${config.mode}`);
    }
  } finally {
    await client.close();
    log('Connection closed.');
  }
}
