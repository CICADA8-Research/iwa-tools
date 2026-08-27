// Connect + authenticate an LdapClient (NTLM / Kerberos / simple, optional
// LDAPS + channel binding) and discover the base DN, then hand back the pieces
// the LdapShell needs. Mirrors the auth wiring used by the other LDAP tools.

import { LdapClient, SCOPE, filter as F } from './ldap/client.js';
import { ntlmSpnegoProducer, parseIdentity } from './ntlm/sasl.js';
import { kerberosSpnegoBind } from './kerberos/ldap-bind.js';
import { loadTls } from './tls/index.js';

const dec = new TextDecoder();

async function readBaseDN(client) {
  // Drain the search fully (no early return) so no SearchResultDone is left on
  // the wire to desync the first shell command (e.g. the whoami extended op).
  let dn = null;
  for await (const e of client.search({ baseDN: '', scope: SCOPE.BASE, filter: F.present('objectClass'), attributes: ['defaultNamingContext'], pageSize: 1 })) {
    const v = e.attributes.defaultNamingContext;
    if (v && v.length && !dn) dn = dec.decode(v[0]);
  }
  return dn;
}

export async function connect(config, log = () => {}) {
  const client = new LdapClient(log);
  const port = config.port || (config.tls ? 636 : 389);
  await client.connect(config.host, port, config.tls ? { tls: { TlsSession: loadTls(), sni: config.host } } : {});

  let channelBinding = null;
  if (config.tls) {
    const cb = await client.channelBinding();
    channelBinding = cb && cb.applicationData;
    log(`TLS up — channel binding ${cb ? cb.hashName : 'none'}.`);
  }

  if (config.authMethod === 'kerberos') {
    const { user, domain } = parseIdentity(config.bindDN, config.domain);
    log(`Kerberos bind as ${user}@${config.domain || domain} …`);
    await kerberosSpnegoBind(client, {
      host: config.host, kdc: config.kdc || null, realm: config.domain || domain, user,
      password: config.password, hash: config.hash || null, ticket: config.ticket || null, channelBinding, log,
    });
  } else if (config.authMethod === 'ntlm') {
    const { user, domain } = parseIdentity(config.bindDN, config.domain);
    log(`NTLMv2 bind as ${domain ? domain + '\\' : ''}${user} …`);
    await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({ user, domain, password: config.password, channelBinding, log }));
  } else {
    log(`Simple bind as ${config.bindDN || '(anonymous)'} …`);
    await client.bind(config.bindDN, config.password);
  }

  const baseDN = config.baseDN || await readBaseDN(client);
  if (!baseDN) throw new Error('could not determine the base DN (set it manually)');
  const domain = config.domain
    || baseDN.split(',').filter((p) => /^DC=/i.test(p)).map((p) => p.slice(3)).join('.');
  log(`Base DN: ${baseDN} (domain ${domain})`);
  return { client, baseDN, domain, tls: !!config.tls };
}
