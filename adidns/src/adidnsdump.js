// Orchestrates an ADIDNS dump, following the approach of
// dirkjanm/adidnsdump:
//   1. bind to the DC over LDAP
//   2. read the domain naming context from RootDSE
//   3. enumerate dnsZone objects under the DomainDnsZones partition
//   4. for the chosen zone, list dnsNode objects and parse their dnsRecord blobs
//   5. (optional) resolve nodes whose dnsRecord is not readable via live DNS

import { LdapClient, SCOPE, filter } from './ldap/client.js';
import { parseDnsRecord } from './dns/record.js';
import { resolveName } from './dns/resolver.js';
import { ntlmSpnegoProducer, parseIdentity } from './ntlm/sasl.js';
import { kerberosSpnegoBind } from './kerberos/ldap-bind.js';
import { loadTls } from './tls/index.js';

const dec = new TextDecoder();

// Build the DomainDnsZones partition root for a domain naming context, e.g.
// "DC=corp,DC=local" -> "CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local".
export function zonePartition(domainNC, forest = false) {
  const part = forest ? 'ForestDnsZones' : 'DomainDnsZones';
  return `CN=MicrosoftDNS,DC=${part},${domainNC}`;
}

async function readRootDSE(client) {
  const it = client.search({
    baseDN: '',
    scope: SCOPE.BASE,
    filter: filter.present('objectClass'),
    attributes: ['defaultNamingContext', 'rootDomainNamingContext'],
    pageSize: 1,
  });
  for await (const entry of it) {
    const get = (k) => entry.attributes[k] && dec.decode(entry.attributes[k][0]);
    return {
      defaultNamingContext: get('defaultNamingContext'),
      rootDomainNamingContext: get('rootDomainNamingContext'),
    };
  }
  throw new Error('could not read RootDSE');
}

export async function listZones(client, partition) {
  const zones = [];
  for await (const entry of client.search({
    baseDN: partition,
    scope: SCOPE.ONE_LEVEL,
    filter: filter.equal('objectClass', 'dnsZone'),
    attributes: ['dc'],
  })) {
    const dc = entry.attributes.dc;
    if (dc && dc.length) zones.push(dec.decode(dc[0]));
  }
  return zones;
}

// Dump one zone. Returns an array of record rows. `onRow` is called as rows
// stream in so the UI can render incrementally.
export async function dumpZone(client, partition, zone, opts = {}) {
  const {
    includeTombstoned = false,
    resolve = false,
    resolveServer = null,
    onRow = () => {},
    log = () => {},
  } = opts;

  const zoneDN = `DC=${zone},${partition}`;
  log(`Dumping zone "${zone}" (${zoneDN}) …`);
  const rows = [];

  for await (const entry of client.search({
    baseDN: zoneDN,
    scope: SCOPE.SUBTREE,
    filter: filter.equal('objectClass', 'dnsNode'),
    attributes: ['dnsRecord', 'dNSTombstoned', 'name'],
  })) {
    const a = entry.attributes;
    const name = a.name && a.name.length ? dec.decode(a.name[0]) : dnFirstRDN(entry.dn);
    const tombstoned = a.dNSTombstoned && dec.decode(a.dNSTombstoned[0]).toUpperCase() === 'TRUE';
    if (tombstoned && !includeTombstoned) continue;

    const fqdn = name === '@' ? `${zone}.` : `${name}.${zone}.`;

    if (a.dnsRecord && a.dnsRecord.length) {
      for (const raw of a.dnsRecord) {
        let rec;
        try {
          rec = parseDnsRecord(raw);
        } catch (e) {
          rec = { typeName: 'PARSE_ERROR', ttl: '', display: String(e) };
        }
        if (rec.typeName === 'ZERO') continue; // tombstone placeholder
        const row = { name, fqdn, type: rec.typeName, ttl: rec.ttl, value: rec.display, tombstoned };
        rows.push(row); onRow(row);
      }
    } else if (resolve && resolveServer) {
      // dnsRecord not readable for this principal — ask DNS directly.
      const answers = await resolveName(resolveServer, fqdn);
      if (answers.length === 0) {
        const row = { name, fqdn, type: '?', ttl: '', value: '(hidden, unresolved)', tombstoned };
        rows.push(row); onRow(row);
      }
      for (const ans of answers) {
        const row = { name, fqdn, type: ans.type, ttl: '', value: `${ans.value} (resolved)`, tombstoned };
        rows.push(row); onRow(row);
      }
    } else {
      const row = { name, fqdn, type: '?', ttl: '', value: '(record not readable)', tombstoned };
      rows.push(row); onRow(row);
    }
  }

  log(`Zone "${zone}": ${rows.length} record(s).`);
  return rows;
}

function dnFirstRDN(dn) {
  const m = /^DC=([^,]+)/i.exec(dn);
  return m ? m[1] : dn;
}

// Top-level driver used by the UI.
export async function run(config, hooks = {}) {
  const log = hooks.log || (() => {});
  const onRow = hooks.onRow || (() => {});
  const client = new LdapClient(log);

  const port = config.port || (config.tls ? 636 : 389);
  await client.connect(config.host, port, config.tls ? { tls: { TlsSession: loadTls(), sni: config.host } } : {});
  try {
    // Over TLS, fetch the tls-server-end-point channel binding so binds satisfy
    // LDAP channel-binding enforcement on hardened DCs.
    let channelBinding = null;
    if (config.tls) {
      const cb = await client.channelBinding();
      channelBinding = cb && cb.applicationData;
      log(`TLS up — channel binding ${cb ? cb.hashName : 'none'}.`);
    }

    if (config.authMethod === 'ntlm') {
      const { user, domain } = parseIdentity(config.bindDN, config.domain);
      if (!user) throw new Error('NTLM requires a username (user@domain or DOMAIN\\user).');
      log(`NTLMv2 bind as ${domain ? domain + '\\' : ''}${user} …`);
      await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({ user, domain, password: config.password, channelBinding, log }));
    } else if (config.authMethod === 'kerberos') {
      const { user, domain } = parseIdentity(config.bindDN, config.domain);
      const realm = config.domain || domain;
      log(`Kerberos bind as ${user}@${realm} (ldap/${config.host}) …`);
      await kerberosSpnegoBind(client, {
        host: config.host, kdc: config.kdc || null, realm, user,
        password: config.password, hash: config.hash || null, channelBinding, log,
      });
    } else {
      await client.bind(config.bindDN, config.password);
    }

    let domainNC = config.baseDN;
    if (!domainNC) {
      const dse = await readRootDSE(client);
      domainNC = dse.defaultNamingContext;
      log(`Domain naming context: ${domainNC}`);
    }
    const partition = config.partition || zonePartition(domainNC, config.forest);
    log(`Zone partition: ${partition}`);

    if (config.listOnly) {
      const zones = await listZones(client, partition);
      log(`Found ${zones.length} zone(s).`);
      return { zones, rows: [] };
    }

    let zones = config.zone ? [config.zone] : await listZones(client, partition);
    if (!config.zone) log(`No zone specified — dumping all ${zones.length} zone(s).`);

    const rows = [];
    for (const zone of zones) {
      const zoneRows = await dumpZone(client, partition, zone, {
        includeTombstoned: config.includeTombstoned,
        resolve: config.resolve,
        resolveServer: config.resolve ? config.host : null,
        onRow,
        log,
      });
      rows.push(...zoneRows);
    }
    return { zones, rows };
  } finally {
    await client.close();
    log('Connection closed.');
  }
}
