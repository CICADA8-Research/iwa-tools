// --dnsdump: enumerate AD-integrated DNS (dnsNode objects) over ADWS and parse
// their dnsRecord blobs with the same parser the adidns tool uses. dnsRecord
// values arrive base64-encoded (NBFX Bytes records).

import { parseDnsRecord } from '../dns/record.js';
import { b64ToBytes } from '../security/sid.js';

const dec = new TextDecoder();

// The DomainDnsZones application partition holds the primary zones; the legacy
// location under the domain NC is the fallback.
export function dnsPartitions(domainNC) {
  return [`DC=DomainDnsZones,${domainNC}`, `CN=MicrosoftDNS,CN=System,${domainNC}`];
}

// zone name from a dnsNode DN: DC=<name>,DC=<zone>,CN=MicrosoftDNS,...
function zoneFromDN(dn) {
  const parts = dn.split(',');
  // parts[0] = DC=<name>; parts[1] = DC=<zone>
  const z = parts[1] && /^DC=/i.test(parts[1]) ? parts[1].slice(3) : '';
  return z;
}

export async function dnsDump(client, domainNC, hooks = {}) {
  const log = hooks.log || (() => {});
  const onRow = hooks.onRow || (() => {});
  const rows = [];
  const seenPartition = [];

  for (const base of dnsPartitions(domainNC)) {
    let found = 0;
    try {
      for await (const obj of client.query({ baseDN: base, filter: '(objectClass=dnsNode)', attributes: ['dnsRecord', 'dc', 'name', 'distinguishedName'] })) {
        const name = (obj.attributes.dc || obj.attributes.name || [''])[0];
        const zone = zoneFromDN(obj.dn || '');
        const fqdn = name === '@' ? `${zone}.` : `${name}.${zone}.`;
        for (const b64 of obj.attributes.dnsRecord || []) {
          let rec;
          try { rec = parseDnsRecord(b64ToBytes(b64)); }
          catch (e) { rec = { typeName: 'PARSE_ERROR', ttl: '', display: String(e) }; }
          if (rec.typeName === 'ZERO') continue;
          const row = { name, fqdn, zone, type: rec.typeName, ttl: rec.ttl, value: rec.display };
          rows.push(row); onRow(row);
          found++;
        }
      }
    } catch (e) {
      log(`DNS partition ${base}: ${e.message}`);
      continue;
    }
    if (found) { seenPartition.push(base); log(`DNS partition ${base}: ${found} record(s).`); break; }
  }
  if (!seenPartition.length) log('No DNS records found in any partition.');
  return rows;
}

export { dec };
