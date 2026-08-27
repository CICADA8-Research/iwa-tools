// --certdump: enumerate AD Certificate Services under the Configuration NC
// (CN=Public Key Services,CN=Services,CN=Configuration,<forestNC>): enterprise
// CAs, certificate templates and root CAs, with their key properties and the
// enrollment/ACL principals. Output is BloodHound-CE-style certificate files.

import { sidFromB64, guidFromB64 } from '../security/sid.js';
import { acesFromDescriptor } from '../security/sddl.js';

const PKI_ATTRS = [
  'distinguishedName', 'objectClass', 'objectGUID', 'name', 'displayName', 'cn',
  'dNSHostName', 'certificateTemplates', 'cACertificate', 'nTSecurityDescriptor',
  'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
  'msPKI-RA-Signature', 'msPKI-Template-Schema-Version', 'msPKI-Certificate-Application-Policy',
  'flags', 'objectSid',
];

const first = (a) => (a && a.length ? a[0] : undefined);

export function configNC(domainNC) {
  return `CN=Configuration,${domainNC}`;
}

export async function certDump(client, domainNC, cache, hooks = {}) {
  const log = hooks.log || (() => {});
  const typeOf = (s) => (cache && cache.IdToTypeCache[s]) || 'Base';
  const base = `CN=Public Key Services,CN=Services,${configNC(domainNC)}`;
  const out = { enterprisecas: [], certtemplates: [], rootcas: [] };

  log(`Enumerating ADCS under ${base} …`);
  let n = 0;
  try {
    for await (const o of client.query({ baseDN: base, filter: '(objectClass=*)', attributes: PKI_ATTRS })) {
      const a = o.attributes;
      const classes = (a.objectClass || []).map((c) => c.toLowerCase());
      const guid = (a.objectGUID ? guidFromB64(first(a.objectGUID)) : '').toUpperCase();
      const aces = acesFromDescriptor(first(a.nTSecurityDescriptor), typeOf);
      n++;

      if (classes.includes('pkienrollmentservice')) {
        out.enterprisecas.push({
          ObjectIdentifier: guid,
          Properties: {
            name: `${first(a.name) || first(a.cn)}@${domainNC}`.toUpperCase(),
            distinguishedname: o.dn, dnshostname: first(a.dNSHostName),
            objectid: guid, caname: first(a.name) || first(a.cn),
          },
          EnabledCertTemplates: (a.certificateTemplates || []),
          Aces: aces, IsDeleted: false, IsACLProtected: false,
        });
      } else if (classes.includes('pkicertificatetemplate')) {
        const nameFlag = Number(first(a['msPKI-Certificate-Name-Flag']) || 0);
        const enrollFlag = Number(first(a['msPKI-Enrollment-Flag']) || 0);
        out.certtemplates.push({
          ObjectIdentifier: guid,
          Properties: {
            name: `${first(a.name) || first(a.cn)}@${domainNC}`.toUpperCase(),
            displayname: first(a.displayName), distinguishedname: o.dn, objectid: guid,
            schemaversion: Number(first(a['msPKI-Template-Schema-Version']) || 1),
            ekus: a.pKIExtendedKeyUsage || [],
            applicationpolicies: a['msPKI-Certificate-Application-Policy'] || [],
            // ESC1 indicator: enrollee supplies subject.
            enrolleesuppliessubject: !!(nameFlag & 0x00000001),
            requiresmanagerapproval: !!(enrollFlag & 0x2),
            authorizedsignatures: Number(first(a['msPKI-RA-Signature']) || 0),
          },
          Aces: aces, IsDeleted: false, IsACLProtected: false,
        });
      } else if (classes.includes('certificationauthority')) {
        out.rootcas.push({
          ObjectIdentifier: guid,
          Properties: { name: `${first(a.name) || first(a.cn)}@${domainNC}`.toUpperCase(), distinguishedname: o.dn, objectid: guid },
          Aces: aces, IsDeleted: false, IsACLProtected: false,
        });
      }
    }
  } catch (e) {
    log(`certdump: ${e.message}`);
  }

  const files = Object.entries(out).map(([type, data]) => ({
    name: `${type}.json`,
    content: { data, meta: { methods: 0, type, count: data.length, version: 6 } },
  }));
  const summary = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.length]));
  log(`ADCS: ${summary.enterprisecas} CA(s), ${summary.certtemplates} template(s), ${summary.rootcas} root CA(s) (scanned ${n} objects).`);
  return { files, summary };
}
