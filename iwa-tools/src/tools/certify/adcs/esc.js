// ESC vulnerability classification for AD CS templates and CAs, following
// GhostPack/Certify + Certipy. Template-level checks (ESC1/2/3/4/9/13/15) are
// fully derived from LDAP; CA-level ESC6/ESC7(ManageCA) need the CA's own config
// over RPC and are only hinted at here (ESC8 web-enrolment is advertised in AD).

import { parseDescriptor } from '../security/sddl.js';
import { b64ToBytes } from '../security/sid.js';
import { NAME_FLAG, ENROLL_FLAG, EKU, AUTH_EKUS, RIGHT_GUID, MASK, isUnsafeSid, isPrivilegedSid } from './constants.js';
import { first, all } from './enum.js';

// Pull enrolment + write/owner principals out of a template/CA security descriptor.
function analyzeAcl(b64) {
  const enroll = new Set(); const write = new Set(); let owner = null;
  if (!b64) return { enroll: [], write: [], owner };
  let d; try { d = parseDescriptor(b64ToBytes(b64)); } catch { return { enroll: [], write: [], owner }; }
  owner = d.ownerSid;
  if (owner) write.add(owner);
  for (const ace of d.aces) {
    if (!ace.sid) continue;
    const m = ace.mask; const ot = ace.objectType;
    const enrollRight = (m & MASK.CONTROL_ACCESS) && (!ot || ot === RIGHT_GUID.ENROLL || ot === RIGHT_GUID.AUTO_ENROLL);
    if ((m & MASK.GENERIC_ALL) || enrollRight) enroll.add(ace.sid);
    // ESC4 = full control over the template: generic rights, or an all-properties
    // write (WRITE_PROP with no objectType). A property-scoped WRITE_PROP (objectType
    // set, e.g. the Enroll right) is NOT template-modification control.
    const fullWrite = (m & MASK.GENERIC_ALL) || (m & MASK.WRITE_OWNER) || (m & MASK.WRITE_DACL) ||
      (m & MASK.GENERIC_WRITE) || ((m & MASK.WRITE_PROP) && !ot);
    if (fullWrite) write.add(ace.sid);
  }
  return { enroll: [...enroll], write: [...write], owner };
}

export function analyzeTemplate(o) {
  const a = o.attributes;
  const name = first(a, 'name') || first(a, 'cn');
  const nameFlag = Number(first(a, 'msPKI-Certificate-Name-Flag') || 0) >>> 0;
  const enrollFlag = Number(first(a, 'msPKI-Enrollment-Flag') || 0) >>> 0;
  const raSig = Number(first(a, 'msPKI-RA-Signature') || 0);
  const schema = Number(first(a, 'msPKI-Template-Schema-Version') || 1);
  const ekus = [...new Set([...all(a, 'pKIExtendedKeyUsage'), ...all(a, 'msPKI-Certificate-Application-Policy')])];
  const policies = all(a, 'msPKI-Certificate-Policy');
  const acl = analyzeAcl(first(a, 'nTSecurityDescriptor'));

  return {
    name, display: first(a, 'displayName') || name, ekus, policies, acl, schema, raSig,
    suppliesSubject: !!(nameFlag & NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT),
    managerApproval: !!(enrollFlag & ENROLL_FLAG.PEND_ALL_REQUESTS),
    noSecurityExt: !!(enrollFlag & ENROLL_FLAG.NO_SECURITY_EXTENSION),
    requiresSignatures: raSig > 0,
    clientAuth: ekus.length === 0 || ekus.some((e) => AUTH_EKUS.has(e)),
    agentEku: ekus.includes(EKU.CERT_REQUEST_AGENT),
    anyPurpose: ekus.includes(EKU.ANY_PURPOSE) || ekus.length === 0,
  };
}

export function templateEscs(t) {
  const out = [];
  const unsafeEnroll = t.acl.enroll.filter(isUnsafeSid);
  const unsafeWrite = t.acl.write.filter((s) => isUnsafeSid(s) && !isPrivilegedSid(s));
  const enrollable = unsafeEnroll.length > 0;
  const noApproval = !t.managerApproval && !t.requiresSignatures;

  if (t.suppliesSubject && t.clientAuth && noApproval && enrollable)
    out.push({ id: 'ESC1', risk: 'Critical', principals: unsafeEnroll, detail: 'Low-priv enrollees can request an auth-capable certificate and supply an arbitrary subject / SAN — impersonate any principal.' });
  if (t.anyPurpose && noApproval && enrollable)
    out.push({ id: 'ESC2', risk: 'High', principals: unsafeEnroll, detail: 'Any Purpose (or no) EKU — issued certificates are usable for anything, including authentication.' });
  if (t.agentEku && noApproval && enrollable)
    out.push({ id: 'ESC3', risk: 'High', principals: unsafeEnroll, detail: 'Certificate Request Agent EKU — obtain an enrolment-agent cert and request on behalf of other users.' });
  if (unsafeWrite.length)
    out.push({ id: 'ESC4', risk: 'High', principals: unsafeWrite, detail: 'Low-priv principals hold write / owner control of the template — it can be reconfigured into ESC1.' });
  if (t.noSecurityExt && t.clientAuth && enrollable)
    out.push({ id: 'ESC9', risk: 'Medium', principals: unsafeEnroll, detail: 'No security extension (szOID_NTDS_CA_SECURITY_EXT absent) — weakens strong certificate mapping.' });
  if (t.policies.length && t.clientAuth && enrollable)
    out.push({ id: 'ESC13', risk: 'Medium', principals: unsafeEnroll, extra: t.policies, detail: 'Template pins an issuance policy OID that may confer group membership on logon — verify the OID→group link.' });
  if (t.schema === 1 && t.clientAuth && enrollable)
    out.push({ id: 'ESC15', risk: 'Medium', principals: unsafeEnroll, detail: 'Schema v1 template (EKUwu / CVE-2024-49019) — application policies can be injected through the CSR.' });
  return out;
}

export function analyzeCA(o) {
  const a = o.attributes;
  return {
    name: first(a, 'name') || first(a, 'cn'),
    dns: first(a, 'dNSHostName'),
    templates: all(a, 'certificateTemplates'),
    enrollmentServers: all(a, 'msPKI-Enrollment-Servers'),
    acl: analyzeAcl(first(a, 'nTSecurityDescriptor')),
  };
}

export function caEscs(ca) {
  const out = [];
  if (ca.enrollmentServers.length)
    out.push({ id: 'ESC8', risk: 'High', principals: [], detail: 'CA advertises HTTP Web Enrolment / CES — susceptible to NTLM relay to the CA endpoint.' });
  const unsafeWrite = ca.acl.write.filter((s) => isUnsafeSid(s) && !isPrivilegedSid(s));
  if (unsafeWrite.length)
    out.push({ id: 'ESC7', risk: 'High', principals: unsafeWrite, detail: 'Low-priv principals hold write control of the CA object (ESC7-class — confirm ManageCA/ManageCertificates via CA config).' });
  return out;
}
