// AD CS constants for the Certify port: certificate-template flag bits, the
// client-auth / agent EKU OIDs, the enrollment extended-right GUIDs, and the
// well-known "low-privileged" principals whose enrolment rights make a template
// dangerous. Mirrors GhostPack/Certify + Certipy classification.

// msPKI-Certificate-Name-Flag
export const NAME_FLAG = {
  ENROLLEE_SUPPLIES_SUBJECT: 0x00000001,
  ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: 0x00010000,
};

// msPKI-Enrollment-Flag
export const ENROLL_FLAG = {
  PEND_ALL_REQUESTS: 0x00000002,        // manager approval required
  NO_SECURITY_EXTENSION: 0x00080000,    // ESC9 (szOID_NTDS_CA_SECURITY_EXT absent)
};

// Extended Key Usage / Application Policy OIDs that make a cert usable for auth.
export const EKU = {
  CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
  SMARTCARD_LOGON: '1.3.6.1.4.1.311.20.2.2',
  PKINIT_CLIENT_AUTH: '1.3.6.1.5.2.3.4',
  ANY_PURPOSE: '2.5.29.37.0',
  CERT_REQUEST_AGENT: '1.3.6.1.4.1.311.20.2.1', // Enrollment Agent (ESC3)
};
export const AUTH_EKUS = new Set([EKU.CLIENT_AUTH, EKU.SMARTCARD_LOGON, EKU.PKINIT_CLIENT_AUTH, EKU.ANY_PURPOSE]);

// Human names for common EKU OIDs (display only).
export const EKU_NAME = {
  '1.3.6.1.5.5.7.3.2': 'Client Authentication',
  '1.3.6.1.5.5.7.3.1': 'Server Authentication',
  '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
  '1.3.6.1.5.2.3.4': 'PKINIT Client Authentication',
  '2.5.29.37.0': 'Any Purpose',
  '1.3.6.1.4.1.311.20.2.1': 'Certificate Request Agent',
  '1.3.6.1.4.1.311.10.3.4': 'Encrypting File System',
  '1.3.6.1.5.5.7.3.4': 'Secure Email',
  '1.3.6.1.4.1.311.10.3.12': 'Document Signing',
};

// Access-right GUIDs (object-type of an object ACE).
export const RIGHT_GUID = {
  ENROLL: '0e10c968-78fb-11d2-90d4-00c04f79dc55',
  AUTO_ENROLL: 'a05b8cc2-17bc-4802-a710-e7c15ab866a2',
};

// ADS access-mask bits used on template/CA DACLs.
export const MASK = {
  GENERIC_ALL: 0x10000000,
  GENERIC_WRITE: 0x40000000,
  WRITE_OWNER: 0x00080000,
  WRITE_DACL: 0x00040000,
  WRITE_PROP: 0x00000020,
  CONTROL_ACCESS: 0x00000100, // extended right (enroll = object ACE with ENROLL guid)
};

// Absolute well-known SIDs -> name.
export const WELLKNOWN = {
  'S-1-1-0': 'Everyone',
  'S-1-5-7': 'Anonymous',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-18': 'SYSTEM',
  'S-1-5-32-544': 'BUILTIN\\Administrators',
  'S-1-5-32-545': 'BUILTIN\\Users',
  'S-1-5-9': 'Enterprise Domain Controllers',
};

// Domain-relative RID -> name.
export const RID_NAME = {
  500: 'Administrator', 512: 'Domain Admins', 513: 'Domain Users', 515: 'Domain Computers',
  516: 'Domain Controllers', 518: 'Schema Admins', 519: 'Enterprise Admins', 520: 'Group Policy Creator Owners',
  526: 'Key Admins', 527: 'Enterprise Key Admins',
};

// Broad, low-privileged principals whose enrol/write rights make a template risky.
const UNSAFE_ABSOLUTE = new Set(['S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545']);
const UNSAFE_RID = new Set([513, 515, 545]);

export function isUnsafeSid(sid) {
  if (!sid) return false;
  if (UNSAFE_ABSOLUTE.has(sid)) return true;
  const m = /^S-1-5-21-[\d-]+-(\d+)$/.exec(sid);
  return m ? UNSAFE_RID.has(Number(m[1])) : false;
}

// Privileged principals to treat as safe (never flagged as the risky enrollee).
const SAFE_RID = new Set([500, 512, 516, 518, 519, 526, 527]);
export function isPrivilegedSid(sid) {
  if (sid === 'S-1-5-18' || sid === 'S-1-5-32-544' || sid === 'S-1-5-9') return true;
  const m = /^S-1-5-21-[\d-]+-(\d+)$/.exec(sid);
  return m ? SAFE_RID.has(Number(m[1])) : false;
}

export function wellKnownName(sid) {
  if (WELLKNOWN[sid]) return WELLKNOWN[sid];
  const m = /^S-1-5-21-[\d-]+-(\d+)$/.exec(sid);
  if (m && RID_NAME[Number(m[1])]) return RID_NAME[Number(m[1])];
  return null;
}
