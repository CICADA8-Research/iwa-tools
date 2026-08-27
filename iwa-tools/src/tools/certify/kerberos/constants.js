// Kerberos 5 protocol constants (RFC 4120, RFC 3961/3962, RFC 4757), mirroring
// the numbers impacket carries in impacket/krb5/constants.py. Only the subset
// the AS/TGS/AP-REQ client flow needs is here.

// Encryption types (etype).
export const ETYPE = {
  DES_CBC_MD5: 3,
  AES128_CTS_HMAC_SHA1_96: 17,
  AES256_CTS_HMAC_SHA1_96: 18,
  RC4_HMAC: 23,
};

// Preference order we advertise in KDC-REQ-BODY.etype. Strongest first; RC4
// last so it is used only when AES is disabled on the account.
export const ETYPE_PREFERENCE = [
  ETYPE.AES256_CTS_HMAC_SHA1_96,
  ETYPE.AES128_CTS_HMAC_SHA1_96,
  ETYPE.RC4_HMAC,
];

// Application (message) types.
export const MSG_TYPE = {
  AS_REQ: 10,
  AS_REP: 11,
  TGS_REQ: 12,
  TGS_REP: 13,
  AP_REQ: 14,
  KRB_ERROR: 30,
};

// PrincipalName name-type.
export const NAME_TYPE = {
  UNKNOWN: 0,
  PRINCIPAL: 1,   // username
  SRV_INST: 2,    // service + instance, e.g. krbtgt/REALM
  SRV_HST: 3,     // service + host, e.g. ldap/dc01.example.com
  ENTERPRISE: 10, // user@realm UPN
};

// PA-DATA padata-type.
export const PADATA = {
  TGS_REQ: 1,           // an AP-REQ for the TGS exchange
  ENC_TIMESTAMP: 2,     // PA-ENC-TIMESTAMP preauth
  PK_AS_REQ: 16,        // PKINIT PA-PK-AS-REQ (RFC 4556)
  PK_AS_REP: 17,        // PKINIT PA-PK-AS-REP
  ETYPE_INFO2: 19,      // salt + etype hints in a PREAUTH_REQUIRED error
  PAC_REQUEST: 128,     // KERB-PA-PAC-REQUEST (MS-specific)
};

// Key-usage numbers (RFC 4120 §7.5.1) for the exchanges we perform.
export const KEY_USAGE = {
  AS_REQ_PA_ENC_TIMESTAMP: 1,
  AS_REP_ENCPART: 3,         // AS-REP enc-part, keyed with the client long-term key
  TGS_REQ_AUTH_CKSUM: 6,     // checksum in a PA-TGS-REQ authenticator
  TGS_REQ_AUTH: 7,           // PA-TGS-REQ authenticator, keyed with the TGT session key
  TGS_REP_ENCPART_SESSKEY: 8,// TGS-REP enc-part, keyed with the TGT session key
  TGS_REP_ENCPART_SUBKEY: 9, // TGS-REP enc-part, keyed with the authenticator subkey
  AP_REQ_AUTH: 11,           // AP-REQ authenticator, keyed with the service session key
  AP_REP_ENCPART: 12,        // AP-REP enc-part (mutual auth), keyed with the session key
};

// GSS-API per-message token key usages (RFC 4121 §2).
export const GSS_USAGE = {
  ACCEPTOR_SEAL: 22,
  ACCEPTOR_SIGN: 23,
  INITIATOR_SEAL: 24,
  INITIATOR_SIGN: 25,
};

// The error codes the client flow branches on.
export const KRB_ERR = {
  SKEW: 37,
  PREAUTH_FAILED: 24,
  PREAUTH_REQUIRED: 25,
};

// Human-readable names for the common KRB-ERROR codes, for log/exception text.
export const KRB_ERR_NAME = {
  6: 'KDC_ERR_C_PRINCIPAL_UNKNOWN (client not found in Kerberos database)',
  7: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (server not found in Kerberos database)',
  18: 'KDC_ERR_CLIENT_REVOKED (account disabled, locked or expired)',
  23: 'KDC_ERR_KEY_EXPIRED (password has expired)',
  24: 'KDC_ERR_PREAUTH_FAILED (wrong password or key)',
  25: 'KDC_ERR_PREAUTH_REQUIRED (additional pre-authentication required)',
  32: 'KRB_AP_ERR_TKT_EXPIRED (ticket expired)',
  37: 'KRB_AP_ERR_SKEW (clock skew too great)',
};

// KDCOptions / APOptions bit positions are numbered from the MSB (bit 0 = the
// top bit of a 32-bit field). These are the assembled 32-bit masks.
export const KDC_OPTIONS = {
  FORWARDABLE: 0x40000000,
  PROXIABLE: 0x10000000,
  RENEWABLE: 0x00800000,
  CANONICALIZE: 0x00010000,
  ENC_TKT_IN_SKEY: 0x00000008, // U2U: encrypt the issued ticket in the session key
  RENEWABLE_OK: 0x00000010,
};

export const AP_OPTIONS = {
  USE_SESSION_KEY: 0x40000000,
  MUTUAL_REQUIRED: 0x20000000,
};
