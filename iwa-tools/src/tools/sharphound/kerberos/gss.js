// GSS-API / SPNEGO packaging of a Kerberos AP-REQ, and the SASL token producer
// that drives an LDAP GSS-SPNEGO bind with a service ticket. This is the
// Kerberos analogue of ntlm/sasl.js: authentication only, no GSS security
// layer (sign/seal) negotiation — matching the NTLM stage-1 posture here.

import { tlv, concat, octetString, sequence, readTLV } from '../ldap/ber.js';
import {
  apReq, authenticator, encryptedData, checksumValue, encryptionKey, oid,
  parseApRep, parseEncApRepPart,
} from './asn1.js';
import { encrypt, decrypt, keySize, randomBytes } from './crypto.js';
import { md5 } from '../crypto/md5.js';
import { KEY_USAGE, AP_OPTIONS, NAME_TYPE } from './constants.js';
import { KerberosSession } from './gss-seal.js';
import { spnegoExtractToken } from '../ntlm/spnego.js';

const SPNEGO_OID = '1.3.6.1.5.5.2';
const KRB5_OID = '1.2.840.113554.1.2.2';

// GSS_C flags carried in the RFC 4121 §4.1.1 authenticator checksum.
const GSS_C = { DELEG: 0x01, MUTUAL: 0x02, REPLAY: 0x04, SEQUENCE: 0x08, CONF: 0x10, INTEG: 0x20 };

// Bnd = MD5 of the serialized gss_channel_bindings_struct (RFC 2744): four
// zeroed address u32s + application_data length + application_data. For
// tls-server-end-point (RFC 5929) the application_data is "tls-server-end-point:"
// + certificate hash, supplied by the TLS layer.
function channelBindingsMd5(appData) {
  const head = new Uint8Array(20); // initiator/acceptor addrtype+len all zero
  new DataView(head.buffer).setUint32(16, appData.length, true); // app_data length (LE)
  return md5(concat([head, appData]));
}

// The 24-byte "0x8003" checksum: Bnd length (16), the 16-byte channel binding
// (zeros = none, or MD5(bindings) when `cbAppData` is given), then GSS flags.
function gssChecksumBytes(flags, cbAppData = null) {
  const b = new Uint8Array(24);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 16, true);
  if (cbAppData && cbAppData.length) b.set(channelBindingsMd5(cbAppData), 4);
  dv.setUint32(20, flags >>> 0, true);
  return b;
}

// Build an AP-REQ from a service ticket (the output of KerberosClient.getTGS),
// with an authenticator carrying the GSS checksum, keyed with the service
// session key at usage 11. `flags` defaults to 0 (no GSS security layer) so the
// server does not expect signed/sealed PDUs after the bind — matching the
// auth-only NTLM posture, which keeps subsequent LDAP searches plaintext.
export function buildGssApReq(serviceTicket, { mutual = false, flags = 0, channelBinding = null } = {}) {
  const sk = serviceTicket.sessionKey;
  const cksum = checksumValue(0x8003, gssChecksumBytes(flags, channelBinding));
  const auth = authenticator({
    crealm: serviceTicket.crealm,
    cname: serviceTicket.cname,
    cnameType: NAME_TYPE.PRINCIPAL,
    // Use the KDC-calibrated clock the ticket carries, to avoid AP-REQ skew.
    ctime: new Date(Date.now() + (serviceTicket.clockOffsetMs || 0)),
    cusec: 0,
    cksum,
  });
  const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.AP_REQ_AUTH, auth));
  const apOptions = mutual ? AP_OPTIONS.MUTUAL_REQUIRED : 0;
  return apReq({ apOptions, ticket: serviceTicket.ticket, encAuthenticator: encAuth });
}

// Wrap a mechanism token in the GSS-API InitialContextToken (RFC 2743 §3.1):
//   [APPLICATION 0] { thisMech = krb5 OID, 0x01 0x00 (AP-REQ tok-id), AP-REQ }.
// This is the token for the raw SASL "GSSAPI" mechanism.
export function gssInitToken(apReqBytes) {
  const tokId = Uint8Array.of(0x01, 0x00);
  return tlv(0x60, concat([oid(KRB5_OID), tokId, apReqBytes]));
}

// SPNEGO NegTokenInit advertising krb5 and carrying the GSS init token as the
// optimistic mechToken — the token for the SASL "GSS-SPNEGO" mechanism.
export function spnegoKrbInitToken(gssToken) {
  const mechTypes = tlv(0xa0, sequence(oid(KRB5_OID)));   // [0] MechTypeList
  const mechToken = tlv(0xa2, octetString(gssToken));     // [2] mechToken
  const negTokenInit = tlv(0xa0, sequence(mechTypes, mechToken));
  return tlv(0x60, concat([oid(SPNEGO_OID), negTokenInit]));
}

// Producer for LdapClient.saslBind('GSS-SPNEGO', producer): a single optimistic
// Kerberos leg. Resolves the SPN automatically from the bind host if not given.
export function kerberosSpnegoProducer({ serviceTicket, channelBinding = null, log = () => {} }) {
  return async (serverCreds, step) => {
    if (step > 0) return null; // auth-only: nothing to send on later legs
    log(`Kerberos: sending AP-REQ for ${serviceTicket.spn} via GSS-SPNEGO${channelBinding ? ' (+channel binding)' : ''}.`);
    return spnegoKrbInitToken(gssInitToken(buildGssApReq(serviceTicket, { channelBinding })));
  };
}

// Producer for the raw SASL "GSSAPI" mechanism (no SPNEGO layer).
export function kerberosGssapiProducer({ serviceTicket, log = () => {} }) {
  return async (serverCreds, step) => {
    if (step > 0) return null;
    log(`Kerberos: sending AP-REQ for ${serviceTicket.spn} via GSSAPI.`);
    return gssInitToken(buildGssApReq(serviceTicket));
  };
}

// ---- Confidentiality context (sign+seal) for ADWS/NNS and WinRM ------------
// These services require a GSS security layer, so we establish a full context:
// an AP-REQ with mutual auth + a fresh initiator subkey + a sequence number,
// then process the server's AP-REP to pick up any acceptor subkey, and hand
// back a KerberosSession that seals/unseals subsequent messages.

function u32be(b) { return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false); }

// Build the optimistic client token (SPNEGO-wrapped GSS AP-REQ) plus the state
// needed to finish the context once the server replies.
export function gssSealInit(serviceTicket, { spnego = true } = {}) {
  const sk = serviceTicket.sessionKey;
  const subkey = { etype: sk.etype, key: randomBytes(keySize(sk.etype)) };
  const seqNumber = u32be(randomBytes(4)) & 0x7fffffff;
  const cksum = checksumValue(0x8003, gssChecksumBytes(GSS_C.MUTUAL | GSS_C.CONF | GSS_C.INTEG));
  const auth = authenticator({
    crealm: serviceTicket.crealm, cname: serviceTicket.cname, cnameType: NAME_TYPE.PRINCIPAL,
    ctime: new Date(Date.now() + (serviceTicket.clockOffsetMs || 0)), cusec: 0, cksum,
    subkey: encryptionKey(subkey.etype, subkey.key), seqNumber,
  });
  const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.AP_REQ_AUTH, auth));
  const ap = apReq({ apOptions: AP_OPTIONS.MUTUAL_REQUIRED, ticket: serviceTicket.ticket, encAuthenticator: encAuth });
  const gss = gssInitToken(ap);
  return {
    token: spnego ? spnegoKrbInitToken(gss) : gss,
    state: { subkey, seqNumber, sessionKey: sk },
  };
}

// Pull the AP-REP out of a server handshake reply (SPNEGO NegTokenResp or a raw
// GSS token) and strip the GSS InitialContextToken wrapper.
function extractApRep(bytes) {
  if (!bytes || !bytes.length) return null;
  let gss = bytes[0] === 0x60 ? bytes : spnegoExtractToken(bytes);
  if (!gss) return null;
  if (gss[0] === 0x6f) return gss;       // bare AP-REP
  if (gss[0] !== 0x60) return null;
  const outer = readTLV(gss, 0);
  const oidT = readTLV(gss, outer.valueStart);
  const pos = oidT.next + 2;             // skip mech OID + 2-byte tok-id (02 00)
  return gss.subarray(pos, outer.valueEnd);
}

// Finish the context from the server's reply: process the AP-REP (mutual auth),
// adopt an acceptor subkey if one was sent, and return the live KerberosSession.
export function gssSealEstablish(serverBytes, state) {
  let acceptorSubkey = null;
  const apRepToken = extractApRep(serverBytes);
  if (apRepToken) {
    const apRep = parseApRep(apRepToken);
    const decd = decrypt(state.sessionKey.etype, state.sessionKey.key, KEY_USAGE.AP_REP_ENCPART, apRep.encPart.cipher);
    const part = parseEncApRepPart(decd);
    if (part.subkey) acceptorSubkey = { etype: part.subkey.etype, key: part.subkey.keyvalue };
  }
  const wrapKey = acceptorSubkey || state.subkey;
  return new KerberosSession(wrapKey, {
    role: 'initiator', acceptorSubkey: !!acceptorSubkey, seq: state.seqNumber,
  });
}

export { GSS_C };
