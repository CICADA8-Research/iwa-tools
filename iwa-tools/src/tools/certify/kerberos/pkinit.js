// PKINIT (RFC 4556): authenticate to the KDC with an X.509 certificate + private
// key instead of a password, using ephemeral Diffie-Hellman. Produces a TGT whose
// reply key is derived from the DH shared secret — the foundation of certipy auth.

import { tlv, sequence, octetString, concat, readTLV } from '../ldap/ber.js';
import { sha1 } from '../crypto/sha1.js';
import { MSG_TYPE, NAME_TYPE, PADATA, KEY_USAGE, KDC_OPTIONS, ETYPE_PREFERENCE, KRB_ERR } from './constants.js';
import { ctx, asnInt, kerberosTime, kdcReqBody, kdcReq, paData, oid as berOid, parseKdcRep, parseEncKdcRepPart, parseKrbError, parseKerberosTime } from './asn1.js';
import { decrypt, keySize } from './crypto.js';
import { DH, genKeyPair, sharedSecret, octetstring2key, intToBytes } from './dh.js';
import { buildSignedAuthPack, extractKdcDhPublicKey } from './cms.js';

const FAR_FUTURE = new Date(Date.UTC(2037, 8, 13, 2, 48, 5));
const ctxP = (n, v) => tlv(0x80 | n, v);
const boolTrue = tlv(0x01, Uint8Array.of(0xff));
const derInt = (mag) => tlv(0x02, mag[0] & 0x80 ? concat([Uint8Array.of(0), mag]) : mag);
const bitString = (b) => tlv(0x03, concat([Uint8Array.of(0), b]));

function randomNonce() {
  const b = globalThis.crypto.getRandomValues(new Uint8Array(4));
  return ((b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0) & 0x7fffffff;
}

// SubjectPublicKeyInfo carrying the DH parameters + our public value y.
function dhPublicKeyInfo(yBytes) {
  const dhParams = sequence(derInt(intToBytes(DH.p)), derInt(intToBytes(DH.g)), derInt(intToBytes(DH.q)));
  return sequence(
    sequence(berOid('1.2.840.10046.2.1'), dhParams),   // AlgorithmIdentifier: dhpublicnumber + params
    bitString(derInt(yBytes)),                          // subjectPublicKey = BIT STRING { INTEGER y }
  );
}

// Extract the PA-PK-AS-REP padata value from an AS-REP.
function extractPaPkAsRep(asRep) {
  const app = readTLV(asRep, 0); const seq = readTLV(asRep, app.valueStart);
  const readInt = (t) => { let n = 0; for (let i = t.valueStart; i < t.valueEnd; i++) n = n * 256 + asRep[i]; return n; };
  for (let p = seq.valueStart; p < seq.valueEnd;) {
    const t = readTLV(asRep, p);
    if (t.tag === 0xa2) { // padata [2]
      const list = readTLV(asRep, t.valueStart);
      for (let q = list.valueStart; q < list.valueEnd;) {
        const pa = readTLV(asRep, q); const m = {};
        for (let r = pa.valueStart; r < pa.valueEnd;) { const e = readTLV(asRep, r); m[e.tag] = e; r = e.next; }
        const type = readInt(readTLV(asRep, m[0xa1].valueStart));
        if (type === PADATA.PK_AS_REP) { const oct = readTLV(asRep, m[0xa2].valueStart); return asRep.subarray(oct.valueStart, oct.valueEnd); }
        q = pa.next;
      }
    }
    p = t.next;
  }
  return null;
}

// certDer: leaf certificate (DER). privateKey: WebCrypto RSASSA-PKCS1-v1_5/SHA-256 key.
export async function getTgtPkinit(transport, { username, realm, certDer, privateKey, log = () => {} }) {
  realm = realm.toUpperCase();
  const { x, y } = genKeyPair();
  let clockOffsetMs = 0;

  const build = async () => {
    const nonce = randomNonce();
    const reqBody = kdcReqBody({
      kdcOptions: KDC_OPTIONS.FORWARDABLE | KDC_OPTIONS.RENEWABLE | KDC_OPTIONS.CANONICALIZE,
      cname: [username], cnameType: NAME_TYPE.PRINCIPAL, realm,
      sname: ['krbtgt', realm], snameType: NAME_TYPE.SRV_INST, till: FAR_FUTURE, nonce, etypes: ETYPE_PREFERENCE,
    });
    const now = new Date(Date.now() + clockOffsetMs);
    const pkAuthenticator = sequence(
      ctx(0, asnInt(0)),                              // cusec
      ctx(1, kerberosTime(now)),                      // ctime
      ctx(2, asnInt(nonce)),                          // nonce
      ctx(3, octetString(sha1(reqBody))),             // paChecksum = SHA1(KDC-REQ-BODY)
    );
    const authPack = sequence(ctx(0, pkAuthenticator), ctx(1, dhPublicKeyInfo(intToBytes(y))));
    const cms = await buildSignedAuthPack(authPack, certDer, privateKey);
    const paPkAsReq = sequence(ctxP(0, cms));          // PA-PK-AS-REQ { signedAuthPack [0] IMPLICIT OCTET STRING }
    const paPac = paData(PADATA.PAC_REQUEST, sequence(ctx(0, boolTrue)));
    return kdcReq(MSG_TYPE.AS_REQ, reqBody, [paData(PADATA.PK_AS_REQ, paPkAsReq), paPac]);
  };

  log(`PKINIT AS-REQ for ${username}@${realm} (cert auth, DH group 14) …`);
  let reply = await transport.request(await build());
  if (reply[0] === 0x7e) {
    const err = parseKrbError(reply);
    if (err.errorCode === KRB_ERR.SKEW && err.stime) {   // fix clock and retry once
      clockOffsetMs = parseKerberosTime(err.stime).getTime() - Date.now();
      log(`Clock skew; recalibrating to KDC time ${err.stime} and retrying …`);
      reply = await transport.request(await build());
    }
    if (reply[0] === 0x7e) {
      const code = parseKrbError(reply).errorCode;
      const detail = {
        62: 'KDC_ERR_CLIENT_NOT_TRUSTED (cert issuer not trusted by KDC — publish the CA to NTAuthCertificates)',
        63: 'KDC_ERR_KDC_NOT_TRUSTED (KDC has no cert / wrong KDC cert)',
        64: 'KDC_ERR_INVALID_SIG (bad signature on request)',
        66: 'KDC_ERR_CERTIFICATE_MISMATCH (cert does not map to an account — KB5014754 strong mapping is enforced; the cert must carry the szOID_NTDS_CA_SECURITY_EXT SID extension. ESC1 spoofs are blocked in Full-Enforcement mode.)',
        70: 'KDC_ERR_CANT_VERIFY_CERTIFICATE (cert chain does not validate to a root the KDC trusts)',
        71: 'KDC_ERR_INVALID_CERTIFICATE',
        72: 'KDC_ERR_REVOKED_CERTIFICATE',
      }[code];
      throw new Error(`PKINIT AS-REQ failed: Kerberos error ${code}${detail ? ' — ' + detail : ''}`);
    }
  }
  if (reply[0] !== 0x6b) throw new Error(`PKINIT: unexpected AS reply tag 0x${reply[0].toString(16)}`);

  const rep = parseKdcRep(reply);
  const paPkRep = extractPaPkAsRep(reply);
  if (!paPkRep) throw new Error('PKINIT: no PA-PK-AS-REP in AS-REP (KDC may require RSA mode)');
  const kdcY = extractKdcDhPublicKey(paPkRep);
  const secret = sharedSecret(kdcY, x);
  const replyEtype = rep.encPart.etype;
  const replyKey = octetstring2key(secret, keySize(replyEtype));
  log(`DH shared secret established; reply key etype ${replyEtype}.`);

  const encPart = decrypt(replyEtype, replyKey, KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher);
  const dec = parseEncKdcRepPart(encPart);
  log(`Got TGT for ${username}@${realm} via PKINIT (session key etype ${dec.key.etype}).`);
  return {
    ticket: rep.ticket,
    sessionKey: { etype: dec.key.etype, key: dec.key.keyvalue },
    replyKey: { etype: replyEtype, key: replyKey },  // needed to decrypt PAC_CREDENTIAL_INFO (UnPAC-the-hash)
    crealm: rep.crealm, cname: [username], username, realm, clockOffsetMs,
  };
}
