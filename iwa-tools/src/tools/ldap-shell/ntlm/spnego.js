// Minimal SPNEGO (RFC 4178) wrapping for the LDAP SASL "GSS-SPNEGO" mechanism.
// We only need to carry NTLMSSP tokens, so this builds NegTokenInit /
// NegTokenResp and pulls the inner NTLM token back out of the server reply.

import { tlv, concat, octetString, sequence, oid, readTLV } from '../ldap/ber.js';

const SPNEGO_OID = '1.3.6.1.5.5.2';
const NTLM_OID = '1.3.6.1.4.1.311.2.2.10';

// First client token: GSSAPI InitialContextToken wrapping NegTokenInit.
//   [APPLICATION 0] { SPNEGO-OID, [0] NegTokenInit { [0] mechTypes, [2] mechToken } }
export function spnegoNegTokenInit(ntlmToken) {
  const mechTypes = tlv(0xa0, sequence(oid(NTLM_OID)));   // [0] MechTypeList
  const mechToken = tlv(0xa2, octetString(ntlmToken));    // [2] mechToken
  const negTokenInit = tlv(0xa0, sequence(mechTypes, mechToken)); // [0] NegTokenInit
  return tlv(0x60, concat([oid(SPNEGO_OID), negTokenInit]));
}

// Subsequent client token: NegTokenResp carrying the NTLM AUTHENTICATE.
//   [1] NegTokenResp { [2] responseToken }
export function spnegoNegTokenResp(ntlmToken) {
  const responseToken = tlv(0xa2, octetString(ntlmToken)); // [2] responseToken
  return tlv(0xa1, sequence(responseToken));
}

// Pull the inner NTLM token out of a server SPNEGO reply. The server's
// NegTokenResp carries the NTLM CHALLENGE in responseToken [2]; we locate the
// first context-[2] holding an OCTET STRING anywhere in the DER tree.
export function spnegoExtractToken(buf) {
  return search(buf, 0, buf.length);
}

function search(buf, start, end) {
  let pos = start;
  while (pos < end) {
    const t = readTLV(buf, pos);
    if (!t) break;
    if (t.tag === 0xa2) {
      const inner = readTLV(buf, t.valueStart);
      if (inner && inner.tag === 0x04) return buf.slice(inner.valueStart, inner.valueEnd);
    }
    if (t.tag & 0x20) { // constructed — descend
      const found = search(buf, t.valueStart, t.valueEnd);
      if (found) return found;
    }
    pos = t.next;
  }
  return null;
}
