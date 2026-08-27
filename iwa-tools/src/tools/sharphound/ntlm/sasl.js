// Glue between the NTLM message layer and the LDAP SASL bind: produces the
// GSS-SPNEGO tokens for an NTLMv2 authentication exchange.

import {
  buildType1, parseType2, buildType3, computeNtlmv2Response,
  nowFiletime, randomClientChallenge,
} from './ntlm.js';
import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from './spnego.js';
import { md5 } from '../crypto/md5.js';
import { concat } from '../ldap/ber.js';

// MsvAvChannelBindings (AvId 0x000A) = MD5 of the gss_channel_bindings_struct
// over the tls-server-end-point application data ([MS-NLMP] §3.1.5.1.2). Insert
// it into the CHALLENGE's AV-pair list (before MsvAvEOL) so the NTProofStr binds
// to the TLS channel and the DC's channel-binding enforcement is satisfied.
function withChannelBinding(targetInfo, appData) {
  const head = new Uint8Array(20);
  new DataView(head.buffer).setUint32(16, appData.length, true);
  const cbHash = md5(concat([head, appData]));
  const av = new Uint8Array(4 + 16);
  av[0] = 0x0a; av[2] = 0x10; // AvId=0x000A, AvLen=16 (little-endian)
  av.set(cbHash, 4);
  // Splice before the trailing 4-byte MsvAvEOL.
  const n = targetInfo.length;
  return concat([targetInfo.subarray(0, n - 4), av, targetInfo.subarray(n - 4)]);
}

// Split "DOMAIN\\user" or "user@domain" into { user, domain }. An explicit
// `domainHint` (from a separate UI field) wins if provided.
export function parseIdentity(identity, domainHint = '') {
  identity = (identity || '').trim();
  let user = identity;
  let domain = domainHint.trim();
  if (identity.includes('\\')) {
    const [d, u] = identity.split('\\');
    if (!domain) domain = d;
    user = u;
  } else if (identity.includes('@')) {
    const [u, d] = identity.split('@');
    user = u;
    if (!domain) domain = d;
  }
  return { user, domain };
}

// Returns an async tokenProducer for LdapClient.saslBind('GSS-SPNEGO', ...).
export function ntlmSpnegoProducer({ user, domain, password, channelBinding = null, log = () => {} }) {
  return async (serverCreds, step) => {
    if (step === 0) {
      log('NTLM: sending NEGOTIATE (type 1).');
      return spnegoNegTokenInit(buildType1());
    }
    const type2 = spnegoExtractToken(serverCreds);
    if (!type2) throw new Error('NTLM: no CHALLENGE token in server SASL response');
    const challenge = parseType2(type2);
    log(`NTLM: received CHALLENGE (type 2), sending AUTHENTICATE (type 3)${channelBinding ? ' (+channel binding)' : ''}.`);

    const clientChallenge = randomClientChallenge();
    const timestamp = challenge.timestamp || nowFiletime();
    const targetInfo = channelBinding
      ? withChannelBinding(challenge.targetInfo, channelBinding)
      : challenge.targetInfo;
    const resp = computeNtlmv2Response(
      user, domain, password,
      challenge.serverChallenge, clientChallenge, timestamp, targetInfo,
    );
    const type3 = buildType3({
      domain, user, workstation: '',
      ntResponse: resp.ntChallengeResponse,
      lmResponse: resp.lmChallengeResponse,
    });
    return spnegoNegTokenResp(type3);
  };
}
