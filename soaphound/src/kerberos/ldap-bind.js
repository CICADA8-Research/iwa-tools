// Orchestration glue: acquire a TGT and an ldap/<host> service ticket over
// Kerberos, then complete an LDAP SASL GSS-SPNEGO bind. Kept dependency-free of
// any specific LDAP client — `ldap` is any object exposing
// saslBind(mechanism, producer) — so this file copies verbatim into every tool
// that binds over LDAP (adidns, sharphound).

import { KerberosClient, KdcSocketTransport } from './client.js';
import { kerberosSpnegoProducer } from './gss.js';
import { ETYPE } from './constants.js';

function hexToBytes(h) {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// creds: { host, kdc?, kdcPort?, realm, user, password? | hash? (RC4 NT hash) |
//          key?+etype?, spn? }. Defaults the SPN to ldap/<host> and the KDC to
// the LDAP host.
export async function kerberosSpnegoBind(ldap, {
  host, kdc = null, kdcPort = 88, realm, user,
  password = null, hash = null, key = null, etype = null, spn = null,
  channelBinding = null, log = () => {},
}) {
  if (!user) throw new Error('Kerberos requires a username.');
  if (!realm) throw new Error('Kerberos requires a realm (domain).');

  const transport = new KdcSocketTransport(kdc || host, kdcPort, log);
  await transport.connect();
  let serviceTicket;
  try {
    const krb = new KerberosClient(transport, log);
    const id = { username: user, realm };
    if (key) { id.key = key; id.etype = etype; }
    else if (hash) { id.key = hexToBytes(hash); id.etype = ETYPE.RC4_HMAC; }
    else id.password = password;

    const tgt = await krb.getTGT(id);
    serviceTicket = await krb.getTGS(tgt, { spn: spn || `ldap/${host}` });
  } finally {
    await transport.close();
  }
  await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket, channelBinding, log }));
}
