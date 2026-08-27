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
  ticket = null, channelBinding = null, log = () => {},
}) {
  const wantSpn = spn || `ldap/${host}`;

  // Imported ticket (ccache/kirbi): prefer a service ticket for the target
  // service (pass-the-ticket — no KDC contact), else fetch one from an imported
  // TGT. Falls through to the password/hash flow when no ticket was supplied.
  if (ticket) {
    const serviceTicket = await serviceTicketFromImport(ticket, { host, kdc, kdcPort, wantSpn, log });
    await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket, channelBinding, log }));
    return;
  }

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
    serviceTicket = await krb.getTGS(tgt, { spn: wantSpn });
  } finally {
    await transport.close();
  }
  await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket, channelBinding, log }));
}

// Resolve a service ticket for `wantSpn` from an imported { tgts, serviceTickets }
// bundle: a stored ticket for the same service is used verbatim (no KDC round
// trip); otherwise a stored TGT is exchanged for one via TGS.
async function serviceTicketFromImport(ticket, { host, kdc, kdcPort, wantSpn, log }) {
  const wantService = wantSpn.split('/')[0].toLowerCase();
  const realmOf = (t) => (t.realm || t.crealm || '').replace(/\.$/, '');
  const svc = (ticket.serviceTickets || []).find((t) => (t.spn || '').split('/')[0].toLowerCase() === wantService);
  if (svc) {
    // Pass-the-ticket: reuse the stored service ticket directly. Imported tickets
    // carry no clock offset, so calibrate against the KDC (time only, no creds)
    // to keep the AP-REQ within the DC's skew window on an unsynced operator box.
    log(`Using imported ${svc.spn} service ticket (pass-the-ticket — no password).`);
    const clockOffsetMs = await kdcClockOffsetMs(kdc || host, kdcPort, svc.cname?.[0], realmOf(svc), log);
    return { ...svc, spn: svc.spn || wantSpn, clockOffsetMs };
  }
  const tgt = (ticket.tgts || [])[0];
  if (!tgt) throw new Error(`imported ticket has no ${wantService} service ticket and no TGT`);
  log(`Using imported TGT for ${tgt.cname.join('/')}@${tgt.crealm}; requesting ${wantSpn} …`);
  const transport = new KdcSocketTransport(kdc || host, kdcPort, log);
  await transport.connect();
  try {
    const krb = new KerberosClient(transport, log);
    await krb.calibrateClock(tgt.cname?.[0], realmOf(tgt)); // sync to the KDC before the TGS
    return await krb.getTGS(tgt, { spn: wantSpn });
  } finally {
    await transport.close();
  }
}

// Best-effort KDC time sync for a pass-the-ticket bind (its own short-lived
// transport): returns the KDC clock offset in ms, or 0 if the KDC is unreachable.
async function kdcClockOffsetMs(kdcHost, kdcPort, username, realm, log) {
  if (!realm) return 0;
  try {
    const transport = new KdcSocketTransport(kdcHost, kdcPort, log);
    await transport.connect();
    try { return await new KerberosClient(transport, log).calibrateClock(username, realm); }
    finally { await transport.close(); }
  } catch { return 0; }
}
