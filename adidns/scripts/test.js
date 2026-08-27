// Offline unit tests for the pure protocol/parsing logic (no browser APIs).
// Run with: node scripts/test.js
import assert from 'node:assert';
import {
  integer, octetString, sequence, set, enumerated, tlv, oid,
  readTLV, children, readInt, readString, concat,
} from '../src/ldap/ber.js';
import { filter, LdapClient } from '../src/ldap/client.js';
import { parseDnsRecord } from '../src/dns/record.js';
import { md4 } from '../src/crypto/md4.js';
import { md5, hmacMd5 } from '../src/crypto/md5.js';
import {
  ntowfv2, computeNtlmv2Response, buildType1, parseType2, buildType3, utf16le,
} from '../src/ntlm/ntlm.js';
import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from '../src/ntlm/spnego.js';
import { Aes } from '../src/crypto/aes.js';
import { sha1, hmacSha1, pbkdf2Sha1 } from '../src/crypto/sha1.js';
import {
  nfold, stringToKey, encrypt as kEncrypt, decrypt as kDecrypt, defaultSalt,
} from '../src/kerberos/crypto.js';
import { ETYPE, KEY_USAGE, MSG_TYPE, NAME_TYPE, PADATA, KRB_ERR } from '../src/kerberos/constants.js';
import {
  app, ctx, asnInt, generalString, kerberosTime, principalName, encryptedData,
  encryptionKey, paData, parseKdcRep, parseEtypeInfo2,
} from '../src/kerberos/asn1.js';
import { KerberosClient } from '../src/kerberos/client.js';
import { buildGssApReq, gssInitToken, spnegoKrbInitToken } from '../src/kerberos/gss.js';
import { KerberosSession } from '../src/kerberos/gss-seal.js';

const PAGED_OID = '1.2.840.113556.1.4.319';
const hex = (u) => Buffer.from(u).toString('hex');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const enc = (s) => new TextEncoder().encode(s);

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }
async function okAsync(name, fn) { await fn(); console.log(`  ok  ${name}`); pass++; }

// ---- BER round-trips ----
ok('integer encodes minimal positive', () => {
  assert.deepStrictEqual([...integer(0)], [0x02, 0x01, 0x00]);
  assert.deepStrictEqual([...integer(3)], [0x02, 0x01, 0x03]);
  assert.deepStrictEqual([...integer(255)], [0x02, 0x02, 0x00, 0xff]); // keep positive
  assert.deepStrictEqual([...integer(256)], [0x02, 0x02, 0x01, 0x00]);
});

ok('sequence wraps children with correct length', () => {
  const seq = sequence(integer(1), octetString('ab'));
  const t = readTLV(seq, 0);
  assert.strictEqual(t.tag, 0x30);
  const kids = [...children(seq, t.valueStart, t.valueEnd)];
  assert.strictEqual(readInt(seq, kids[0].valueStart, kids[0].valueEnd), 1);
  assert.strictEqual(readString(seq, kids[1].valueStart, kids[1].valueEnd), 'ab');
});

ok('long-form length (>127 bytes)', () => {
  const big = octetString('x'.repeat(200));
  const t = readTLV(big, 0);
  assert.strictEqual(t.length, 200);
  assert.strictEqual(t.valueEnd - t.valueStart, 200);
});

ok('filter equality has [3] tag and two octet strings', () => {
  const f = filter.equal('objectClass', 'dnsNode');
  assert.strictEqual(f[0], 0xa3);
  const kids = [...children(f, readTLV(f, 0).valueStart, readTLV(f, 0).valueEnd)];
  assert.strictEqual(readString(f, kids[0].valueStart, kids[0].valueEnd), 'objectClass');
  assert.strictEqual(readString(f, kids[1].valueStart, kids[1].valueEnd), 'dnsNode');
});

ok('filter present has [7] primitive tag', () => {
  const f = filter.present('objectClass');
  assert.strictEqual(f[0], 0x87);
});

// ---- dnsRecord parsing ----
function rpcRecord(type, ttl, dataBytes) {
  const buf = new Uint8Array(24 + dataBytes.length);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, dataBytes.length, true); // DataLength
  dv.setUint16(2, type, true);             // Type
  buf[4] = 5;                              // Version
  buf[5] = 0xf0;                           // Rank
  dv.setUint32(8, 1, true);                // Serial
  dv.setUint32(12, ttl, false);            // TtlSeconds (BIG endian)
  buf.set(dataBytes, 24);
  return buf;
}

function countName(labels) {
  const parts = [];
  for (const l of labels) { parts.push(l.length); for (const c of l) parts.push(c.charCodeAt(0)); }
  const raw = Uint8Array.from(parts);
  return Uint8Array.from([raw.length, labels.length, ...raw]);
}

ok('parses A record', () => {
  const rec = parseDnsRecord(rpcRecord(1, 600, Uint8Array.of(10, 0, 0, 1)));
  assert.strictEqual(rec.typeName, 'A');
  assert.strictEqual(rec.ttl, 600);
  assert.strictEqual(rec.display, '10.0.0.1');
});

ok('parses AAAA record with compression', () => {
  const data = new Uint8Array(16); data[0] = 0x20; data[1] = 0x01; data[15] = 0x01;
  const rec = parseDnsRecord(rpcRecord(28, 300, data));
  assert.strictEqual(rec.typeName, 'AAAA');
  assert.strictEqual(rec.display, '2001::1');
});

ok('parses CNAME counted name', () => {
  const data = countName(['www', 'corp', 'local']);
  const rec = parseDnsRecord(rpcRecord(5, 3600, data));
  assert.strictEqual(rec.typeName, 'CNAME');
  assert.strictEqual(rec.display, 'www.corp.local.');
});

ok('parses SRV record', () => {
  const head = new Uint8Array(6);
  const dv = new DataView(head.buffer);
  dv.setUint16(0, 0, false); dv.setUint16(2, 100, false); dv.setUint16(4, 389, false);
  const data = concat([head, countName(['dc01', 'corp', 'local'])]);
  const rec = parseDnsRecord(rpcRecord(33, 600, data));
  assert.strictEqual(rec.typeName, 'SRV');
  assert.strictEqual(rec.display, '0 100 389 dc01.corp.local.');
});

ok('parses SOA record', () => {
  const head = new Uint8Array(20);
  const dv = new DataView(head.buffer);
  [25, 900, 600, 86400, 3600].forEach((v, i) => dv.setUint32(i * 4, v, false));
  const data = concat([head, countName(['dc01', 'corp', 'local']), countName(['hostmaster', 'corp', 'local'])]);
  const rec = parseDnsRecord(rpcRecord(6, 3600, data));
  assert.strictEqual(rec.typeName, 'SOA');
  assert.match(rec.display, /dc01\.corp\.local\. hostmaster\.corp\.local\. \(serial 25/);
});

ok('parses TXT record', () => {
  const s = 'hello'; const data = Uint8Array.from([s.length, ...[...s].map((c) => c.charCodeAt(0))]);
  const rec = parseDnsRecord(rpcRecord(16, 600, data));
  assert.strictEqual(rec.display, '"hello"');
});

// ---- LDAP message framing / parsing ----
ok('frames an LDAPMessage and identifies bind response op (0x61)', () => {
  const bindResp = tlv(0x61, concat([enumerated(0), octetString(''), octetString('')]));
  const msg = sequence(integer(1), bindResp);
  const c = new LdapClient();
  c._buf = msg;
  const framed = c._tryFrame();
  assert.strictEqual(framed.messageId, 1);
  assert.strictEqual(framed.op.tag, 0x61);
  assert.strictEqual(c._resultCode(framed), 0);
});

ok('parses a SearchResultEntry with name + binary dnsRecord', () => {
  const aRecord = parseAndReencodeA();
  const entry = tlv(0x64, concat([
    octetString('DC=www,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local'),
    sequence(
      sequence(octetString('name'), set(octetString('www'))),
      sequence(octetString('dnsRecord'), set(octetString(aRecord))),
    ),
  ]));
  const msg = sequence(integer(2), entry);
  const c = new LdapClient();
  c._buf = msg;
  const framed = c._tryFrame();
  const parsed = c._parseEntry(framed);
  assert.strictEqual(readString(parsed.attributes.name[0], 0, parsed.attributes.name[0].length), 'www');
  const rec = parseDnsRecord(parsed.attributes.dnsRecord[0]);
  assert.strictEqual(rec.display, '10.0.0.1');
});

ok('extracts paged-results cookie from SearchResultDone controls', () => {
  const cookie = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const done = tlv(0x65, concat([enumerated(0), octetString(''), octetString('')]));
  // Controls ::= [0] SEQUENCE OF Control — the [0] tag IS the sequence-of, so
  // Control SEQUENCEs sit directly inside it (matches what AD sends back).
  const controls = tlv(0xa0, sequence(
    octetString(PAGED_OID),
    octetString(sequence(integer(0), octetString(cookie))),
  ));
  const msg = sequence(integer(3), done, controls);
  const c = new LdapClient();
  c._buf = msg;
  const framed = c._tryFrame();
  assert.deepStrictEqual([...c._pagedCookie(framed)], [...cookie]);
});

await okAsync('search ignores a stale SearchResultDone from a prior aborted search', async () => {
  // Regression: readRootDSE() breaks out of its search after the first entry,
  // leaving that search's SearchResultDone unread on the wire. The next search
  // must skip it (messageId mismatch) instead of treating it as its own Done
  // and returning zero entries.
  const ldapMsg = (id, op) => sequence(integer(id), op);
  const entry = (id, dn) => ldapMsg(id, tlv(0x64, concat([octetString(dn), sequence()])));
  const done = (id) => ldapMsg(id, tlv(0x65, concat([enumerated(0), octetString(''), octetString('')])));

  const c = new LdapClient();
  c._writer = { write: async () => {} };
  c._buf = new Uint8Array(0);
  c._msgId = 1; // so the next search uses messageId 2

  // Queue: a leftover Done for the *previous* search (id 1), then this search's
  // (id 2) entry and Done.
  const queue = [done(1), entry(2, 'DC=pk.lab,CN=MicrosoftDNS'), done(2)];
  let qi = 0;
  c._reader = { read: async () => (qi < queue.length ? { value: queue[qi++], done: false } : { done: true }) };

  const dns = [];
  for await (const e of c.search({ baseDN: 'x', filter: filter.present('objectClass'), attributes: [] })) {
    dns.push(e.dn);
  }
  assert.deepStrictEqual(dns, ['DC=pk.lab,CN=MicrosoftDNS']);
});

ok('framing returns null on a partial message (needs more bytes)', () => {
  const full = sequence(integer(1), tlv(0x61, concat([enumerated(0), octetString(''), octetString('')])));
  const c = new LdapClient();
  c._buf = full.subarray(0, full.length - 2); // truncated
  assert.strictEqual(c._tryFrame(), null);
});

function parseAndReencodeA() {
  const buf = new Uint8Array(28);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, 4, true); dv.setUint16(2, 1, true); buf[4] = 5; buf[5] = 0xf0;
  dv.setUint32(12, 600, false);
  buf.set([10, 0, 0, 1], 24);
  return buf;
}

// ---- Crypto primitives (standard vectors) ----
ok('MD4 / MD5 / HMAC-MD5 match published vectors', () => {
  assert.strictEqual(hex(md4(enc(''))), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.strictEqual(hex(md4(enc('abc'))), 'a448017aaf21d8525fc10ae87aa6729d');
  assert.strictEqual(hex(md5(enc(''))), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.strictEqual(hex(hmacMd5(enc('Jefe'), enc('what do ya want for nothing?'))), '750c783e6ab0b503eaa86e310a5db738');
});

// ---- NTLMv2 against the [MS-NLMP] section 4.2.4 reference vectors ----
// User="User", Domain="Domain", Password="Password",
// ServerChallenge=0123456789abcdef, ClientChallenge=aaaaaaaaaaaaaaaa, Time=0.
const NLMP = {
  user: 'User', domain: 'Domain', password: 'Password',
  serverChallenge: fromHex('0123456789abcdef'),
  clientChallenge: fromHex('aaaaaaaaaaaaaaaa'),
  time: fromHex('0000000000000000'),
  // AV pairs: MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", EOL.
  targetInfo: fromHex('02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000'),
};

ok('NTOWFv2 matches MS-NLMP 4.2.4.1.1', () => {
  assert.strictEqual(hex(ntowfv2(NLMP.user, NLMP.domain, NLMP.password)), '0c868a403bfd7a93a3001ef22ef02e3f');
});

ok('NTLMv2 NTProofStr + SessionBaseKey match MS-NLMP 4.2.4.2', () => {
  const r = computeNtlmv2Response(
    NLMP.user, NLMP.domain, NLMP.password,
    NLMP.serverChallenge, NLMP.clientChallenge, NLMP.time, NLMP.targetInfo,
  );
  assert.strictEqual(hex(r.ntProofStr), '68cd0ab851e51c96aabc927bebef6a1c');
  assert.strictEqual(hex(r.sessionBaseKey), '8de40ccadbc14a82f15cb0ad0de95ca3');
  // NtChallengeResponse = NTProofStr || temp; LMv2 response is 24 bytes.
  assert.strictEqual(hex(r.ntChallengeResponse.subarray(0, 16)), '68cd0ab851e51c96aabc927bebef6a1c');
  assert.strictEqual(r.lmChallengeResponse.length, 24);
});

// ---- NTLMSSP message round-trips ----
ok('buildType1 has NTLMSSP signature and message type 1', () => {
  const t1 = buildType1();
  assert.strictEqual(hex(t1.subarray(0, 8)), '4e544c4d53535000');
  assert.strictEqual(new DataView(t1.buffer, t1.byteOffset).getUint32(8, true), 1);
});

ok('parseType2 extracts serverChallenge, targetInfo and timestamp', () => {
  const ti = concat([
    fromHex('07000800'), // AvId=7 (MsvAvTimestamp) LE, AvLen=8 LE
    fromHex('1122334455667788'), // the 8-byte timestamp value
    NLMP.targetInfo,
  ]);
  const type2 = buildSyntheticType2(NLMP.serverChallenge, ti);
  const parsed = parseType2(type2);
  assert.strictEqual(hex(parsed.serverChallenge), '0123456789abcdef');
  assert.strictEqual(hex(parsed.targetInfo), hex(ti));
  assert.strictEqual(hex(parsed.timestamp), '1122334455667788');
});

ok('buildType3 embeds the NTLMv2 response at its declared offset', () => {
  const r = computeNtlmv2Response(
    NLMP.user, NLMP.domain, NLMP.password,
    NLMP.serverChallenge, NLMP.clientChallenge, NLMP.time, NLMP.targetInfo,
  );
  const t3 = buildType3({
    domain: NLMP.domain, user: NLMP.user, workstation: '',
    ntResponse: r.ntChallengeResponse, lmResponse: r.lmChallengeResponse,
  });
  const dv = new DataView(t3.buffer, t3.byteOffset, t3.byteLength);
  assert.strictEqual(hex(t3.subarray(0, 8)), '4e544c4d53535000');
  assert.strictEqual(dv.getUint32(8, true), 3); // AUTHENTICATE
  // NtChallengeResponseFields at offset 20: len, maxlen, offset.
  const ntLen = dv.getUint16(20, true);
  const ntOff = dv.getUint32(24, true);
  assert.strictEqual(ntLen, r.ntChallengeResponse.length);
  assert.strictEqual(hex(t3.subarray(ntOff, ntOff + ntLen)), hex(r.ntChallengeResponse));
  // UserName field at offset 36 should hold UTF-16LE "User".
  const userLen = dv.getUint16(36, true);
  const userOff = dv.getUint32(40, true);
  assert.strictEqual(hex(t3.subarray(userOff, userOff + userLen)), hex(utf16le('User')));
});

// ---- SPNEGO wrapping ----
ok('oid() encodes SPNEGO and NTLM mech OIDs', () => {
  assert.strictEqual(hex(oid('1.3.6.1.5.5.2')), '06062b0601050502');
  assert.strictEqual(hex(oid('1.3.6.1.4.1.311.2.2.10')), '060a2b06010401823702020a');
});

ok('SPNEGO init/resp round-trip through spnegoExtractToken', () => {
  const t1 = buildType1();
  const init = spnegoNegTokenInit(t1);
  assert.strictEqual(init[0], 0x60); // GSSAPI InitialContextToken
  assert.strictEqual(hex(spnegoExtractToken(init)), hex(t1));

  const t3 = fromHex('4e544c4d535350000300000000');
  const resp = spnegoNegTokenResp(t3);
  assert.strictEqual(resp[0], 0xa1); // NegTokenResp
  assert.strictEqual(hex(spnegoExtractToken(resp)), hex(t3));
});

ok('spnegoExtractToken pulls CHALLENGE out of a server NegTokenResp', () => {
  // Server reply: [1] { [0] negState=1, [1] supportedMech=NTLM, [2] responseToken=type2 }
  const type2 = buildSyntheticType2(NLMP.serverChallenge, NLMP.targetInfo);
  const reply = tlv(0xa1, sequence(
    tlv(0xa0, enumerated(1)),                 // negState accept-incomplete
    tlv(0xa1, oid('1.3.6.1.4.1.311.2.2.10')), // supportedMech NTLM
    tlv(0xa2, octetString(type2)),            // responseToken
  ));
  assert.strictEqual(hex(spnegoExtractToken(reply)), hex(type2));
  assert.strictEqual(hex(parseType2(spnegoExtractToken(reply)).serverChallenge), '0123456789abcdef');
});

// ---- Full SASL GSS-SPNEGO handshake through LdapClient (fake socket) ----
import { ntlmSpnegoProducer } from '../src/ntlm/sasl.js';

await okAsync('saslBind drives type1 -> CHALLENGE -> type3 and completes', async () => {
  const client = new LdapClient();
  const written = [];
  client._writer = { write: async (b) => { written.push(b); } };

  // Server scripts: (1) saslBindInProgress(14) with a CHALLENGE, (2) success(0).
  const type2 = buildSyntheticType2(fromHex('0123456789abcdef'), NLMP.targetInfo);
  const resp0 = bindResponseMsg(1, 14, spnegoNegTokenResp(type2));
  const resp1 = bindResponseMsg(2, 0, null);
  const queue = [resp0, resp1];
  let qi = 0;
  client._reader = { read: async () => (qi < queue.length ? { value: queue[qi++], done: false } : { done: true }) };
  client._buf = new Uint8Array(0);

  await client.saslBind('GSS-SPNEGO', ntlmSpnegoProducer({
    user: 'User', domain: 'Domain', password: 'Password',
  }));

  assert.strictEqual(written.length, 2, 'two bind requests sent');

  // Inspect the AUTHENTICATE bind request (second message).
  const top = readTLV(written[1], 0);
  const msgKids = [...children(written[1], top.valueStart, top.valueEnd)];
  const opKids = [...children(written[1], msgKids[1].valueStart, msgKids[1].valueEnd)];
  const auth = opKids[2]; // authentication sasl [3]
  assert.strictEqual(auth.tag, 0xa3);
  const authKids = [...children(written[1], auth.valueStart, auth.valueEnd)];
  const mech = readString(written[1], authKids[0].valueStart, authKids[0].valueEnd);
  assert.strictEqual(mech, 'GSS-SPNEGO');
  const creds = written[1].slice(authKids[1].valueStart, authKids[1].valueEnd);
  const type3 = spnegoExtractToken(creds);
  const dv = new DataView(type3.buffer, type3.byteOffset, type3.byteLength);
  assert.strictEqual(hex(type3.subarray(0, 8)), '4e544c4d53535000');
  assert.strictEqual(dv.getUint32(8, true), 3); // AUTHENTICATE
  const userOff = dv.getUint32(40, true);
  const userLen = dv.getUint16(36, true);
  assert.strictEqual(hex(type3.subarray(userOff, userOff + userLen)), hex(utf16le('User')));
});

function bindResponseMsg(msgId, code, saslCreds) {
  const parts = [enumerated(code), octetString(''), octetString('')];
  if (saslCreds) parts.push(tlv(0x87, saslCreds)); // serverSaslCreds [7]
  const op = tlv(0x61, concat(parts));
  return sequence(integer(msgId), op);
}

function buildSyntheticType2(serverChallenge, targetInfo) {
  const buf = new Uint8Array(48 + targetInfo.length);
  buf.set(enc('NTLMSSP\0'), 0);
  const dv = new DataView(buf.buffer);
  dv.setUint32(8, 2, true);      // messageType = CHALLENGE
  dv.setUint32(20, 0x00080001, true); // some flags
  buf.set(serverChallenge, 24);
  dv.setUint16(40, targetInfo.length, true); // TargetInfoFields len
  dv.setUint16(42, targetInfo.length, true); // maxlen
  dv.setUint32(44, 48, true);                // offset
  buf.set(targetInfo, 48);
  return buf;
}

// ===========================================================================
// Kerberos
// ===========================================================================

// ---- SHA-1 / HMAC-SHA1 / PBKDF2 (FIPS 180-4, RFC 2202, RFC 6070) ----
ok('SHA-1 / HMAC-SHA1 / PBKDF2 match published vectors', () => {
  assert.strictEqual(hex(sha1(enc('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.strictEqual(hex(sha1(enc(''))), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
  // RFC 2202 HMAC-SHA1 test case 1.
  assert.strictEqual(hex(hmacSha1(fromHex('0b'.repeat(20)), enc('Hi There'))), 'b617318655057264e28bc0b6fb378c8ef146be00');
  // RFC 6070 PBKDF2-HMAC-SHA1.
  assert.strictEqual(hex(pbkdf2Sha1(enc('password'), enc('salt'), 1, 20)), '0c60c80f961f0e71f3a9b524af6012062fe037a6');
  assert.strictEqual(hex(pbkdf2Sha1(enc('password'), enc('salt'), 2, 20)), 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
});

// ---- AES block (FIPS-197 Appendix C) ----
ok('AES-128/256 single block matches FIPS-197', () => {
  const pt = fromHex('00112233445566778899aabbccddeeff');
  const a128 = new Aes(fromHex('000102030405060708090a0b0c0d0e0f'));
  const c128 = a128.encryptBlock(pt);
  assert.strictEqual(hex(c128), '69c4e0d86a7b0430d8cdb78070b4c55a');
  assert.strictEqual(hex(a128.decryptBlock(c128)), hex(pt));
  const a256 = new Aes(fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'));
  const c256 = a256.encryptBlock(pt);
  assert.strictEqual(hex(c256), '8ea2b7ca516745bfeafc49904b496089');
  assert.strictEqual(hex(a256.decryptBlock(c256)), hex(pt));
});

// ---- n-fold (RFC 3961 §5.1 sample vectors) ----
ok('n-fold matches RFC 3961 vectors', () => {
  assert.strictEqual(hex(nfold(enc('012345'), 8)), 'be072631276b1955');
  assert.strictEqual(hex(nfold(enc('password'), 7)), '78a07b6caf85fa');
  // The "kerberos" constant used by AES key derivation.
  assert.strictEqual(hex(nfold(enc('kerberos'), 16)), '6b65726265726f737b9b5b2b93132b93');
});

// ---- string-to-key (RFC 3962 Appendix B; RFC 4757 = NT hash) ----
ok('AES string-to-key matches RFC 3962 (iteration count 2)', () => {
  const salt = enc('ATHENA.MIT.EDUraeburn');
  assert.strictEqual(hex(stringToKey(ETYPE.AES128_CTS_HMAC_SHA1_96, 'password', salt, 2)),
    'c651bf29e2300ac27fa469d693bdda13');
  assert.strictEqual(hex(stringToKey(ETYPE.AES256_CTS_HMAC_SHA1_96, 'password', salt, 2)),
    'a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff');
  // RFC 3962 Appendix B also documents iteration counts 1 and 1200 for AES256.
  assert.strictEqual(hex(stringToKey(ETYPE.AES256_CTS_HMAC_SHA1_96, 'password', salt, 1)),
    'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161');
  assert.strictEqual(hex(stringToKey(ETYPE.AES256_CTS_HMAC_SHA1_96, 'password', salt, 1200)),
    '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a');
});

ok('RC4-HMAC string-to-key is the NT hash', () => {
  assert.strictEqual(hex(stringToKey(ETYPE.RC4_HMAC, 'password')), '8846f7eaee8fb117ad06bdd830b7586c');
});

// ---- encrypt/decrypt round-trips, exercising CTS at several lengths ----
ok('AES-256 encrypt/decrypt round-trips across block boundaries', () => {
  const key = stringToKey(ETYPE.AES256_CTS_HMAC_SHA1_96, 'password', enc('SALT'), 2);
  for (const n of [1, 5, 16, 17, 31, 32, 33, 64]) {
    const pt = Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) & 0xff);
    const ct = kEncrypt(ETYPE.AES256_CTS_HMAC_SHA1_96, key, 4, pt);
    assert.strictEqual(hex(kDecrypt(ETYPE.AES256_CTS_HMAC_SHA1_96, key, 4, ct)), hex(pt));
  }
});

ok('RC4-HMAC round-trips and detects tampering', () => {
  const key = stringToKey(ETYPE.RC4_HMAC, 'Passw0rd!');
  const pt = enc('the quick brown fox');
  const ct = kEncrypt(ETYPE.RC4_HMAC, key, KEY_USAGE.AS_REP_ENCPART, pt);
  assert.strictEqual(hex(kDecrypt(ETYPE.RC4_HMAC, key, KEY_USAGE.AS_REP_ENCPART, ct)), hex(pt));
  const bad = ct.slice(); bad[bad.length - 1] ^= 0x01;
  assert.throws(() => kDecrypt(ETYPE.RC4_HMAC, key, KEY_USAGE.AS_REP_ENCPART, bad));
});

// ---- ASN.1 build/parse ----
ok('ETYPE-INFO2 round-trips through parseEtypeInfo2', () => {
  const info = sequence(
    sequence(ctx(0, asnInt(ETYPE.AES256_CTS_HMAC_SHA1_96)), ctx(1, generalString('EXAMPLE.COMuser'))),
    sequence(ctx(0, asnInt(ETYPE.RC4_HMAC))),
  );
  const parsed = parseEtypeInfo2(info);
  assert.strictEqual(parsed.length, 2);
  assert.strictEqual(parsed[0].etype, ETYPE.AES256_CTS_HMAC_SHA1_96);
  assert.strictEqual(new TextDecoder().decode(parsed[0].salt), 'EXAMPLE.COMuser');
  assert.strictEqual(parsed[1].etype, ETYPE.RC4_HMAC);
  assert.strictEqual(parsed[1].salt, null);
});

// ---- Full getTGT flow against a scripted fake KDC ----
// The fake KDC demands pre-auth, then returns an AS-REP whose enc-part we
// encrypt with the very key the client will derive — so a correct client
// recovers the session key end to end (KRB-ERROR + ETYPE-INFO2 parse,
// string-to-key, PA-ENC-TIMESTAMP, AES CTS decrypt, EncKDCRepPart parse).
await okAsync('getTGT performs the pre-auth handshake and recovers the session key', async () => {
  const realm = 'EXAMPLE.COM', user = 'user', password = 'Passw0rd!';
  const etype = ETYPE.AES256_CTS_HMAC_SHA1_96;
  const salt = defaultSalt(realm, user);
  const userKey = stringToKey(etype, password, salt);
  const sessionKey = Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff);
  const ticketRaw = app(1, sequence(generalString(realm))); // opaque to the client

  // KRB-ERROR(25) with PA-ETYPE-INFO2.
  const etypeInfo2 = sequence(sequence(ctx(0, asnInt(etype)), ctx(1, generalString(realm + user))));
  const methodData = sequence(paData(PADATA.ETYPE_INFO2, etypeInfo2));
  const krbErr = app(MSG_TYPE.KRB_ERROR, sequence(
    ctx(0, asnInt(5)), ctx(1, asnInt(MSG_TYPE.KRB_ERROR)),
    ctx(4, kerberosTime(new Date())), ctx(5, asnInt(0)),
    ctx(6, asnInt(KRB_ERR.PREAUTH_REQUIRED)),
    ctx(9, generalString(realm)),
    ctx(10, principalName(NAME_TYPE.SRV_INST, ['krbtgt', realm])),
    ctx(12, octetString(methodData)),
  ));

  // AS-REP whose enc-part decrypts with userKey at usage 3.
  const encAsRep = app(25, sequence(
    ctx(0, encryptionKey(etype, sessionKey)),
    ctx(2, asnInt(12345)),
  ));
  const encPartCipher = kEncrypt(etype, userKey, KEY_USAGE.AS_REP_ENCPART, encAsRep);
  const asRep = app(MSG_TYPE.AS_REP, sequence(
    ctx(0, asnInt(5)), ctx(1, asnInt(MSG_TYPE.AS_REP)),
    ctx(3, generalString(realm)),
    ctx(4, principalName(NAME_TYPE.PRINCIPAL, [user])),
    ctx(5, ticketRaw),
    ctx(6, encryptedData(etype, encPartCipher)),
  ));

  let call = 0;
  const sent = [];
  const transport = { request: async (req) => { sent.push(req); return ++call === 1 ? krbErr : asRep; } };
  const client = new KerberosClient(transport);
  const tgt = await client.getTGT({ username: user, realm, password });

  assert.strictEqual(call, 2, 'two AS-REQs (optimistic, then pre-auth)');
  assert.strictEqual(sent[0][0], 0x6a, 'first request is an AS-REQ ([APPLICATION 10])');
  assert.strictEqual(tgt.sessionKey.etype, etype);
  assert.strictEqual(hex(tgt.sessionKey.key), hex(sessionKey));
  assert.strictEqual(hex(tgt.ticket), hex(ticketRaw));
});

// ---- getTGS flow ----
await okAsync('getTGS sends a TGS-REQ and recovers the service session key', async () => {
  const etype = ETYPE.AES256_CTS_HMAC_SHA1_96;
  const tgtSession = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 1) & 0xff);
  const tgt = {
    ticket: app(1, sequence(generalString('EXAMPLE.COM'))),
    sessionKey: { etype, key: tgtSession },
    crealm: 'EXAMPLE.COM', cname: ['user'], realm: 'EXAMPLE.COM',
  };
  const svcSession = Uint8Array.from({ length: 32 }, (_, i) => (i * 5 + 2) & 0xff);
  const encTgsRep = app(26, sequence(ctx(0, encryptionKey(etype, svcSession)), ctx(2, asnInt(7))));
  const cipher = kEncrypt(etype, tgtSession, KEY_USAGE.TGS_REP_ENCPART_SESSKEY, encTgsRep);
  const tgsRep = app(MSG_TYPE.TGS_REP, sequence(
    ctx(0, asnInt(5)), ctx(1, asnInt(MSG_TYPE.TGS_REP)),
    ctx(3, generalString('EXAMPLE.COM')),
    ctx(4, principalName(NAME_TYPE.PRINCIPAL, ['user'])),
    ctx(5, app(1, sequence(generalString('svc')))),
    ctx(6, encryptedData(etype, cipher)),
  ));

  const sent = [];
  const transport = { request: async (req) => { sent.push(req); return tgsRep; } };
  const st = await new KerberosClient(transport).getTGS(tgt, { spn: 'ldap/dc01.example.com' });

  assert.strictEqual(sent[0][0], 0x6c, 'request is a TGS-REQ ([APPLICATION 12])');
  assert.strictEqual(st.sessionKey.etype, etype);
  assert.strictEqual(hex(st.sessionKey.key), hex(svcSession));
  assert.strictEqual(st.spn, 'ldap/dc01.example.com');
});

// ---- GSS / SPNEGO wrapping ----
ok('GSS and SPNEGO tokens wrap the AP-REQ with the right tags/OIDs', () => {
  const etype = ETYPE.AES256_CTS_HMAC_SHA1_96;
  const st = {
    ticket: app(1, sequence(generalString('R'))),
    sessionKey: { etype, key: Uint8Array.from({ length: 32 }, (_, i) => i) },
    crealm: 'EXAMPLE.COM', cname: ['user'], spn: 'ldap/dc01',
  };
  const ap = buildGssApReq(st);
  assert.strictEqual(ap[0], 0x6e, 'AP-REQ is [APPLICATION 14]');
  const gss = gssInitToken(ap);
  assert.strictEqual(gss[0], 0x60, 'GSS InitialContextToken');
  assert.strictEqual(hex(gss).includes('06092a864886f71201020'), true, 'carries the krb5 mech OID');
  const spnego = spnegoKrbInitToken(gss);
  assert.strictEqual(spnego[0], 0x60);
  assert.strictEqual(hex(spnego).includes('06062b0601050502'), true, 'carries the SPNEGO OID');
});

// ---- GSS-API per-message wrap (RFC 4121 CFX), for ADWS/WinRM sealing ----
ok('GSS Wrap seal/unseal round-trips both directions', () => {
  const key = { etype: ETYPE.AES256_CTS_HMAC_SHA1_96, key: Uint8Array.from({ length: 32 }, (_, i) => i + 1) };
  const cli = new KerberosSession(key, { role: 'initiator', seq: 42 });
  const srv = new KerberosSession(key, { role: 'acceptor', seq: 42 });
  for (const m of ['', 'hello ADWS', 'A'.repeat(100)]) {
    assert.strictEqual(new TextDecoder().decode(srv.unseal(cli.seal(enc(m)))), m);
  }
  for (const m of ['server reply', 'B'.repeat(60)]) {
    assert.strictEqual(new TextDecoder().decode(cli.unseal(srv.seal(enc(m)))), m);
  }
  // token header: TOK_ID 05 04, Sealed flag.
  assert.strictEqual(hex(cli.seal(enc('z')).subarray(0, 3)), '050402');
});

ok('GSS wrapForHttp (WinRM split) keeps data length = plaintext length', () => {
  const key = { etype: ETYPE.AES256_CTS_HMAC_SHA1_96, key: Uint8Array.from({ length: 32 }, (_, i) => i * 3 + 1) };
  const cli = new KerberosSession(key, { role: 'initiator', seq: 7 });
  const srv = new KerberosSession(key, { role: 'acceptor', seq: 7 });
  for (const m of ['', '<soap>hi</soap>', 'Z'.repeat(200)]) {
    const { sigLen, blob } = cli.wrapForHttp(enc(m));
    assert.strictEqual(blob.length - sigLen, m.length); // SECBUFFER_DATA length
    assert.strictEqual(new TextDecoder().decode(srv.unseal(blob)), m);
  }
});

console.log(`\n${pass} tests passed.`);
