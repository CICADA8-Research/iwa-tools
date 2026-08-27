// Offline unit tests for the pure protocol/parsing logic (no browser APIs).
// Run with: node scripts/test.js
import assert from 'node:assert';
import {
  integer, octetString, sequence, set, enumerated, tlv, oid,
  readTLV, children, readInt, readString, concat,
} from '../src/ldap/ber.js';
import { parseDnsRecord } from '../src/dns/record.js';
import { md4 } from '../src/crypto/md4.js';
import { md5, hmacMd5 } from '../src/crypto/md5.js';
import { Rc4, rc4 } from '../src/crypto/rc4.js';
import {
  ntowfv2, computeNtlmv2Response, buildType1, parseType2, buildType3, utf16le,
} from '../src/ntlm/ntlm.js';
import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from '../src/ntlm/spnego.js';
import { buildNegotiate, buildAuthenticate, NtlmSession, NEGOTIATE_FLAGS, NF } from '../src/ntlm/seal.js';
import { encodeVarint, decodeVarint, preamble, sizedEnvelope, REC } from '../src/nmf/nmf.js';
import { Nns } from '../src/nns/nns.js';
import { encodeNbfse, decodeNbfse } from '../src/encoder/nbfse.js';
import { enumerateXml } from '../src/soap/templates.js';

const hex = (u) => Buffer.from(u).toString('hex');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const enc = (s) => new TextEncoder().encode(s);

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }
async function okAsync(name, fn) { await fn(); console.log(`  ok  ${name}`); pass++; }

// ---- BER round-trips ----
ok('integer encodes minimal positive', () => {
  assert.deepStrictEqual([...integer(0)], [0x02, 0x01, 0x00]);
  assert.deepStrictEqual([...integer(255)], [0x02, 0x02, 0x00, 0xff]);
});

ok('sequence wraps children with correct length', () => {
  const seq = sequence(integer(1), octetString('ab'));
  const t = readTLV(seq, 0);
  assert.strictEqual(t.tag, 0x30);
  const kids = [...children(seq, t.valueStart, t.valueEnd)];
  assert.strictEqual(readInt(seq, kids[0].valueStart, kids[0].valueEnd), 1);
  assert.strictEqual(readString(seq, kids[1].valueStart, kids[1].valueEnd), 'ab');
});

// ---- dnsRecord parsing (used by the dnsdump mode) ----
function rpcRecord(type, ttl, dataBytes) {
  const buf = new Uint8Array(24 + dataBytes.length);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, dataBytes.length, true);
  dv.setUint16(2, type, true);
  buf[4] = 5; buf[5] = 0xf0;
  dv.setUint32(8, 1, true);
  dv.setUint32(12, ttl, false);
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
  assert.strictEqual(rec.display, '10.0.0.1');
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

// ---- Crypto primitives (standard vectors) ----
ok('MD4 / MD5 / HMAC-MD5 match published vectors', () => {
  assert.strictEqual(hex(md4(enc(''))), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.strictEqual(hex(md5(enc(''))), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.strictEqual(hex(hmacMd5(enc('Jefe'), enc('what do ya want for nothing?'))), '750c783e6ab0b503eaa86e310a5db738');
});

ok('RC4 matches the standard "Key"/"Plaintext" test vector', () => {
  // RFC 6229-style known answer: key="Key", data="Plaintext".
  assert.strictEqual(hex(rc4(enc('Key'), enc('Plaintext'))), 'bbf316e8d940af0ad3');
});

ok('RC4 keystream is continuous across update() calls (stateful handle)', () => {
  const one = rc4(enc('Key'), enc('Plaintext'));
  const h = new Rc4(enc('Key'));
  const split = concat([h.update(enc('Plain')), h.update(enc('text'))]);
  assert.strictEqual(hex(split), hex(one));
});

// ---- NTLMv2 against the [MS-NLMP] section 4.2.4 reference vectors ----
const NLMP = {
  user: 'User', domain: 'Domain', password: 'Password',
  serverChallenge: fromHex('0123456789abcdef'),
  clientChallenge: fromHex('aaaaaaaaaaaaaaaa'),
  time: fromHex('0000000000000000'),
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
});

// ---- NTLM sign+seal (cross-checked against impacket SIGNKEY/SEALKEY/SEAL) ----
ok('NEGOTIATE_FLAGS advertise sign+seal+keyexch+128 (ESS path)', () => {
  for (const f of ['SIGN', 'SEAL', 'KEY_EXCH', 'N128', 'EXTENDED_SESSIONSECURITY', 'NTLM', 'UNICODE']) {
    assert.ok((NEGOTIATE_FLAGS & NF[f]) >>> 0, `flag ${f} set`);
  }
});

ok('buildNegotiate is an NTLMSSP NEGOTIATE with the sealing flags', () => {
  const t1 = buildNegotiate();
  assert.strictEqual(hex(t1.subarray(0, 8)), '4e544c4d53535000');
  const dv = new DataView(t1.buffer, t1.byteOffset, t1.byteLength);
  assert.strictEqual(dv.getUint32(8, true), 1);
  assert.strictEqual(dv.getUint32(12, true) >>> 0, NEGOTIATE_FLAGS >>> 0);
});

// Session keys / signature / sealed bytes verified byte-for-byte against
// impacket: SIGNKEY/SEALKEY/SEAL with flags=ESS|KEY_EXCH|128 and
// ExportedSessionKey = 00 01 02 .. 0f, message="Hello ADWS world", seq=0.
ok('NtlmSession derives keys + seals exactly like impacket', () => {
  const sk = Uint8Array.from({ length: 16 }, (_, i) => i);
  const s = new NtlmSession(sk);
  assert.strictEqual(hex(s.clientSignKey), '9b52e70996bd32c71f2398b552d207d2');
  assert.strictEqual(hex(s.serverSignKey), '24708083b479de7c5807cac27aeefbce');
  const payload = s.seal(enc('Hello ADWS world'));
  assert.strictEqual(hex(payload.subarray(0, 16)), '01000000f2717227d59d1cde00000000');
  assert.strictEqual(hex(payload.subarray(16)), '3c67f73f1e611c46419837598f0e4c91');
});

ok('seal/unseal round-trips both directions and advances sequence numbers', () => {
  const sk = Uint8Array.from({ length: 16 }, (_, i) => (i * 7) & 0xff);
  const client = new NtlmSession(sk, 'client');
  const server = new NtlmSession(sk, 'server'); // mirror peer
  const msgs = ['first', 'second message', 'third!'].map(enc);
  for (let i = 0; i < msgs.length; i++) {
    // client -> server
    const wire = client.seal(msgs[i]);
    assert.strictEqual(new DataView(wire.buffer, wire.byteOffset).getUint32(12, true), i, 'send seq');
    assert.strictEqual(hex(server.unseal(wire)), hex(msgs[i]), 'server recovers plaintext');
    // server -> client
    const back = server.seal(msgs[i]);
    assert.strictEqual(hex(client.unseal(back)), hex(msgs[i]), 'client recovers plaintext');
  }
  // Tampering with the ciphertext must fail signature verification.
  const w = client.seal(enc('tamper me'));
  w[w.length - 1] ^= 0xff;
  assert.throws(() => server.unseal(w), /signature verification failed/);
});

// ---- NMF framing ----
await okAsync('varint round-trips (incl. multi-byte)', async () => {
  for (const n of [0, 1, 0x7f, 0x80, 0x2f, 300, 16384, 1234567]) {
    const bytes = encodeVarint(n);
    let i = 0;
    const got = await decodeVarint(() => bytes[i++]);
    assert.strictEqual(got, n, `varint ${n}`);
  }
});

ok('preamble emits version/mode(duplex)/via/known-encoding(NBFSE)', () => {
  const via = 'net.tcp://dc01.corp.local:9389/ActiveDirectoryWebServices/Windows/Enumeration';
  const p = preamble(via);
  assert.deepStrictEqual([...p.subarray(0, 3)], [REC.VERSION, 1, 0]);
  assert.deepStrictEqual([...p.subarray(3, 5)], [REC.MODE, 0x02]);
  assert.strictEqual(p[5], REC.VIA);
  // last two bytes: known-encoding record = 0x03 0x08 (NBFSE)
  assert.deepStrictEqual([...p.subarray(p.length - 2)], [REC.KNOWN_ENCODING, 0x08]);
  // the via string survives intact
  assert.ok(Buffer.from(p).toString('latin1').includes(via));
});

ok('sizedEnvelope prefixes a 0x06 record with a varint length', () => {
  const env = sizedEnvelope(enc('abc'));
  assert.strictEqual(env[0], REC.SIZED_ENVELOPE);
  assert.strictEqual(env[1], 3);
  assert.strictEqual(Buffer.from(env.subarray(2)).toString(), 'abc');
});

// ---- NNS handshake + sealed stream over a fake socket ----
function fakeConn() {
  const written = [];
  let inbound = new Uint8Array(0);
  return {
    written,
    feed(bytes) { const o = new Uint8Array(inbound.length + bytes.length); o.set(inbound); o.set(bytes, inbound.length); inbound = o; },
    write: async (b) => { written.push(Uint8Array.from(b)); },
    readExact: async (n) => { const out = inbound.subarray(0, n); inbound = inbound.subarray(n); return out; },
  };
}

await okAsync('Nns drives type1 -> CHALLENGE -> type3 -> DONE and seals a frame', async () => {
  const conn = fakeConn();
  const nns = new Nns(conn);

  // Server scripts a handshake: in-progress(0x16) frame carrying a NegTokenResp
  // wrapping a synthetic NTLM CHALLENGE, then a done(0x14) frame.
  const type2 = buildSyntheticType2(NLMP.serverChallenge, NLMP.targetInfo);
  const challenge = spnegoNegTokenResp(type2);
  const hsFrame = (id, payload) => concat([Uint8Array.of(id, 1, 0, (payload.length >> 8) & 0xff, payload.length & 0xff), payload]);
  conn.feed(hsFrame(0x16, challenge));
  conn.feed(hsFrame(0x14, new Uint8Array(0)));

  await nns.authenticate({ user: 'User', domain: 'Domain', password: 'Password' });
  assert.ok(nns.session, 'session established');

  // Two handshake messages were written (type1, type3), each with a 5-byte header.
  assert.strictEqual(conn.written.length, 2);
  assert.strictEqual(conn.written[0][0], 0x16);
  // type1 NegTokenInit begins with GSSAPI app tag 0x60.
  assert.strictEqual(conn.written[0][5], 0x60);

  // A sealed write produces a 4-byte LE length prefix + 16-byte signature + body.
  conn.written.length = 0;
  await nns.secureWrite(enc('hello'));
  const frame = conn.written[0];
  const plen = new DataView(frame.buffer, frame.byteOffset).getUint32(0, true);
  assert.strictEqual(plen, frame.length - 4);
  assert.strictEqual(plen, 16 + 5, 'signature(16) + sealed("hello")');
});

// ---- NBFX / NBFSE codec ----
ok('NBFSE encodes a blank in-band dictionary then round-trips XML', () => {
  const xml = '<s:Envelope xmlns:s="urn:s" xmlns:a="urn:a">' +
    '<s:Header><a:Action s:mustUnderstand="1">urn:Enumerate</a:Action></s:Header>' +
    '<s:Body><wsen:Pull xmlns:wsen="urn:en"><wsen:MaxElements>256</wsen:MaxElements>' +
    '<wsen:EnumerationContext>ctx-123</wsen:EnumerationContext></wsen:Pull></s:Body></s:Envelope>';
  const bytes = encodeNbfse(xml);
  assert.strictEqual(bytes[0], 0x00, 'blank dictionary size byte');
  const { xml: back } = decodeNbfse(bytes);
  assert.strictEqual(back, xml);
});

ok('NBFX decodes dictionary, int, bool and bytes(base64) text records', () => {
  // Hand-built NBFX: <r xmlns="urn"><a>5</a><b>true</b><c>AQI=</c><d>To</d></r>
  // 0x40 short-element "r"; 0x08 xmlns "urn"; children use Int8/True/Bytes8/DictText.
  const u = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));
  const cat = (...a) => { const t = a.reduce((n, x) => n + x.length, 0); const o = new Uint8Array(t); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const elem = (n) => cat(Uint8Array.of(0x40, n.length), u(n));
  const child = (n, ...rec) => cat(Uint8Array.of(0x40, n.length), u(n), cat(...rec), Uint8Array.of(0x01));
  const bytes = cat(
    Uint8Array.of(0x00),                                   // empty dict
    Uint8Array.of(0x40, 1), u('r'), Uint8Array.of(0x08, 3), u('urn'),
    child('a', Uint8Array.of(0x88, 5)),                    // Int8 = 5
    child('b', Uint8Array.of(0x86)),                       // True
    child('c', Uint8Array.of(0x9e, 2, 0x01, 0x02)),        // Bytes8 -> base64 "AQI="
    child('d', Uint8Array.of(0xaa, 0x0c)),                 // DictionaryText idx 0x0c -> "To"
    Uint8Array.of(0x01),
  );
  const { tree } = decodeNbfse(bytes);
  const r = tree[0];
  const kids = Object.fromEntries(r.children.filter((c) => c.kind === 'el').map((c) => [c.name, c.children.map((t) => t.value).join('')]));
  assert.strictEqual(kids.a, '5');
  assert.strictEqual(kids.b, 'true');
  assert.strictEqual(kids.c, 'AQI=');
  assert.strictEqual(kids.d, 'To'); // static dictionary[0x0c]
});

ok('enumerateXml emits the LdapQuery filter, base and selection properties', () => {
  const xml = enumerateXml({ fqdn: 'dc01', port: 9389, uuid: 'U', query: '(objectClass=*)', baseObject: 'DC=pk,DC=lab', attributes: ['objectSid', 'distinguishedName'] });
  assert.ok(xml.includes('<adlq:Filter>(objectClass=*)</adlq:Filter>'));
  assert.ok(xml.includes('<adlq:BaseObject>DC=pk,DC=lab</adlq:BaseObject>'));
  assert.ok(xml.includes('<ad:SelectionProperty>addata:objectSid</ad:SelectionProperty>'));
  assert.ok(xml.includes('/Windows/Enumeration'));
});

ok('enumerateXml emits RangeLow/RangeHigh for range retrieval hints', () => {
  const xml = enumerateXml({
    fqdn: 'dc01', port: 9389, uuid: 'U', query: '(objectClass=*)', baseObject: 'CN=g,DC=x',
    attributes: ['member'], rangeHints: { member: { low: 1500, high: '*' } },
  });
  assert.ok(xml.includes('<ad:SelectionProperty RangeLow="1500" RangeHigh="*">addata:member</ad:SelectionProperty>'));
});

// ---- helpers ----
function buildSyntheticType2(serverChallenge, targetInfo) {
  const buf = new Uint8Array(48 + targetInfo.length);
  buf.set(enc('NTLMSSP\0'), 0);
  const dv = new DataView(buf.buffer);
  dv.setUint32(8, 2, true);            // CHALLENGE
  dv.setUint32(20, 0x00080001, true);  // flags (ESS bit set)
  buf.set(serverChallenge, 24);
  dv.setUint16(40, targetInfo.length, true);
  dv.setUint16(42, targetInfo.length, true);
  dv.setUint32(44, 48, true);
  buf.set(targetInfo, 48);
  return buf;
}

console.log(`\n${pass} tests passed.`);
