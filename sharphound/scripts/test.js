// Offline unit tests for the pure protocol/parsing logic (no browser APIs).
// Run with: node scripts/test.js
import assert from 'node:assert';
import {
  integer, octetString, sequence, tlv, readTLV, children, readInt, readString, concat,
} from '../src/ldap/ber.js';
import { md4 } from '../src/crypto/md4.js';
import { md5, hmacMd5 } from '../src/crypto/md5.js';
import { ntowfv2, computeNtlmv2Response, buildType1 } from '../src/ntlm/ntlm.js';
import { spnegoNegTokenInit, spnegoExtractToken } from '../src/ntlm/spnego.js';
import { bytesToSid, bytesToGuid } from '../src/security/sid.js';
import { parseDescriptor, acesFromDescriptor } from '../src/security/sddl.js';
import { labelFor } from '../src/modes/buildcache.js';
import { parseFilter } from '../src/ldap/source.js';

const hex = (u) => Buffer.from(u).toString('hex');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const enc = (s) => new TextEncoder().encode(s);
const b64 = (u) => Buffer.from(u).toString('base64');

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }

ok('BER sequence round-trips', () => {
  const seq = sequence(integer(1), octetString('ab'));
  const t = readTLV(seq, 0);
  const kids = [...children(seq, t.valueStart, t.valueEnd)];
  assert.strictEqual(readInt(seq, kids[0].valueStart, kids[0].valueEnd), 1);
  assert.strictEqual(readString(seq, kids[1].valueStart, kids[1].valueEnd), 'ab');
});

ok('MD4/HMAC-MD5 + NTLMv2 match MS-NLMP 4.2.4 vectors', () => {
  assert.strictEqual(hex(md4(enc(''))), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.strictEqual(hex(md5(enc(''))), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.strictEqual(hex(hmacMd5(enc('Jefe'), enc('what do ya want for nothing?'))), '750c783e6ab0b503eaa86e310a5db738');
  assert.strictEqual(hex(ntowfv2('User', 'Domain', 'Password')), '0c868a403bfd7a93a3001ef22ef02e3f');
  const r = computeNtlmv2Response('User', 'Domain', 'Password',
    fromHex('0123456789abcdef'), fromHex('aaaaaaaaaaaaaaaa'), fromHex('0000000000000000'),
    fromHex('02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000'));
  assert.strictEqual(hex(r.ntProofStr), '68cd0ab851e51c96aabc927bebef6a1c');
});

ok('SPNEGO wraps/extracts the NTLM token', () => {
  const t1 = buildType1();
  const init = spnegoNegTokenInit(t1);
  assert.strictEqual(init[0], 0x60);
  assert.strictEqual(hex(spnegoExtractToken(init)), hex(t1));
});

ok('bytesToSid decodes a domain SID', () => {
  const b = new Uint8Array([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0]);
  assert.strictEqual(bytesToSid(b), 'S-1-5-21-1-2-3-512');
});
ok('bytesToGuid decodes the mixed-endian objectGUID layout', () => {
  const b = fromHex('a8525633f393ff45aae8186051aabab7');
  assert.strictEqual(bytesToGuid(b), '335652a8-93f3-45ff-aae8-186051aabab7');
});

ok('parses owner + a GenericAll ACCESS_ALLOWED ACE into BloodHound Aces', () => {
  const ownerSid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];            // S-1-5-18 (12 bytes)
  const aceSid = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0]; // ...-512
  const header = new Uint8Array(20);
  const dv = new DataView(header.buffer);
  dv.setUint8(0, 1); dv.setUint16(2, 0x8004, true);
  dv.setUint32(4, 20, true);                       // owner offset
  dv.setUint32(16, 20 + ownerSid.length, true);    // dacl offset
  const aceSize = 8 + aceSid.length;
  const acl = new Uint8Array(8 + aceSize);
  const av = new DataView(acl.buffer);
  av.setUint8(0, 2); av.setUint16(2, acl.length, true); av.setUint16(4, 1, true);
  av.setUint8(8, 0x00);                            // ACCESS_ALLOWED_ACE_TYPE
  av.setUint16(10, aceSize, true);
  av.setUint32(12, 0x10000000, true);              // GENERIC_ALL
  acl.set(aceSid, 16);
  const desc = concat([header, Uint8Array.from(ownerSid), acl]);

  assert.strictEqual(parseDescriptor(desc).ownerSid, 'S-1-5-18');
  const aces = acesFromDescriptor(b64(desc), (s) => (s === 'S-1-5-18' ? 'User' : 'Group'));
  assert.deepStrictEqual(aces[0], { PrincipalSID: 'S-1-5-18', PrincipalType: 'User', RightName: 'Owns', IsInherited: false });
  assert.ok(aces.some((a) => a.RightName === 'GenericAll' && a.PrincipalSID === 'S-1-5-21-1-2-3-512'));
});

ok('labelFor classifies common object classes', () => {
  assert.strictEqual(labelFor(['top', 'person', 'organizationalPerson', 'user']), 'User');
  assert.strictEqual(labelFor(['top', 'group']), 'Group');
  assert.strictEqual(labelFor(['top', 'computer']), 'Computer');
  assert.strictEqual(labelFor(['top', 'organizationalUnit']), 'OU');
  assert.strictEqual(labelFor(['top', 'groupPolicyContainer']), 'GPO');
  assert.strictEqual(labelFor(['top', 'domainDNS']), 'Domain');
});

ok('parseFilter builds present / equality / and / substring filters', () => {
  assert.strictEqual(parseFilter('(objectClass=*)')[0], 0x87);  // [7] present
  assert.strictEqual(parseFilter('(sAMAccountName=bob)')[0], 0xa3); // [3] equalityMatch
  const and = parseFilter('(&(objectClass=user)(sAMAccountName=bob))');
  assert.strictEqual(and[0], 0xa0);                              // [0] and
  const kids = [...children(and, readTLV(and, 0).valueStart, readTLV(and, 0).valueEnd)];
  assert.strictEqual(kids.length, 2);
  assert.strictEqual(parseFilter('(name=*adm*)')[0], 0xa4);      // [4] substrings
});

console.log(`\n${pass} tests passed.`);
