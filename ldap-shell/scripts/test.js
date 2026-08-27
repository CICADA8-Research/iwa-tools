// Offline unit tests for the LDAP shell: BER of the write operations, and the
// shell's encoders (unicodePwd, RBCD security descriptor, RFC 4515 filter).
// Run with: node scripts/test.js
import assert from 'node:assert';
import {
  integer, octetString, sequence, enumerated, tlv,
  readTLV, children, readInt, readString, concat,
} from '../src/ldap/ber.js';
import { LdapClient } from '../src/ldap/client.js';
import { _internals } from '../src/shell.js';

const hex = (u) => Buffer.from(u).toString('hex');
let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }
async function okAsync(name, fn) { await fn(); console.log(`  ok  ${name}`); pass++; }

// A fake-socket LdapClient that captures written PDUs and replies with a
// success LDAPResult for each write op.
function fakeClient(responseOpTag) {
  const c = new LdapClient();
  c._written = [];
  c._writer = { write: async (b) => { c._written.push(b); } };
  let n = 0;
  c._reader = {
    read: async () => {
      n++;
      const op = tlv(responseOpTag, concat([enumerated(0), octetString(''), octetString('')]));
      return { value: sequence(integer(n), op), done: false };
    },
  };
  c._buf = new Uint8Array(0);
  return c;
}

function opOf(pdu) {
  const top = readTLV(pdu, 0);
  const kids = [...children(pdu, top.valueStart, top.valueEnd)];
  return kids[1]; // protocolOp
}

await okAsync('add() emits AddRequest [APPLICATION 8] with entry + attributes', async () => {
  const c = fakeClient(0x69);
  await c.add('CN=svc,CN=Users,DC=pk,DC=lab', { sAMAccountName: ['svc'], objectClass: ['top', 'user'] });
  const op = opOf(c._written[0]);
  assert.strictEqual(op.tag, 0x68);
  const k = [...children(c._written[0], op.valueStart, op.valueEnd)];
  assert.strictEqual(readString(c._written[0], k[0].valueStart, k[0].valueEnd), 'CN=svc,CN=Users,DC=pk,DC=lab');
});

await okAsync('modify() emits ModifyRequest [APPLICATION 6] with operation + attr', async () => {
  const c = fakeClient(0x67);
  await c.modify('CN=g,DC=pk,DC=lab', [{ op: 'add', type: 'member', values: ['CN=u,DC=pk,DC=lab'] }]);
  const op = opOf(c._written[0]);
  assert.strictEqual(op.tag, 0x66);
  const k = [...children(c._written[0], op.valueStart, op.valueEnd)];
  const changes = [...children(c._written[0], k[1].valueStart, k[1].valueEnd)];
  const ch0 = [...children(c._written[0], changes[0].valueStart, changes[0].valueEnd)];
  assert.strictEqual(readInt(c._written[0], ch0[0].valueStart, ch0[0].valueEnd), 0); // add
});

await okAsync('delete() emits DelRequest [APPLICATION 10] primitive = DN', async () => {
  const c = fakeClient(0x6b);
  await c.delete('CN=svc,CN=Users,DC=pk,DC=lab');
  const op = opOf(c._written[0]);
  assert.strictEqual(op.tag, 0x4a);
  assert.strictEqual(readString(c._written[0], op.valueStart, op.valueEnd), 'CN=svc,CN=Users,DC=pk,DC=lab');
});

ok('unicodePwd is UTF-16LE of the quoted password', () => {
  const v = _internals.unicodePwd('Pw1');
  assert.strictEqual(hex(v), hex(Buffer.from('"Pw1"', 'utf16le')));
});

ok('buildRbcdSd produces a valid self-relative SD embedding the attacker SID', () => {
  const sid = Uint8Array.from([0x01, 0x05, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0xf4, 0x01, 0, 0]);
  const sd = _internals.buildRbcdSd(sid);
  assert.strictEqual(sd[0], 0x01);                       // revision
  const dv = new DataView(sd.buffer);
  assert.strictEqual(dv.getUint16(2, true), 0x8004);     // SELF_RELATIVE | DACL_PRESENT
  const daclOff = dv.getUint32(16, true);
  assert.strictEqual(sd[daclOff], 0x02);                 // ACL revision
  const aceSidOff = daclOff + 8 + 8;                     // ACL hdr (8) + ACE hdr+mask (8)
  assert.strictEqual(hex(sd.subarray(aceSidOff, aceSidOff + sid.length)), hex(sid));
});

ok('parseFilter builds present / equality / and', () => {
  assert.strictEqual(readTLV(_internals.parseFilter('(objectClass=*)'), 0).tag, 0x87);
  assert.strictEqual(readTLV(_internals.parseFilter('(sAMAccountName=bob)'), 0).tag, 0xa3);
  assert.strictEqual(readTLV(_internals.parseFilter('(&(objectClass=user)(cn=a))'), 0).tag, 0xa0);
});

console.log(`\n${pass} tests passed.`);
