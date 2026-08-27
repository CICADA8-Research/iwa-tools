// Offline unit tests for the target/port parsers. Run with: node scripts/test.js
import assert from 'node:assert';
import { expandTargets, countHosts, expandPorts, COMMON_PORTS } from '../src/targets.js';

let pass = 0;
function ok(name, fn) { fn(); console.log(`  ok  ${name}`); pass++; }

ok('single host', () => {
  assert.deepStrictEqual(expandTargets('10.0.0.5'), ['10.0.0.5']);
});

ok('CIDR /30 expands to 4 addresses incl. network/broadcast', () => {
  assert.deepStrictEqual(expandTargets('192.168.1.0/30'), ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']);
});

ok('CIDR uses the network base even from a host address', () => {
  assert.deepStrictEqual(expandTargets('192.168.1.130/30'), ['192.168.1.128', '192.168.1.129', '192.168.1.130', '192.168.1.131']);
});

ok('last-octet range', () => {
  assert.deepStrictEqual(expandTargets('10.0.0.1-3'), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
});

ok('multi-octet ranges (cartesian product)', () => {
  assert.deepStrictEqual(expandTargets('10.0.1-2.1'), ['10.0.1.1', '10.0.2.1']);
});

ok('space/comma separated tokens combine', () => {
  assert.deepStrictEqual(expandTargets('10.0.0.1, 10.0.0.2 10.0.0.3'), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
});

ok('countHosts matches expansion (incl. /24 = 256)', () => {
  assert.strictEqual(countHosts('10.0.0.0/24'), 256);
  assert.strictEqual(countHosts('10.0.0.1-10'), 10);
});

ok('rejects bad octets / CIDR', () => {
  assert.throws(() => expandTargets('10.0.0.256'));
  assert.throws(() => expandTargets('10.0.0.0/33'));
  assert.throws(() => expandTargets('10.0.0'));
});

ok('ports: list, range, mix, dedup+sort', () => {
  assert.deepStrictEqual(expandPorts('80'), [80]);
  assert.deepStrictEqual(expandPorts('443,80,22'), [22, 80, 443]);
  assert.deepStrictEqual(expandPorts('20-22'), [20, 21, 22]);
  assert.deepStrictEqual(expandPorts('80,1-2,80'), [1, 2, 80]);
});

ok('ports: blank -> common set; bad -> throws', () => {
  assert.deepStrictEqual(expandPorts(''), COMMON_PORTS);
  assert.throws(() => expandPorts('0'));
  assert.throws(() => expandPorts('70000'));
  assert.throws(() => expandPorts('10-5'));
});

console.log(`\n${pass} tests passed.`);
