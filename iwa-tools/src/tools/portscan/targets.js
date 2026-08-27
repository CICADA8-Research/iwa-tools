// Parse nmap-style target and port specifications.
//
// Targets (space/comma/newline separated):
//   10.0.0.1                single host
//   10.0.0.0/24             CIDR
//   10.0.0.1-50             range in the last octet
//   10.0.1-2.1-254          ranges in any octet (cartesian product)
// Ports:
//   80   1-1024   22,80,443   1-100,443
//
// expandTargets / expandPorts return arrays; ipsFromSpec is a lazy generator so
// large ranges don't all materialise at once.

function ipToInt(ip) {
  const o = ip.split('.');
  if (o.length !== 4) throw new Error(`bad IP: ${ip}`);
  return o.reduce((acc, p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error(`bad octet in ${ip}`);
    return (acc * 256 + n) >>> 0;
  }, 0) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

// Yield every IP in one token (CIDR / per-octet ranges / single host).
function* hostsOfToken(token) {
  token = token.trim();
  if (!token) return;

  if (token.includes('/')) {                          // CIDR
    const [base, bitsStr] = token.split('/');
    const bits = Number(bitsStr);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error(`bad CIDR: ${token}`);
    const baseInt = ipToInt(base);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const network = (baseInt & mask) >>> 0;
    const count = 2 ** (32 - bits);
    for (let i = 0; i < count; i++) yield intToIp((network + i) >>> 0);
    return;
  }

  // Per-octet: each octet is N or N-M.
  const octets = token.split('.');
  if (octets.length !== 4) throw new Error(`bad target: ${token}`);
  const ranges = octets.map((o) => {
    if (o.includes('-')) {
      const [a, b] = o.split('-').map(Number);
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b > 255 || a > b) throw new Error(`bad octet range in ${token}`);
      return [a, b];
    }
    const n = Number(o);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error(`bad octet in ${token}`);
    return [n, n];
  });
  for (let a = ranges[0][0]; a <= ranges[0][1]; a++)
    for (let b = ranges[1][0]; b <= ranges[1][1]; b++)
      for (let c = ranges[2][0]; c <= ranges[2][1]; c++)
        for (let d = ranges[3][0]; d <= ranges[3][1]; d++)
          yield `${a}.${b}.${c}.${d}`;
}

// Lazy generator over all hosts in a target spec (dedup by skipping is left to
// the caller; tokens shouldn't usually overlap).
export function* ipsFromSpec(spec) {
  for (const token of (spec || '').split(/[\s,]+/).filter(Boolean)) {
    yield* hostsOfToken(token);
  }
}

export function expandTargets(spec) { return [...ipsFromSpec(spec)]; }

// Count hosts without materialising them (for progress / guard rails).
export function countHosts(spec) {
  let n = 0;
  for (const _ of ipsFromSpec(spec)) n++;
  return n;
}

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 593, 636, 993, 995, 1433, 3268, 3269, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 9389];

export function expandPorts(spec) {
  spec = (spec || '').trim();
  if (!spec) return COMMON_PORTS.slice();
  const out = new Set();
  for (const part of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
    if (part.includes('-')) {
      const [a, b] = part.split('-').map(Number);
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 1 || b > 65535 || a > b) throw new Error(`bad port range: ${part}`);
      for (let p = a; p <= b; p++) out.add(p);
    } else {
      const p = Number(part);
      if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error(`bad port: ${part}`);
      out.add(p);
    }
  }
  return [...out].sort((x, y) => x - y);
}

export { COMMON_PORTS };
