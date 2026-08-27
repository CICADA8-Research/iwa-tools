export function parseTargets(input) {
  const results = [];
  for (const token of input.trim().split(/[\s,]+/).filter(Boolean)) {
    if (token.includes('/')) {
      for (const ip of expandCidr(token)) results.push(ip);
    } else if (token.includes('-')) {
      for (const ip of expandRange(token)) results.push(ip);
    } else {
      results.push(token);
    }
  }
  return results;
}

function expandCidr(cidr) {
  const [base, bits] = cidr.split('/');
  const mask = ~((1 << (32 - Number(bits))) - 1) >>> 0;
  const ip = ipToNum(base);
  const net = ip & mask;
  const bcast = net | ~mask >>> 0;
  const out = [];
  for (let i = net + 1; i < bcast; i++) out.push(numToIp(i));
  return out;
}

function expandRange(s) {
  const parts = s.split('.');
  const out = [];
  const last = parts[parts.length - 1];
  if (last.includes('-')) {
    const [lo, hi] = last.split('-').map(Number);
    const prefix = parts.slice(0, -1).join('.');
    for (let i = lo; i <= hi; i++) out.push(`${prefix}.${i}`);
  } else {
    out.push(s);
  }
  return out;
}

function ipToNum(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function numToIp(n) {
  return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
}
