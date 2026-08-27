// Parser for the binary `dnsRecord` attribute stored on dnsNode objects, as
// defined by [MS-DNSP] DNS_RPC_RECORD. Mirrors the record handling in
// dirkjanm/adidnsdump (dnstool.py).
//
// Record header (24 bytes), little-endian except TtlSeconds (big-endian):
//   u16 DataLength | u16 Type | u8 Version | u8 Rank | u16 Flags |
//   u32 Serial | u32 TtlSeconds(BE) | u32 Reserved | u32 TimeStamp | Data[]

const TYPE_NAMES = {
  0: 'ZERO', 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 13: 'HINFO',
  15: 'MX', 16: 'TXT', 24: 'SIG', 25: 'KEY', 28: 'AAAA', 33: 'SRV',
  35: 'NAPTR', 39: 'DNAME', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
};

const dec = new TextDecoder();

// DNS_COUNT_NAME: u8 totalLen, u8 labelCount, then length-prefixed labels.
// Returns { name, end } where `name` is a dotted FQDN with a trailing dot.
function readCountName(b, off) {
  const labelCount = b[off + 1];
  let pos = off + 2;
  const labels = [];
  for (let i = 0; i < labelCount; i++) {
    const len = b[pos++];
    labels.push(dec.decode(b.subarray(pos, pos + len)));
    pos += len;
  }
  labels.push(''); // trailing dot
  return { name: labels.join('.'), end: pos };
}

function ipv4(b, off) {
  return `${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}`;
}

function ipv6(b, off) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((b[off + i] << 8) | b[off + i + 1]).toString(16));
  }
  return compressIpv6(groups);
}

// Collapse the longest run of zero groups into '::' (RFC 5952, best effort).
function compressIpv6(groups) {
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(':');
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

function parseData(type, data, dv, base) {
  switch (type) {
    case 1: // A
      return { address: ipv4(data, 0) };
    case 28: // AAAA
      return { address: ipv6(data, 0) };
    case 2:  // NS
    case 5:  // CNAME
    case 12: // PTR
    case 39: // DNAME
      return { target: readCountName(data, 0).name };
    case 15: { // MX
      const preference = dv.getUint16(base, false);
      return { preference, exchange: readCountName(data, 2).name };
    }
    case 33: { // SRV
      return {
        priority: dv.getUint16(base, false),
        weight: dv.getUint16(base + 2, false),
        port: dv.getUint16(base + 4, false),
        target: readCountName(data, 6).name,
      };
    }
    case 6: { // SOA
      const serial = dv.getUint32(base, false);
      const refresh = dv.getUint32(base + 4, false);
      const retry = dv.getUint32(base + 8, false);
      const expire = dv.getUint32(base + 12, false);
      const minimumTtl = dv.getUint32(base + 16, false);
      const primary = readCountName(data, 20);
      const admin = readCountName(data, primary.end);
      return {
        serial, refresh, retry, expire, minimumTtl,
        primaryServer: primary.name, adminEmail: admin.name,
      };
    }
    case 16: { // TXT — one or more DNS_COUNT_STRING (u8 len + chars)
      const strings = [];
      let pos = 0;
      while (pos < data.length) {
        const len = data[pos++];
        strings.push(dec.decode(data.subarray(pos, pos + len)));
        pos += len;
      }
      return { strings };
    }
    default:
      return { hex: [...data].map((x) => x.toString(16).padStart(2, '0')).join('') };
  }
}

// Render a parsed record's data to a single human-readable string.
export function formatValue(rec) {
  const v = rec.value;
  switch (rec.type) {
    case 1:
    case 28: return v.address;
    case 2:
    case 5:
    case 12:
    case 39: return v.target;
    case 15: return `${v.preference} ${v.exchange}`;
    case 33: return `${v.priority} ${v.weight} ${v.port} ${v.target}`;
    case 6: return `${v.primaryServer} ${v.adminEmail} (serial ${v.serial}, refresh ${v.refresh}, retry ${v.retry}, expire ${v.expire}, minTTL ${v.minimumTtl})`;
    case 16: return v.strings.map((s) => `"${s}"`).join(' ');
    default: return v.hex ? `0x${v.hex}` : JSON.stringify(v);
  }
}

export function parseDnsRecord(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const dataLength = dv.getUint16(0, true);
  const type = dv.getUint16(2, true);
  const ttl = dv.getUint32(12, false); // big-endian
  const serial = dv.getUint32(8, true);
  const data = bytes.subarray(24, 24 + dataLength);
  // DataView over the whole record so per-field offsets stay aligned to 24.
  const value = parseData(type, data, dv, 24);
  const rec = { type, typeName: TYPE_NAMES[type] || `TYPE${type}`, ttl, serial, value };
  rec.display = formatValue(rec);
  return rec;
}
