// Best-effort DNS resolver over a Direct Sockets UDPSocket, used for the
// `--resolve` mode: when an authenticated user can enumerate a dnsNode's name
// but cannot read its dnsRecord, we ask the DNS server (the DC) directly.

const enc = new TextEncoder();

function buildQuery(id, name, qtype) {
  const labels = name.replace(/\.$/, '').split('.');
  const parts = [];
  // Header: id, flags=0x0100 (RD), qd=1, an=0, ns=0, ar=0
  const header = new Uint8Array(12);
  const hv = new DataView(header.buffer);
  hv.setUint16(0, id, false);
  hv.setUint16(2, 0x0100, false);
  hv.setUint16(4, 1, false);
  parts.push(header);
  for (const label of labels) {
    const b = enc.encode(label);
    parts.push(Uint8Array.of(b.length), b);
  }
  parts.push(Uint8Array.of(0)); // root
  const tail = new Uint8Array(4);
  new DataView(tail.buffer).setUint16(0, qtype, false); // QTYPE
  new DataView(tail.buffer).setUint16(2, 1, false);     // QCLASS = IN
  parts.push(tail);
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// Skip a (possibly compressed) name and return the offset just past it.
function skipName(view, off) {
  for (;;) {
    const len = view.getUint8(off);
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2; // pointer
    off += 1 + len;
  }
}

function parseAnswers(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const anCount = view.getUint16(6, false);
  let off = 12;
  off = skipName(view, off) + 4; // question name + qtype + qclass
  const results = [];
  for (let i = 0; i < anCount; i++) {
    off = skipName(view, off);
    const type = view.getUint16(off, false);
    const rdlen = view.getUint16(off + 8, false);
    const rdata = off + 10;
    if (type === 1 && rdlen === 4) {
      results.push({ type: 'A', value: `${buf[rdata]}.${buf[rdata + 1]}.${buf[rdata + 2]}.${buf[rdata + 3]}` });
    } else if (type === 28 && rdlen === 16) {
      const groups = [];
      for (let k = 0; k < 16; k += 2) groups.push(((buf[rdata + k] << 8) | buf[rdata + k + 1]).toString(16));
      results.push({ type: 'AAAA', value: groups.join(':') });
    }
    off = rdata + rdlen;
  }
  return results;
}

// Query one name for A and AAAA against `server` (UDP/53). Returns [] on
// timeout or error rather than throwing, so it never aborts a dump.
export async function resolveName(server, name, { timeoutMs = 3000 } = {}) {
  if (typeof UDPSocket === 'undefined') return [];
  let socket;
  try {
    socket = new UDPSocket({ remoteAddress: server, remotePort: 53 });
    const { readable, writable } = await socket.opened;
    const writer = writable.getWriter();
    const reader = readable.getReader();

    const out = [];
    for (const [qtype] of [[1], [28]]) {
      await writer.write({ data: buildQuery(qtype === 1 ? 0x1111 : 0x2222, name, qtype) });
      const res = await Promise.race([
        reader.read(),
        new Promise((resolve) => setTimeout(() => resolve({ value: null }), timeoutMs)),
      ]);
      if (res && res.value && res.value.data) out.push(...parseAnswers(res.value.data));
    }
    reader.releaseLock();
    writer.releaseLock();
    return out;
  } catch {
    return [];
  } finally {
    try { await socket?.close(); } catch { /* ignore */ }
  }
}
