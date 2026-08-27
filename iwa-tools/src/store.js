// A tiny in-memory pseudo file storage for the iwa-tools console.
//
// The console keeps operator files here between commands: scan scopes, LDAP
// filters, Kerberos tickets you upload, and tool results (SharpHound/SOAPHound
// JSON, requested certs) that would otherwise vanish into the browser's
// downloads. It is deliberately *not* persistent — everything lives in a Map for
// the lifetime of the app window — which keeps every read synchronous, so the
// console can expand `@file` arguments and load tickets without going async.
//
// Paths are opaque slash-delimited keys ("scope/targets.txt", "tickets/adm.ccache",
// "loot/Users.json"); there is no real directory hierarchy, only string prefixes.

// Normalise arbitrary content into bytes, matching the rule the console's
// download helper has always used: a Uint8Array is kept verbatim, a string is
// UTF-8 encoded, anything else is pretty-printed as JSON. Exported so main.js's
// `io.download` and the store agree on how a value becomes a file.
export function toBytes(content) {
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  if (typeof content === 'string') return new TextEncoder().encode(content);
  return new TextEncoder().encode(JSON.stringify(content, null, 2));
}

function normPath(p) {
  const s = String(p == null ? '' : p).trim().replace(/^\/+/, '').replace(/\/+/g, '/');
  if (!s) throw new Error('empty path');
  return s;
}

export class Store {
  constructor() { this._files = new Map(); } // path -> { bytes, mtime }

  // List entries, optionally filtered to those under a path prefix, sorted by
  // path. Returns shallow copies so callers can't mutate stored bytes.
  list(prefix = '') {
    const pre = String(prefix || '').replace(/^\/+/, '');
    const out = [];
    for (const [path, f] of this._files) {
      if (pre && !path.startsWith(pre)) continue;
      out.push({ path, size: f.bytes.length, mtime: f.mtime });
    }
    out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return out;
  }

  has(path) { return this._files.has(normPath(path)); }

  // Raw bytes, or null if absent.
  get(path) {
    const f = this._files.get(normPath(path));
    return f ? f.bytes : null;
  }

  // Bytes decoded as UTF-8 text, or null if absent.
  getText(path) {
    const b = this.get(path);
    return b == null ? null : new TextDecoder().decode(b);
  }

  // Write a file, creating or overwriting. Content may be bytes, a string, or a
  // JSON-serialisable object. Returns the stored path.
  put(path, content) {
    const p = normPath(path);
    this._files.set(p, { bytes: toBytes(content), mtime: Date.now() });
    return p;
  }

  remove(path) { return this._files.delete(normPath(path)); }

  rename(from, to) {
    const src = normPath(from);
    const f = this._files.get(src);
    if (!f) throw new Error(`no such file: ${src}`);
    this._files.set(normPath(to), f);
    this._files.delete(src);
  }
}
