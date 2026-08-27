// Live Kerberos check against a real KDC, from the command line — no browser /
// IWA build needed. The IWA itself talks to the KDC through the Direct Sockets
// TCPSocket (see KdcSocketTransport), which only exists in the browser; here we
// plug the same KerberosClient into a Node `net` transport instead, so the
// crypto + message flow can be exercised against a live DC.
//
//   node scripts/krb-live.js --kdc 100.100.10.100 --realm pk.lab \
//       --user user01 --pass 'P@ss0wrd' [--spn ldap/dc01.pk.lab]
//
//   # overpass-the-hash instead of a password:
//   node scripts/krb-live.js --kdc ... --realm pk.lab --user user01 \
//       --rc4 8846f7eaee8fb117ad06bdd830b7586c
//
// Kerberos is clock-sensitive: the test host and the DC must agree to within
// ~5 minutes or you'll get KRB_AP_ERR_SKEW (37).

import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { KerberosClient } from '../src/kerberos/client.js';
import { ETYPE } from '../src/kerberos/constants.js';

// KerberosClient uses globalThis.crypto.getRandomValues; provide it on older Node.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Kerberos-over-TCP framing: a 4-byte big-endian length prefix per PDU.
class NetKdcTransport {
  constructor(host, port = 88) { this._host = host; this._port = port; }

  connect() {
    return new Promise((resolve, reject) => {
      this._buf = Buffer.alloc(0);
      this._sock = net.connect(this._port, this._host, () => resolve());
      this._sock.on('data', (chunk) => {
        this._buf = Buffer.concat([this._buf, chunk]);
        this._tryResolve();
      });
      this._sock.on('error', (e) => { this._reject?.(e); reject(e); });
      this._sock.on('close', () => this._reject?.(new Error('KDC closed the connection')));
    });
  }

  _tryResolve() {
    if (!this._pending || this._buf.length < 4) return;
    const len = this._buf.readUInt32BE(0);
    if (this._buf.length < 4 + len) return;
    const msg = Uint8Array.from(this._buf.subarray(4, 4 + len));
    this._buf = this._buf.subarray(4 + len);
    const { resolve } = this._pending;
    this._pending = null; this._reject = null;
    resolve(msg);
  }

  request(reqBytes) {
    return new Promise((resolve, reject) => {
      this._pending = { resolve };
      this._reject = reject;
      const framed = Buffer.alloc(4 + reqBytes.length);
      framed.writeUInt32BE(reqBytes.length, 0);
      framed.set(reqBytes, 4);
      this._sock.write(framed);
      this._tryResolve();
    });
  }

  close() { try { this._sock.destroy(); } catch { /* ignore */ } }
}

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { a[k] = true; } // boolean flag
    else { a[k] = next; i++; }
  }
  return a;
}

const hex = (u) => Buffer.from(u).toString('hex');

async function main() {
  const a = parseArgs(process.argv);
  if (!a.kdc || !a.realm || !a.user || (!a.pass && !a.rc4 && !a.aes)) {
    console.error('usage: node scripts/krb-live.js --kdc <ip> --realm <realm> --user <name> (--pass <pw> | --rc4 <nthash> | --aes <key>) [--spn service/host] [--port 88]');
    process.exit(2);
  }

  const transport = new NetKdcTransport(a.kdc, Number(a.port) || 88);
  await transport.connect();
  const krb = new KerberosClient(transport, (m) => console.log('  ·', m));

  const id = { username: a.user, realm: a.realm };
  if (a.pass) id.password = a.pass;
  else if (a.rc4) { id.key = Uint8Array.from(Buffer.from(a.rc4, 'hex')); id.etype = ETYPE.RC4_HMAC; }
  else if (a.aes) { id.key = Uint8Array.from(Buffer.from(a.aes, 'hex')); id.etype = a.aes.length === 64 ? ETYPE.AES256_CTS_HMAC_SHA1_96 : ETYPE.AES128_CTS_HMAC_SHA1_96; }

  console.log(`\n[*] AS-REQ  ${a.user}@${a.realm}  via KDC ${a.kdc}`);
  const tgt = await krb.getTGT(id);
  console.log(`[+] TGT obtained.`);
  console.log(`    session key: etype ${tgt.sessionKey.etype}, ${tgt.sessionKey.key.length} bytes`);
  console.log(`    ticket:      ${tgt.ticket.length} bytes`);

  let st = null;
  if (a.spn) {
    console.log(`\n[*] TGS-REQ ${a.spn}`);
    st = await krb.getTGS(tgt, { spn: a.spn });
    console.log(`[+] Service ticket obtained for ${st.spn}.`);
    console.log(`    session key: etype ${st.sessionKey.etype}, ${st.sessionKey.key.length} bytes`);
    console.log(`    ticket:      ${st.ticket.length} bytes (sha-prefix ${hex(st.ticket.slice(0, 8))}…)`);
  }
  transport.close();

  // --ldap: drive the real production LdapClient.saslBind('GSS-SPNEGO', …) over
  // a Node net socket, to validate the full LDAP Kerberos bind end to end.
  if (a.ldap) {
    if (!st) throw new Error('--ldap requires --spn ldap/<dc-fqdn>');
    const { LdapClient, SCOPE, filter } = await import('../src/ldap/client.js');
    const { kerberosSpnegoProducer } = await import('../src/kerberos/gss.js');
    const ldapHost = a.ldaphost || a.kdc;
    console.log(`\n[*] LDAP GSS-SPNEGO bind to ${ldapHost}:389`);
    const sock = net.connect(389, ldapHost);
    await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
    const ldap = new LdapClient((m) => console.log('  ·', m));
    Object.assign(ldap, makeLdapStreams(sock));
    await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket: st, log: (m) => console.log('  ·', m) }));
    // Prove the bound session works: read defaultNamingContext from rootDSE.
    for await (const e of ldap.search({ baseDN: '', scope: SCOPE.BASE, filter: filter.present('objectClass'), attributes: ['defaultNamingContext'], pageSize: 1 })) {
      const v = e.attributes.defaultNamingContext;
      console.log('[+] Bound. rootDSE defaultNamingContext =', v ? new TextDecoder().decode(v[0]) : '(none)');
    }
    sock.destroy();
  }

  console.log('\n[+] OK');
}

// Adapt a Node net socket to the {_reader,_writer} shape LdapClient uses.
function makeLdapStreams(sock) {
  const chunks = []; let waiting = null, ended = false, error = null;
  sock.on('data', (d) => {
    const u = Uint8Array.from(d);
    if (waiting) { const w = waiting; waiting = null; w.resolve({ value: u, done: false }); }
    else chunks.push(u);
  });
  sock.on('end', () => { ended = true; if (waiting) { const w = waiting; waiting = null; w.resolve({ done: true }); } });
  sock.on('error', (e) => { error = e; if (waiting) { const w = waiting; waiting = null; w.reject(e); } });
  return {
    _reader: {
      read() {
        if (chunks.length) return Promise.resolve({ value: chunks.shift(), done: false });
        if (error) return Promise.reject(error);
        if (ended) return Promise.resolve({ done: true });
        return new Promise((resolve, reject) => { waiting = { resolve, reject }; });
      },
      releaseLock() {},
    },
    _writer: {
      write: (bytes) => new Promise((resolve, reject) => sock.write(Buffer.from(bytes), (e) => (e ? reject(e) : resolve()))),
      releaseLock() {},
    },
  };
}

main().catch((e) => { console.error('\n[!]', e.message); process.exit(1); });
