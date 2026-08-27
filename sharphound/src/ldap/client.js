// A small LDAPv3 client that speaks BER straight onto a Direct Sockets
// TCPSocket. Supports simple bind and subtree/onelevel/base searches with the
// Microsoft paged-results control (1.2.840.113556.1.4.319) so result sets
// larger than the server MaxPageSize (1000 by default) are fully retrieved.
//
// NOTE: TCPSocket is plaintext only — there is no TLS in the Direct Sockets
// API today — so this talks LDAP on 389, not LDAPS on 636. Simple bind
// therefore sends credentials in cleartext. Use only against hosts you are
// authorised to test, ideally on a trusted/lab network.

import {
  TAG, tlv, concat, integer, enumerated, boolean, octetString,
  sequence, readTLV, children, readInt, readString, toBytes,
} from './ber.js';
import { TlsSocket } from '../tls/tls-socket.js';

// LDAP protocol-op tags (APPLICATION class, constructed/primitive as needed).
const OP = {
  BIND_REQUEST: 0x60,
  BIND_RESPONSE: 0x61,
  SEARCH_REQUEST: 0x63,
  SEARCH_RESULT_ENTRY: 0x64,
  SEARCH_RESULT_DONE: 0x65,
  UNBIND_REQUEST: 0x42,
};

const PAGED_OID = '1.2.840.113556.1.4.319';
const SD_FLAGS_OID = '1.2.840.113556.1.4.801';

export const SCOPE = { BASE: 0, ONE_LEVEL: 1, SUBTREE: 2 };

// ---- Filter builders ------------------------------------------------------
// Each returns the BER encoding of an RFC 4515 filter component.
export const filter = {
  present: (attr) => tlv(0x87, toBytes(attr)),                       // [7] primitive
  equal: (attr, value) => tlv(0xa3, concat([octetString(attr), octetString(value)])), // [3] AVA
  and: (...subs) => tlv(0xa0, concat(subs)),                         // [0] SET OF
  or: (...subs) => tlv(0xa1, concat(subs)),                          // [1] SET OF
};

export class LdapError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'LdapError';
    this.code = code;
  }
}

export class LdapClient {
  constructor(log = () => {}) {
    this._log = log;
    this._msgId = 0;
    this._buf = new Uint8Array(0);
    this._reader = null;
    this._writer = null;
    this._socket = null;
  }

  // `opts.tls = { TlsSession, sni }` wraps the connection in TLS (LDAPS) using
  // the wasm engine; the LDAP messages then ride inside the encrypted channel.
  async connect(host, port = 389, opts = {}) {
    if (typeof TCPSocket === 'undefined') {
      throw new Error('TCPSocket is unavailable — open this app as an installed Isolated Web App.');
    }
    this._log(`Connecting to ${host}:${port} …`);
    this._socket = new TCPSocket(host, port);
    const info = await this._socket.opened;
    const rawReader = info.readable.getReader();
    const rawWriter = info.writable.getWriter();
    this._log(`TCP connected (${info.remoteAddress}:${info.remotePort}).`);

    if (opts.tls) {
      this._log('Starting TLS (LDAPS) …');
      this._tls = new TlsSocket(opts.tls.TlsSession, rawReader, rawWriter, opts.tls.sni || host);
      await this._tls.handshake();
      this._reader = this._tls._reader;
      this._writer = this._tls._writer;
      this._log('TLS established.');
    } else {
      this._reader = rawReader;
      this._writer = rawWriter;
    }
  }

  // tls-server-end-point channel binding for the current LDAPS connection
  // (null when not using TLS). Used to satisfy LDAP channel-binding enforcement.
  async channelBinding() {
    return this._tls ? this._tls.channelBinding() : null;
  }

  async close() {
    try {
      await this._writeMessage(this._nextId(), tlv(OP.UNBIND_REQUEST, new Uint8Array(0)));
    } catch { /* ignore */ }
    try { this._reader?.releaseLock(); } catch { /* ignore */ }
    try { this._writer?.releaseLock(); } catch { /* ignore */ }
    try { await this._socket?.close(); } catch { /* ignore */ }
  }

  _nextId() { return ++this._msgId; }

  async _writeMessage(messageId, protocolOp, controls = null) {
    const parts = [integer(messageId), protocolOp];
    if (controls) parts.push(controls);
    await this._writer.write(sequence(...parts));
  }

  // Pull the next complete LDAPMessage off the wire.
  async _readMessage() {
    for (;;) {
      const framed = this._tryFrame();
      if (framed) return framed;
      const { value, done } = await this._reader.read();
      if (done) throw new Error('connection closed by server');
      this._buf = concat([this._buf, value]);
    }
  }

  _tryFrame() {
    const outer = readTLV(this._buf, 0);
    if (!outer || outer.tag !== TAG.SEQUENCE) {
      if (outer && outer.tag !== TAG.SEQUENCE) throw new Error('malformed LDAP message');
      return null; // need more bytes
    }
    const msgBuf = this._buf.subarray(0, outer.next);
    this._buf = this._buf.subarray(outer.next);

    const kids = [...children(msgBuf, outer.valueStart, outer.valueEnd)];
    const messageId = readInt(msgBuf, kids[0].valueStart, kids[0].valueEnd);
    const op = kids[1];
    const controls = kids[2] && kids[2].tag === 0xa0 ? kids[2] : null;
    return { buf: msgBuf, messageId, op, controls };
  }

  // ---- Operations ---------------------------------------------------------

  async bind(dn, password) {
    const id = this._nextId();
    const req = tlv(OP.BIND_REQUEST, concat([
      integer(3),                         // LDAP version 3
      octetString(dn || ''),              // bind DN / UPN
      tlv(0x80, toBytes(password || '')), // [0] simple authentication
    ]));
    await this._writeMessage(id, req);

    const { code, diag } = await this._readBindResponse();
    if (code !== 0) {
      throw new LdapError(`bind failed (code ${code})${diag ? ': ' + diag : ''}`, code);
    }
    this._log(`Bound as ${dn || '(anonymous)'}.`);
  }

  // Multi-round SASL bind. `tokenProducer(serverSaslCreds, step)` returns the
  // next client SASL token (Uint8Array) given the previous serverSaslCreds
  // (null on the first call). The loop continues while the server replies with
  // saslBindInProgress (14).
  async saslBind(mechanism, tokenProducer, dn = '') {
    let serverCreds = null;
    for (let step = 0; step < 8; step++) {
      const token = await tokenProducer(serverCreds, step);
      const credParts = [octetString(mechanism)];
      if (token) credParts.push(octetString(token));
      const sasl = tlv(0xa3, concat(credParts)); // authentication sasl [3] SaslCredentials
      const req = tlv(OP.BIND_REQUEST, concat([integer(3), octetString(dn), sasl]));
      await this._writeMessage(this._nextId(), req);

      const { code, diag, saslCreds } = await this._readBindResponse();
      if (code === 0) { this._log(`SASL ${mechanism} bind successful.`); return; }
      if (code === 14) { serverCreds = saslCreds; continue; } // saslBindInProgress
      throw new LdapError(`SASL ${mechanism} bind failed (code ${code})${diag ? ': ' + diag : ''}`, code);
    }
    throw new Error('SASL bind did not complete within the expected number of steps');
  }

  async _readBindResponse() {
    const msg = await this._readMessage();
    if (msg.op.tag !== OP.BIND_RESPONSE) throw new Error('expected bind response');
    const kids = [...children(msg.buf, msg.op.valueStart, msg.op.valueEnd)];
    const code = readInt(msg.buf, kids[0].valueStart, kids[0].valueEnd);
    const diag = kids[2] ? readString(msg.buf, kids[2].valueStart, kids[2].valueEnd) : '';
    let saslCreds = null;
    // serverSaslCreds is the optional [7] field after the core LDAPResult.
    for (let i = 3; i < kids.length; i++) {
      if (kids[i].tag === 0x87) saslCreds = msg.buf.slice(kids[i].valueStart, kids[i].valueEnd);
    }
    return { code, diag, saslCreds };
  }

  // Paged subtree/onelevel/base search. Yields each SearchResultEntry as
  // { dn, attributes } where attributes maps name -> array of Uint8Array.
  async *search({ baseDN, scope = SCOPE.SUBTREE, filter: filt, attributes = [], pageSize = 1000, sdFlags = false }) {
    let cookie = new Uint8Array(0);
    let page = 0;
    do {
      page++;
      const id = this._nextId();
      const attrSeq = sequence(...attributes.map((a) => octetString(a)));
      const req = tlv(OP.SEARCH_REQUEST, concat([
        octetString(baseDN),
        enumerated(scope),
        enumerated(0),          // derefAliases: neverDerefAliases
        integer(0),             // sizeLimit (0 = server max)
        integer(0),             // timeLimit
        boolean(false),         // typesOnly
        filt,
        attrSeq,
      ]));

      const pagedValue = sequence(integer(pageSize), octetString(cookie));
      const pagedControl = sequence(octetString(PAGED_OID), octetString(pagedValue));
      // LDAP_SERVER_SD_FLAGS_OID — ask for Owner+Group+DACL (0x07) of the
      // nTSecurityDescriptor without SACL (which needs SeSecurityPrivilege).
      const sdControl = sdFlags ? sequence(
        octetString(SD_FLAGS_OID),
        boolean(true),
        octetString(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x07)),
      ) : new Uint8Array(0);
      const controls = tlv(0xa0, concat([pagedControl, sdControl]));

      await this._writeMessage(id, req, controls);

      cookie = null;
      for (;;) {
        const msg = await this._readMessage();
        // Responses are correlated to requests by messageId. Skip anything that
        // is not for this request — e.g. a SearchResultDone left unread on the
        // wire by an earlier search whose consumer broke out of the loop early
        // (readRootDSE does exactly this). Consuming a stale Done here would
        // otherwise terminate this search with zero entries.
        if (msg.messageId !== id) continue;
        if (msg.op.tag === OP.SEARCH_RESULT_ENTRY) {
          yield this._parseEntry(msg);
        } else if (msg.op.tag === OP.SEARCH_RESULT_DONE) {
          const code = this._resultCode(msg);
          if (code !== 0 && code !== 4 /* sizeLimitExceeded */) {
            throw new LdapError(`search failed (code ${code})`, code);
          }
          cookie = this._pagedCookie(msg);
          break;
        }
        // Other op types (referrals etc.) are ignored.
      }
      this._log(`Page ${page}: cookie ${cookie && cookie.length ? cookie.length + ' bytes' : 'empty (last page)'}.`);
    } while (cookie && cookie.length > 0);
  }

  _resultCode(msg) {
    const first = readTLV(msg.buf, msg.op.valueStart);
    return readInt(msg.buf, first.valueStart, first.valueEnd);
  }

  _parseEntry(msg) {
    const kids = [...children(msg.buf, msg.op.valueStart, msg.op.valueEnd)];
    const dn = readString(msg.buf, kids[0].valueStart, kids[0].valueEnd);
    const attributes = {};
    // kids[1] is a SEQUENCE OF PartialAttribute
    for (const attr of children(msg.buf, kids[1].valueStart, kids[1].valueEnd)) {
      const ac = [...children(msg.buf, attr.valueStart, attr.valueEnd)];
      const name = readString(msg.buf, ac[0].valueStart, ac[0].valueEnd);
      const values = [];
      if (ac[1]) {
        for (const val of children(msg.buf, ac[1].valueStart, ac[1].valueEnd)) {
          values.push(msg.buf.slice(val.valueStart, val.valueEnd));
        }
      }
      attributes[name] = values;
    }
    return { dn, attributes };
  }

  _pagedCookie(msg) {
    if (!msg.controls) return new Uint8Array(0);
    for (const ctrl of children(msg.buf, msg.controls.valueStart, msg.controls.valueEnd)) {
      const cc = [...children(msg.buf, ctrl.valueStart, ctrl.valueEnd)];
      const oid = readString(msg.buf, cc[0].valueStart, cc[0].valueEnd);
      if (oid !== PAGED_OID) continue;
      // Last element is the controlValue OCTET STRING wrapping the paged struct.
      const valueOctet = cc[cc.length - 1];
      const inner = readTLV(msg.buf, valueOctet.valueStart); // SEQUENCE { size, cookie }
      const seqKids = [...children(msg.buf, inner.valueStart, inner.valueEnd)];
      const cookieTlv = seqKids[1];
      return msg.buf.slice(cookieTlv.valueStart, cookieTlv.valueEnd);
    }
    return new Uint8Array(0);
  }
}
