// .NET NegotiateStream Protocol (MS-NNS). After the NMF upgrade, the security
// layer runs here: a cleartext SPNEGO/NTLM handshake (framed with a 5-byte
// handshake header), then a sealed data stream where every frame is
// length-prefixed and carries an NTLM signature + RC4-sealed payload.
//
// Handshake header: messageId(1) major(1) minor(1) payloadLen(2, big-endian).
//   0x16 in-progress, 0x14 done, 0x15 error.

import { spnegoNegTokenInit, spnegoNegTokenResp, spnegoExtractToken } from '../ntlm/spnego.js';
import { parseType2 } from '../ntlm/ntlm.js';
import { buildNegotiate, buildAuthenticate, NtlmSession } from '../ntlm/seal.js';
import { gssSealInit, gssSealEstablish } from '../kerberos/gss.js';

const HS_IN_PROGRESS = 0x16;
const HS_DONE = 0x14;
const HS_ERROR = 0x15;

// NegotiateStream caps each sealed frame's plaintext at 0xFC30 bytes.
const MAX_CHUNK = 0xfc30;

function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}
function readU32le(b) {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true);
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

export class Nns {
  constructor(conn, log = () => {}) {
    this._conn = conn;
    this._log = log;
    this.session = null;
    this._plain = new Uint8Array(0); // decrypted-but-unconsumed bytes
  }

  // ---- Handshake (cleartext) -----------------------------------------------

  async _sendHandshake(messageId, payload) {
    const hdr = Uint8Array.of(messageId, 1, 0, (payload.length >> 8) & 0xff, payload.length & 0xff);
    await this._conn.write(concat(hdr, payload));
  }

  async _readHandshake() {
    const hdr = await this._conn.readExact(5);
    const id = hdr[0];
    const len = (hdr[3] << 8) | hdr[4];
    const payload = len ? await this._conn.readExact(len) : new Uint8Array(0);
    return { id, payload };
  }

  // Drive the chosen SSP with sign+seal. Leaves this.session (NtlmSession or
  // KerberosSession — both expose seal/unseal) ready for secureWrite/Read.
  async authenticate(creds) {
    if (creds.authMethod === 'kerberos') return this._authenticateKerberos(creds);
    return this._authenticateNtlm(creds);
  }

  // SPNEGO Kerberos with mutual auth: one AP-REQ, then process the AP-REP the
  // server returns in the handshake to establish the sealed GSS context.
  async _authenticateKerberos({ serviceTicket }) {
    const { token, state } = gssSealInit(serviceTicket);
    this._log('NNS: sending Kerberos AP-REQ (GSS-SPNEGO, mutual + seal).');
    await this._sendHandshake(HS_IN_PROGRESS, token);

    let apRep = null;
    for (let i = 0; i < 4; i++) {
      const f = await this._readHandshake();
      if (f.id === HS_ERROR) throw new Error('NNS: Kerberos handshake rejected by server');
      if (f.payload && f.payload.length) apRep = f.payload;
      if (f.id === HS_DONE) break;
    }
    this.session = gssSealEstablish(apRep, state);
    this._log('NNS: Kerberos authenticated; secure channel established.');
  }

  async _authenticateNtlm({ user, domain, password }) {
    this._log('NNS: sending NEGOTIATE (NTLM type 1, sign+seal).');
    await this._sendHandshake(HS_IN_PROGRESS, spnegoNegTokenInit(buildNegotiate()));

    const challengeFrame = await this._readHandshake();
    if (challengeFrame.id === HS_ERROR) throw new Error('NNS: server returned handshake error on challenge');
    const type2Raw = spnegoExtractToken(challengeFrame.payload);
    if (!type2Raw) throw new Error('NNS: no NTLM CHALLENGE in server handshake');
    const type2 = parseType2(type2Raw);
    this._log('NNS: received CHALLENGE (type 2), sending AUTHENTICATE (type 3).');

    const sessionKey = new Uint8Array(16);
    (globalThis.crypto || {}).getRandomValues?.(sessionKey);
    const { type3, exportedSessionKey } = buildAuthenticate({
      user, domain, password, type2, exportedSessionKey: sessionKey,
    });
    await this._sendHandshake(HS_IN_PROGRESS, spnegoNegTokenResp(type3));

    const done = await this._readHandshake();
    if (done.id === HS_ERROR) throw new Error('NNS: authentication rejected (handshake error)');
    if (done.id !== HS_DONE) throw new Error(`NNS: unexpected handshake message 0x${done.id.toString(16)}`);

    this.session = new NtlmSession(exportedSessionKey);
    this._log('NNS: authenticated; secure channel established.');
  }

  // ---- Sealed data stream (post-auth) --------------------------------------

  async secureWrite(bytes) {
    for (let off = 0; off < bytes.length || off === 0; off += MAX_CHUNK) {
      const chunk = bytes.subarray(off, off + MAX_CHUNK);
      const payload = this.session.seal(chunk);
      await this._conn.write(concat(u32le(payload.length), payload));
      if (bytes.length === 0) break;
    }
  }

  async _pullFrame() {
    const lenBytes = await this._conn.readExact(4);
    const len = readU32le(lenBytes);
    const payload = await this._conn.readExact(len);
    const plain = this.session.unseal(payload);
    this._plain = concat(this._plain, plain);
  }

  async secureReadExact(n) {
    while (this._plain.length < n) await this._pullFrame();
    const out = this._plain.subarray(0, n);
    this._plain = this._plain.subarray(n);
    return out;
  }

  async secureReadByte() {
    return (await this.secureReadExact(1))[0];
  }
}
