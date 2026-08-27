// GSS-API per-message confidentiality for Kerberos (RFC 4121 §4.2, the "CFX"
// Wrap token used by AES enctypes). This is the Kerberos analogue of NTLM's
// seal.js: a KerberosSession exposes seal(plaintext) -> wrap token and
// unseal(token) -> plaintext with the same shape the NNS/WinRM transports
// expect, so they can carry either SSP.
//
// Wrap token (confidentiality present):
//   header(16) || RRC-rotated( Encrypt(Ke, usage, plaintext | EC-filler | header) )
// header = TOK_ID(05 04) Flags Filler(FF) EC(2) RRC(2) SND_SEQ(8), all big-endian.

import { concat } from '../ldap/ber.js';
import { encrypt, decrypt } from './crypto.js';
import { GSS_USAGE } from './constants.js';

const TOK_WRAP = Uint8Array.of(0x05, 0x04);
const FLAG_SENT_BY_ACCEPTOR = 0x01;
const FLAG_SEALED = 0x02;
const FLAG_ACCEPTOR_SUBKEY = 0x04;

function u16be(n) { return Uint8Array.of((n >> 8) & 0xff, n & 0xff); }

// Rotate a byte array left / right by n (mod length).
function rotl(buf, n) {
  if (buf.length === 0) return buf;
  n = ((n % buf.length) + buf.length) % buf.length;
  return concat([buf.subarray(n), buf.subarray(0, n)]);
}
function rotr(buf, n) {
  if (buf.length === 0) return buf;
  n = ((n % buf.length) + buf.length) % buf.length;
  return concat([buf.subarray(buf.length - n), buf.subarray(0, buf.length - n)]);
}

export class KerberosSession {
  // key = { etype, key }. role 'initiator' (client) sends with INITIATOR_SEAL
  // and receives with ACCEPTOR_SEAL. `acceptorSubkey` sets the matching flag in
  // tokens we send. `seq` is the initial SND_SEQ (the AP-REQ authenticator's
  // seq-number), which the acceptor expects our first Wrap token to carry.
  constructor(key, { role = 'initiator', acceptorSubkey = false, seq = 0 } = {}) {
    this.etype = key.etype;
    this.key = key.key;
    this.role = role;
    this.acceptorSubkey = acceptorSubkey;
    this.sendSeq = seq >>> 0;
    this._sendUsage = role === 'initiator' ? GSS_USAGE.INITIATOR_SEAL : GSS_USAGE.ACCEPTOR_SEAL;
    this._recvUsage = role === 'initiator' ? GSS_USAGE.ACCEPTOR_SEAL : GSS_USAGE.INITIATOR_SEAL;
  }

  _header(flags, ec, rrc, seq) {
    const h = new Uint8Array(16);
    h.set(TOK_WRAP, 0);
    h[2] = flags;
    h[3] = 0xff;
    h.set(u16be(ec), 4);
    h.set(u16be(rrc), 6);
    const dv = new DataView(h.buffer);
    dv.setUint32(8, 0, false);          // SND_SEQ high 32 bits
    dv.setUint32(12, seq >>> 0, false); // SND_SEQ low 32 bits
    return h;
  }

  // seal: build a Wrap token with confidentiality. We send with EC=0 and RRC=0
  // (no rotation), which is valid and the simplest for an acceptor to verify.
  seal(plaintext) {
    let flags = FLAG_SEALED;
    if (this.role === 'acceptor') flags |= FLAG_SENT_BY_ACCEPTOR;
    if (this.acceptorSubkey) flags |= FLAG_ACCEPTOR_SUBKEY;
    const seq = this.sendSeq;
    this.sendSeq = (this.sendSeq + 1) >>> 0;
    const header = this._header(flags, 0, 0, seq);
    const cipher = encrypt(this.etype, this.key, this._sendUsage, concat([plaintext, header]));
    return concat([header, cipher]);
  }

  // WinRM message encryption (MS-WSMV) splits the GSS output into a "security
  // trailer" (token) and the encrypted data, on the wire as
  // <4-byte LE sigLen><token><data>, where data is exactly plaintext.length
  // bytes. We build the Wrap token rotated (RRC) so its trailing plaintext-many
  // bytes are the encrypted payload, then report sigLen = total − plaintext.len.
  // Returns { sigLen, blob } where blob = token | data (a valid Wrap token the
  // acceptor reassembles and unwraps).
  wrapForHttp(plaintext) {
    let flags = FLAG_SEALED;
    if (this.acceptorSubkey) flags |= FLAG_ACCEPTOR_SUBKEY;
    const seq = this.sendSeq;
    this.sendSeq = (this.sendSeq + 1) >>> 0;
    // Encrypt with RRC=0 in the appended header copy (RRC is applied after).
    const cipher = encrypt(this.etype, this.key, this._sendUsage, concat([plaintext, this._header(flags, 0, 0, seq)]));
    const rrc = cipher.length - plaintext.length - 16; // = confounder + checksum overhead
    const blob = concat([this._header(flags, 0, rrc, seq), rotr(cipher, rrc)]);
    return { sigLen: blob.length - plaintext.length, blob };
  }

  // unseal: parse the header, undo the RRC rotation, decrypt, and strip the
  // trailing EC filler + header copy that the sender appended for integrity.
  unseal(token) {
    if (token.length < 16) throw new Error('GSS Wrap token too short');
    const header = token.subarray(0, 16);
    if (header[0] !== 0x05 || header[1] !== 0x04) {
      throw new Error(`unexpected GSS token id ${header[0].toString(16)}${header[1].toString(16)}`);
    }
    const ec = (header[4] << 8) | header[5];
    const rrc = (header[6] << 8) | header[7];
    let cipher = token.subarray(16);
    if (rrc) cipher = rotl(cipher, rrc);
    const full = decrypt(this.etype, this.key, this._recvUsage, cipher);
    // full = plaintext | EC-filler | header(16)
    return full.subarray(0, full.length - 16 - ec);
  }
}
