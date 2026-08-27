import { sha256, hmacSha256 } from '../crypto/sha256.js';
import { concat } from '../ldap/ber.js';
import { Aes } from '../crypto/aes.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

const SSH_MSG = {
  DISCONNECT: 1, IGNORE: 2, UNIMPLEMENTED: 3, DEBUG: 4,
  SERVICE_REQUEST: 5, SERVICE_ACCEPT: 6,
  KEXINIT: 20, NEWKEYS: 21,
  KEXDH_INIT: 30, KEXDH_REPLY: 31,
  USERAUTH_REQUEST: 50, USERAUTH_FAILURE: 51, USERAUTH_SUCCESS: 52,
  GLOBAL_REQUEST: 80, REQUEST_SUCCESS: 81, REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90, CHANNEL_OPEN_CONFIRM: 91, CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93, CHANNEL_DATA: 94, CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96, CHANNEL_CLOSE: 97, CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99, CHANNEL_FAILURE: 100,
};

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function readU32(buf, off) {
  return new DataView(buf.buffer, buf.byteOffset).getUint32(off, false);
}

function sshString(s) {
  const bytes = typeof s === 'string' ? enc.encode(s) : s;
  return concat([u32be(bytes.length), bytes]);
}

function readString(buf, off) {
  const len = readU32(buf, off);
  return { data: buf.slice(off + 4, off + 4 + len), next: off + 4 + len };
}

function mpint(n) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex[0], 16) >= 8) hex = '00' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return sshString(bytes);
}

function readMpint(buf, off) {
  const { data, next } = readString(buf, off);
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  return { value: n, next };
}

function modpow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

const DH_GROUP14_P = BigInt('0x' +
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF');
const DH_G = 2n;

function randomBigInt(bits) {
  const bytes = new Uint8Array(bits / 8);
  crypto.getRandomValues(bytes);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

const KEX_ALGOS = 'diffie-hellman-group14-sha256,diffie-hellman-group14-sha1';
const HOST_KEY_ALGOS = 'ssh-rsa,rsa-sha2-256,ssh-ed25519';
const CIPHERS = 'aes128-ctr,aes256-ctr';
// Announce only the classical E&M `hmac-sha2-256` so the server can't pick an
// ETM MAC (which our packet reader doesn't implement — ETM MACs cover the
// ciphertext including the length field, not the decrypted plaintext).
// hmac-sha1 removed for the same reason.
const MACS = 'hmac-sha2-256';
const COMPRESSION = 'none';

function buildKexInit() {
  const cookie = new Uint8Array(16);
  crypto.getRandomValues(cookie);
  return concat([
    Uint8Array.of(SSH_MSG.KEXINIT),
    cookie,
    sshString(KEX_ALGOS),
    sshString(HOST_KEY_ALGOS),
    sshString(CIPHERS), sshString(CIPHERS),
    sshString(MACS), sshString(MACS),
    sshString(COMPRESSION), sshString(COMPRESSION),
    sshString(''), sshString(''),
    Uint8Array.of(0),
    u32be(0),
  ]);
}

export class SshClient {
  constructor(host, port = 22) {
    this._host = host;
    this._port = port;
    this._buf = new Uint8Array(0);
    this._seqIn = 0;
    this._seqOut = 0;
    this._encOut = null;
    this._encIn = null;
    this._macKeyOut = null;
    this._macKeyIn = null;
    this._blockSize = 8;
    this._macLen = 0;
    this._banner = '';
    this._nextCh = 0;
  }

  async connect() {
    this._socket = new TCPSocket(this._host, this._port);
    const info = await this._socket.opened;
    this._reader = info.readable.getReader();
    this._writer = info.writable.getWriter();
    this._banner = await this._readLine();
    await this._writer.write(enc.encode('SSH-2.0-nxc_iwa\r\n'));
  }

  async close() {
    try { this._reader?.releaseLock(); } catch {}
    try { this._writer?.releaseLock(); } catch {}
    try { await this._socket?.close(); } catch {}
  }

  get banner() { return this._banner; }

  async _readLine() {
    let line = '';
    for (;;) {
      if (this._buf.length === 0) {
        const { value, done } = await this._reader.read();
        if (done) throw new Error('SSH: connection closed');
        this._buf = value;
      }
      for (let i = 0; i < this._buf.length; i++) {
        if (this._buf[i] === 0x0a) {
          line += dec.decode(this._buf.subarray(0, i));
          this._buf = this._buf.subarray(i + 1);
          return line.replace(/\r$/, '');
        }
      }
      line += dec.decode(this._buf);
      this._buf = new Uint8Array(0);
    }
  }

  async _readBytes(n) {
    while (this._buf.length < n) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('SSH: connection closed');
      this._buf = concat([this._buf, value]);
    }
    const out = this._buf.slice(0, n);
    this._buf = this._buf.subarray(n);
    return out;
  }

  async _readPacket() {
    let firstBlock;
    if (this._encIn) {
      const raw = await this._readBytes(16);
      firstBlock = this._decryptBlock(raw);
    } else {
      firstBlock = await this._readBytes(this._blockSize);
    }
    const pktLen = new DataView(firstBlock.buffer, firstBlock.byteOffset).getUint32(0, false);
    const padLen = firstBlock[4];
    // Sanity: legitimate SSH packets don't exceed ~35000 bytes per RFC 4253
    // §6.1; anything else means we lost frame sync.
    if (pktLen > 0x100000 || pktLen < 12) throw new Error(`SSH: implausible pktLen=${pktLen} at seqIn=${this._seqIn} — frame lost`);
    const remaining = pktLen + 4 - firstBlock.length;
    let rest = new Uint8Array(0);
    if (remaining > 0) {
      const raw = await this._readBytes(remaining);
      if (this._encIn) {
        rest = this._decryptBytes(raw);
      } else {
        rest = raw;
      }
    }
    if (this._macLen) {
      const mac = await this._readBytes(this._macLen);
      const seqBuf = u32be(this._seqIn);
      const data = concat([seqBuf, firstBlock, rest]);
      const expected = hmacSha256(this._macKeyIn, data).subarray(0, this._macLen);
      let ok = true;
      for (let i = 0; i < this._macLen; i++) if (mac[i] !== expected[i]) ok = false;
      if (!ok) throw new Error('SSH: MAC verification failed');
    }
    this._seqIn++;
    const payload = concat([firstBlock.subarray(5), rest.subarray(0, rest.length)]);
    return payload.subarray(0, pktLen - padLen - 1);
  }

  _decryptBlock(block) {
    return this._encIn.decryptBlock(block);
  }

  _decryptBytes(data) {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 16) {
      const block = this._encIn.decryptBlock(data.subarray(i, i + 16));
      out.set(block, i);
    }
    return out;
  }

  async _sendPacket(payload) {
    const bs = this._encOut ? 16 : 8;
    let padLen = bs - ((5 + payload.length) % bs);
    if (padLen < 4) padLen += bs;
    const pad = new Uint8Array(padLen);
    crypto.getRandomValues(pad);
    const pktLen = 1 + payload.length + padLen;
    const pkt = concat([u32be(pktLen), Uint8Array.of(padLen), payload, pad]);

    if (this._encOut) {
      const seqBuf = u32be(this._seqOut);
      const mac = hmacSha256(this._macKeyOut, concat([seqBuf, pkt])).subarray(0, this._macLen);
      const encrypted = new Uint8Array(pkt.length);
      for (let i = 0; i < pkt.length; i += 16) {
        const block = this._encOut.encryptBlock(pkt.subarray(i, i + 16));
        encrypted.set(block, i);
      }
      await this._writer.write(concat([encrypted, mac]));
    } else {
      await this._writer.write(pkt);
    }
    this._seqOut++;
  }

  async kex() {
    const clientKexInit = buildKexInit();
    await this._sendPacket(clientKexInit);

    const serverKexInitPayload = await this._readPacket();
    if (serverKexInitPayload[0] !== SSH_MSG.KEXINIT) throw new Error('SSH: expected KEXINIT');

    const x = randomBigInt(2048);
    const e = modpow(DH_G, x, DH_GROUP14_P);
    await this._sendPacket(concat([Uint8Array.of(SSH_MSG.KEXDH_INIT), mpint(e)]));

    const reply = await this._readPacket();
    if (reply[0] !== SSH_MSG.KEXDH_REPLY) throw new Error('SSH: expected KEXDH_REPLY');

    let off = 1;
    const hostKey = readString(reply, off); off = hostKey.next;
    const fMpint = readMpint(reply, off); off = fMpint.next;
    const f = fMpint.value;

    const K = modpow(f, x, DH_GROUP14_P);

    const V_C = sshString('SSH-2.0-nxc_iwa');
    const V_S = sshString(this._banner);
    const I_C = sshString(clientKexInit);
    const I_S = sshString(serverKexInitPayload);
    const K_S = sshString(hostKey.data);

    const hashInput = concat([V_C, V_S, I_C, I_S, K_S, mpint(e), mpint(f), mpint(K)]);
    const H = sha256(hashInput);
    this._sessionId = this._sessionId || H;
    this._K = K;
    this._H = H;

    await this._sendPacket(Uint8Array.of(SSH_MSG.NEWKEYS));
    const nk = await this._readPacket();
    if (nk[0] !== SSH_MSG.NEWKEYS) throw new Error('SSH: expected NEWKEYS');

    this._deriveKeys();
  }

  _deriveKeys() {
    const deriveKey = (letter, len) => {
      const input = concat([mpint(this._K), this._H, enc.encode(letter), this._sessionId]);
      let key = sha256(input);
      while (key.length < len) {
        key = concat([key, sha256(concat([mpint(this._K), this._H, key]))]);
      }
      return key.subarray(0, len);
    };

    const ivC2S = deriveKey('A', 16);
    const ivS2C = deriveKey('B', 16);
    const keyC2S = deriveKey('C', 16);
    const keyS2C = deriveKey('D', 16);
    this._macKeyOut = deriveKey('E', 32);
    this._macKeyIn = deriveKey('F', 32);

    this._encOut = new AesCtr(keyC2S, ivC2S);
    this._encIn = new AesCtr(keyS2C, ivS2C);
    this._blockSize = 16;
    this._macLen = 32;
  }

  async auth(username, password) {
    await this._sendPacket(concat([
      Uint8Array.of(SSH_MSG.SERVICE_REQUEST),
      sshString('ssh-userauth'),
    ]));
    const svcAccept = await this._readPacket();
    if (svcAccept[0] !== SSH_MSG.SERVICE_ACCEPT) throw new Error('SSH: service request denied');

    await this._sendPacket(concat([
      Uint8Array.of(SSH_MSG.USERAUTH_REQUEST),
      sshString(username),
      sshString('ssh-connection'),
      sshString('password'),
      Uint8Array.of(0),
      sshString(password),
    ]));

    const authReply = await this._readPacket();
    if (authReply[0] === SSH_MSG.USERAUTH_SUCCESS) return true;
    if (authReply[0] === SSH_MSG.USERAUTH_FAILURE) return false;
    throw new Error(`SSH: unexpected auth reply type ${authReply[0]}`);
  }

  // Read the next transport packet, transparently handling messages that are
  // valid at any point (IGNORE / DEBUG / GLOBAL_REQUEST). OpenSSH ≥ 6.8 sends
  // a `hostkeys-00@openssh.com` GLOBAL_REQUEST right after USERAUTH_SUCCESS,
  // which we previously mistook for a channel-open failure ("type 80").
  async _readNextIgnoringNoise() {
    for (;;) {
      const pkt = await this._readPacket();
      if (pkt[0] === SSH_MSG.IGNORE || pkt[0] === SSH_MSG.DEBUG) continue;
      if (pkt[0] === SSH_MSG.GLOBAL_REQUEST) {
        // RFC 4254 §4: skip request-name string; want_reply is the byte after.
        // If want_reply=true, we owe a REQUEST_FAILURE so the server unblocks.
        const { off: afterName } = readString(pkt, 1);
        const wantReply = pkt[afterName];
        if (wantReply) {
          await this._sendPacket(Uint8Array.of(SSH_MSG.REQUEST_FAILURE));
        }
        continue;
      }
      return pkt;
    }
  }

  async exec(command) {
    const localCh = this._nextCh++;
    await this._sendPacket(concat([
      Uint8Array.of(SSH_MSG.CHANNEL_OPEN),
      sshString('session'),
      u32be(localCh), u32be(0x7fffffff), u32be(0x4000),
    ]));

    let pkt = await this._readNextIgnoringNoise();
    if (pkt[0] === SSH_MSG.CHANNEL_OPEN_FAILURE) {
      // Body: recipient_ch(u32) + reason_code(u32) + description(string).
      const reason = readU32(pkt, 5);
      const { data: descBytes } = readString(pkt, 9);
      throw new Error(`SSH: channel open rejected (reason ${reason}): ${dec.decode(descBytes) || '(no description)'}`);
    }
    if (pkt[0] !== SSH_MSG.CHANNEL_OPEN_CONFIRM) throw new Error(`SSH: channel open failed (msg type ${pkt[0]})`);

    const remoteCh = readU32(pkt, 5);

    await this._sendPacket(concat([
      Uint8Array.of(SSH_MSG.CHANNEL_REQUEST),
      u32be(remoteCh),
      sshString('exec'),
      Uint8Array.of(1),                 // want_reply
      sshString(command),
    ]));

    let output = '', stderr = '', sawClose = false;
    for (;;) {
      pkt = await this._readNextIgnoringNoise();
      if (pkt[0] === SSH_MSG.CHANNEL_DATA) {
        const { data } = readString(pkt, 5);
        output += dec.decode(data);
      } else if (pkt[0] === SSH_MSG.CHANNEL_EXTENDED_DATA) {
        const { data } = readString(pkt, 9);
        stderr += dec.decode(data);
      } else if (pkt[0] === SSH_MSG.CHANNEL_CLOSE) {
        sawClose = true;
        break;
      } else if (pkt[0] === SSH_MSG.CHANNEL_EOF) {
        // Server signalled it's done writing — keep draining until CLOSE so
        // the trailing CHANNEL_REQUEST(exit-status) etc. don't leak into
        // the next exec() call on the same connection.
        continue;
      } else if (pkt[0] === SSH_MSG.CHANNEL_WINDOW_ADJUST
              || pkt[0] === SSH_MSG.CHANNEL_REQUEST
              || pkt[0] === SSH_MSG.CHANNEL_SUCCESS
              || pkt[0] === SSH_MSG.CHANNEL_FAILURE) {
        continue;
      } else if (pkt[0] === SSH_MSG.DISCONNECT) {
        break;
      }
    }

    // Reciprocal close (RFC 4254 §5.3) — after both sides send CLOSE, the
    // channel is gone. Doing this properly leaves the SSH session in a clean
    // state for a follow-up exec() on the same client.
    try {
      await this._sendPacket(concat([Uint8Array.of(SSH_MSG.CHANNEL_CLOSE), u32be(remoteCh)]));
    } catch {}
    if (!sawClose) {
      // Still expecting server's CLOSE; drain until we see it (or the peer
      // disconnects). Bounded read count so a misbehaving server can't hang us.
      for (let i = 0; i < 64; i++) {
        try {
          const pkt2 = await this._readNextIgnoringNoise();
          if (pkt2[0] === SSH_MSG.CHANNEL_CLOSE || pkt2[0] === SSH_MSG.DISCONNECT) break;
        } catch { break; }
      }
    }

    return stderr ? output + stderr : output;
  }
}

class AesCtr {
  constructor(key, iv) {
    this._aes = new Aes(key);
    this._ctr = new Uint8Array(iv);
  }

  encryptBlock(block) {
    // The Aes class exposes `encryptBlock` — old code called `.encrypt`
    // (doesn't exist) which threw on the very first authenticated packet,
    // breaking every SSH module except `sshBanner` (which doesn't need
    // encryption).
    const keystream = this._aes.encryptBlock(this._ctr);
    this._incrementCtr();
    const out = new Uint8Array(block.length);
    for (let i = 0; i < block.length; i++) out[i] = block[i] ^ keystream[i];
    return out;
  }

  decryptBlock(block) {
    return this.encryptBlock(block);
  }

  _incrementCtr() {
    // GOTCHA: `++arr[i]` on a Uint8Array element wraps the STORED value
    // (255 → 0) but the EXPRESSION RESULT is 256, not 0 — so testing
    // `!== 0` never sees the overflow and we never carry into the next
    // byte. That silently desyncs CTR from the server after the low byte
    // wraps (block 240 for an IV whose low byte started at 0x10, etc.),
    // corrupting every subsequent decryption. Read the byte back
    // explicitly after the increment.
    for (let i = this._ctr.length - 1; i >= 0; i--) {
      this._ctr[i] = (this._ctr[i] + 1) & 0xff;
      if (this._ctr[i] !== 0) break;
    }
  }
}
