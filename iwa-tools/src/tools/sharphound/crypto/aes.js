// AES (FIPS-197) single-block encrypt/decrypt for 128- and 256-bit keys.
//
// Why hand-roll it: Kerberos AES enctypes (RFC 3962) use AES in CTS
// (ciphertext-stealing) mode and the RFC 3961 key-derivation function, both of
// which need a *raw* single-block primitive — encrypt one 16-byte block, no
// padding, no chaining. WebCrypto's AES-CBC always applies PKCS#7 padding and
// has no ECB mode, and AES-CTR can't give us a raw block decrypt at all, so it
// can't express those operations. This keeps the whole Kerberos crypto path
// synchronous and self-contained, matching md4/md5/rc4 here.

// ---- GF(2^8) tables, built once at module load ----------------------------
const sbox = new Uint8Array(256);
const invSbox = new Uint8Array(256);
const rcon = new Uint8Array(11);

(function initTables() {
  const xtime = (x) => ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
  // Multiplicative inverse in GF(2^8) via exp/log over generator 3.
  const exp = new Uint8Array(256);
  const log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    x ^= xtime(x); // x = x * 3 = x ^ (x<<1)
  }
  const inv = (a) => (a === 0 ? 0 : exp[(255 - log[a]) % 255]);
  for (let i = 0; i < 256; i++) {
    const acc = inv(i);
    // Affine transform over GF(2): each output bit folds in 5 rotated input
    // bits plus the constant 0x63.
    let res = 0x63;
    for (let b = 0; b < 8; b++) {
      const bit = ((acc >> b) & 1) ^ ((acc >> ((b + 4) % 8)) & 1)
        ^ ((acc >> ((b + 5) % 8)) & 1) ^ ((acc >> ((b + 6) % 8)) & 1)
        ^ ((acc >> ((b + 7) % 8)) & 1);
      res ^= bit << b;
    }
    sbox[i] = res & 0xff;
  }
  for (let i = 0; i < 256; i++) invSbox[sbox[i]] = i;

  let r = 1;
  for (let i = 1; i <= 10; i++) { rcon[i] = r; r = xtime(r); }
})();

// GF(2^8) multiply.
function mul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

export class Aes {
  constructor(key) {
    if (key.length !== 16 && key.length !== 32) {
      throw new Error(`AES key must be 16 or 32 bytes, got ${key.length}`);
    }
    this.Nk = key.length / 4;
    this.Nr = this.Nk + 6; // 10 rounds for AES-128, 14 for AES-256
    this._expandKey(key);
  }

  _expandKey(key) {
    const Nk = this.Nk, Nr = this.Nr;
    const total = 4 * (Nr + 1); // number of 4-byte words
    const w = new Array(total);
    for (let i = 0; i < Nk; i++) {
      w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for (let i = Nk; i < total; i++) {
      let t = w[i - 1].slice();
      if (i % Nk === 0) {
        t = [t[1], t[2], t[3], t[0]];          // RotWord
        t = t.map((b) => sbox[b]);              // SubWord
        t[0] ^= rcon[i / Nk];                   // Rcon
      } else if (Nk > 6 && i % Nk === 4) {
        t = t.map((b) => sbox[b]);              // extra SubWord for AES-256
      }
      w[i] = [
        w[i - Nk][0] ^ t[0], w[i - Nk][1] ^ t[1],
        w[i - Nk][2] ^ t[2], w[i - Nk][3] ^ t[3],
      ];
    }
    // Flatten round keys to 16-byte arrays.
    this._rk = [];
    for (let round = 0; round <= Nr; round++) {
      const rk = new Uint8Array(16);
      for (let c = 0; c < 4; c++) rk.set(w[round * 4 + c], c * 4);
      this._rk.push(rk);
    }
  }

  encryptBlock(input) {
    // Uint8Array.from copies regardless of source — guards against callers
    // passing a Node Buffer, whose .slice() returns an aliasing view.
    const s = Uint8Array.from(input.subarray(0, 16));
    addRoundKey(s, this._rk[0]);
    for (let round = 1; round < this.Nr; round++) {
      subBytes(s, sbox); shiftRows(s); mixColumns(s); addRoundKey(s, this._rk[round]);
    }
    subBytes(s, sbox); shiftRows(s); addRoundKey(s, this._rk[this.Nr]);
    return s;
  }

  decryptBlock(input) {
    const s = Uint8Array.from(input.subarray(0, 16));
    addRoundKey(s, this._rk[this.Nr]);
    for (let round = this.Nr - 1; round >= 1; round--) {
      invShiftRows(s); subBytes(s, invSbox); addRoundKey(s, this._rk[round]); invMixColumns(s);
    }
    invShiftRows(s); subBytes(s, invSbox); addRoundKey(s, this._rk[0]);
    return s;
  }
}

// State is column-major (AES standard): byte index = row + 4*col.
function addRoundKey(s, rk) { for (let i = 0; i < 16; i++) s[i] ^= rk[i]; }
function subBytes(s, box) { for (let i = 0; i < 16; i++) s[i] = box[s[i]]; }

function shiftRows(s) {
  const t = s.slice();
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
  }
}
function invShiftRows(s) {
  const t = s.slice();
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) s[r + 4 * c] = t[r + 4 * ((c - r + 4) % 4)];
  }
}

function mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    s[i] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
    s[i + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
    s[i + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
    s[i + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
  }
}
function invMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    s[i] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
    s[i + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
    s[i + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
    s[i + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
  }
}
