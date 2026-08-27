// RC4 stream cipher. Used here by the Kerberos RC4-HMAC enctype (RFC 4757),
// where a fresh keystream encrypts each blob. update() XORs the next keystream
// bytes over the input (encrypt and decrypt are the same operation).

export class Rc4 {
  constructor(key) {
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 0xff;
      const t = S[i]; S[i] = S[j]; S[j] = t;
    }
    this._S = S; this._i = 0; this._j = 0;
  }

  update(data) {
    const S = this._S;
    let i = this._i, j = this._j;
    const out = new Uint8Array(data.length);
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      j = (j + S[i]) & 0xff;
      const t = S[i]; S[i] = S[j]; S[j] = t;
      out[k] = data[k] ^ S[(S[i] + S[j]) & 0xff];
    }
    this._i = i; this._j = j;
    return out;
  }
}

// One-shot convenience (fresh handle each call).
export function rc4(key, data) {
  return new Rc4(key).update(data);
}
