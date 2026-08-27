# Kerberos (`src/kerberos/`)

A self-contained Kerberos 5 client (RFC 4120) for the IWA tools, ported from
[impacket](https://github.com/fortra/impacket)'s `impacket/krb5/` package
(`crypto.py`, `kerberosv5.py`, `gssapi.py`). Pure JS, no runtime dependencies —
it builds on the same vendored primitives as the rest of the app and talks raw
TCP through the Direct Sockets API, so it drops into any of the tools the way
the NTLM stack does.

## What it does

* **AS exchange** — `getTGT()` requests a TGT, transparently handling the
  `KDC_ERR_PREAUTH_REQUIRED` round-trip: it reads `PA-ETYPE-INFO2` for the
  account's salt/etype, derives the key, and re-sends with `PA-ENC-TIMESTAMP`.
  Also works against pre-auth-disabled accounts (AS-REP roast shape).
* **TGS exchange** — `getTGS()` exchanges a TGT for a service ticket (builds the
  `PA-TGS-REQ` AP-REQ + authenticator).
* **GSS** — `buildGssApReq()` / `gssInitToken()` / `spnegoKrbInitToken()` wrap a
  service ticket as a GSS-API / SPNEGO token, with SASL producers ready for
  `LdapClient.saslBind`.

## Encryption types

| etype | name | primitives |
|------:|------|-----------|
| 18 | `aes256-cts-hmac-sha1-96` | `crypto/aes.js` + `crypto/sha1.js` (PBKDF2/HMAC) |
| 17 | `aes128-cts-hmac-sha1-96` | as above |
| 23 | `rc4-hmac` | `crypto/rc4.js` + `crypto/md4.js` + HMAC-MD5 |

AES uses RFC 3962 CTS + RFC 3961 key derivation (n-fold / DK). WebCrypto can't
express the raw single-block / no-padding operations these need, hence the
hand-rolled `aes.js`.

## File layout

| File | Role | impacket analogue |
|------|------|-------------------|
| `constants.js` | etypes, msg/padata types, key usages, error codes | `constants.py` |
| `crypto.js` | etype profiles: string2key / encrypt / decrypt / checksum | `crypto.py` |
| `asn1.js` | build AS/TGS/AP-REQ; parse AS/TGS-REP, KRB-ERROR, ETYPE-INFO2 | `asn1.py` |
| `client.js` | `KerberosClient` flow + `KdcSocketTransport` (TCP/88) | `kerberosv5.py` |
| `gss.js` | GSS-API / SPNEGO wrapping + SASL producers | `gssapi.py` |

New shared primitives: `../crypto/aes.js`, `../crypto/sha1.js`, `../crypto/rc4.js`.

## Using it for an LDAP bind

```js
import { LdapClient } from './ldap/client.js';
import { KerberosClient, KdcSocketTransport } from './kerberos/client.js';
import { kerberosSpnegoProducer } from './kerberos/gss.js';

// 1. TGT, then a service ticket for the DC's LDAP SPN.
const kdc = new KdcSocketTransport('10.0.0.1', 88, log);
await kdc.connect();
const krb = new KerberosClient(kdc, log);
const tgt = await krb.getTGT({ username: 'user', realm: 'EXAMPLE.COM', password });
// or overpass-the-hash: { username, realm, key: ntHash, etype: 23 }
const st = await krb.getTGS(tgt, { spn: 'ldap/dc01.example.com' });
await kdc.close();

// 2. GSS-SPNEGO bind, reusing the existing SASL loop.
const ldap = new LdapClient(log);
await ldap.connect('dc01.example.com', 389);
await ldap.saslBind('GSS-SPNEGO', kerberosSpnegoProducer({ serviceTicket: st, log }));
```

The other tools (soaphound / sharphound / evil-winrm) reuse this by copying
`kerberos/` plus the new `crypto/*.js` files, exactly as they already duplicate
`crypto/`, `ldap/ber.js` and `ntlm/`. The service SPN differs per tool
(`ldap/…` for LDAP, `HTTP/…` for WinRM, `HOST/…` or the ADWS SPN for SOAPHound).

## Tests & verification status

Unit tests live in `scripts/test.js` and assert against published vectors:
FIPS-197 (AES), RFC 3961 (n-fold), RFC 3962 App. B (AES string-to-key),
RFC 2202/6070 (HMAC-SHA1/PBKDF2), the RC4 NT-hash, CTS encrypt/decrypt
round-trips across block boundaries, ASN.1 round-trips, and a full scripted
`getTGT` / `getTGS` flow against a fake KDC transport.

Run them with `npm --prefix adidns test` (or `make test-adidns`). The suite
passes (37 tests); the AES/string-to-key vectors were additionally
cross-checked against Node's native `crypto` to confirm the RFC 3962 constants.

The crypto is covered by authoritative RFC known-answer vectors, so a green
suite is strong evidence of wire correctness — but still exercise the live
AS/TGS path against a real KDC (see `scripts/krb-live.js`) before relying on it.

## GSS sign+seal (ADWS / WinRM)

`gss-seal.js` implements the GSS-API per-message Wrap token (RFC 4121 CFX, for
AES enctypes) as a `KerberosSession` with the same `seal()`/`unseal()` interface
as NTLM's `NtlmSession`, plus `wrapForHttp()` for the WinRM SECBUFFER split.
`gss.js` adds `gssSealInit()` / `gssSealEstablish()` to set up a mutual-auth
context (AP-REQ with subkey → process the AP-REP / acceptor subkey). This is
what soaphound (ADWS NegotiateStream) and evil-winrm (WinRM message encryption)
use. All four tools are live-validated against a Windows DC.

## PKINIT & UnPAC-the-hash

`dh.js`, `cms.js`, `pkinit.js` add **PKINIT** (RFC 4556): certificate pre-auth with
ephemeral Diffie-Hellman (MODP group 14), a CMS `SignedData` over the AuthPack
signed by the cert's RSA key (WebCrypto), and the `octetstring2key` reply-key
derivation — producing a TGT from an X.509 cert + key. `unpac.js` adds
**UnPAC-the-hash**: a User-to-User TGS-REQ to self makes the PAC readable, and the
`PAC_CREDENTIAL_INFO` is decrypted with the reply key to recover the account's NT
hash. This is the `certify auth` command; validated live (the recovered hash
equals `MD4(UTF16LE(password))`).

## Not implemented (yet)

* S4U2self / S4U2proxy (constrained delegation), cross-realm referrals.
* RC4 (RFC 1964) GSS Wrap tokens — the sealed path requires an AES session key
  (etype 17/18), which modern DCs negotiate; RC4 is still supported for AS/TGS
  and overpass-the-hash.
* DES etypes (1/3) — obsolete; intentionally omitted.
