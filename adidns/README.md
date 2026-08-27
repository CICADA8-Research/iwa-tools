# ADIDNSDump IWA

A browser port of [dirkjanm/adidnsdump](https://github.com/dirkjanm/adidnsdump),
built as a Chrome **Isolated Web App (IWA)** that talks raw LDAP to a domain
controller using the **Direct Sockets API** (`TCPSocket`/`UDPSocket`).

It enumerates Active Directory Integrated DNS (ADIDNS): it binds over LDAP,
reads the DomainDnsZones / ForestDnsZones partitions, lists `dnsZone` objects,
walks the `dnsNode` objects in a zone, and decodes the binary `dnsRecord`
attribute ([MS-DNSP] `DNS_RPC_RECORD`) into readable A / AAAA / CNAME / NS /
MX / SRV / SOA / TXT / PTR records.

> ⚠️ **Authorised use only.** This is an offensive-security enumeration tool.
> Run it only against directories you own or are explicitly authorised to test.

## Why an IWA?

Ordinary web pages cannot open raw TCP/UDP sockets. The Direct Sockets API is
gated behind Isolated Web Apps — apps shipped as a **Signed Web Bundle**
(`.swbn`), served from a stable `isolated-app://` origin, with a strict CSP and
the `direct-sockets` permission policy. That combination is what lets this app
speak the LDAP wire protocol directly from the browser.

## How it maps to adidnsdump

| adidnsdump | This app |
|---|---|
| `ldap3` connection | `src/ldap/client.js` — hand-rolled LDAPv3 over `TCPSocket` |
| `ldap3` NTLM / impacket `ntlm.py` | `src/ntlm/` — NTLMv2 over SASL `GSS-SPNEGO` |
| BER encoding | `src/ldap/ber.js` — minimal ASN.1 BER encoder/decoder |
| paged search (MaxPageSize) | paged-results control `1.2.840.113556.1.4.319` |
| `dnstool.py` `DNS_RECORD` | `src/dns/record.js` — `DNS_RPC_RECORD` parser |
| `--zone` / list zones | Zone field / **List zones** button |
| `--include-tombstoned` | **Include tombstoned** checkbox |
| `-r/--resolve` hidden nodes | **Resolve hidden records** — live DNS over `UDPSocket` |
| ForestDnsZones | **ForestDnsZones partition** checkbox |

## Build

```bash
npm install
npm run keygen     # one-time: generate the Ed25519 signing key (fixes the app origin)
npm test           # offline unit tests for the BER + dnsRecord + LDAP framing logic
npm run build      # produces dist/adidnsdump-iwa.swbn
npm run id         # print the resulting isolated-app:// origin
```

`signing.key` determines the app's permanent `isolated-app://…` identity. Keep
it; regenerating it (`npm run keygen -- --force`) changes the origin and makes
Chrome treat it as a different app.

## Install in Chrome

IWAs require a recent Chrome/Chromium (desktop).

1. Enable the flags at `chrome://flags`:
   - **Isolated Web Apps** → Enabled
   - **Isolated Web App Developer Mode** → Enabled
   - **Local Network Access check** → Disabled (needed to reach a DC on a
     private/local IP; see below)
2. Go to `chrome://web-app-internals/`.
3. Under *Install IWA from Signed Web Bundle*, choose `dist/adidnsdump-iwa.swbn`.
4. Launch the installed **ADIDNSDump** app.

When you change the manifest, you must **uninstall and reinstall** — the
manifest (and its `permissions_policy`) is only read at install time.

### Required manifest permissions

`.well-known/manifest.webmanifest` must grant all three, or socket calls fail:

```json
"permissions_policy": {
  "direct-sockets": ["self"],
  "direct-sockets-private": ["self"],
  "cross-origin-isolated": ["self"]
}
```

- without `cross-origin-isolated` → `new TCPSocket()` throws
  *"Frame is not sufficiently isolated to use Direct Sockets"*;
- without `direct-sockets-private` → connecting to a private/local IP fails with
  *"Access to local network is blocked"* (a DC is almost always on a private IP).

(For a live-reload dev loop you can instead run a dev proxy and use
*Install IWA from Dev Mode Proxy*, but the signed-bundle path above is the
simplest way to run it.)

## Usage

1. **Domain Controller** — hostname or IP of a DC (it is both the LDAP server
   and the DNS server used for `--resolve`).
2. **Authentication**:
   - **NTLMv2 (GSS-SPNEGO)** — recommended. Username as `user@domain` or
     `DOMAIN\user` (+ optional Domain override) and password. The password is
     never sent; an NTLMv2 response is computed in-browser.
   - **Simple bind** — full DN/UPN + password, sent in cleartext.
3. **Base / domain DN** — optional; auto-discovered from RootDSE
   (`defaultNamingContext`) when blank.
4. **Zone** — optional; blank dumps every zone in the partition.
5. **List zones** to enumerate zones, or **Dump records** to pull records.
   Click a zone chip to dump just that zone. **Export CSV** saves the table.

## Authentication internals

NTLM is implemented from scratch because WebCrypto lacks the needed primitives:

- `src/crypto/md4.js`, `src/crypto/md5.js` — MD4 and MD5/HMAC-MD5 in pure JS.
- `src/ntlm/ntlm.js` — `NTOWFv2`, the NTLMv2 response (`computeNtlmv2Response`),
  and NTLMSSP NEGOTIATE/CHALLENGE/AUTHENTICATE (type 1/2/3) messages.
- `src/ntlm/spnego.js` — SPNEGO (RFC 4178) wrapping of the NTLM tokens.
- `src/ldap/client.js` `saslBind()` — the multi-round `GSS-SPNEGO` SASL bind.

The crypto is verified offline against the published **[MS-NLMP] §4.2.4**
reference vectors (`NTOWFv2`, `NTProofStr`, `SessionBaseKey`) — see
`scripts/test.js` / `npm test`.

## Limitations / security notes

- **No TLS.** The Direct Sockets `TCPSocket` has no TLS, so this speaks LDAP on
  **389**, not LDAPS on 636. Use on trusted/lab networks.
- **NTLMv2 = authentication only (no sign/seal).** The bind is unsigned and
  unsealed. It works against DCs that do not *require* LDAP signing/channel
  binding, but **fails against hardened DCs** (`LdapEnforceChannelBinding=2` or
  "require signing"): channel binding needs the TLS certificate hash, which is
  impossible without a TLS stack. Message signing/sealing (Stage 2) and
  Kerberos (Stage 3) are not yet implemented.
- **Simple bind sends the password in cleartext.**
- **`--resolve`** is best-effort plain DNS over UDP/53 to the DC; it returns A
  and AAAA answers for nodes whose `dnsRecord` your principal can list but not
  read. It does not implement zone-transfer-style brute forcing.
- TTL is shown as decoded from the record; tombstoned rows are dimmed.

## Project layout

```
src/
  ldap/ber.js       ASN.1 BER encode/decode (+ DER OID)
  ldap/client.js    LDAPv3 client over TCPSocket (simple + SASL bind, paged search)
  crypto/md4.js     MD4 (RFC 1320)
  crypto/md5.js     MD5 + HMAC-MD5 (RFC 1321 / 2104)
  ntlm/ntlm.js      NTLMv2 + NTLMSSP type 1/2/3
  ntlm/spnego.js    SPNEGO wrapping for GSS-SPNEGO
  ntlm/sasl.js      NTLM token producer for the SASL bind
  dns/record.js     DNS_RPC_RECORD (dnsRecord) parser
  dns/resolver.js   DNS-over-UDPSocket resolver (--resolve)
  adidnsdump.js     orchestration (RootDSE → zones → nodes → records)
  main.js           UI controller
public/
  index.html        UI shell
  .well-known/manifest.webmanifest  IWA manifest (fetched from this fixed
                    path at install time)
scripts/            keygen, icon generation, tests
rollup.config.js    bundles + signs the .swbn
```
