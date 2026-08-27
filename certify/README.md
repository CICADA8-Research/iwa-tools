# Certify IWA

A browser port of **[GhostPack/Certify](https://github.com/GhostPack/Certify)**, built
as a Chrome **Isolated Web App (IWA)** that talks raw **LDAP** to a domain
controller over the **Direct Sockets API** (`TCPSocket`) and enumerates **Active
Directory Certificate Services** to find vulnerable certificate templates.

It reads the CAs and certificate templates from the Configuration naming context,
parses their flags / EKUs / security descriptors, and reports the **ESC**
misconfiguration classes (ESC1–ESC15) — the same analysis Certify / Certipy do.

> ⚠️ **Authorised use only.** This is an offensive-security tool. Run it only
> against directories you own or are explicitly authorised to test.

## Modes

- **Find** — enumerate CAs + templates and report all findings.
- **Vulnerable** — findings only.
- **Templates** / **CAs** — raw inventory of one object type.
- **Request** — obtain a certificate from a CA over MS-ICPR (see below).
- **Authenticate** — PKINIT with a certificate → TGT, and UnPAC-the-hash → the
  account's **NT hash** (Certipy's `auth`, see below).

## What it detects

Fully derived from LDAP (template attributes + `nTSecurityDescriptor`):

| ESC | Condition |
|-----|-----------|
| **ESC1** | `ENROLLEE_SUPPLIES_SUBJECT` + client-auth EKU + no manager approval, enrollable by a low-priv principal → request a cert with an arbitrary SAN. |
| **ESC2** | Any Purpose (or no) EKU, enrollable + no approval. |
| **ESC3** | Certificate Request Agent EKU (enrollment agent), enrollable + no approval. |
| **ESC4** | Low-priv principal has **write/owner** control (GenericAll/Write, WriteDacl/Owner, all-property write) over the template. |
| **ESC9** | `NO_SECURITY_EXTENSION` on a client-auth template (weak certificate mapping). |
| **ESC13** | Template pins an issuance-policy OID that may confer group membership. |
| **ESC15** | Schema **v1** template (EKUwu / CVE-2024-49019) — application policies injectable via the CSR. |
| **ESC8** | CA advertises HTTP Web Enrolment / CES (NTLM-relay target). |
| **ESC7** | Low-priv **write** on the CA object (confirm `ManageCA` via CA config). |

CA-level **ESC6** (`EDITF_ATTRIBUTESUBJECTALTNAME2`) and true **ESC7** (`ManageCA`)
live in the CA's own configuration (registry), reachable only over RPC
(`ICertAdmin`) — they are noted but not asserted from LDAP alone.

Enrolment / write principals are resolved to names (well-known table + AD `<SID=…>`
bind), and only **low-privileged** trustees (Domain Users, Authenticated Users,
Everyone, Domain Computers, …) trigger a finding — privileged holders are ignored,
so default templates don't produce noise.

## Certificate requests (ESC1) — `requestCert`

Beyond enumeration, the tool can request a certificate from a CA over **MS-ICPR**
(`CertServerRequest` on the `\cert` named pipe), including the ESC1 abuse of
supplying an arbitrary **SubjectAltName** (`otherName:UPN`) to impersonate another
principal. The pipeline (`src/adcs/pkcs10.js` + `src/adcs/icpr.js`):

1. **RSA-2048 keypair** via WebCrypto (`SubjectPublicKeyInfo` taken from the SPKI
   export).
2. A DER **PKCS#10 CSR**, optionally carrying a SAN `extensionRequest` for ESC1
   (verified with OpenSSL: valid self-signed request, `UPN:user@domain` SAN).
3. **`CertServerRequest`** over DCE-RPC with `CertificateTemplate:<name>` attributes.
4. The issued cert (leaf extracted from the PKCS#7) + private key are returned as PEM.

ICPR requires **RPC-level authentication**, so the DCE-RPC layer implements a full
NTLM `BIND`/`AUTH3` handshake with **packet privacy** (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`):
each request stub is RC4-sealed and the NTLM signature covers the whole PDU
(header + stub + sec_trailer, per MS-RPCE), with SMB2 async `STATUS_PENDING`
handled while the CA issues the cert. **Validated live** against the lab CA — a
`User` cert was issued (`subject=CN=Administrator`, EKU *Client Authentication*),
the leaf extracted from the returned PKCS#7 (`subject != issuer`), and the private
key verified to match. For an ESC1 template the same path embeds the attacker's
`UPN` SAN to impersonate an arbitrary principal.

## Authenticate — PKINIT + UnPAC-the-hash (`authenticate`)

Certipy's `auth`: turn a certificate into a Kerberos TGT, and the TGT into the
account's NT hash — no password needed. Implemented in `src/kerberos/`:

1. **PKINIT** (RFC 4556) — `dh.js` (MODP group 14 + BigInt modexp + `octetstring2key`),
   `cms.js` (a CMS `SignedData` over the AuthPack, signed by the cert's RSA key via
   WebCrypto), `pkinit.js` (PA-PK-AS-REQ, DH reply-key derivation, AS-REP decryption)
   → a **TGT** authenticated by the certificate.
2. **UnPAC-the-hash** — `unpac.js` sends a **User-to-User** TGS-REQ to self
   (`ENC-TKT-IN-SKEY`) so the issued ticket's PAC is readable, decrypts
   `PAC_CREDENTIAL_INFO` with the PKINIT reply key, and reads the
   `NTLM_SUPPLEMENTAL_CREDENTIAL` → the **NT hash**.

**Validated live** end-to-end: request a `User` cert → PKINIT (DH group 14, AES256
reply key) → TGT → U2U → NT hash, and the recovered hash equals
`MD4(UTF16LE(password))`.

```
certify auth -k dc01 --cahost ca01 -ca corp-CA -t User -u administrator -d corp.local -p Passw0rd
```

## How it works

Reuses the repo's LDAP stack (the `adidns`/`sharphound` client): the hand-rolled
LDAPv3 client over `TCPSocket`, NTLMv2 / **Kerberos** GSS-SPNEGO bind, optional
**LDAPS via WASM rustls + channel binding**, and the `LDAP_SERVER_SD_FLAGS` control
so template DACLs are readable. The AD CS logic lives in `src/adcs/`:

```
src/adcs/constants.js   flag bits, EKU OIDs, right GUIDs, low-priv SID logic
src/adcs/enum.js        Config-NC discovery + CA/template enumeration + SID resolve
src/adcs/esc.js         template/CA analysis -> ESC findings
src/certify.js          orchestration (connect -> enumerate -> analyse)
src/main.js             UI controller (tables)
```

## Build

```bash
npm install
npm run keygen     # one-time Ed25519 signing key (fixes the app origin)
npm run build      # -> dist/certify-iwa.swbn
npm run id         # print the isolated-app:// origin
```

Install `dist/certify-iwa.swbn` via `chrome://web-app-internals/` (with the IWA
flags enabled), or publish it over the network like the other tools — see
[`iwa-tools/README.md`](../iwa-tools/README.md).

## Usage

1. **Domain Controller** + **credentials** (NTLMv2 / Kerberos / simple; TLS optional).
2. Pick a **mode** and **Run**. Findings, templates and CAs render as tables.

Inside the combined `iwa-tools` console, Certipy-style subcommands + short flags:

```
certify vulnerable -H dc01 -u admin -d corp.local --tls
certify req --cahost ca01 -ca corp-CA -t User -u admin -d corp.local -upn administrator@corp.local
certify auth -k dc01 --cahost ca01 -ca corp-CA -u administrator -d corp.local -p pass   # PKINIT → NT hash
```
(short flags: `-u` user, `-p` password, `-d` domain, `-k` kdc, `-H` host, `-c`/`-ca` ca, `-t` template.)
