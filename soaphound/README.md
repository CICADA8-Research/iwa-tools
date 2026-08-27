# SOAPHound IWA

A browser port of [FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound)
(with the protocol stack modelled on the from-scratch Python client
[logangoins/SOAPy](https://github.com/logangoins/SOAPy)), built as a Chrome
**Isolated Web App (IWA)** that talks **ADWS** (Active Directory Web Services,
TCP **9389**) to a domain controller using the **Direct Sockets API**
(`TCPSocket`).

Instead of querying LDAP directly, ADWS wraps LDAP queries in SOAP and the DC's
ADWS service forwards them to its own LDAP server — so the LDAP queries never go
over the wire, making this harder to spot with LDAP-focused monitoring.

> ⚠️ **Authorised use only.** This is an offensive-security collection tool. Run
> it only against directories you own or are explicitly authorised to test.

## What it does

Four collection modes (plus a raw query):

- **Build cache** — enumerate every object and emit a compact `cache.json`
  (`ValueToIdCache` DN→SID/GUID, `IdToTypeCache` id→type). This is the map the
  ACL/relationship resolution in the other modes uses.
- **BloodHound dump** — emit **BloodHound Community Edition** JSON
  (`users/groups/computers/domains/gpos/ous/containers.json`) with properties,
  group membership, primary-group and GPO-link edges, child objects, and ACEs
  parsed from `nTSecurityDescriptor`. Download individually or as one `.zip`.
- **ADCS dump** — enumerate AD Certificate Services under the Configuration NC
  (enterprise CAs, certificate templates, root CAs) with enrollment ACLs.
- **ADIDNS dump** — enumerate `dnsNode` objects and decode the binary
  `dnsRecord` ([MS-DNSP] `DNS_RPC_RECORD`) into readable records (the same
  parser the sibling `adidns` tool uses).
- **Custom LDAP query** — arbitrary base / filter / attribute list.

## The ADWS protocol stack

ADWS is not a simple line protocol. It layers several Microsoft protocols, all
implemented here from scratch in JS (there is no .NET runtime in a browser):

| Layer | Spec | This app |
|---|---|---|
| Message framing | **MC-NMF** (.NET Message Framing) | `src/nmf/nmf.js` — preamble, upgrade, sized envelopes |
| Auth + sign/seal | **MS-NNS** (.NET NegotiateStream) | `src/nns/nns.js` + `src/ntlm/seal.js` |
| Binary SOAP | **MC-NBFX / NBFS / NBFSE** | `src/encoder/` — record codec + static dictionary |
| Query | **WS-Enumeration** (Enumerate/Pull) | `src/soap/templates.js` + `src/adws/client.js` |

ADWS **requires every post-authentication message to be signed and sealed**
(this is also why ADWS resists NTLM relay). So unlike the LDAP-bind in the
sibling `adidns` tool — which is authentication-only — this implements full NTLM
**confidentiality**: key exchange, `SIGNKEY`/`SEALKEY` derivation, RC4 sealing
handles, and per-message `GSS_WrapEx` signatures with sequence numbers
(`src/ntlm/seal.js`). That code is verified byte-for-byte against impacket and
the [MS-NLMP] §4.2 vectors in `scripts/test.js`.

The NBFSE binary-XML responses are decoded against the MC-NBFS static dictionary
(`src/encoder/dictionary.js`) plus the server's in-band session dictionary; on
send we use a **blank in-band dictionary** (a documented simplification).

## Build

```bash
npm install
npm run keygen     # one-time: generate the Ed25519 signing key (fixes the app origin)
npm test           # offline tests: NTLM sign/seal vectors, RC4, NMF framing, NBFX round-trips
npm run build      # produces dist/soaphound-iwa.swbn
npm run id         # print the resulting isolated-app:// origin
```

`signing.key` determines the app's permanent `isolated-app://…` identity. Keep
it; regenerating (`npm run keygen -- --force`) changes the origin and makes
Chrome treat it as a different app.

## Install in Chrome

IWAs require a recent Chrome/Chromium (desktop).

1. Enable the flags at `chrome://flags`:
   - **Isolated Web Apps** → Enabled
   - **Isolated Web App Developer Mode** → Enabled
   - **Local Network Access check** → Disabled (to reach a DC on a private IP)
2. Go to `chrome://web-app-internals/`.
3. Under *Install IWA from Signed Web Bundle*, choose `dist/soaphound-iwa.swbn`.
4. Launch the installed **SOAPHound** app.

The `permissions_policy` in `.well-known/manifest.webmanifest` must grant
`direct-sockets`, `direct-sockets-private` and `cross-origin-isolated`, or socket
calls fail (private/local DC IPs need `direct-sockets-private`). Reinstall after
any manifest change — it is only read at install time.

## Usage

1. **Domain Controller** — hostname or IP of a DC running ADWS (TCP 9389).
   Set **SOAP FQDN** if the DC's expected `net.tcp://…` host differs from what
   you connect to.
2. **Credentials (NTLMv2)** — `user@domain` or `DOMAIN\user` (+ optional Domain
   override) and password. The password is never sent; an NTLMv2 response is
   computed in-browser and the channel is signed+sealed.
3. **Mode** — pick a collection mode (and a base DN, optional — auto-derived from
   the domain). For *Custom LDAP query*, set the filter and attribute list.
4. **Run.** Tabular modes stream into the table; cache/BloodHound/ADCS modes show
   a summary and per-file (and `.zip`) download buttons.

## How it maps to SOAPHound

| SOAPHound | This app |
|---|---|
| `--buildcache` (cache.txt) | **Build cache** → `cache.json` |
| `--bhdump` (BloodHound JSON) | **BloodHound dump** → CE `*.json` (+ zip) |
| `--certdump` (ADCS) | **ADCS dump** |
| `--dnsdump` (ADIDNS) | **ADIDNS dump** |
| `.NET ServiceModel NetTcpBinding` | `src/nmf` + `src/nns` + `src/encoder` (hand-rolled) |
| current-token / `--user` `--password` | NTLMv2 sign+seal (`src/ntlm/seal.js`) |

## Limitations / security notes

- **NTLM only.** Kerberos is not implemented; ADWS accepts NTLM sign+seal by
  default, which is what this uses.
- **No TLS needed.** ADWS `NetTcpBinding` transport security is the NegotiateStream
  sign/seal layer (implemented here), not TLS, so this works over plain TCP 9389.
- **Collection scope.** BloodHound output covers AD-derivable data (objects,
  memberships, ACLs, GPO links, trusts). Session/local-admin collection
  (SharpHound's host methods) is out of scope and emitted as empty collections.
- **Large domains.** bhdump streams the enumeration and does not retain raw
  objects or their security descriptors (it keeps only the lean cache + output
  nodes, resolving edges in a second in-memory pass), so memory scales with the
  result rather than with descriptor size. buildcache/dnsdump/query are streaming
  and lean. The peak ceiling is still the in-memory output arrays; for million-
  object domains the next step would be streaming output to disk (File System
  Access API) rather than the SOAPHound-style object-count `--autosplit`.
- **Range retrieval** of very large multi-valued attributes (e.g. `member` on
  groups past the server's `MaxValRange`, ~1500) is implemented: truncated
  attributes are detected via their `RangeLow`/`RangeHigh` markers and completed
  with follow-up windowed queries (`src/adws/client.js` `_expandRanges`). Large
  *result sets* are handled by the paged Pull loop, so SOAPHound's `--autosplit`
  (which works around large object counts) is not needed here.

## Project layout

```
src/
  net/socket.js         buffered byte stream over TCPSocket
  nmf/nmf.js            MC-NMF framing (preamble, upgrade, sized envelopes)
  nns/nns.js            MS-NNS handshake + sealed data stream
  ntlm/ntlm.js          NTLMv2 base (NTOWFv2, type 1/2/3)  [shared with adidns]
  ntlm/seal.js          NTLM sign+seal (key exch, SIGNKEY/SEALKEY, GSS_WrapEx)
  ntlm/spnego.js        SPNEGO wrapping
  crypto/{md4,md5,rc4}.js  MD4 / MD5+HMAC / RC4
  encoder/dictionary.js MC-NBFS static string dictionary
  encoder/nbfx.js       MC-NBFX record encode/decode
  encoder/nbfse.js      NBFSE wrapper (in-band dictionary)
  encoder/xml.js        tiny XML tree parse/serialize
  soap/templates.js     WS-Enumeration Enumerate/Pull envelopes
  adws/client.js        connect + Enumerate/Pull query loop
  security/sid.js       SID / GUID decoding
  security/sddl.js      nTSecurityDescriptor -> BloodHound Aces
  dns/record.js         DNS_RPC_RECORD parser  [shared with adidns]
  modes/                buildcache, dnsdump, bhdump, certdump
  soaphound.js          orchestration (mode dispatch)
  zip.js                store-only .zip writer for multi-file downloads
  main.js               UI controller
public/
  index.html            UI shell
  .well-known/manifest.webmanifest   IWA manifest
scripts/                keygen, icon generation, tests
rollup.config.js        bundles + signs the .swbn
```
