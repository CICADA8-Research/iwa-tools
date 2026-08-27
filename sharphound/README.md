# SharpHound IWA

A browser port of **SharpHound** (the BloodHound data collector), built as a
Chrome **Isolated Web App (IWA)** that talks raw **LDAP** to a domain controller
using the **Direct Sockets API** (`TCPSocket`) and emits **BloodHound Community
Edition** JSON.

This implements SharpHound's **DCOnly** collection — everything obtainable from
the directory itself over LDAP: users, groups, computers, domains, OUs, GPOs,
containers, their memberships, GPO links, child objects and ACLs (parsed from
`nTSecurityDescriptor`) — plus an optional **host-based** pass that adds the
local-group edges SharpHound normally gathers over SMB/RPC. It is the
LDAP-transport sibling of the [`soaphound`](../soaphound) tool, which collects the
same BloodHound data over ADWS.

> ⚠️ **Authorised use only.** This is an offensive-security collection tool. Run
> it only against directories you own or are explicitly authorised to test.

## Modes

- **BloodHound dump** — emit BloodHound CE JSON
  (`users/groups/computers/domains/gpos/ous/containers.json`). Collects:
  - **Properties** — enabled, admincount, pwdlastset/lastlogon, SPNs, hasspn,
    unconstrained/constrained/`trustedtoauth` delegation, `dontreqpreauth`
    (AS-REP-roastable), `passwordnotreqd`, `pwdneverexpires`, `sensitive`,
    `sidhistory`, `haslaps`, operatingsystem, domain `machineaccountquota` /
    functionallevel, gpcpath, email/title/home…
  - **Edges** — group membership, primary group, GPO links, `Contains`/child
    objects, **`AllowedToDelegate`** (constrained delegation), **`AllowedToAct`**
    (RBCD, parsed from the SD), **`HasSIDHistory`**, domain **`Trusts`**, and
    **ACEs** from `nTSecurityDescriptor` (Owns, GenericAll/Write, WriteDacl/Owner,
    ForceChangePassword, AddMember/AddSelf, AddKeyCredentialLink, WriteSPN,
    WriteAccountRestrictions, GetChanges*/DCSync, AllExtendedRights) with
    `IsInherited` / `IsACLProtected`.

  Download individually or as one `.zip`.
- **Host-based collection** (optional checkbox / `--collect-local`) — for each
  enabled computer, connect over **SMB2** and collect:
  - **Local groups** via **SAMR** → **`LocalAdmins`** (BUILTIN\Administrators),
    **`RemoteDesktopUsers`**, **`DcomUsers`**, **`PSRemoteUsers`**. Member SIDs are
    typed from the directory cache, falling back to **LSAT** (`LsarLookupSids`) for
    local / well-known / cross-domain SIDs the cache doesn't know.
  - **Sessions** via **SRVSVC** (`NetrSessionEnum`) → the **`Sessions`** edge (user
    → the computer they connect from) and **PrivilegedSessions** via **WKSSVC**
    (`NetrWkstaUserEnum`, needs local admin) → users logged on to this host, both
    with names resolved to SIDs from the directory pass.
  - **RegistrySessions** via **WINREG** (`OpenUsers` + `BaseRegEnumKey` over
    `HKEY_USERS`) → loaded user hives → the **`RegistrySessions`** edge (user →
    this computer). Remote Registry is trigger-started by accessing the pipe
    (retried until ready).

  Unreachable or access-denied hosts are marked `Collected:false` per interface and
  never block the run.
- **Build cache** — a compact `cache.json` (DN→SID/GUID, id→type), the same map
  SOAPHound builds.
- **Custom LDAP query** — arbitrary base / filter / attribute list (filter
  strings are compiled to BER: presence, equality, substring, `&`/`|`/`!`).

## How it works

SharpHound-IWA reuses two existing pieces of this repo:

- **LDAP transport** from the [`adidns`](../adidns) tool: a hand-rolled LDAPv3
  client over `TCPSocket` (`src/ldap/`), NTLMv2 over SASL `GSS-SPNEGO`
  (`src/ntlm/`, `src/crypto/`), and the Microsoft paged-results control.
- **BloodHound processors** from the [`soaphound`](../soaphound) tool: SID/GUID
  decoding (`src/security/sid.js`), `nTSecurityDescriptor` → ACE parsing
  (`src/security/sddl.js`) and the per-type node builders (`src/modes/bhdump.js`,
  `src/modes/buildcache.js`).

The glue is `src/ldap/source.js`, an adapter that exposes the same `query()`
interface the processors expect, sourcing rows over LDAP instead of ADWS:

- adds the **`LDAP_SERVER_SD_FLAGS` control** (`1.2.840.113556.1.4.801`, Owner +
  Group + DACL) so `nTSecurityDescriptor` DACLs are readable without
  `SeSecurityPrivilege` (`src/ldap/client.js`);
- base64-encodes binary attributes (`objectSid`, `objectGUID`,
  `nTSecurityDescriptor`, …) so the shared processors decode them unchanged;
- performs **LDAP range retrieval** (`member;range=0-1499` → follow-up reads)
  so large group memberships are completed transparently.

The base DN is auto-discovered from RootDSE (`defaultNamingContext`).

### Host-based collection (SMB2 + DCE-RPC + SAMR)

There is no ready browser/JS library for SMB+DCERPC+SAMR (the JS SMB packages do
file I/O only; impacket is the Python reference), so the stack is implemented from
scratch over `TCPSocket` in `src/smb/`:

- **`smb2.js`** — an SMB2 (dialect 2.1) client: NEGOTIATE, SPNEGO **session setup**
  reusing the project's NTLM (the exported session key becomes the SMB signing
  key), **HMAC-SHA256 request signing** (mandatory against a DC), TREE_CONNECT to
  `IPC$`, CREATE on a named pipe, and `FSCTL_PIPE_TRANSCEIVE` to carry RPC.
- **`dcerpc.js`** — minimal DCE-RPC (MS-RPCE): BIND to an interface + NDR transfer
  syntax, then REQUEST/RESPONSE with fragment reassembly.
- **`ndr.js`** — the little-endian NDR marshalling the calls need (context handles,
  conformant SID arrays, `[string,unique]` wide strings).
- **`samr.js`** — SAMR: `SamrConnect2` → `SamrOpenDomain`(BUILTIN `S-1-5-32`) →
  `SamrOpenAlias`(RID 544/555/562/580) → `SamrGetMembersInAlias` → member SIDs.
- **`lsat.js`** — LSAT: `LsarOpenPolicy2` + `LsarLookupSids` → SID → name + type.
- **`srvsvc.js`** — SRVSVC: `NetrSessionEnum` (level 10) → sessions.
- **`wkssvc.js`** — WKSSVC: `NetrWkstaUserEnum` (level 1) → logged-on users.
- **`winreg.js`** — WINREG (MS-RRP): `OpenUsers` + `BaseRegEnumKey` over `HKU` →
  loaded user hives (registry sessions).
- **`hostcollect.js`** — per-host orchestration + per-interface timeouts, shaping
  the result into BloodHound `LocalGroup` / `Sessions` / `RegistrySessions` edges.

## Build

```bash
npm install
npm run keygen     # one-time: generate the Ed25519 signing key (fixes the app origin)
npm test           # offline tests: BER, NTLMv2 vectors, SID/SDDL, label + filter parser
npm run build      # produces dist/sharphound-iwa.swbn
npm run id         # print the resulting isolated-app:// origin
```

## Install in Chrome

Same as the other tools: enable **Isolated Web Apps**, **IWA Developer Mode** and
disable **Local Network Access check** at `chrome://flags`, then install
`dist/sharphound-iwa.swbn` via `chrome://web-app-internals/`. The manifest grants
`direct-sockets`, `direct-sockets-private` and `cross-origin-isolated`.

## Usage

1. **Domain Controller** — host/IP of a DC (LDAP, port 389).
2. **Authentication** — NTLMv2 (`user@domain` / `DOMAIN\user` + password; password
   is never sent, an NTLMv2 response is computed in-browser) or simple bind.
3. **Mode** — BloodHound dump, build cache, or a custom query. Base DN is optional
   (auto from RootDSE). Tick **Host-based collection** to also enumerate local
   groups over SMB/SAMR on each enabled computer.
4. **Run.** The query mode streams into the table; dump/cache modes show a summary
   and download buttons.

## How it maps to SharpHound

| SharpHound | This app |
|---|---|
| `--collectionmethods DCOnly` | LDAP collection (default) |
| `--collectionmethods LocalGroup,Session,LoggedOn,RegistrySession,PSRemote` | host-based pass (`--collect-local`, `src/smb/`) |
| LDAP + paged results + SD flags control | `src/ldap/` |
| ACL processing (`nTSecurityDescriptor`) | `src/security/sddl.js` |
| BloodHound JSON output | `src/modes/bhdump.js` (CE schema) |
| range retrieval of large attributes | `src/ldap/source.js` `_expandRange` |
| SMB session + SAMR local-group enum | `src/smb/` (SMB2 / DCE-RPC / NDR / SAMR) |

## Limitations / security notes

- **Collection scope.** DCOnly (directory-derived) edges are full: `MemberOf`, ACL
  edges, `Contains`, `GPLink`, delegation, `HasSIDHistory`, `Trusts`, RBCD. The
  optional host-based pass adds the SAMR local-group edges (`LocalAdmins`,
  `RemoteDesktopUsers`, `DcomUsers`, `PSRemoteUsers`) and all three session edges:
  `Sessions` (SRVSVC `NetrSessionEnum`), `PrivilegedSessions` (WKSSVC
  `NetrWkstaUserEnum`) and `RegistrySessions` (WINREG HKU hives) — full parity with
  SharpHound's host-based collection methods.
- **Host-based collection requires reachability + rights.** SMB/445 to each target
  and local-admin on it (e.g. a Domain Admin). The SMB2 session is **signed**
  (HMAC-SHA256), so it works against signing-required DCs. Targets that are offline
  or deny access are reported `Collected:false` and skipped.
- **TLS / channel binding.** LDAP can run over **LDAPS (636)** with the WASM-TLS
  stack and **channel binding**, or plain LDAP on 389. See the top-level README.
- **Auth.** NTLMv2, **Kerberos** (AS/TGS, AES/RC4, overpass-the-hash) or simple
  bind for LDAP; the host-based pass authenticates over NTLM. Simple bind sends the
  password in cleartext.

## Project layout

```
src/
  ldap/ber.js       ASN.1 BER encode/decode            [shared with adidns]
  ldap/client.js    LDAPv3 client over TCPSocket (+ SD flags control)
  ldap/source.js    LDAP -> BloodHound query() adapter (range retrieval, filters)
  crypto/, ntlm/    MD4/MD5, NTLMv2, SPNEGO, SASL       [shared with adidns]
  security/sid.js   SID / GUID decoding                 [shared with soaphound]
  security/sddl.js  nTSecurityDescriptor -> ACEs        [shared with soaphound]
  smb/smb2.js       SMB2 client (negotiate/auth/sign/IPC$/pipe)
  smb/dcerpc.js     DCE-RPC bind + request/response
  smb/ndr.js        NDR marshalling (SIDs, handles, strings)
  smb/samr.js       SAMR local-group member enumeration
  smb/lsat.js       LSAT SID -> name/type resolution
  smb/srvsvc.js     SRVSVC NetrSessionEnum (sessions)
  smb/wkssvc.js     WKSSVC NetrWkstaUserEnum (logged-on)
  smb/winreg.js     WINREG HKU enumeration (registry sessions)
  smb/hostcollect.js  per-host LocalGroup + Sessions + RegistrySessions

  modes/bhdump.js   BloodHound CE node builders         [shared with soaphound]
  modes/buildcache.js  SID/DN/type cache                [shared with soaphound]
  sharphound.js     orchestration (RootDSE -> mode dispatch)
  zip.js            store-only .zip writer
  main.js           UI controller
public/             UI shell + IWA manifest
scripts/            keygen, icon generation, tests
rollup.config.js    bundles + signs the .swbn
```
