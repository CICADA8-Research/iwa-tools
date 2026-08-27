# iwa-tools console (IWA)

A single **Isolated Web App** bundling all of the repo's Direct Sockets utilities
(`portscan`, `adidns`, `soaphound`, `sharphound`, `evil-winrm`, `ldap-shell`)
behind one pseudo-terminal. Run any tool with arguments inline; interactive tools
open a sub-shell.

> ⚠️ **Authorised testing only.**

## Build

```bash
npm install
npm run keygen    # one-time: generates signing.key (fixes the app's origin / Web Bundle ID)
npm test
npm run build     # -> dist/iwa-tools.swbn
npm run id        # print the Web Bundle ID + isolated-app:// origin
```

The Web Bundle ID is derived from `signing.key`. **Keep `signing.key` stable** — it
is the app's identity; regenerating it changes the origin and makes Chrome treat it
as a different app (a fresh install, no shared storage).

## Install from a local file (dev)

In `chrome://flags` enable **Isolated Web Apps** (`#enable-isolated-web-apps`) and
**Isolated Web App Developer Mode** (`#enable-isolated-web-app-dev-mode`), then in
`chrome://web-app-internals/` use **“Install IWA from Signed Web Bundle”** and pick
`dist/iwa-tools.swbn`.

## Publish over the network (install from a URL)

IWAs are not installed by "just visiting a page" — Chrome installs them from an
**Update Manifest** (a small JSON that points at the `.swbn` and its version). Host
the manifest + bundle on an **HTTPS** server, then install by URL.

### 1. Generate the update manifest

```bash
npm run build
npm run manifest            # -> dist/update.json  (src = iwa-tools.swbn, version from package.json)
# or pin an absolute bundle URL:
npm run manifest -- https://apps.example.com/iwa/iwa-tools.swbn
```

`dist/update.json`:

```json
{
  "versions": [
    { "version": "1.0.0", "src": "iwa-tools.swbn" }
  ]
}
```

`src` is resolved relative to the manifest's own URL (so hosting `update.json` and
`iwa-tools.swbn` side-by-side just works), or it can be an absolute `https://` URL.

### 2. Host the two files over HTTPS

Serve `update.json` and `iwa-tools.swbn` from the same HTTPS origin. The bundle must
be sent with the right MIME type. Example nginx:

```nginx
server {
    listen 443 ssl;
    server_name apps.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location /iwa/ {
        root /var/www;                       # files at /var/www/iwa/{update.json,iwa-tools.swbn}
        types { application/json json; }
        location ~ \.swbn$ { default_type application/swbn; add_header Cache-Control "no-cache"; }
    }
}
```

Requirements:
- **HTTPS is mandatory** (only `http://localhost` is exempt).
- Serve `*.swbn` as `application/swbn` (or `application/octet-stream`); `update.json`
  as `application/json`.
- Keep both files on the **same origin** to avoid CORS; otherwise add
  `Access-Control-Allow-Origin` on both.

### 3a. Install via URL — dev mode

With the two IWA flags enabled (above), open `chrome://web-app-internals/` →
**“Install IWA from Update Manifest”**, paste:

```
https://apps.example.com/iwa/update.json
```

Chrome fetches the manifest, downloads the bundle and installs it — no local file.

### 3b. Install via URL — managed / production (no dev flags)

For managed Chrome, force-install with the **`IsolatedWebAppInstallForceList`**
enterprise policy (requires `IsolatedWebAppsEnabled`). The `web_bundle_id` is this
app's ID from `npm run id`:

```json
[
  {
    "update_manifest_url": "https://apps.example.com/iwa/update.json",
    "web_bundle_id": "5eh64kbwdzgwr7vogb2mdtxvwqd3kaswpqsjdh5pepbwp3yqdpoaaaic"
  }
]
```

Set it where your platform reads Chrome policy, e.g. Windows registry:

```
HKLM\SOFTWARE\Policies\Google\Chrome\IsolatedWebAppInstallForceList\1 =
  {"update_manifest_url":"https://apps.example.com/iwa/update.json","web_bundle_id":"5eh64kbwdzgwr7vogb2mdtxvwqd3kaswpqsjdh5pepbwp3yqdpoaaaic"}
```

(Or the `managed_policy` JSON on Linux/macOS, or via Google Admin / Intune.) Chrome
installs the app on the next policy refresh and keeps it updated from the manifest.

### Shipping an update

1. Bump `version` in `package.json` (and the `version` in
   `public/manifest.webmanifest`) — it **must increase**.
2. `npm run build && npm run manifest`.
3. Replace `update.json` + `iwa-tools.swbn` on the server.

Force-installed clients pick up the new version automatically; dev installs update
on next launch (or re-run the manifest install).

> The Web Bundle ID never changes as long as `signing.key` is the same — that's what
> lets Chrome recognise a new bundle as an *update* to the installed app rather than
> a different app.
