let stealthChromium;

async function getStealthChromium() {
  if (!stealthChromium) {
    const { chromium } = await import('playwright-extra');
    const { default: StealthPlugin } = await import('puppeteer-extra-plugin-stealth');
    chromium.use(StealthPlugin());
    stealthChromium = chromium;
  }
  return stealthChromium;
}

export async function fetchLoginPageHtmlViaBrowser(url, userAgent) {
  const chromium = await getStealthChromium();
  const browser = await chromium.launch({ headless: true });

  try {
    const context = await browser.newContext({
      userAgent,
      locale: 'en-US',
      viewport: { width: 1280, height: 720 },
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
    return await page.content();
  } finally {
    await browser.close();
  }
}

export function browserBrandingDepsHint() {
  return 'npm install playwright playwright-extra puppeteer-extra-plugin-stealth && npx playwright install chromium';
}
