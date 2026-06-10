const MS_BACKGROUND_PRESETS = {
  2: 'https://aadcdn.msftauth.net/shared/1.0/content/images/backgrounds/2_11d9e3bcdfede9ce5ce5ace2d129f1c4.svg',
  3: 'https://aadcdn.msftauth.net/shared/1.0/content/images/backgrounds/3_14dac81de7cff440337e4719b2fc0585.svg',
  4: 'https://aadcdn.msftauth.net/shared/1.0/content/images/backgrounds/4_eae2dd7eb3a55636dc2d74f4fa4c386e.svg',
};

export const DEFAULT_BRANDING = {
  logoUrl: '/assets/img/microsoft-logo.svg',
  bannerLogo: '',
  backgroundColor: '#f2f2f2',
  backgroundImage: 'https://aadcdn.msftauth.net/shared/1.0/content/images/backgrounds/2_11d9e3bcdfede9ce5ce5ace2d129f1c4.svg',
  isTenantLogo: false,
};

function extractConfigJson(html) {
  const marker = '$Config=';
  let start = html.indexOf(marker);
  if (start === -1) {
    start = html.indexOf('Config=');
    if (start === -1) {
      return null;
    }
    start += 'Config='.length;
  } else {
    start += marker.length;
  }

  while (start < html.length && /\s/.test(html[start])) {
    start += 1;
  }
  if (html[start] !== '{') {
    return null;
  }

  let depth = 0;
  for (let i = start; i < html.length; i += 1) {
    if (html[i] === '{') {
      depth += 1;
    } else if (html[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        return JSON.parse(html.slice(start, i + 1));
      }
    }
  }
  return null;
}

function buildBranding({ bannerLogo, backgroundColor, backgroundImage, illustrationIndex }) {
  const color = backgroundColor || DEFAULT_BRANDING.backgroundColor;
  let image = backgroundImage || '';

  if (!image && illustrationIndex !== undefined && MS_BACKGROUND_PRESETS[illustrationIndex]) {
    image = MS_BACKGROUND_PRESETS[illustrationIndex];
  }
  if (!image && !bannerLogo) {
    image = DEFAULT_BRANDING.backgroundImage;
  }
  // Custom tenant logos usually use a flat brand color, not the MS illustration overlay.
  if (bannerLogo && backgroundColor && !backgroundImage) {
    image = '';
  }

  if (bannerLogo) {
    return {
      logoUrl: bannerLogo,
      bannerLogo,
      backgroundColor: color,
      backgroundImage: image,
      isTenantLogo: true,
    };
  }

  return {
    ...DEFAULT_BRANDING,
    backgroundColor: color,
    backgroundImage: image || DEFAULT_BRANDING.backgroundImage,
  };
}

export function brandingFromLoginConfig(config) {
  const branding = config?.staticTenantBranding?.[0] || {};
  return buildBranding({
    bannerLogo: branding.BannerLogo || '',
    backgroundColor: branding.BackgroundColor,
    backgroundImage: branding.BackgroundImage,
    illustrationIndex: config?.iBackgroundImage,
  });
}

export function normalizeBranding(raw = {}) {
  if (raw.bannerLogo || raw.logoUrl?.startsWith('http')) {
    return buildBranding({
      bannerLogo: raw.bannerLogo || raw.logoUrl || '',
      backgroundColor: raw.backgroundColor,
      backgroundImage: raw.backgroundImage,
    });
  }
  return {
    ...DEFAULT_BRANDING,
    backgroundColor: raw.backgroundColor || DEFAULT_BRANDING.backgroundColor,
    backgroundImage: raw.backgroundImage || DEFAULT_BRANDING.backgroundImage,
  };
}

export function tenantLoginPreviewUrl(tenant) {
  return `https://login.microsoftonline.com/?whr=${encodeURIComponent(tenant)}`;
}

async function fetchLoginPageHtml(url, userAgent) {
  const response = await fetch(url, {
    headers: {
      'User-Agent': userAgent,
      Accept: 'text/html,application/xhtml+xml',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.text();
}

async function fetchLoginPageHtmlWithBrowser(url, userAgent, log = () => {}) {
  try {
    const { fetchLoginPageHtmlViaBrowser } = await import('./tenant-branding-browser.mjs');
    log(`Tenant branding: fetching ${url} via headless browser (stealth)`);
    return await fetchLoginPageHtmlViaBrowser(url, userAgent);
  } catch (error) {
    if (error.code === 'ERR_MODULE_NOT_FOUND') {
      const { browserBrandingDepsHint } = await import('./tenant-branding-browser.mjs');
      throw new Error(`Playwright stealth dependencies missing. Run: ${browserBrandingDepsHint()}`);
    }
    throw error;
  }
}

function brandingFromHtml(html) {
  const loginConfig = extractConfigJson(html);
  if (!loginConfig) {
    return null;
  }
  return brandingFromLoginConfig(loginConfig);
}

function brandingLooksGeneric(branding) {
  return !branding?.isTenantLogo;
}

export async function fetchTenantBranding(tenant, userAgent, clientId = null, options = {}) {
  const { browserFallback = false, log = () => {} } = options;
  const whrUrl = tenantLoginPreviewUrl(tenant);
  const errors = [];
  let genericBranding = null;

  try {
    const html = await fetchLoginPageHtml(whrUrl, userAgent);
    const branding = brandingFromHtml(html);
    if (branding) {
      if (!browserFallback || !brandingLooksGeneric(branding)) {
        return branding;
      }
      genericBranding = branding;
      errors.push('WHR HTTP returned generic Microsoft branding');
    } else {
      errors.push('WHR page had no parseable Config');
    }
  } catch (error) {
    errors.push(`WHR: ${error.message}`);
  }

  if (clientId) {
    try {
      const authorizeUrl =
        `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/authorize` +
        `?client_id=${encodeURIComponent(clientId)}` +
        '&response_type=code' +
        '&redirect_uri=https%3A%2F%2Flocalhost' +
        '&scope=openid';
      const html = await fetchLoginPageHtml(authorizeUrl, userAgent);
      const branding = brandingFromHtml(html);
      if (branding) {
        if (!browserFallback || !brandingLooksGeneric(branding)) {
          return branding;
        }
        genericBranding = branding;
        errors.push('Authorize HTTP returned generic Microsoft branding');
      } else {
        errors.push('Authorize page had no parseable Config');
      }
    } catch (error) {
      errors.push(`Authorize: ${error.message}`);
    }
  }

  if (!browserFallback) {
    if (genericBranding) {
      return genericBranding;
    }
    throw new Error(`Tenant branding fetch failed for ${tenant}: ${errors.join('; ')}`);
  }

  try {
    const html = await fetchLoginPageHtmlWithBrowser(whrUrl, userAgent, log);
    const branding = brandingFromHtml(html);
    if (branding && !brandingLooksGeneric(branding)) {
      return branding;
    }
    if (branding) {
      return branding;
    }
    throw new Error('Could not parse login Config from WHR page (browser)');
  } catch (error) {
    if (genericBranding) {
      log(`Tenant branding browser fallback failed, using HTTP result: ${error.message}`, 'error');
      return genericBranding;
    }
    throw new Error(`Tenant branding fetch failed for ${tenant}: ${error.message}`);
  }
}

export async function loadTenantBranding(config, log = () => {}) {
  if (!config.microsoftTenant) {
    if (config.tenantBranding) {
      return normalizeBranding(config.tenantBranding);
    }
    log('No microsoftTenant in config — using default Microsoft branding');
    return DEFAULT_BRANDING;
  }

  try {
    const branding = await fetchTenantBranding(
      config.microsoftTenant,
      config.userAgent,
      config.clientId,
      { browserFallback: config.tenantBrandingBrowserFallback === true, log }
    );
    config.tenantBranding = branding;
    const logoLabel = branding.isTenantLogo ? 'custom tenant logo' : 'Microsoft default logo';
    log(
      `Tenant branding loaded for ${config.microsoftTenant} (${logoLabel}, background ${branding.backgroundColor})`
    );
    log(`Tenant login preview: ${tenantLoginPreviewUrl(config.microsoftTenant)}`);
    return branding;
  } catch (error) {
    log(`Tenant branding fetch failed for ${config.microsoftTenant}: ${error.message}`, 'error');
    if (config.tenantBranding) {
      log('Falling back to tenantBranding cached in config.json');
      return normalizeBranding(config.tenantBranding);
    }
    log('Using default Microsoft branding', 'error');
    return DEFAULT_BRANDING;
  }
}
