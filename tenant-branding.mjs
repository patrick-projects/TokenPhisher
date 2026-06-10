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

export async function fetchTenantBranding(tenant, userAgent, clientId = null) {
  const headers = {
    'User-Agent': userAgent,
    Accept: 'text/html,application/xhtml+xml',
  };

  const whrUrl = tenantLoginPreviewUrl(tenant);
  let response = await fetch(whrUrl, { headers });

  if (!response.ok) {
    throw new Error(`Tenant branding fetch failed (HTTP ${response.status}) for ${tenant}`);
  }

  let html = await response.text();
  let loginConfig = extractConfigJson(html);

  // Fall back to tenant authorize page if WHR HTML has no Config blob.
  if (!loginConfig && clientId) {
    const authorizeUrl =
      `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/authorize` +
      `?client_id=${encodeURIComponent(clientId)}` +
      '&response_type=code' +
      '&redirect_uri=https%3A%2F%2Flocalhost' +
      '&scope=openid';
    response = await fetch(authorizeUrl, { headers });
    if (!response.ok) {
      throw new Error(`Tenant branding fetch failed (HTTP ${response.status}) for ${tenant}`);
    }
    html = await response.text();
    loginConfig = extractConfigJson(html);
  }

  if (!loginConfig) {
    throw new Error(`Could not parse login Config for tenant ${tenant}`);
  }

  return brandingFromLoginConfig(loginConfig);
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
      config.clientId
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
