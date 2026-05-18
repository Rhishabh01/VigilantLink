// Brand Impersonation Engine for VigilantLink
// Lightweight impersonation checks using domain mismatch and title matching

function checkImpersonation(url, title = "") {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  
  const BRANDS = {
    Google: {
      domains: ['google.com', 'youtube.com', 'gmail.com', 'google.co.in'],
      keywords: ['google', 'gmail', 'youtube']
    },
    Microsoft: {
      domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'windows.net', 'azure.com', 'sharepoint.com'],
      keywords: ['microsoft', 'outlook', 'office365', 'sharepoint', 'microsoft-login']
    },
    Discord: {
      domains: ['discord.com', 'discordapp.com', 'discord.gg'],
      keywords: ['discord']
    },
    Steam: {
      domains: ['steampowered.com', 'steamcommunity.com', 'steamcard'],
      keywords: ['steamcommunity', 'steampowered', 'steamlogin']
    },
    PayPal: {
      domains: ['paypal.com'],
      keywords: ['paypal']
    },
    Amazon: {
      domains: ['amazon.com'],
      keywords: ['amazon']
    },
    GitHub: {
      domains: ['github.com'],
      keywords: ['github']
    },
    Apple: {
      domains: ['apple.com', 'icloud.com'],
      keywords: ['apple', 'icloud']
    }
  };

  const titleLower = title.toLowerCase();

  for (const [brandName, brand] of Object.entries(BRANDS)) {
    // Check if the current domain is one of the official ones
    const isOfficial = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
    if (isOfficial) continue;

    // Check if hostname contains brand keywords
    const hostnameContainsBrand = brand.keywords.some(kw => hostname.includes(kw));
    
    // Check title contains brand and login keywords
    const titleContainsBrand = titleLower.includes(brandName.toLowerCase());
    const isLoginTitle = titleLower.includes('login') || titleLower.includes('sign in') || titleLower.includes('auth') || titleLower.includes('verification') || titleLower.includes('secure');

    if (hostnameContainsBrand) {
      return {
        brand: brandName,
        reason: `This page appears to imitate ${brandName} but is not hosted on an official ${brandName} domain.`
      };
    }

    if (titleContainsBrand && isLoginTitle) {
      return {
        brand: brandName,
        reason: `Page title resembles ${brandName} authentication but is hosted on an unofficial domain (${hostname}).`
      };
    }
  }

  return null;
}
