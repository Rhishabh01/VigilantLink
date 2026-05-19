// Brand Distance Scoring Engine for VigilantLink
// Levenshtein + Jaro-Winkler against bundled top brand domains
// Zero API calls — fully local, runs in service worker

// ── Brand Registry ─────────────────────────────────────────────────────────
// Format: [brandName, primaryDomain, ...aliasDomains]
// Organized by phishing target frequency
var BRAND_REGISTRY = [
  // ── Tech Giants ──
  ['google','google.com','gmail.com','youtube.com','googleapis.com','google.co.uk','google.co.in','google.de','google.fr','google.com.br'],
  ['microsoft','microsoft.com','live.com','outlook.com','office.com','office365.com','sharepoint.com','onedrive.com','azure.com','windows.com','xbox.com','skype.com','hotmail.com','msn.com','bing.com','microsoftonline.com','teams.microsoft.com'],
  ['apple','apple.com','icloud.com','itunes.com','me.com','mac.com','apple.co.uk'],
  ['amazon','amazon.com','amazon.co.uk','amazon.de','amazon.fr','amazon.co.jp','amazon.in','amazon.com.br','amazon.ca','amazon.es','amazon.it','aws.amazon.com','primevideo.com'],
  ['meta','facebook.com','fb.com','instagram.com','whatsapp.com','messenger.com','threads.net','meta.com','oculus.com'],
  ['netflix','netflix.com'],
  ['twitter','twitter.com','x.com','t.co'],
  ['linkedin','linkedin.com'],
  ['tiktok','tiktok.com'],
  ['snapchat','snapchat.com','snap.com'],
  ['pinterest','pinterest.com'],
  ['reddit','reddit.com'],
  ['tumblr','tumblr.com'],
  ['telegram','telegram.org','t.me','web.telegram.org'],
  ['signal','signal.org'],
  ['zoom','zoom.us'],
  ['slack','slack.com'],
  ['dropbox','dropbox.com'],
  ['adobe','adobe.com','creativecloud.com'],
  ['salesforce','salesforce.com','force.com'],
  ['oracle','oracle.com'],
  ['ibm','ibm.com'],
  ['intel','intel.com'],
  ['nvidia','nvidia.com'],
  ['samsung','samsung.com'],
  ['huawei','huawei.com'],
  ['lenovo','lenovo.com'],
  ['dell','dell.com'],
  ['hp','hp.com'],
  ['cisco','cisco.com'],
  ['vmware','vmware.com'],
  ['atlassian','atlassian.com','jira.com','bitbucket.org','trello.com','confluence.com'],
  ['github','github.com','github.io','githubusercontent.com'],
  ['gitlab','gitlab.com'],
  ['docker','docker.com','hub.docker.com'],
  ['cloudflare','cloudflare.com'],
  ['digitalocean','digitalocean.com'],
  ['heroku','heroku.com'],
  ['vercel','vercel.com'],
  ['netlify','netlify.com','netlify.app'],
  ['godaddy','godaddy.com'],
  ['namecheap','namecheap.com'],
  ['wordpress','wordpress.com','wordpress.org','wp.com'],
  ['squarespace','squarespace.com'],
  ['wix','wix.com'],
  ['shopify','shopify.com','myshopify.com'],

  // ── Financial & Banking ──
  ['paypal','paypal.com','paypal.me'],
  ['stripe','stripe.com'],
  ['square','squareup.com','square.com','cash.app'],
  ['venmo','venmo.com'],
  ['wise','wise.com','transferwise.com'],
  ['revolut','revolut.com'],
  ['robinhood','robinhood.com'],
  ['coinbase','coinbase.com'],
  ['binance','binance.com','binance.us'],
  ['kraken','kraken.com'],
  ['chase','chase.com','jpmorganchase.com'],
  ['bankofamerica','bankofamerica.com','bofa.com'],
  ['wellsfargo','wellsfargo.com'],
  ['citibank','citibank.com','citi.com','citigroup.com'],
  ['capitalone','capitalone.com'],
  ['americanexpress','americanexpress.com','amex.com'],
  ['discover','discover.com'],
  ['usbank','usbank.com'],
  ['pnc','pnc.com'],
  ['tdbank','td.com','tdbank.com','tdameritrade.com'],
  ['hsbc','hsbc.com','hsbc.co.uk'],
  ['barclays','barclays.com','barclays.co.uk'],
  ['lloyds','lloydsbank.com'],
  ['natwest','natwest.com'],
  ['santander','santander.com','santander.co.uk'],
  ['bnpparibas','bnpparibas.com'],
  ['deutschebank','db.com','deutschebank.com'],
  ['ubs','ubs.com'],
  ['creditsuisse','credit-suisse.com'],
  ['goldmansachs','goldmansachs.com','gs.com'],
  ['morganstanley','morganstanley.com'],
  ['fidelity','fidelity.com'],
  ['schwab','schwab.com'],
  ['vanguard','vanguard.com'],
  ['etrade','etrade.com'],
  ['interactivebrokers','interactivebrokers.com'],
  ['visa','visa.com'],
  ['mastercard','mastercard.com'],
  ['klarna','klarna.com'],
  ['affirm','affirm.com'],
  ['zelle','zellepay.com'],
  ['ally','ally.com'],
  ['sofi','sofi.com'],
  ['chime','chime.com'],
  ['monzo','monzo.com'],
  ['n26','n26.com'],
  ['nubank','nubank.com.br'],

  // ── E-commerce & Retail ──
  ['ebay','ebay.com','ebay.co.uk','ebay.de'],
  ['walmart','walmart.com'],
  ['target','target.com'],
  ['bestbuy','bestbuy.com'],
  ['costco','costco.com'],
  ['homedepot','homedepot.com'],
  ['lowes','lowes.com'],
  ['macys','macys.com'],
  ['nordstrom','nordstrom.com'],
  ['nike','nike.com'],
  ['adidas','adidas.com'],
  ['zara','zara.com'],
  ['hm','hm.com'],
  ['uniqlo','uniqlo.com'],
  ['etsy','etsy.com'],
  ['wayfair','wayfair.com'],
  ['aliexpress','aliexpress.com'],
  ['alibaba','alibaba.com'],
  ['wish','wish.com'],
  ['temu','temu.com'],
  ['shein','shein.com'],
  ['ikea','ikea.com'],
  ['sephora','sephora.com'],
  ['ulta','ulta.com'],
  ['newegg','newegg.com'],

  // ── Gaming ──
  ['steam','steampowered.com','steamcommunity.com','store.steampowered.com'],
  ['discord','discord.com','discordapp.com','discord.gg'],
  ['epicgames','epicgames.com','fortnite.com','unrealengine.com'],
  ['riotgames','riotgames.com','leagueoflegends.com'],
  ['ea','ea.com','origin.com'],
  ['blizzard','blizzard.com','battle.net','battlenet.com'],
  ['ubisoft','ubisoft.com'],
  ['playstation','playstation.com','sonyentertainmentnetwork.com'],
  ['nintendo','nintendo.com','nintendo.co.jp'],
  ['roblox','roblox.com'],
  ['twitch','twitch.tv'],
  ['mojang','mojang.com','minecraft.net'],
  ['valve','valvesoftware.com'],

  // ── Streaming & Entertainment ──
  ['spotify','spotify.com'],
  ['hulu','hulu.com'],
  ['disneyplus','disneyplus.com','disney.com'],
  ['hbomax','hbomax.com','max.com'],
  ['peacock','peacocktv.com'],
  ['paramount','paramountplus.com'],
  ['crunchyroll','crunchyroll.com'],
  ['soundcloud','soundcloud.com'],
  ['deezer','deezer.com'],
  ['pandora','pandora.com'],
  ['applemusic','music.apple.com'],

  // ── Crypto & DeFi ──
  ['metamask','metamask.io'],
  ['phantom','phantom.app'],
  ['opensea','opensea.io'],
  ['uniswap','uniswap.org','app.uniswap.org'],
  ['ledger','ledger.com'],
  ['trezor','trezor.io'],
  ['blockchain','blockchain.com'],
  ['cryptocom','crypto.com'],
  ['gemini','gemini.com'],
  ['bitfinex','bitfinex.com'],
  ['kucoin','kucoin.com'],
  ['bybit','bybit.com'],
  ['okx','okx.com'],
  ['gate','gate.io'],
  ['trustwallet','trustwallet.com'],
  ['exodus','exodus.com'],
  ['etherscan','etherscan.io'],
  ['polygonscan','polygonscan.com'],
  ['solscan','solscan.io'],

  // ── Telecom & ISPs ──
  ['att','att.com'],
  ['verizon','verizon.com'],
  ['tmobile','t-mobile.com'],
  ['comcast','comcast.com','xfinity.com'],
  ['spectrum','spectrum.com'],
  ['sprint','sprint.com'],
  ['vodafone','vodafone.com','vodafone.co.uk'],
  ['orange','orange.com','orange.fr'],
  ['bt','bt.com'],
  ['ee','ee.co.uk'],
  ['three','three.co.uk'],
  ['telstra','telstra.com.au'],
  ['rogers','rogers.com'],
  ['bell','bell.ca'],

  // ── Travel & Airlines ──
  ['booking','booking.com'],
  ['airbnb','airbnb.com'],
  ['expedia','expedia.com'],
  ['tripadvisor','tripadvisor.com'],
  ['kayak','kayak.com'],
  ['delta','delta.com'],
  ['united','united.com'],
  ['americanairlines','aa.com','americanairlines.com'],
  ['southwest','southwest.com'],
  ['ryanair','ryanair.com'],
  ['easyjet','easyjet.com'],
  ['emirates','emirates.com'],
  ['lufthansa','lufthansa.com'],
  ['uber','uber.com'],
  ['lyft','lyft.com'],
  ['doordash','doordash.com'],
  ['grubhub','grubhub.com'],
  ['ubereats','ubereats.com'],
  ['instacart','instacart.com'],

  // ── Government & Services ──
  ['irs','irs.gov'],
  ['ssa','ssa.gov'],
  ['usps','usps.com'],
  ['fedex','fedex.com'],
  ['ups','ups.com'],
  ['dhl','dhl.com'],
  ['royalmail','royalmail.com'],
  ['hmrc','gov.uk'],
  ['nhs','nhs.uk'],
  ['medicare','medicare.gov'],

  // ── Security & Identity ──
  ['norton','norton.com','nortonlifelock.com'],
  ['mcafee','mcafee.com'],
  ['avast','avast.com'],
  ['kaspersky','kaspersky.com'],
  ['bitdefender','bitdefender.com'],
  ['malwarebytes','malwarebytes.com'],
  ['lastpass','lastpass.com'],
  ['onepassword','1password.com'],
  ['dashlane','dashlane.com'],
  ['bitwarden','bitwarden.com'],
  ['authy','authy.com'],
  ['duo','duo.com','duosecurity.com'],
  ['okta','okta.com'],
  ['auth0','auth0.com'],

  // ── News & Media ──
  ['cnn','cnn.com'],
  ['bbc','bbc.com','bbc.co.uk'],
  ['nytimes','nytimes.com'],
  ['washingtonpost','washingtonpost.com'],
  ['guardian','theguardian.com'],
  ['reuters','reuters.com'],
  ['bloomberg','bloomberg.com'],
  ['forbes','forbes.com'],
  ['wsj','wsj.com'],

  // ── Education ──
  ['coursera','coursera.org'],
  ['udemy','udemy.com'],
  ['edx','edx.org'],
  ['khanacademy','khanacademy.org'],
  ['duolingo','duolingo.com'],

  // ── Food & Delivery ──
  ['mcdonalds','mcdonalds.com'],
  ['starbucks','starbucks.com'],
  ['dominos','dominos.com'],
  ['pizzahut','pizzahut.com'],
  ['subway','subway.com'],
  ['chipotle','chipotle.com'],

  // ── Health & Insurance ──
  ['unitedhealth','uhc.com','unitedhealthgroup.com'],
  ['anthem','anthem.com'],
  ['aetna','aetna.com'],
  ['cigna','cigna.com'],
  ['humana','humana.com'],
  ['kaiser','kaiserpermanente.org'],
  ['cvs','cvs.com'],
  ['walgreens','walgreens.com'],

  // ── Automotive ──
  ['tesla','tesla.com'],
  ['ford','ford.com'],
  ['toyota','toyota.com'],
  ['bmw','bmw.com'],
  ['mercedes','mercedes-benz.com'],

  // ── Other High-Value Targets ──
  ['docusign','docusign.com','docusign.net'],
  ['intuit','intuit.com','turbotax.com','quickbooks.com','mint.com'],
  ['zendesk','zendesk.com'],
  ['hubspot','hubspot.com'],
  ['mailchimp','mailchimp.com'],
  ['sendgrid','sendgrid.com'],
  ['twilio','twilio.com'],
  ['notion','notion.so'],
  ['figma','figma.com'],
  ['canva','canva.com'],
  ['grammarly','grammarly.com'],
  ['evernote','evernote.com'],
  ['todoist','todoist.com'],
  ['asana','asana.com'],
  ['monday','monday.com'],
  ['airtable','airtable.com'],
  ['surveymonkey','surveymonkey.com'],
  ['typeform','typeform.com'],
  ['calendly','calendly.com'],
  ['loom','loom.com'],
  ['miro','miro.com'],
  ['intercom','intercom.com'],
  ['freshdesk','freshdesk.com'],
  ['protonmail','protonmail.com','proton.me'],
  ['tutanota','tutanota.com','tuta.com'],
  ['yahoo','yahoo.com','yahoo.co.jp','aol.com'],
  ['yandex','yandex.com','yandex.ru'],
  ['baidu','baidu.com'],
  ['tencent','tencent.com','qq.com','wechat.com'],
  ['rakuten','rakuten.com','rakuten.co.jp'],
  ['mercadolibre','mercadolibre.com','mercadolivre.com.br'],
  ['flipkart','flipkart.com'],
  ['paytm','paytm.com'],
  ['phonepe','phonepe.com'],
  ['gpay','pay.google.com'],
  ['line','line.me'],
  ['viber','viber.com'],
  ['weibo','weibo.com'],
  ['naver','naver.com'],
  ['kakao','kakao.com','kakaocorp.com']
];

// ── Precomputed Index ──────────────────────────────────────────────────────
// Build a flat lookup of all alias domains → brand index for O(1) legitimacy checks
var _brandAliasMap = null;

function getBrandAliasMap() {
  if (_brandAliasMap) return _brandAliasMap;
  _brandAliasMap = {};
  for (let i = 0; i < BRAND_REGISTRY.length; i++) {
    const entry = BRAND_REGISTRY[i];
    for (let d = 1; d < entry.length; d++) {
      _brandAliasMap[entry[d]] = i;
    }
  }
  return _brandAliasMap;
}

// ── Jaro-Winkler Similarity ────────────────────────────────────────────────
// Returns 0.0 (no match) to 1.0 (identical)
function jaroWinklerSimilarity(s1, s2) {
  if (s1 === s2) return 1.0;
  const len1 = s1.length;
  const len2 = s2.length;
  if (len1 === 0 || len2 === 0) return 0.0;

  const matchWindow = Math.max(0, Math.floor(Math.max(len1, len2) / 2) - 1);
  const s1Matches = new Array(len1).fill(false);
  const s2Matches = new Array(len2).fill(false);

  let matches = 0;
  let transpositions = 0;

  // Find matches
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0.0;

  // Count transpositions
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  const jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3;

  // Winkler prefix bonus (up to 4 chars)
  let prefixLen = 0;
  for (let i = 0; i < Math.min(4, Math.min(len1, len2)); i++) {
    if (s1[i] === s2[i]) prefixLen++;
    else break;
  }

  return jaro + prefixLen * 0.1 * (1 - jaro);
}

// ── Levenshtein (local copy for modularity) ────────────────────────────────
function brandLevenshtein(s1, s2) {
  if (s1.length < s2.length) return brandLevenshtein(s2, s1);
  if (s2.length === 0) return s1.length;
  let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      curr.push(Math.min(
        prev[j + 1] + 1,
        curr[j] + 1,
        prev[j] + (s1[i] !== s2[j] ? 1 : 0)
      ));
    }
    prev = curr;
  }
  return prev[prev.length - 1];
}

// ── Normalized Levenshtein (0.0 = identical, 1.0 = completely different) ───
function normalizedLevenshtein(s1, s2) {
  const maxLen = Math.max(s1.length, s2.length);
  if (maxLen === 0) return 0;
  return brandLevenshtein(s1, s2) / maxLen;
}

// ── Core Analysis Function ─────────────────────────────────────────────────
// Analyzes hostname against the brand registry
// Returns null if no suspicious match, or a result object with scoring signals
function analyzeBrandDistance(hostname) {
  if (!hostname || hostname.length < 3) return null;

  const aliasMap = getBrandAliasMap();

  // Extract the registrable domain (SLD) for comparison
  const parts = hostname.split('.');
  let sld = hostname; // second-level domain name only
  if (parts.length >= 2) {
    // Handle co.uk, com.br style TLDs
    const twoPartTLDs = ['co.uk','com.br','co.in','com.au','co.jp','co.kr','com.mx','org.uk','net.au','com.sg','com.hk','co.nz'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTLDs.includes(lastTwo) && parts.length >= 3) {
      sld = parts[parts.length - 3];
    } else {
      sld = parts[parts.length - 2];
    }
  }

  // Check if this is a legitimate domain (exact alias match)
  const rootDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const rootDomainLong = parts.length >= 3 ? parts.slice(-3).join('.') : rootDomain;

  if (aliasMap.hasOwnProperty(rootDomain) || aliasMap.hasOwnProperty(rootDomainLong) || aliasMap.hasOwnProperty(hostname)) {
    return null; // Legitimate brand domain — no alert
  }

  const sldLower = sld.toLowerCase();
  if (sldLower.length < 3) return null;

  let bestMatch = null;
  let bestComposite = 0;

  for (let i = 0; i < BRAND_REGISTRY.length; i++) {
    const entry = BRAND_REGISTRY[i];
    const brandName = entry[0];
    const brandDomain = entry[1];
    const brandSLD = brandDomain.split('.')[0];

    // Skip very short brand names to avoid false positives (e.g., 'hp', 'bt', 'ee')
    if (brandSLD.length <= 2) continue;

    // ── Phase 1: Quick reject — skip if length difference is too large
    const lenDiff = Math.abs(sldLower.length - brandSLD.length);
    if (lenDiff > 4) continue;

    // ── Phase 2: Compute distances
    const levDist = brandLevenshtein(sldLower, brandSLD);
    const normLev = normalizedLevenshtein(sldLower, brandSLD);
    const jwSim = jaroWinklerSimilarity(sldLower, brandSLD);

    // ── Phase 3: Adaptive threshold based on brand name length
    let maxAllowedDist = 1;
    if (brandSLD.length >= 10) maxAllowedDist = 3;
    else if (brandSLD.length >= 6) maxAllowedDist = 2;

    // Skip if Levenshtein is too far AND Jaro-Winkler similarity is too low
    if (levDist > maxAllowedDist && jwSim < 0.85) continue;

    // Skip exact matches (already handled by alias check above)
    if (levDist === 0) continue;

    // ── Phase 4: Composite scoring
    // Higher = more suspicious. Range: 0-100
    const levComponent = Math.max(0, 1 - normLev) * 50;  // 0-50 points from Levenshtein similarity
    const jwComponent = jwSim * 50;                       // 0-50 points from Jaro-Winkler
    let composite = (levComponent + jwComponent);

    // Bonus: if the hostname contains the brand name as a substring (e.g., "google-login.xyz")
    if (sldLower.includes(brandSLD) && sldLower !== brandSLD) {
      composite = Math.max(composite, 80);
    }

    // Bonus: brand name is a substring of the SLD (e.g., "micr0soft" contains "micr" from "microsoft")
    // Detect character substitution attacks (0→o, 1→l, 5→s, etc.)
    const deconfused = sldLower
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/8/g, 'b')
      .replace(/\$/g, 's')
      .replace(/@/g, 'a')
      .replace(/!/g, 'i');

    if (deconfused !== sldLower) {
      const deconfusedLev = brandLevenshtein(deconfused, brandSLD);
      const deconfusedJW = jaroWinklerSimilarity(deconfused, brandSLD);
      if (deconfusedLev < levDist || deconfusedJW > jwSim) {
        const dLevComp = Math.max(0, 1 - (deconfusedLev / Math.max(deconfused.length, brandSLD.length))) * 50;
        const dJwComp = deconfusedJW * 50;
        composite = Math.max(composite, dLevComp + dJwComp + 10); // +10 bonus for deliberate confusion
      }
    }

    // Scale to 0-100
    composite = Math.min(100, Math.round(composite));

    if (composite > bestComposite && composite >= 55) {
      bestComposite = composite;
      bestMatch = {
        brand: brandName,
        brandDomain: brandDomain,
        levenshteinDist: levDist,
        jaroWinklerSim: Math.round(jwSim * 1000) / 1000,
        compositeScore: composite,
        reason: null // Set below
      };
    }
  }

  if (!bestMatch) return null;

  // ── Generate explanation ───────────────────────────────────────────────
  const brand = bestMatch.brand.charAt(0).toUpperCase() + bestMatch.brand.slice(1);
  if (bestMatch.compositeScore >= 85) {
    bestMatch.reason = `Domain closely mimics ${brand} (${bestMatch.brandDomain}) — likely impersonation attempt`;
  } else if (bestMatch.compositeScore >= 70) {
    bestMatch.reason = `Domain resembles ${brand} (${bestMatch.brandDomain}) — possible brand spoofing`;
  } else {
    bestMatch.reason = `Domain has similarity to ${brand} (${bestMatch.brandDomain}) — verify legitimacy`;
  }

  return bestMatch;
}
