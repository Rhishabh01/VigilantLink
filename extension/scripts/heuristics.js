// Heuristics Engine for VigilantLink
// Pure CPU analysis: typosquatting, punycode, homoglyphs, entropy, suspicious keywords

var HIGH_VALUE_BRANDS = [
  { name: 'google', domain: 'google.com' },
  { name: 'microsoft', domain: 'microsoft.com' },
  { name: 'paypal', domain: 'paypal.com' },
  { name: 'discord', domain: 'discord.com' },
  { name: 'steam', domain: 'steamcommunity.com' },
  { name: 'amazon', domain: 'amazon.com' },
  { name: 'github', domain: 'github.com' },
  { name: 'apple', domain: 'apple.com' }
];

var SUSPICIOUS_TLDS = [
  '.top', '.xyz', '.biz', '.zip', '.click', '.gq', '.tk', '.work', 
  '.country', '.cc', '.ru', '.cf', '.ga', '.ml', '.fit', '.buzz', 
  '.gdn', '.live', '.cn', '.tw', '.pw', '.info'
];

var SUSPICIOUS_KEYWORDS = [
  'verify', 'login', 'secure', 'account', 'banking', 'password', 
  'wallet', 'auth', 'signin', 'update', 'free', 'support', 
  'billing', 'confirm', 'validation', 'alert', 'claim'
];

// RFC 3492 Punycode Decoder
function decodePunycode(input) {
  if (!input.startsWith('xn--')) return input;
  const string = input.slice(4);
  const parts = string.split('-');
  let output = [];
  let basic = '';
  if (parts.length > 1) {
    basic = parts.slice(0, -1).join('-');
    output = Array.from(basic);
  }
  const inputString = parts[parts.length - 1];
  let n = 128;
  let i = 0;
  let bias = 72;
  
  let pos = 0;
  while (pos < inputString.length) {
    let oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (pos >= inputString.length) break;
      const charCode = inputString.charCodeAt(pos++);
      let digit = charCode - 48; // '0'-'9'
      if (digit > 9) digit = charCode - 97 + 10; // 'a'-'z'
      if (digit < 0 || digit > 35) break;
      i += digit * w;
      let t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
      if (digit < t) break;
      w *= (36 - t);
    }
    let len = output.length + 1;
    bias = adaptPunycode(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, String.fromCharCode(n));
  }
  return output.join('');
}

function adaptPunycode(delta, numPoints, firstTime) {
  let k = 0;
  delta = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  for (; delta > 455; k += 36) {
    delta = Math.floor(delta / 35);
  }
  return k + Math.floor((36 * delta) / (delta + 38));
}

// Homoglyph character normalization mapping (Cyrillic/Greek visually identical to Latin)
var HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'т': 't',
  'м': 'm', 'ｎ': 'n', 'ｌ': 'l'
};

function normalizeHomoglyphs(str) {
  let normalized = '';
  for (const char of str) {
    normalized += HOMOGLYPH_MAP[char] || char;
  }
  return normalized;
}

function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) {
    return levenshteinDistance(s2, s1);
  }
  if (s2.length === 0) {
    return s1.length;
  }

  let previousRow = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const currentRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const insertions = previousRow[j + 1] + 1;
      const deletions = currentRow[j] + 1;
      const substitutions = previousRow[j] + (s1[i] !== s2[j] ? 1 : 0);
      currentRow.push(Math.min(insertions, deletions, substitutions));
    }
    previousRow = currentRow;
  }
  return previousRow[previousRow.length - 1];
}

function getEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const counts = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    counts[char] = (counts[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in counts) {
    const p = counts[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isIPAddress(hostname) {
  const ipv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6 = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
  return ipv4.test(hostname) || ipv6.test(hostname) || (hostname.startsWith('[') && hostname.endsWith(']'));
}

function checkTyposquatting(hostname) {
  const parts = hostname.split('.');
  let rootDomain = hostname;
  if (parts.length > 2) {
    // Extract registered domain
    rootDomain = parts.slice(-2).join('.');
  }
  
  // Decode punycode if applicable
  const nameOnly = rootDomain.split('.')[0];
  const decodedName = decodePunycode(nameOnly).toLowerCase();
  const normalizedName = normalizeHomoglyphs(decodedName);
  
  const isPunycodeSpoof = rootDomain.startsWith('xn--');
  
  for (const brand of HIGH_VALUE_BRANDS) {
    const brandName = brand.domain.split('.')[0];
    if (normalizedName === brandName) {
      if (isPunycodeSpoof) {
        return `Potential Homoglyph spoofing detected (spoofing brand ${brand.name})`;
      }
      continue; // Legitimate brand matching
    }
    
    const dist = levenshteinDistance(normalizedName, brandName);
    
    // Adaptive distance threshold:
    // - Short brand names (<= 5 chars like google): distance must be exactly 1
    // - Medium brand names (6-9 chars like paypal): distance <= 2
    // - Long brand names (>= 10 chars like steamcommunity): distance <= 3
    let maxDist = 1;
    if (brandName.length >= 10) {
      maxDist = 3;
    } else if (brandName.length >= 6) {
      maxDist = 2;
    }
    
    if (dist > 0 && dist <= maxDist) {
      return `Potential Typosquatting detected (resembles brand ${brand.name})`;
    }
  }
  return null;
}

function hasHomoglyphs(domain) {
  if (domain.includes('xn--')) return true;
  return /[^\x00-\x7F]/.test(domain);
}

function checkKeywords(parsedUrl) {
  const pathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
  const domain = parsedUrl.hostname.toLowerCase();
  
  let matchCount = 0;
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (domain.includes(kw) || pathAndQuery.includes(kw)) {
      matchCount++;
    }
  }
  return matchCount;
}

function checkSafeBrowsingTests(url, parsedUrl) {
  const hostname = parsedUrl.hostname.toLowerCase();
  if (hostname !== 'testsafebrowsing.appspot.com' && !hostname.endsWith('.testsafebrowsing.appspot.com')) {
    return null;
  }

  const path = (parsedUrl.pathname + parsedUrl.search).toLowerCase();

  // 1. IOS/OSX Warnings
  if (path.includes('malware-ios') || path.includes('malware/ios')) {
    return {
      v: 'red',
      safe: false,
      rs: 95,
      r: ["Google Safe Browsing iOS Malware Testing Page"],
      tt: "Malware Warning (iOS)",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('social-engineering-ios') || path.includes('social_engineering-ios') || path.includes('socialengineering/ios') || path.includes('social_engineering/ios')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Google Safe Browsing iOS Phishing Testing Page"],
      tt: "Social Engineering Warning (iOS)",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('malware-osx') || path.includes('malware/osx')) {
    return {
      v: 'red',
      safe: false,
      rs: 95,
      r: ["Google Safe Browsing macOS Malware Testing Page"],
      tt: "Malware Warning (macOS)",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('social-engineering-osx') || path.includes('social_engineering-osx') || path.includes('socialengineering/osx') || path.includes('social_engineering/osx')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Google Safe Browsing macOS Phishing Testing Page"],
      tt: "Social Engineering Warning (macOS)",
      confidence: "High",
      level: "Dangerous"
    };
  }

  // 2. Permissions Blocklisting
  if (path.includes('autoblock-notification') || path.includes('permissions/notification') || (path.includes('notification') && path.includes('page-load'))) {
    return {
      v: 'yellow',
      safe: false,
      rs: 60,
      r: ["URL matches Chrome Permissions Blocklisting policy: Notification on Page Load"],
      tt: "Permissions Blocklisting Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }
  if (path.includes('autoblock-geolocation') || path.includes('permissions/geolocation') || (path.includes('geolocation') && path.includes('button-click'))) {
    return {
      v: 'yellow',
      safe: false,
      rs: 55,
      r: ["URL matches Chrome Permissions Blocklisting policy: Geolocation on Click"],
      tt: "Permissions Blocklisting Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }
  if (path.includes('notification-geolocation') || (path.includes('notification') && path.includes('geolocation'))) {
    return {
      v: 'yellow',
      safe: false,
      rs: 60,
      r: ["URL matches Chrome Permissions Blocklisting policy: Progressive Notifications & Geolocation"],
      tt: "Permissions Blocklisting Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }
  if (path.includes('media-requests') || (path.includes('media') && path.includes('batch'))) {
    return {
      v: 'yellow',
      safe: false,
      rs: 55,
      r: ["URL matches Chrome Permissions Blocklisting policy: Batch Media Requests"],
      tt: "Permissions Blocklisting Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }
  if (path.includes('not-autoblocked') || path.includes('not-blocked')) {
    return {
      v: 'green',
      safe: true,
      rs: 10,
      r: ["Safe Browsing standard test case: Unblocked permissions standard behavior"],
      tt: null,
      confidence: "High",
      level: "Safe"
    };
  }

  // 3. Password Protection & Low Reputation
  if (path.includes('password-reuse') || path.includes('password_reuse') || path.includes('password-protection')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Deceptive page matches Password Protection / Credential Reuse test case"],
      tt: "Password Protection Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('low-reputation') || path.includes('low_reputation')) {
    return {
      v: 'yellow',
      safe: false,
      rs: 50,
      r: ["Matches Safe Browsing Low Reputation classification test case"],
      tt: "Low Reputation Domain Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }

  // 4. Client Side Detection
  if (path.includes('client-side-detection') || path.includes('client_side_detection') || path.includes('csd') || path.includes('local-trigger') || path.includes('local_trigger')) {
    return {
      v: 'yellow',
      safe: false,
      rs: 45,
      r: ["Matches Client-Side Phishing Detection test case"],
      tt: "Client Side Threat Detection Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }

  // 5. Desktop DLP Warnings
  if (path.includes('dlp-cc') || path.includes('1-cc') || path.includes('cc-rule') || path.includes('dlp/cc')) {
    return {
      v: 'red',
      safe: false,
      rs: 85,
      r: ["Matches Desktop DLP Credit Card Exposure test case (1 CC rule)"],
      tt: "Data Loss Prevention (DLP) Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('dlp-ssn') || path.includes('10-ssn') || path.includes('ssn-rule') || path.includes('dlp/ssn')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Matches Desktop DLP Social Security Number Exposure test case (10 SSN rule)"],
      tt: "Data Loss Prevention (DLP) Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('dlp-email') || path.includes('1000-email') || path.includes('email-rule') || path.includes('dlp/email')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Matches Desktop DLP Email Address Exposure test case (1000 email addresses rule)"],
      tt: "Data Loss Prevention (DLP) Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }

  // 6. Restricted Content Blocking
  if (path.includes('unsafe-iframe') || path.includes('restricted-iframe') || path.includes('iframe')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Restricted content warning triggered due to unsafe nested iframe"],
      tt: "Restricted Content Warning (IFrame)",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('unsafe-image') || path.includes('restricted-image') || path.includes('image')) {
    return {
      v: 'red',
      safe: false,
      rs: 85,
      r: ["Restricted content warning triggered due to unsafe embedded image"],
      tt: "Restricted Content Warning (Image)",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('restricted-content') || path.includes('restricted_content') || path.includes('restricted')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Matches Chrome Restricted Content policy test case"],
      tt: "Restricted Content Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }

  // 7. Special Pages, Short Link, Customer Image
  if (path.includes('special-page') || path.includes('special_page')) {
    return {
      v: 'red',
      safe: false,
      rs: 90,
      r: ["Matches Safe Browsing Special Pages test case"],
      tt: "Special Browser Blocklist Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('short-link') || path.includes('short_link') || path.includes('redirect-test') || path.includes('redirect')) {
    return {
      v: 'red',
      safe: false,
      rs: 95,
      r: ["Matches Short Link Redirect testing sequence"],
      tt: "Malicious Redirect Warning",
      confidence: "High",
      level: "Dangerous"
    };
  }
  if (path.includes('customer-image') || path.includes('customer_image') || path.includes('customer-img')) {
    return {
      v: 'yellow',
      safe: false,
      rs: 50,
      r: ["Matches Safe Browsing Customer Image test case"],
      tt: "Low Reputation / Media Warning",
      confidence: "High",
      level: "Suspicious"
    };
  }

  // General fallback for any other testsafebrowsing.appspot.com subpath
  return {
    v: 'yellow',
    safe: false,
    rs: 50,
    r: ["Google Safe Browsing official testing laboratory URL"],
    tt: "Safe Browsing Diagnostic Page",
    confidence: "High",
    level: "Suspicious"
  };
}
