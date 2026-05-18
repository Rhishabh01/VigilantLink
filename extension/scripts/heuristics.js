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
