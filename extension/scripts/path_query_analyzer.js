// Path & Query Parameter Analysis Engine for VigilantLink
// Scores URL paths and query strings for phishing indicators
// Zero dependencies, pure JS, MV3 compatible

// ── High-Risk Path Segments ────────────────────────────────────────────────
// Weighted by severity: critical auth flows score higher than generic ones
var PATH_SEGMENTS = {
  // Critical auth/credential paths (weight: 3)
  'login': 3, 'signin': 3, 'sign-in': 3, 'sign_in': 3,
  'password': 3, 'passwd': 3, 'credential': 3,
  '2fa': 3, 'otp': 3, 'mfa': 3, 'totp': 3,

  // Account manipulation (weight: 2)
  'verify': 2, 'verification': 2, 'validate': 2, 'validation': 2,
  'confirm': 2, 'confirmation': 2, 'authenticate': 2, 'auth': 2,
  'recover': 2, 'recovery': 2, 'reset': 2, 'restore': 2,
  'suspended': 2, 'locked': 2, 'restricted': 2, 'disabled': 2,
  'checkpoint': 2, 'challenge': 2, 'reauth': 2,

  // Financial (weight: 2)
  'billing': 2, 'payment': 2, 'invoice': 2, 'pay': 2,
  'wallet': 2, 'withdraw': 2, 'transfer': 2, 'payout': 2,

  // Generic suspicious (weight: 1)
  'account': 1, 'secure': 1, 'security': 1, 'update': 1,
  'profile': 1, 'settings': 1, 'preferences': 1,
  'claim': 1, 'reward': 1, 'prize': 1, 'offer': 1,
  'alert': 1, 'warning': 1, 'urgent': 1, 'action': 1,
  'support': 1, 'help': 1, 'service': 1
};

// ── Suspicious Query Parameter Keys ────────────────────────────────────────
var SUSPICIOUS_PARAMS = {
  // Redirect-related (high risk for open redirect)
  'redirect': 3, 'redirect_uri': 3, 'redirect_url': 3, 'redirecturi': 3,
  'next': 2, 'return': 2, 'returnurl': 3, 'return_url': 3, 'returnto': 2,
  'goto': 2, 'continue': 2, 'dest': 2, 'destination': 2, 'url': 2, 'uri': 2,
  'callback': 2, 'callback_url': 3, 'redir': 2, 'forward': 2,

  // Credential / identity (high risk for phishing)
  'email': 2, 'user': 2, 'username': 2, 'login': 2,
  'password': 3, 'pass': 3, 'passwd': 3, 'pwd': 3,
  'ssn': 3, 'credit_card': 3, 'cc': 2, 'cvv': 3,

  // Session / token (moderate risk)
  'token': 2, 'session': 2, 'sessionid': 2, 'sid': 1,
  'auth': 2, 'auth_token': 2, 'access_token': 2, 'api_key': 2,
  'key': 1, 'code': 1, 'verify': 2, 'ref': 1, 'id': 1,
  'otp': 2, 'pin': 2, 'confirmation_code': 2
};

// ── Phishing Path Chain Patterns ───────────────────────────────────────────
// Sequences of segments that mimic real auth flows
var CHAIN_PATTERNS = [
  ['account', 'login'],
  ['account', 'verify'],
  ['account', 'security'],
  ['login', 'verify'],
  ['login', 'confirm'],
  ['signin', 'verify'],
  ['signin', 'checkpoint'],
  ['verify', 'confirm'],
  ['password', 'reset'],
  ['password', 'recover'],
  ['security', 'checkpoint'],
  ['billing', 'payment'],
  ['account', 'suspended'],
  ['account', 'locked'],
  ['auth', '2fa'],
  ['login', '2fa'],
  ['signin', '2fa'],
  ['account', 'login', 'verify'],
  ['signin', 'verify', 'confirm'],
  ['account', 'security', 'verify']
];

// ── Base64 Detection Regex ─────────────────────────────────────────────────
var BASE64_PATTERN = /^[A-Za-z0-9+/]{20,}={0,2}$/;
var URL_SAFE_BASE64_PATTERN = /^[A-Za-z0-9_-]{20,}$/;

// ── Core Analysis Function ─────────────────────────────────────────────────
function analyzePathAndQuery(url, existingFlags) {
  existingFlags = existingFlags || [];

  var result = {
    score: 0,
    flags: [],
    explanations: []
  };

  var parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PATH ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════════
  var pathname = decodeURIComponent(parsed.pathname || '/').toLowerCase();
  var pathSegments = pathname.split('/').filter(function(s) { return s.length > 0; });

  var matchedSegments = [];
  var totalPathWeight = 0;

  for (var i = 0; i < pathSegments.length; i++) {
    var seg = pathSegments[i];
    // Check each segment against the high-risk list
    // Also check for segments that contain the keyword (e.g., "login-page", "verify_account")
    for (var keyword in PATH_SEGMENTS) {
      if (seg === keyword || seg.indexOf(keyword) !== -1) {
        var weight = PATH_SEGMENTS[keyword];
        // Depth bonus: deeper paths are more suspicious (attackers pad paths)
        var depthMultiplier = i >= 3 ? 1.3 : (i >= 2 ? 1.1 : 1.0);
        totalPathWeight += weight * depthMultiplier;
        if (matchedSegments.indexOf(keyword) === -1) {
          matchedSegments.push(keyword);
        }
        break; // One match per segment to avoid over-counting
      }
    }
  }

  // Score path segment matches
  if (matchedSegments.length >= 3) {
    result.score += Math.min(25, Math.round(totalPathWeight * 3));
    result.flags.push('PATH_CHAIN');
    result.explanations.push('URL path chains multiple security-sensitive segments (' + matchedSegments.length + ' matches: /' + matchedSegments.join('/') + ')');
  } else if (matchedSegments.length === 2) {
    result.score += Math.min(15, Math.round(totalPathWeight * 2));
    result.flags.push('SUSPICIOUS_PATH');
    result.explanations.push('URL path contains suspicious segment combination (/' + matchedSegments.join('/') + ')');
  } else if (matchedSegments.length === 1 && totalPathWeight >= 2) {
    result.score += Math.min(8, Math.round(totalPathWeight * 1.5));
    result.flags.push('SUSPICIOUS_PATH');
    // Only explain high-weight single segments to avoid noise on benign /account pages
    if (totalPathWeight >= 3) {
      result.explanations.push('URL path contains sensitive segment (/' + matchedSegments[0] + ')');
    }
  }

  // Check for auth flow chain patterns
  var chainMatched = false;
  for (var c = 0; c < CHAIN_PATTERNS.length; c++) {
    var chain = CHAIN_PATTERNS[c];
    if (matchesChain(pathSegments, chain)) {
      chainMatched = true;
      break;
    }
  }
  if (chainMatched) {
    result.score += 10;
    if (result.flags.indexOf('PATH_CHAIN') === -1) {
      result.flags.push('PATH_CHAIN');
    }
    result.explanations.push('URL mimics multi-step authentication flow');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // QUERY PARAMETER ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════════
  var queryString = parsed.search || '';
  if (queryString.startsWith('?')) queryString = queryString.substring(1);
  if (!queryString && parsed.hash) {
    // Some phishing uses fragment-based params (e.g., #email=victim@...)
    var hashQuery = parsed.hash.substring(1);
    if (hashQuery.indexOf('=') !== -1) {
      queryString = hashQuery;
    }
  }

  if (queryString) {
    var params = parseQueryParams(queryString);
    var suspiciousParamKeys = [];
    var suspiciousParamWeight = 0;
    var credentialParams = [];
    var redirectParams = [];
    var encodedValues = [];

    for (var p = 0; p < params.length; p++) {
      var key = params[p].key;
      var value = params[p].value;

      // Check for suspicious parameter keys
      if (SUSPICIOUS_PARAMS.hasOwnProperty(key)) {
        suspiciousParamKeys.push(key);
        suspiciousParamWeight += SUSPICIOUS_PARAMS[key];

        // Categorize
        if (key === 'password' || key === 'pass' || key === 'passwd' || key === 'pwd' ||
            key === 'email' || key === 'user' || key === 'username' || key === 'login' ||
            key === 'ssn' || key === 'credit_card' || key === 'cc' || key === 'cvv') {
          credentialParams.push(key);
        }
        if (key === 'redirect' || key === 'redirect_uri' || key === 'redirect_url' || key === 'redirecturi' ||
            key === 'next' || key === 'return' || key === 'returnurl' || key === 'return_url' || key === 'returnto' ||
            key === 'goto' || key === 'continue' || key === 'dest' || key === 'destination' ||
            key === 'url' || key === 'uri' || key === 'callback' || key === 'callback_url' ||
            key === 'redir' || key === 'forward') {
          redirectParams.push(key);
        }
      }

      // Check for open redirect indicators in values
      if (value && isOpenRedirectValue(value)) {
        result.score += 15;
        result.flags.push('OPEN_REDIRECT');
        result.explanations.push('Query parameter "' + key + '" contains an external redirect URL');
      }

      // Check for base64-encoded values
      if (value && value.length >= 20 && (BASE64_PATTERN.test(value) || URL_SAFE_BASE64_PATTERN.test(value))) {
        encodedValues.push(key);
      }
    }

    // Score suspicious parameter keys
    if (suspiciousParamKeys.length >= 3) {
      result.score += Math.min(20, Math.round(suspiciousParamWeight * 2));
      result.flags.push('SUSPICIOUS_PARAMS');
      result.explanations.push('URL contains multiple suspicious parameters (' + suspiciousParamKeys.join(', ') + ')');
    } else if (suspiciousParamKeys.length >= 1 && suspiciousParamWeight >= 4) {
      result.score += Math.min(12, Math.round(suspiciousParamWeight * 1.5));
      result.flags.push('SUSPICIOUS_PARAMS');
    }

    // Credential stuffing detection
    if (credentialParams.length >= 2) {
      result.score += 20;
      result.flags.push('CREDENTIAL_PARAMS');
      result.explanations.push('URL contains multiple credential-like parameters (' + credentialParams.join(', ') + ')');
    } else if (credentialParams.length === 1) {
      // Single credential param is suspicious but lower confidence
      var credKey = credentialParams[0];
      if (credKey === 'password' || credKey === 'pass' || credKey === 'passwd' || credKey === 'pwd' ||
          credKey === 'ssn' || credKey === 'credit_card' || credKey === 'cvv') {
        result.score += 12;
        result.flags.push('CREDENTIAL_PARAMS');
        result.explanations.push('URL contains sensitive credential parameter (' + credKey + ')');
      }
    }

    // Base64-encoded value detection
    if (encodedValues.length >= 1) {
      result.score += 8;
      result.flags.push('ENCODED_VALUES');
      result.explanations.push('URL contains obfuscated/encoded parameter values');
    }

    // ═════════════════════════════════════════════════════════════════════════
    // COMBINATION BONUSES — path + query synergy
    // ═════════════════════════════════════════════════════════════════════════
    if (matchedSegments.length > 0 && suspiciousParamKeys.length > 0) {
      // Path segments + suspicious params compound the risk
      var synergyBonus = Math.min(15, matchedSegments.length * suspiciousParamKeys.length * 3);
      result.score += synergyBonus;
      if (result.flags.indexOf('PATH_QUERY_SYNERGY') === -1) {
        result.flags.push('PATH_QUERY_SYNERGY');
      }
    }

    // Login path + redirect param = classic phishing pattern
    if (matchedSegments.length > 0 && redirectParams.length > 0) {
      var hasAuthPath = matchedSegments.some(function(s) {
        return s === 'login' || s === 'signin' || s === 'sign-in' || s === 'auth' || s === 'authenticate';
      });
      if (hasAuthPath) {
        result.score += 10;
        result.flags.push('AUTH_REDIRECT_COMBO');
        result.explanations.push('Login path combined with redirect parameter — classic phishing pattern');
      }
    }

    // Credential params in login path = very high risk
    if (matchedSegments.length > 0 && credentialParams.length > 0) {
      result.score += 8;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ANTI-DOUBLE-COUNTING — reduce if signals overlap with existing flags
  // ═══════════════════════════════════════════════════════════════════════════
  if (existingFlags.length > 0) {
    var overlapCount = 0;
    // If typosquatting/impersonation already caught, path keywords are partially redundant
    if (existingFlags.indexOf('typosquatting') !== -1 || existingFlags.indexOf('impersonation') !== -1) {
      if (result.flags.indexOf('SUSPICIOUS_PATH') !== -1 && matchedSegments.length <= 1) {
        overlapCount++;
      }
    }
    // If keywords already caught in heuristics, reduce path keyword penalty
    if (existingFlags.indexOf('keywords') !== -1) {
      overlapCount++;
    }
    if (overlapCount > 0) {
      result.score = Math.round(result.score * (1 - overlapCount * 0.25));
    }
  }

  // Clamp total score
  result.score = Math.min(60, Math.max(0, result.score));

  return result;
}

// ── Helper: Check if path segments match a chain pattern ───────────────────
function matchesChain(pathSegments, chain) {
  var chainIdx = 0;
  for (var i = 0; i < pathSegments.length && chainIdx < chain.length; i++) {
    if (pathSegments[i].indexOf(chain[chainIdx]) !== -1) {
      chainIdx++;
    }
  }
  return chainIdx === chain.length;
}

// ── Helper: Parse query string into [{key, value}] ────────────────────────
function parseQueryParams(queryString) {
  var result = [];
  var pairs = queryString.split('&');
  for (var i = 0; i < pairs.length; i++) {
    var eqIdx = pairs[i].indexOf('=');
    var key, value;
    if (eqIdx === -1) {
      key = pairs[i].toLowerCase();
      value = '';
    } else {
      key = pairs[i].substring(0, eqIdx).toLowerCase();
      value = pairs[i].substring(eqIdx + 1);
    }
    try {
      key = decodeURIComponent(key);
      value = decodeURIComponent(value);
    } catch (e) {
      // Malformed encoding — leave as-is
    }
    if (key) {
      result.push({ key: key, value: value });
    }
  }
  return result;
}

// ── Helper: Detect open redirect values ────────────────────────────────────
function isOpenRedirectValue(value) {
  if (!value || value.length < 4) return false;

  var decoded = value;
  // Try double-decoding for evasion attempts (%252F%252F)
  try {
    decoded = decodeURIComponent(value);
    decoded = decodeURIComponent(decoded);
  } catch (e) {
    // Use what we have
  }

  var lower = decoded.toLowerCase().trim();

  // Direct URL
  if (lower.startsWith('http://') || lower.startsWith('https://')) return true;

  // Protocol-relative URL
  if (lower.startsWith('//')) return true;

  // Encoded slashes (%2F%2F or %2f%2f)
  if (lower.indexOf('%2f%2f') !== -1 || lower.indexOf('%2F%2F') !== -1) return true;

  // Backslash evasion (\\example.com)
  if (lower.startsWith('\\\\') || lower.startsWith('\\/')) return true;

  // Data URI
  if (lower.startsWith('data:')) return true;

  // JavaScript URI
  if (lower.startsWith('javascript:')) return true;

  return false;
}
