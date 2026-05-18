const SIGNAL_WEIGHTS = {
  typosquatting_distance_1: 25,
  typosquatting_distance_2: 12,
  typosquatting_embedded: 20,
  brand_in_path: 15,
  homoglyph_punycode: 30,
  homoglyph_cyrillic: 25,
  homoglyph_mixed_script: 20,
  suspicious_tld: 10,
  excessive_subdomains_4_plus: 8,
  excessive_subdomains_5_plus: 15,
  high_entropy_subdomain: 12,
  hex_digit_path: 10,
  suspicious_keywords_1: 8,
  suspicious_keywords_2: 15,
  suspicious_keywords_3_plus: 25,
  credentials_in_url: 35,
  ip_url: 20,
  ip_private: 5,
  suspicious_port: 10,
  excessive_redirects: 15,
  cross_domain_redirect: 10,
  shortened_url: 5,
  login_page_on_suspicious_domain: 20,
}

const VERDICT_RED_THRESHOLD = 60
const VERDICT_YELLOW_THRESHOLD = 25

const MAX_SINGLE_SIGNAL = 30

function determineVerdict(score) {
  if (score >= VERDICT_RED_THRESHOLD) return { verdict: 'red', safe: false }
  if (score >= VERDICT_YELLOW_THRESHOLD) return { verdict: 'yellow', safe: false }
  return { verdict: 'green', safe: true }
}

function determineConfidence(signals, score) {
  const signalCount = signals.length
  const strongSignals = signals.filter(s => s.weight >= 20).length
  const veryStrongSignals = signals.filter(s => s.weight >= 30).length
  if (score >= VERDICT_RED_THRESHOLD && (strongSignals >= 2 || veryStrongSignals >= 1)) return 'high'
  if (score >= VERDICT_YELLOW_THRESHOLD && signalCount >= 2) return 'medium'
  if (score >= VERDICT_YELLOW_THRESHOLD && signalCount >= 1) return 'low'
  return 'low'
}

function getThreatType(signals) {
  for (const s of signals) {
    if (s.type === 'homoglyph_punycode' || s.type === 'homoglyph_cyrillic') return 'Punycode Homograph Attack'
    if (s.type === 'typosquatting_distance_1') return 'Typosquatting Detected'
    if (s.type === 'credentials_in_url') return 'Credentials in URL'
    if (s.type === 'ip_url') return 'IP Address URL'
    if (s.type === 'excessive_redirects') return 'Excessive Redirect Chain'
    if (s.type === 'brand_in_path' || s.type === 'typosquatting_embedded') return 'Brand Impersonation'
  }
  const keywordSignals = signals.filter(s => s.type.startsWith('suspicious_keywords'))
  if (keywordSignals.length > 0 && keywordSignals.some(s => s.data?.count >= 2)) return 'Suspicious Keywords'
  if (signals.length >= 2) return 'Multiple Risk Factors'
  return null
}

const KEYWORD_TO_REASON_MAP = {
  'login': 'Suspicious login page detected',
  'signin': 'Suspicious sign-in detected',
  'verify': 'Suspicious verification request',
  'secure': 'Suspicious secure-login pattern',
  'password': 'Password reset page detected',
  'account': 'Account verification page detected',
  'wallet': 'Cryptocurrency wallet page detected',
  'claim': 'Claim/scam page detected',
  'bonus': 'Bonus/prize scam detected',
  'auth': 'Authentication page on suspicious domain',
  'recovery': 'Account recovery page detected',
  'billing': 'Suspicious billing page detected',
  'support': 'Fraudulent support page detected',
  'alert': 'Fake security alert detected',
  'confirm': 'Suspicious confirmation page',
  'payment': 'Suspicious payment page detected',
}

function buildReasons(signals) {
  const reasons = []
  for (const s of signals) {
    if (s.type === 'typosquatting_distance_1') {
      reasons.push(`Domain closely resembles ${s.data?.target} (Typosquatting)`)
    } else if (s.type === 'typosquatting_distance_2') {
      reasons.push(`Domain similar to ${s.data?.target}`)
    } else if (s.type === 'typosquatting_embedded') {
      reasons.push(`Domain contains embedded brand name "${s.data?.target}"`)
    } else if (s.type === 'brand_in_path') {
      reasons.push(`Brand "${s.data?.target}" found in URL path on different domain`)
    } else if (s.type === 'homoglyph_punycode') {
      reasons.push('CRITICAL: Punycode Homograph Attack Detected')
    } else if (s.type === 'homoglyph_cyrillic') {
      reasons.push('Deceptive Cyrillic characters detected in domain')
    } else if (s.type === 'homoglyph_mixed_script') {
      reasons.push('Mixed Latin and Cyrillic characters in domain')
    } else if (s.type === 'suspicious_tld') {
      reasons.push(`Suspicious TLD: ${s.data?.tld}`)
    } else if (s.type === 'excessive_subdomains') {
      reasons.push(`Excessive subdomain depth (${s.data?.count} levels)`)
    } else if (s.type === 'high_entropy_subdomain') {
      reasons.push('Random-looking subdomain pattern detected')
    } else if (s.type === 'hex_digit_path') {
      reasons.push('Suspicious encoded path segments detected')
    } else if (s.type.startsWith('suspicious_keywords')) {
      const kws = s.data?.keywords || []
      const mapped = kws.map(kw => KEYWORD_TO_REASON_MAP[kw] || `Suspicious keyword: ${kw}`)
      const unique = [...new Set(mapped)]
      reasons.push(...unique.slice(0, 3))
    } else if (s.type === 'credentials_in_url') {
      reasons.push('Credentials detected in URL')
    } else if (s.type === 'ip_url') {
      if (s.data?.private) {
        reasons.push('URL uses private IP address')
      } else {
        reasons.push('URL uses raw IP address instead of domain name')
      }
    } else if (s.type === 'suspicious_port') {
      reasons.push(`Unusual port detected (${s.data?.port})`)
    } else if (s.type === 'excessive_redirects') {
      reasons.push('Excessive redirect chain detected')
    } else if (s.type === 'cross_domain_redirect') {
      reasons.push('Cross-domain redirect detected')
    } else if (s.type === 'shortened_url') {
      reasons.push('URL shortened — final destination hidden')
    } else if (s.type === 'login_page_suspicious') {
      reasons.push('Login form detected on suspicious domain')
    }
  }
  return [...new Set(reasons)]
}
