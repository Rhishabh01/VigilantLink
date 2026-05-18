const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq',
  '.xyz', '.top', '.click', '.zip', '.work', '.country',
  '.download', '.review', '.trade', '.bid', '.win', '.men',
  '.date', '.loan', '.accountant', '.science',
  '.party', '.racing', '.faith', '.stream',
  '.ooo', '.online', '.site', '.live', '.space', '.website',
  '.cn.com', '.eu.org',
])

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon', 'auth',
  'verify', 'verification', 'verify-account', 'verify-email',
  'secure', 'security', 'secure-login', 'secur',
  'password', 'password-reset', 'reset-password', 'forgot-password',
  'account', 'account-update', 'update-account', 'account-verify',
  'recovery', 'recover', 'recover-account',
  'wallet', 'connect-wallet', 'claim', 'claim-reward',
  'bonus', 'free-money', 'free-bitcoin', 'free-gift',
  'prize', 'winner', 'congratulations', 'congrats',
  'update-password', 'change-password', 'confirm',
  'authenticate', 'authorize', '2fa', 'two-factor',
  'billing', 'invoice', 'payment', 'checkout',
  'support', 'help-desk', 'customer-service',
  'alert', 'notification', 'activity',
  'suspicious', 'unusual', 'blocked', 'limited',
  'restricted', 'locked', 'disabled',
]

const ENTROPY_THRESHOLDS = {
  subdomain_min_length: 12,
  subdomain_max_entropy: 3.5,
  path_min_hex_ratio: 0.4,
  path_min_digit_ratio: 0.5,
}

function detectSuspiciousTLD(domain) {
  if (!domain) return null
  const d = domain.toLowerCase()
  for (const tld of SUSPICIOUS_TLDS) {
    if (d.endsWith(tld)) {
      return tld
    }
  }
  return null
}

function detectExcessiveSubdomains(domain) {
  if (!domain) return 0
  const parts = domain.toLowerCase().split('.')
  if (parts.length <= 2) return 0
  const subdomainCount = parts.length - 2
  return subdomainCount
}

function shannonEntropy(str) {
  const len = str.length
  if (len === 0) return 0
  const freq = {}
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1
  }
  let entropy = 0
  for (const ch in freq) {
    const p = freq[ch] / len
    entropy -= p * (Math.log2(p) || 0)
  }
  return entropy
}

function detectHighEntropySubdomain(domain) {
  if (!domain) return false
  const parts = domain.toLowerCase().split('.')
  if (parts.length <= 2) return false
  const subdomain = parts.slice(0, -2).join('.')
  if (subdomain.length < ENTROPY_THRESHOLDS.subdomain_min_length) return false
  const entropy = shannonEntropy(subdomain)
  return entropy > ENTROPY_THRESHOLDS.subdomain_max_entropy
}

function detectHexOrDigitPath(path) {
  if (!path || path === '/' || path === '') return false
  const segments = path.split('/').filter(s => s.length > 0)
  let hexCount = 0
  let digitCount = 0
  for (const seg of segments) {
    if (/^[0-9a-f]{8,}$/i.test(seg)) hexCount++
    else if (/^\d{6,}$/.test(seg)) digitCount++
  }
  const total = segments.length
  if (total === 0) return false
  const hexRatio = hexCount / total
  const digitRatio = digitCount / total
  return hexRatio >= ENTROPY_THRESHOLDS.path_min_hex_ratio ||
         digitRatio >= ENTROPY_THRESHOLDS.path_min_digit_ratio
}

function detectSuspiciousKeywords(url, domain, path) {
  const lowerDomain = (domain || '').toLowerCase()
  const lowerPath = (path || '').toLowerCase()
  const found = []
  for (const kw of SUSPICIOUS_KEYWORDS) {
    const pattern = kw.replace(/-/g, '[.-]?')
    const regex = new RegExp(pattern, 'i')
    if (regex.test(lowerPath) || regex.test(lowerDomain)) {
      found.push(kw)
    }
  }
  return found
}

function detectCredentialsInURL(url) {
  if (!url) return false
  try {
    const parsed = new URL(url)
    return parsed.username !== '' || parsed.password !== ''
  } catch {
    return url.includes('@') && /[a-zA-Z0-9._%+-]+:[^@]+@/.test(url)
  }
}

function detectIPURL(url) {
  if (!url) return { isIP: false, isPrivate: false }
  try {
    const parsed = new URL(url)
    const hostname = parsed.hostname
    const ipMatch = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
    if (!ipMatch) return { isIP: false, isPrivate: false }
    const parts = ipMatch.slice(1).map(Number)
    if (parts.some(p => p > 255)) return { isIP: false, isPrivate: false }
    const isPrivate =
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 127) ||
      (parts[0] === 0) ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
    return { isIP: true, isPrivate, port: parsed.port }
  } catch {
    return { isIP: false, isPrivate: false }
  }
}

function detectSuspiciousPort(url) {
  if (!url) return false
  try {
    const parsed = new URL(url)
    if (!parsed.port) return false
    const port = parseInt(parsed.port, 10)
    const commonPorts = [80, 443, 8080, 8443]
    if (commonPorts.includes(port)) return false
    if (port === 21 || port === 22 || port === 23 || port === 25) return true
    if (port >= 1024 && port <= 49151) {
      const uncommon = [4444, 6666, 1337, 31337, 1234, 4321, 5555, 7777, 8888, 9999]
      return uncommon.includes(port)
    }
    return false
  } catch {
    return false
  }
}

function analyzeRedirects(hops) {
  if (!hops || hops.length <= 1) return { count: 0, crossDomain: false, excessive: false }
  const count = hops.length - 1
  let crossDomainCount = 0
  for (let i = 1; i < hops.length; i++) {
    try {
      const prevDomain = new URL(hops[i - 1].u || hops[i - 1].url).hostname
      const currDomain = new URL(hops[i].u || hops[i].url).hostname
      if (prevDomain !== currDomain) crossDomainCount++
    } catch {}
  }
  return {
    count,
    crossDomain: crossDomainCount > 0,
    crossDomainCount,
    excessive: count > 3,
  }
}

function detectURLShortener(domain) {
  if (!domain) return false
  const shorteners = new Set([
    'bit.ly', 'tinyurl.com', 'tiny.cc', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'shorturl.at', 'tr.im', 'rb.gy',
    's.id', 'cutt.ly', 'rebrand.ly', 'bl.ink', 'short.link',
    'shorte.st', 'bc.vc', 'adf.ly', 'u.to', 'curt.ly',
    'v.gd', 'cli.gs', 'zpr.io', 'soo.gd', 's2r.co',
    'link.tl', 'gg.gg', 'ro.tc', 'qrco.de', '1url.com',
  ])
  return shorteners.has(domain.toLowerCase())
}
