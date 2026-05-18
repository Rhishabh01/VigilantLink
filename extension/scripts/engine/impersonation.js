const IMPERSONATION_TARGETS = [
  { domain: 'google', label: 'Google', weight: 1.0 },
  { domain: 'gmail', label: 'Gmail', weight: 1.0 },
  { domain: 'youtube', label: 'YouTube', weight: 1.0 },
  { domain: 'facebook', label: 'Facebook', weight: 1.0 },
  { domain: 'instagram', label: 'Instagram', weight: 1.0 },
  { domain: 'twitter', label: 'Twitter', weight: 1.0 },
  { domain: 'linkedin', label: 'LinkedIn', weight: 1.0 },
  { domain: 'github', label: 'GitHub', weight: 1.0 },
  { domain: 'gitlab', label: 'GitLab', weight: 1.0 },
  { domain: 'bitbucket', label: 'Bitbucket', weight: 0.9 },
  { domain: 'microsoft', label: 'Microsoft', weight: 1.0 },
  { domain: 'outlook', label: 'Outlook', weight: 1.0 },
  { domain: 'office', label: 'Microsoft Office', weight: 1.0 },
  { domain: 'windows', label: 'Windows', weight: 0.9 },
  { domain: 'azure', label: 'Azure', weight: 0.8 },
  { domain: 'apple', label: 'Apple', weight: 1.0 },
  { domain: 'icloud', label: 'iCloud', weight: 1.0 },
  { domain: 'itunes', label: 'iTunes', weight: 0.8 },
  { domain: 'amazon', label: 'Amazon', weight: 1.0 },
  { domain: 'aws', label: 'AWS', weight: 1.0 },
  { domain: 'paypal', label: 'PayPal', weight: 1.0 },
  { domain: 'ebay', label: 'eBay', weight: 1.0 },
  { domain: 'netflix', label: 'Netflix', weight: 0.9 },
  { domain: 'spotify', label: 'Spotify', weight: 0.8 },
  { domain: 'twitch', label: 'Twitch', weight: 0.8 },
  { domain: 'discord', label: 'Discord', weight: 1.0 },
  { domain: 'steam', label: 'Steam', weight: 1.0 },
  { domain: 'steamcommunity', label: 'Steam Community', weight: 1.0 },
  { domain: 'reddit', label: 'Reddit', weight: 0.8 },
  { domain: 'dropbox', label: 'Dropbox', weight: 0.9 },
  { domain: 'adobe', label: 'Adobe', weight: 0.9 },
  { domain: 'zoom', label: 'Zoom', weight: 0.8 },
  { domain: 'whatsapp', label: 'WhatsApp', weight: 0.8 },
  { domain: 'telegram', label: 'Telegram', weight: 0.8 },
  { domain: 'bankofamerica', label: 'Bank of America', weight: 1.0 },
  { domain: 'chase', label: 'Chase', weight: 1.0 },
  { domain: 'wellsfargo', label: 'Wells Fargo', weight: 1.0 },
  { domain: 'citibank', label: 'Citibank', weight: 1.0 },
  { domain: 'hsbc', label: 'HSBC', weight: 1.0 },
  { domain: 'capitalone', label: 'Capital One', weight: 1.0 },
  { domain: 'amex', label: 'American Express', weight: 1.0 },
  { domain: 'discover', label: 'Discover', weight: 0.9 },
  { domain: 'epicgames', label: 'Epic Games', weight: 0.8 },
  { domain: 'notion', label: 'Notion', weight: 0.7 },
  { domain: 'medium', label: 'Medium', weight: 0.6 },
  { domain: 'atlassian', label: 'Atlassian', weight: 0.7 },
  { domain: 'trello', label: 'Trello', weight: 0.6 },
  { domain: 'slack', label: 'Slack', weight: 0.8 },
]

function levenshteinDistance(s1, s2) {
  const m = s1.length
  const n = s2.length
  if (m === 0) return n
  if (n === 0) return m
  if (m < n) return levenshteinDistance(s2, s1)
  let prev = new Array(n + 1)
  let curr = new Array(n + 1)
  for (let j = 0; j <= n; j++) prev[j] = j
  for (let i = 1; i <= m; i++) {
    curr[0] = i
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      )
    }
    ;[prev, curr] = [curr, prev]
  }
  return prev[n]
}

function detectTyposquatting(domain, rootDomain) {
  if (!domain || !rootDomain) return []
  const root = rootDomain.toLowerCase().replace(/\.com$/, '')
  const results = []
  for (const target of IMPERSONATION_TARGETS) {
    const td = target.domain.toLowerCase()
    if (root === td) continue
    if (root.includes(td) || td.includes(root)) {
      const larger = root.length >= td.length ? root : td
      const smaller = root.length < td.length ? root : td
      if (larger.includes(smaller) && larger.length - smaller.length <= 2) {
        results.push({
          target: target.label,
          distance: larger.length - smaller.length,
          type: 'embedded',
        })
        continue
      }
    }
    const dist = levenshteinDistance(root, td)
    if (dist === 1) {
      results.push({
        target: target.label,
        distance: 1,
        type: 'typosquatting',
      })
    } else if (dist === 2 && root.length >= 4 && td.length >= 4) {
      results.push({
        target: target.label,
        distance: 2,
        type: 'similar',
      })
    }
  }
  return results
}

function detectHomoglyph(domain) {
  if (!domain) return { detected: false, cyrillic: false, punycode: false, mixedScript: false }
  const d = domain.toLowerCase()
  const punycode = d.startsWith('xn--') || d.includes('.xn--')
  const cyrillic = /[а-яА-ЯёЁ]/u.test(domain)
  const latinLookalikes = /[аеорсухАЕОРСУХ]/u.test(domain)
  const hasLatin = /[a-z]/i.test(domain)
  const mixedScript = cyrillic && hasLatin
  return {
    detected: punycode || cyrillic || mixedScript,
    punycode,
    cyrillic: cyrillic && latinLookalikes,
    mixedScript,
  }
}

function detectBrandInPath(domain, path) {
  if (!path || !domain) return []
  const lowerPath = path.toLowerCase()
  const lowerDomain = domain.toLowerCase()
  const results = []
  for (const target of IMPERSONATION_TARGETS) {
    const td = target.domain.toLowerCase()
    if (lowerPath.includes(td) && !lowerDomain.includes(td)) {
      results.push({
        target: target.label,
        type: 'brand-in-path',
      })
    }
  }
  return results
}

function isLoginPage(path) {
  if (!path) return false
  const loginPatterns = [
    /\/login/i, /\/signin/i, /\/auth/i, /\/logon/i,
    /\/authenticate/i, /\/authorize/i, /\/oauth/i,
    /\/password/i, /\/2fa/i, /\/verify/i,
    /\/account\/login/i, /\/account\/signin/i,
  ]
  return loginPatterns.some(p => p.test(path))
}

function extractRootDomain(domain) {
  if (!domain) return ''
  const parts = domain.toLowerCase().split('.')
  if (parts.length <= 2) return domain
  return parts.slice(-2).join('.')
}
