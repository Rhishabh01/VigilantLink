const LocalEngine = {
  analyze(url) {
    const startTime = performance.now()
    const result = this._analyzeURL(url)
    result.ms = Math.round(performance.now() - startTime)
    return result
  },

  _analyzeURL(url) {
    let parsed
    try {
      parsed = new URL(url)
    } catch {
      return this._buildError(url, 'Invalid URL')
    }

    const domain = parsed.hostname.toLowerCase()
    const path = parsed.pathname
    const signals = []

    const ipInfo = detectIPURL(url)
    if (ipInfo.isIP) {
      signals.push({
        type: 'ip_url',
        weight: SIGNAL_WEIGHTS.ip_url,
        data: { private: ipInfo.isPrivate },
      })
      if (ipInfo.isPrivate) {
        signals[signals.length - 1].weight = SIGNAL_WEIGHTS.ip_private
      }
      if (ipInfo.port && detectSuspiciousPort(url)) {
        signals.push({
          type: 'suspicious_port',
          weight: SIGNAL_WEIGHTS.suspicious_port,
          data: { port: ipInfo.port },
        })
      }
    } else {
      const suspiciousPort = detectSuspiciousPort(url)
      if (suspiciousPort) {
        signals.push({
          type: 'suspicious_port',
          weight: SIGNAL_WEIGHTS.suspicious_port,
          data: { port: parsed.port },
        })
      }
    }

    if (detectCredentialsInURL(url)) {
      signals.push({
        type: 'credentials_in_url',
        weight: SIGNAL_WEIGHTS.credentials_in_url,
        data: {},
      })
    }

    if (!ipInfo.isIP) {
      const parts = domain.split('.')
      const rootDomain = parts.length > 2
        ? parts.slice(-2).join('.')
        : domain

      const tld = detectSuspiciousTLD(domain)
      if (tld) {
        signals.push({
          type: 'suspicious_tld',
          weight: SIGNAL_WEIGHTS.suspicious_tld,
          data: { tld },
        })
      }

      const subdomainCount = detectExcessiveSubdomains(domain)
      if (subdomainCount >= 4) {
        signals.push({
          type: 'excessive_subdomains',
          weight: subdomainCount >= 5 ? SIGNAL_WEIGHTS.excessive_subdomains_5_plus : SIGNAL_WEIGHTS.excessive_subdomains_4_plus,
          data: { count: subdomainCount },
        })
      }

      if (detectHighEntropySubdomain(domain)) {
        signals.push({
          type: 'high_entropy_subdomain',
          weight: SIGNAL_WEIGHTS.high_entropy_subdomain,
          data: {},
        })
      }

      const pathAnomaly = detectHexOrDigitPath(path)
      if (pathAnomaly) {
        signals.push({
          type: 'hex_digit_path',
          weight: SIGNAL_WEIGHTS.hex_digit_path,
          data: {},
        })
      }

      const keywords = detectSuspiciousKeywords(url, domain, path)
      if (keywords.length > 0) {
        const count = keywords.length
        let weight = SIGNAL_WEIGHTS.suspicious_keywords_1
        if (count >= 3) weight = SIGNAL_WEIGHTS.suspicious_keywords_3_plus
        else if (count >= 2) weight = SIGNAL_WEIGHTS.suspicious_keywords_2
        signals.push({
          type: `suspicious_keywords_${count}`,
          weight,
          data: { keywords, count },
        })
      }

      const homoglyph = detectHomoglyph(domain)
      if (homoglyph.detected) {
        if (homoglyph.punycode) {
          signals.push({
            type: 'homoglyph_punycode',
            weight: SIGNAL_WEIGHTS.homoglyph_punycode,
            data: {},
          })
        } else if (homoglyph.cyrillic) {
          signals.push({
            type: 'homoglyph_cyrillic',
            weight: SIGNAL_WEIGHTS.homoglyph_cyrillic,
            data: {},
          })
        } else if (homoglyph.mixedScript) {
          signals.push({
            type: 'homoglyph_mixed_script',
            weight: SIGNAL_WEIGHTS.homoglyph_mixed_script,
            data: {},
          })
        }
      }

      const typosquatting = detectTyposquatting(domain, rootDomain)
      for (const t of typosquatting) {
        if (isTrustedDomain(domain) && t.type === 'similar') continue
        let type
        let weight
        if (t.type === 'typosquatting') {
          type = 'typosquatting_distance_1'
          weight = SIGNAL_WEIGHTS.typosquatting_distance_1
        } else if (t.type === 'similar') {
          type = 'typosquatting_distance_2'
          weight = SIGNAL_WEIGHTS.typosquatting_distance_2
        } else {
          type = 'typosquatting_embedded'
          weight = SIGNAL_WEIGHTS.typosquatting_embedded
        }
        signals.push({ type, weight, data: { target: t.target } })
      }

      const brandInPath = detectBrandInPath(domain, path)
      for (const b of brandInPath) {
        signals.push({
          type: 'brand_in_path',
          weight: SIGNAL_WEIGHTS.brand_in_path,
          data: { target: b.target },
        })
      }

      const isLogin = isLoginPage(path)
      const isTrusted = isTrustedDomain(domain)
      if (isLogin && !isTrusted && (keywords.length > 0 || typosquatting.length > 0)) {
        signals.push({
          type: 'login_page_suspicious',
          weight: SIGNAL_WEIGHTS.login_page_on_suspicious_domain,
          data: {},
        })
      }

      const shortened = detectURLShortener(domain)
      if (shortened) {
        signals.push({
          type: 'shortened_url',
          weight: SIGNAL_WEIGHTS.shortened_url,
          data: {},
        })
      }
    }

    const hasTrustedDomain = isTrustedDomain(domain)

    let rawScore = 0
    for (const s of signals) {
      rawScore += s.weight
    }

    if (hasTrustedDomain) {
      const trustedWeight = getTrustedWeight(domain)
      const effectiveSignals = signals.filter(s => {
        if (s.type === 'suspicious_tld') return false
        if (s.type.startsWith('suspicious_keywords') && s.data?.count <= 1) return false
        return true
      })
      if (effectiveSignals.length === 0) {
        rawScore = Math.max(0, rawScore - 40)
      } else {
        const strongSignals = signals.filter(s => s.weight >= 20)
        if (strongSignals.length === 0) {
          rawScore = Math.floor(rawScore * trustedWeight)
        }
      }
    }

    const cappedScore = Math.min(rawScore, 100)

    const { verdict, safe } = determineVerdict(cappedScore)
    const confidence = determineConfidence(signals, cappedScore)
    const threatType = getThreatType(signals)
    const reasons = buildReasons(signals)

    const suspiciousRedirects = signals.some(s => s.type === 'excessive_redirects')
    const typosquattingDetected = signals.some(s => s.type.startsWith('typosquatting'))

    return {
      s: 2,
      id: 'local_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      url,
      furl: url,
      hops: [],
      t: null,
      d: null,
      img: null,
      fav: null,
      ss: null,
      sec: {
        safe,
        v: verdict,
        rs: cappedScore,
        tt: threatType,
        age: null,
        sr: suspiciousRedirects,
        ts: typosquattingDetected,
        r: reasons,
        gsb: false,
        gsbt: null,
      },
      ms: 0,
      _signals: signals,
      _confidence: confidence,
    }
  },

  _buildError(url, errorMsg) {
    return {
      s: 2,
      id: 'error',
      url,
      furl: url,
      hops: [],
      t: null,
      d: null,
      img: null,
      fav: null,
      ss: null,
      sec: {
        safe: true,
        v: 'gray',
        rs: 0,
        tt: null,
        age: null,
        sr: false,
        ts: false,
        r: [errorMsg],
        gsb: false,
        gsbt: null,
      },
      ms: 0,
      _signals: [],
      _confidence: 'low',
    }
  },
}
