const GSB = {
  _cache: new Map(),
  _cacheTTL: 5 * 60 * 1000,
  _timeout: 5000,

  async check(url) {
    const cached = this._getCached(url)
    if (cached !== undefined) return cached

    const apiKey = await this._getApiKey()
    if (!apiKey) return null

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), this._timeout)

    try {
      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'vigilantlink', clientVersion: '1.0.0' },
            threatInfo: {
              threatTypes: [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
              ],
              platformTypes: ['ALL_PLATFORMS'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }],
            },
          }),
          signal: controller.signal,
        }
      )

      if (!response.ok) {
        this._setCache(url, null)
        return null
      }

      const data = await response.json()
      let result = null
      if (data.matches && data.matches.length > 0) {
        result = { threat: true, threatType: data.matches[0].threatType }
      } else {
        result = { threat: false, threatType: null }
      }
      this._setCache(url, result)
      return result
    } catch (e) {
      if (e.name !== 'AbortError') {
        this._setCache(url, null)
      }
      return null
    } finally {
      clearTimeout(timeout)
    }
  },

  clearCache() {
    this._cache.clear()
  },

  _getCached(url) {
    const key = url.toLowerCase()
    const entry = this._cache.get(key)
    if (!entry) return undefined
    if (Date.now() - entry.time > this._cacheTTL) {
      this._cache.delete(key)
      return undefined
    }
    return entry.result
  },

  _setCache(url, result) {
    const key = url.toLowerCase()
    this._cache.set(key, { result, time: Date.now() })
  },

  _getApiKey() {
    return new Promise(resolve => {
      chrome.storage.local.get(['gsbApiKey'], result => {
        resolve(result.gsbApiKey || null)
      })
    })
  },
}
