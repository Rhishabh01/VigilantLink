importScripts(
  'engine/reputation.js',
  'engine/heuristics.js',
  'engine/impersonation.js',
  'engine/scoring.js',
  'engine/behavior.js',
  'engine/index.js'
)

const GSB_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
const GSB_THREAT_PRIORITY = ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE']
const GSB_TIMEOUT_MS = 5000
const GSB_MIN_RS_THRESHOLD = 30
const GSB_CACHE_TTL_MS = 300000
const gsbCache = new Map()

let gsbEnabled = false
let gsbApiKey = ''

chrome.storage.local.get(['gsbEnabled', 'gsbApiKey'], (result) => {
  gsbEnabled = result.gsbEnabled === true
  gsbApiKey = result.gsbApiKey || ''
})

chrome.storage.onChanged.addListener((changes) => {
  if (changes.gsbEnabled) gsbEnabled = changes.gsbEnabled.newValue === true
  if (changes.gsbApiKey) gsbApiKey = changes.gsbApiKey.newValue || ''
})

const activeRequests = new Map()
const requestGenerations = new Map()

chrome.tabs.onRemoved.addListener((tabId) => {
  requestGenerations.delete(tabId)
  activeRequests.delete(tabId)
})

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab?.id

  if (request.action === 'analyze_link') {
    cancelRequest(tabId)
    const generation = (requestGenerations.get(tabId) || 0) + 1
    requestGenerations.set(tabId, generation)
    const controller = new AbortController()
    activeRequests.set(tabId, { controller, generation })

    const result = LocalEngine.analyze(request.url)
    activeRequests.delete(tabId)

    sendResponse({ success: true, data: result })

    if (gsbEnabled && gsbApiKey && result.sec.rs >= GSB_MIN_RS_THRESHOLD && tabId) {
      checkGSB(request.url, tabId, generation, result)
    }

    return true
  }

  if (request.action === 'cancel_analysis') {
    cancelRequest(tabId)
    sendResponse({ success: true })
    return false
  }

  if (request.action === 'resume_deep_scan') {
    sendResponse({ success: false })
    return false
  }
})

function cancelRequest(tabId) {
  if (!tabId) return
  const entry = activeRequests.get(tabId)
  if (entry) {
    entry.controller.abort()
    activeRequests.delete(tabId)
  }
}

async function checkGSB(url, tabId, generation, localResult) {
  const cacheKey = url.toLowerCase()
  const cached = gsbCache.get(cacheKey)
  if (cached && Date.now() - cached.timestamp < GSB_CACHE_TTL_MS) {
    if (cached.threats.length > 0) {
      sendGSBResult(tabId, generation, localResult, cached.threats)
    }
    return
  }

  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), GSB_TIMEOUT_MS)

    const response = await fetch(gsbApiUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(gsbPayload(url)),
      signal: controller.signal,
    })
    clearTimeout(timeout)

    let threats = []
    if (response.ok) {
      const data = await response.json()
      const matches = data.matches || []
      threats = matches
        .map(m => m.threatType)
        .filter(t => GSB_THREAT_PRIORITY.includes(t))
    }

    gsbCache.set(cacheKey, { threats, timestamp: Date.now() })
    if (threats.length > 0) {
      sendGSBResult(tabId, generation, localResult, threats)
    }
  } catch {}
}

function sendGSBResult(tabId, generation, localResult, threats) {
  const threatType = GSB_THREAT_PRIORITY.find(t => threats.includes(t)) || threats[0]
  const gsbReasons = threats.map(t => `Flagged by Google Safe Browsing (${t})`)

  const gsbResult = JSON.parse(JSON.stringify(localResult))
  gsbResult.sec.gsb = true
  gsbResult.sec.gsbt = threatType
  gsbResult.sec.r = [...new Set([...gsbResult.sec.r, ...gsbReasons])]

  if (!gsbResult.sec.tt) {
    gsbResult.sec.tt = threatType
  }

  const boost = Math.min(25 + threats.length * 10, 40)
  gsbResult.sec.rs = Math.min(gsbResult.sec.rs + boost, 100)
  if (gsbResult.sec.rs >= 60) {
    gsbResult.sec.v = 'red'
    gsbResult.sec.safe = false
  } else if (gsbResult.sec.rs >= 25 && gsbResult.sec.v === 'green') {
    gsbResult.sec.v = 'yellow'
    gsbResult.sec.safe = false
  }

  try {
    chrome.tabs.sendMessage(tabId, {
      action: 'phase2_result',
      requestId: localResult.id,
      url: localResult.url,
      data: gsbResult,
    })
  } catch {}
}

function gsbApiUrl() {
  return `${GSB_API_URL}?key=${encodeURIComponent(gsbApiKey)}`
}

function gsbPayload(url) {
  return {
    client: { clientId: 'vigilantlink', clientVersion: '1.2.0' },
    threatInfo: {
      threatTypes: GSB_THREAT_PRIORITY,
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  }
}
