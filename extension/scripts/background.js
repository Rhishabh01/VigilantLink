importScripts(
  'engine/reputation.js',
  'engine/heuristics.js',
  'engine/impersonation.js',
  'engine/scoring.js',
  'engine/behavior.js',
  'engine/index.js'
)

const BACKEND_URL = 'https://vigilantlink-production.up.railway.app'
const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 15000
const BACKGROUND_POLL_MAX_MS = 30000

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

    // 1. Local engine — instant, privacy-first
    const localResult = LocalEngine.analyze(request.url)

    // 2. Return local result immediately
    sendResponse({ success: true, data: localResult })

    // 3. Fire backend asynchronously for RDAP, SSL, GSB, metadata, screenshot
    if (tabId) {
      fetchBackendAnalysis(request.url, controller.signal, tabId, generation, localResult)
    }

    return true
  }

  if (request.action === 'cancel_analysis') {
    cancelRequest(tabId)
    sendResponse({ success: true })
    return false
  }

  if (request.action === 'resume_deep_scan') {
    const { requestId, url } = request
    if (!tabId || !requestId || !url) {
      sendResponse({ success: false })
      return false
    }
    cancelRequest(tabId)
    const generation = (requestGenerations.get(tabId) || 0) + 1
    requestGenerations.set(tabId, generation)
    const controller = new AbortController()
    activeRequests.set(tabId, { controller, generation })
    pollForDeepScanBackground(requestId, controller.signal, tabId, url, generation, null)
    sendResponse({ success: true })
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

function cleanupRequest(tabId, generation) {
  const entry = activeRequests.get(tabId)
  if (entry && entry.generation === generation) {
    activeRequests.delete(tabId)
  }
}

async function fetchBackendAnalysis(url, signal, tabId, generation, localResult) {
  try {
    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, cache_only: false }),
      signal,
    })

    if (!response.ok) return
    const data = await response.json()

    if (signal.aborted) return

    if (data.s === 2) {
      cleanupRequest(tabId, generation)
      const merged = mergeWithBackend(localResult, data)
      try {
        chrome.tabs.sendMessage(tabId, {
          action: 'phase2_result',
          requestId: data.id || localResult.id,
          url,
          data: merged,
        })
      } catch {}
    } else if (data.s === 1 && data.id) {
      const merged = mergeWithBackend(localResult, data)
      try {
        chrome.tabs.sendMessage(tabId, {
          action: 'phase2_result',
          requestId: data.id,
          url,
          data: merged,
        })
      } catch {}
      pollForDeepScanBackground(data.id, signal, tabId, url, generation, merged)
    }
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.warn('VigilantLink: Backend unavailable, using local result only', e)
    }
  }
}

function mergeWithBackend(local, backend) {
  const merged = JSON.parse(JSON.stringify(local))
  const beSec = backend.sec || {}

  // Metadata from backend
  if (backend.t) merged.t = backend.t
  if (backend.d) merged.d = backend.d
  if (backend.img) merged.img = backend.img
  if (backend.fav) merged.fav = backend.fav
  if (backend.ss) merged.ss = backend.ss

  // Redirect chain from backend
  if (backend.hops && backend.hops.length > 0) {
    merged.hops = backend.hops
  }

  // SSL cert age from backend
  if (beSec.age !== undefined && beSec.age !== null) {
    merged.sec.age = beSec.age
  }

  // GSB data from backend
  if (beSec.gsb || beSec.gsbt) {
    merged.sec.gsb = true
    merged.sec.gsbt = beSec.gsbt
    if (beSec.gsbt && !merged.sec.tt) {
      merged.sec.tt = beSec.gsbt
    }
    const gsbReason = `Flagged by Google Safe Browsing (${beSec.gsbt || 'threat'})`
    if (!merged.sec.r.includes(gsbReason)) {
      merged.sec.r.push(gsbReason)
    }
    const boost = 25
    if (!local.sec.gsb) {
      merged.sec.rs = Math.min(merged.sec.rs + boost, 100)
      if (merged.sec.rs >= 60) {
        merged.sec.v = 'red'
        merged.sec.safe = false
      } else if (merged.sec.rs >= 25 && merged.sec.v === 'green') {
        merged.sec.v = 'yellow'
        merged.sec.safe = false
      }
    }
  }

  // Backend risk score — take the higher one
  if (beSec.rs > merged.sec.rs) {
    merged.sec.rs = beSec.rs
    merged.sec.v = beSec.v || merged.sec.v
    merged.sec.safe = beSec.safe !== undefined ? beSec.safe : merged.sec.safe
    if (beSec.r && beSec.r.length > 0) {
      for (const r of beSec.r) {
        if (!merged.sec.r.includes(r)) {
          merged.sec.r.push(r)
        }
      }
    }
  }

  // Backend threat type if local had none
  if (beSec.tt && !merged.sec.tt) {
    merged.sec.tt = beSec.tt
  }

  return merged
}

async function pollForDeepScanBackground(requestId, signal, tabId, url, generation, currentResult) {
  try {
    const phase2Data = await pollForDeepScan(requestId, signal, BACKGROUND_POLL_MAX_MS)
    const entry = activeRequests.get(tabId)
    if (entry && entry.generation === generation && tabId) {
      const finalResult = currentResult ? mergeWithBackend(currentResult, phase2Data) : phase2Data
      try {
        chrome.tabs.sendMessage(tabId, {
          action: 'phase2_result',
          requestId,
          url,
          data: finalResult,
        })
      } catch {}
    }
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.warn('VigilantLink: Background Phase 2 polling failed', e)
    }
  } finally {
    cleanupRequest(tabId, generation)
  }
}

async function pollForDeepScan(requestId, signal, timeoutMs = POLL_TIMEOUT_MS) {
  const startTime = Date.now()
  while (Date.now() - startTime < timeoutMs) {
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS))
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
    try {
      const response = await fetch(`${BACKEND_URL}/analyze/deep/${requestId}`, { signal })
      if (response.status === 404 || response.status === 410) {
        throw new Error('Analysis session expired')
      }
      if (!response.ok) continue
      const data = await response.json()
      if (data.s === 2) {
        return data
      }
    } catch (e) {
      if (e.name === 'AbortError') throw e
      if (e.message === 'Analysis session expired') throw e
    }
  }
  throw new Error('Deep scan polling timed out')
}
