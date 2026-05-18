importScripts(
  'engine/reputation.js',
  'engine/heuristics.js',
  'engine/impersonation.js',
  'engine/scoring.js',
  'engine/behavior.js',
  'engine/index.js',
  'engine/gsb.js'
)

const BACKEND_URL = 'https://vigilantlink-production.up.railway.app'

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
    const analysisId = 'a_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7)
    const requestEntry = { controller, generation, result: null }
    activeRequests.set(tabId, requestEntry)

    const skeleton = {
      s: 1,
      id: analysisId,
      url: request.url,
      furl: request.url,
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
        r: [],
        gsb: false,
        gsbt: null,
      },
    }

    sendResponse({ success: true, data: skeleton })
    performGSBThenLocal(request.url, tabId, generation, analysisId)

    if (tabId) {
      fetchBackendData(request.url, controller.signal, tabId, generation)
    }

    return true
  }

  if (request.action === 'cancel_analysis') {
    cancelRequest(tabId)
    sendResponse({ success: true })
    return false
  }

  if (request.action === 'resume_deep_scan') {
    sendResponse({ success: true })
    return false
  }

  return false
})

function tryParseURL(url) {
  try { return new URL(url) } catch { return null }
}

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

async function performGSBThenLocal(url, tabId, generation, analysisId) {
  try {
    const gsbResult = await GSB.check(url)

    const entry = activeRequests.get(tabId)
    if (!entry || entry.generation !== generation) return

    const localResult = LocalEngine.analyze(url)
    const merged = mergeGSBResult(localResult, gsbResult)
    merged.id = analysisId
    entry.result = merged
    cleanupRequest(tabId, generation)

    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'phase2_result',
        requestId: analysisId,
        url,
        data: merged,
      })
    } catch {}
  } catch (e) {
    console.warn('VigilantLink: GSB→Local analysis failed', e)
    const entry = activeRequests.get(tabId)
    if (!entry || entry.generation !== generation) return
    cleanupRequest(tabId, generation)
    const localResult = LocalEngine.analyze(url)
    localResult.id = analysisId
    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'phase2_result',
        requestId: analysisId,
        url,
        data: localResult,
      })
    } catch {}
  }
}

function mergeGSBResult(local, gsb) {
  if (!gsb || !gsb.threat) {
    return Object.assign({}, local, { s: 2 })
  }

  const merged = JSON.parse(JSON.stringify(local))
  merged.s = 2
  merged.sec.gsb = true
  merged.sec.gsbt = gsb.threatType

  if (gsb.threatType && !merged.sec.tt) {
    merged.sec.tt = gsb.threatType
  }

  const reason = `Flagged by Google Safe Browsing (${gsb.threatType || 'threat'})`
  if (!merged.sec.r.includes(reason)) {
    merged.sec.r.push(reason)
  }

  const boost = 25
  merged.sec.rs = Math.min(merged.sec.rs + boost, 100)

  if (merged.sec.rs >= 60) {
    merged.sec.v = 'red'
    merged.sec.safe = false
  } else if (merged.sec.rs >= 25 && merged.sec.v === 'green') {
    merged.sec.v = 'yellow'
    merged.sec.safe = false
  }

  return merged
}

async function fetchBackendData(url, signal, tabId, generation) {
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

    const entry = activeRequests.get(tabId)
    if (!entry || entry.generation !== generation) return
    if (!entry.result) return

    const current = entry.result
    const update = JSON.parse(JSON.stringify(current))

    if (data.t) update.t = data.t
    if (data.d) update.d = data.d
    if (data.img) update.img = data.img
    if (data.ss) update.ss = data.ss
    if (data.fav) update.fav = data.fav
    if (data.hops && data.hops.length > 0) update.hops = data.hops

    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'phase2_result',
        requestId: update.id,
        url,
        data: update,
      })
    } catch {}
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.warn('VigilantLink: Backend unavailable, skipping screenshot', e)
    }
  }
}
