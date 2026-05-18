importScripts(
  'engine/reputation.js',
  'engine/heuristics.js',
  'engine/impersonation.js',
  'engine/scoring.js',
  'engine/behavior.js',
  'engine/index.js',
  'engine/gsb.js'
)

<<<<<<< Updated upstream
const BACKEND_URL = 'https://vigilantlink-production.up.railway.app'
=======
// Import local engines
importScripts(
  'heuristics.js',
  'impersonation.js',
  'feeds.js',
  'gsb.js',
  'scoring.js'
);

var BACKEND_URL = "https://vigilantlink-production.up.railway.app";
var POLL_INTERVAL_MS = 1000;
var POLL_TIMEOUT_MS = 15000;
var BACKGROUND_POLL_MAX_MS = 30000;
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
=======
    // Cancel any stale poll before starting a fresh one
    cancelRequest(tabId);
    const generation = (requestGenerations.get(tabId) || 0) + 1;
    requestGenerations.set(tabId, generation);
    const controller = new AbortController();
    activeRequests.set(tabId, { controller, generation });
    // Resume phase2 polling only — no phase1 re-run
    pollForDeepScanBackground(requestId, requestId, controller.signal, tabId, url, generation);
    sendResponse({ success: true });
    return false;
  }
});
>>>>>>> Stashed changes

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

<<<<<<< Updated upstream
function cancelRequest(tabId) {
  if (!tabId) return
  const entry = activeRequests.get(tabId)
  if (entry) {
    entry.controller.abort()
    activeRequests.delete(tabId)
  }
=======
// -------------------------------------------------------------
// Orchestrates local + remote hybrid analysis
// -------------------------------------------------------------
async function analyzeLocal(url, title = "", redirectHops = []) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return {
      v: 'green',
      safe: true,
      rs: 0,
      r: ["Invalid URL format"],
      tt: null,
      confidence: 'Low',
      level: 'Safe'
    };
  }
  
  const hostname = parsedUrl.hostname.toLowerCase();
  
  // Heuristics checks
  const typosquattingRes = checkTyposquatting(hostname);
  const punycode = hasHomoglyphs(hostname);
  const keywordsCount = checkKeywords(parsedUrl);
  const excessiveSubdomains = hostname.split('.').length > 5;
  const isIP = isIPAddress(hostname);
  const highEntropy = getEntropy(hostname) > 4.2;
  const hasCredentials = parsedUrl.username || parsedUrl.password || /[^/]*@/.test(url);
  
  const tldMatch = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  const suspiciousTLD = !!tldMatch;
  
  const heuristics = {
    domain: hostname,
    typosquatting: !!typosquattingRes,
    typosquattingReason: typosquattingRes,
    punycode,
    keywordsCount,
    keywords: keywordsCount > 0,
    excessiveSubdomains,
    isIP,
    highEntropy,
    hasCredentials,
    suspiciousTLD,
    tld: tldMatch || '',
    redirectChainLength: redirectHops.length
  };
  
  // 2. Local feeds lookup
  const feedMatch = await lookupLocalFeeds(url);
  
  // 3. Impersonation detection
  const impersonation = checkImpersonation(url, title);
  
  // 4. Check if we should query GSB
  const initialScore = calculateLocalScore(heuristics, feedMatch, null, impersonation);
  
  let gsbMatch = null;
  const shouldCheckGSB = initialScore.rs >= 20 || impersonation || feedMatch || redirectHops.length > 3;
  const isTrusted = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  
  if (shouldCheckGSB && !isTrusted) {
    gsbMatch = await checkGoogleSafeBrowsingLocal(url);
  }
  
  // 5. Final scoring calculation
  return calculateLocalScore(heuristics, feedMatch, gsbMatch, impersonation);
}

async function analyzeTwoPhase(url, signal, tabId, generation, cacheOnly = false) {
  // Always run local analysis first to be the primary verdict driver
  const localSec = await analyzeLocal(url);
  const localRequestId = "local_" + Date.now() + "_" + Math.random().toString(36).substr(2, 5);

  if (cacheOnly) {
    // Check if backend has a cached result
    try {
      const response = await fetch(`${BACKEND_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, cache_only: true }),
        signal
      });
      if (response.ok) {
        const backendData = await response.json();
        if (!backendData.cache_miss && backendData.s === 2) {
          // Merge local analysis with backend metadata/screenshot
          const finalSec = await analyzeLocal(backendData.furl || url, backendData.t || "", backendData.hops || []);
          backendData.sec = finalSec;
          cleanupRequest(tabId, generation);
          return backendData;
        }
      }
    } catch (e) {
      console.warn("Backend cache lookup failed:", e);
    }
    
    // If local has flagged suspicious/dangerous threat feed/impersonation/heuristics, return as cached hit
    if (localSec.rs >= 35) {
      const localCachedResult = {
        id: localRequestId,
        s: 2,
        url: url,
        furl: url,
        hops: [],
        sec: localSec,
        t: "",
        d: "Local Threat Intelligence Engine Hit"
      };
      cleanupRequest(tabId, generation);
      return localCachedResult;
    }
    return { cache_miss: true };
  }

  // --- Phase 1: Return Local Verdict Instantly (as s: 2!) ---
  const localPhase2Data = {
    id: localRequestId,
    s: 2, // Finalized locally to bypass skeleton loader instantly
    url: url,
    furl: url,
    hops: [],
    sec: localSec,
    t: "",
    d: "Local Threat Intelligence Engine Active"
  };

  // Launch backend deep scan in background
  (async () => {
    try {
      const phase1Response = await fetch(`${BACKEND_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, cache_only: false }),
        signal
      });

      if (!phase1Response.ok) {
        throw new Error(`Status ${phase1Response.status}`);
      }
      
      const phase1Data = await phase1Response.json();
      if (phase1Data.cache_miss) return;

      // If backend returns a cached result immediately
      if (phase1Data.s === 2) {
        const finalSec = await analyzeLocal(phase1Data.furl || url, phase1Data.t || "", phase1Data.hops || []);
        phase1Data.sec = finalSec;
        if (tabId) {
          chrome.tabs.sendMessage(tabId, {
            action: "phase2_result",
            requestId: localRequestId, // Match localRequestId in content script
            url: url,
            data: phase1Data
          });
        }
        return;
      }

      const requestId = phase1Data.id;
      if (requestId) {
        pollForDeepScanBackground(requestId, localRequestId, signal, tabId, url, generation);
      }
    } catch (error) {
      console.warn("Backend connection failed, staying offline:", error);
    }
  })();

  // Return the completed local verdict so the popup renders it instantly!
  return localPhase2Data;
>>>>>>> Stashed changes
}

function cleanupRequest(tabId, generation) {
  const entry = activeRequests.get(tabId)
  if (entry && entry.generation === generation) {
    activeRequests.delete(tabId)
  }
}

<<<<<<< Updated upstream
async function performGSBThenLocal(url, tabId, generation, analysisId) {
  try {
    const gsbResult = await GSB.check(url)

    const entry = activeRequests.get(tabId)
    if (!entry || entry.generation !== generation) return
=======
async function pollForDeepScanBackground(requestId, localRequestId, signal, tabId, url, generation) {
  console.log("Starting phase2 polling:", requestId);
  try {
    const phase2Data = await pollForDeepScan(requestId, localRequestId, signal, tabId, url, BACKGROUND_POLL_MAX_MS);
    
    // Merge backend results with local analysis!
    const finalSec = await analyzeLocal(phase2Data.furl || url, phase2Data.t || "", phase2Data.hops || []);
    phase2Data.sec = finalSec;

    // Check generation
    const entry = activeRequests.get(tabId);
    if (entry && entry.generation === generation && tabId) {
      try {
        console.log("Sending phase2 result to content script");
        chrome.tabs.sendMessage(tabId, {
          action: "phase2_result",
          requestId: localRequestId,   // Match localRequestId
          url: url,
          data: phase2Data
        });
      } catch (e) {
        // Tab may have closed
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.warn("VigilantLink: Deep scan polling failed, relying on local engine", e);
    }
  } finally {
    cleanupRequest(tabId, generation);
  }
}

async function pollForDeepScan(requestId, localRequestId, signal, tabId, url, timeoutMs = POLL_TIMEOUT_MS) {
  const startTime = Date.now();
>>>>>>> Stashed changes

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

<<<<<<< Updated upstream
function mergeGSBResult(local, gsb) {
  if (!gsb || !gsb.threat) {
    return Object.assign({}, local, { s: 2 })
=======
      if (response.status === 404 || response.status === 410) {
        throw new Error("Analysis session expired");
      }
      if (!response.ok) continue;

      const data = await response.json();
      console.log("Poll data received:", data);

      if (data.s === 2) {
        if (data.p3 === "pending") {
          console.log("Phase2 intelligence ready, Phase3 pending. Sending update...");
          
          // Merge local analysis for partial updates
          const partialSec = await analyzeLocal(data.furl || url, data.t || "", data.hops || []);
          data.sec = partialSec;

          // Send partial result so UI shows intelligence immediately
          chrome.tabs.sendMessage(tabId, {
            action: "phase2_result",
            requestId: localRequestId, // Match localRequestId in content script!
            url: url,
            data: data
          });
          // Continue loop to wait for Phase3
          continue;
        }

        console.log("Phase2 and Phase3 complete:", data);
        return data;
      }
      // s=0 → keep polling
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      if (e.message === "Analysis session expired") throw e;
      // Network error — keep trying until timeoutMs
    }
>>>>>>> Stashed changes
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

// -------------------------------------------------------------
// Alarm & Feed updates listeners
// -------------------------------------------------------------

function extractHostFromKey(key) {
  let temp = key.toLowerCase().trim();
  if (temp.includes('://')) {
    try {
      return new URL(temp).hostname;
    } catch(e) {}
  }
  // Strip any protocol prefixes
  temp = temp.replace(/^[a-z]+:\/*/, '');
  // Strip any paths
  temp = temp.split('/')[0];
  // Strip ports
  temp = temp.split(':')[0];
  return temp;
}

async function sanitizeThreatFeedsDatabase() {
  try {
    const result = await chrome.storage.local.get(['threatFeeds']);
    if (result.threatFeeds) {
      const feeds = result.threatFeeds;
      let modified = false;
      
      const trusted = [
        "google.com", "youtube.com", "github.com", "microsoft.com",
        "cloudflare.com", "discord.com", "linkedin.com", "apple.com",
        "wikipedia.org"
      ];
      
      for (const key in feeds) {
        const host = extractHostFromKey(key);
        const isTrusted = trusted.some(d => host === d || host.endsWith('.' + d));
        if (isTrusted) {
          delete feeds[key];
          modified = true;
        }
      }
      
      if (modified) {
        await chrome.storage.local.set({ threatFeeds: feeds });
        console.log("[DB SANITIZER] Successfully pruned trusted domains from local threat feeds!");
      }
    }
  } catch (e) {
    console.warn("[DB SANITIZER] Sanitization failed:", e);
  }
}

// Run database sanitization on startup
sanitizeThreatFeedsDatabase().catch(console.error);

chrome.runtime.onInstalled.addListener(() => {
  console.log("VigilantLink Extension installed.");
  updateThreatFeeds().catch(console.error);
});

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.get(['lastFeedUpdate'], (result) => {
    const lastUpdate = result.lastFeedUpdate || 0;
    const sixHours = 6 * 60 * 60 * 1000;
    if (Date.now() - lastUpdate > sixHours) {
      updateThreatFeeds().catch(console.error);
    }
  });
});

chrome.alarms.create('update_feeds_alarm', { periodInMinutes: 360 }); // 6 hours
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'update_feeds_alarm') {
    updateThreatFeeds().catch(console.error);
  }
});
