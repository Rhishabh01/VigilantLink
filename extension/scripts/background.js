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

var BACKEND_URL = "http://localhost:8000";
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

function cancelRequest(tabId) {
  if (!tabId) return;
  const entry = activeRequests.get(tabId);
  if (entry) {
    entry.controller.abort();
    activeRequests.delete(tabId);
  }
}

// -------------------------------------------------------------
// Orchestrates local + remote hybrid analysis
// -------------------------------------------------------------
async function analyzeLocal(url, title = "", redirectHops = [], skipGSB = false) {
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
  
  if (shouldCheckGSB && !isTrusted && !skipGSB) {
    gsbMatch = await checkGoogleSafeBrowsingLocal(url);
  }
  
  // 5. Final scoring calculation
  return calculateLocalScore(heuristics, feedMatch, gsbMatch, impersonation);
}
async function analyzeTwoPhase(url, signal, tabId, generation, cacheOnly = false) {
  // Always run local analysis first to be the primary verdict driver, skipping GSB initially
  const localSec = await analyzeLocal(url, "", [], true); // skipGSB = true
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
          const finalSec = await analyzeLocal(backendData.furl || url, backendData.t || "", backendData.hops || [], false);
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

  // --- Phase 1: Return Local Verdict Instantly (with pending statuses) ---
  const localPhase2Data = {
    id: localRequestId,
    s: 2,
    p2: "pending", // Phase 2: GSB verification pending
    p3: "pending", // Phase 3: Visual preview screenshot pending
    url: url,
    furl: url,
    hops: [],
    sec: localSec,
    t: "",
    d: "Local Threat Intelligence Engine Active"
  };

  // Launch background phases
  (async () => {
    try {
      // --- Phase 2: Google Safe Browsing verification (runs asynchronously in background) ---
      const gsbSec = await analyzeLocal(url, "", [], false); // skipGSB = false (runs GSB check)
      
      if (tabId) {
        try {
          console.log("[PHASE 2] GSB verification complete. Sending update to content script...");
          chrome.tabs.sendMessage(tabId, {
            action: "phase2_result",
            requestId: localRequestId,
            url: url,
            data: {
              id: localRequestId,
              s: 2,
              p2: "done",
              p3: "pending",
              url: url,
              furl: url,
              hops: [],
              sec: gsbSec,
              t: "",
              d: "Local Threat Intelligence Engine Active"
            }
          });
        } catch (e) {
          // Tab may have closed
        }
      }

      // --- Phase 3: Deep Scan Screenshot Fetch ---
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
        const finalSec = await analyzeLocal(phase1Data.furl || url, phase1Data.t || "", phase1Data.hops || [], false);
        phase1Data.sec = finalSec;
        phase1Data.p2 = "done";
        phase1Data.p3 = "done";
        if (tabId) {
          try {
            chrome.tabs.sendMessage(tabId, {
              action: "phase2_result",
              requestId: localRequestId,
              url: url,
              data: phase1Data
            });
          } catch (e) {}
        }
        return;
      }

      const requestId = phase1Data.id;
      if (requestId) {
        pollForDeepScanBackground(requestId, localRequestId, signal, tabId, url, generation);
      }
    } catch (error) {
      console.warn("Backend or GSB connection failed, staying offline:", error);
    }
  })();

  // Return the completed local verdict so the popup renders it instantly!
  return localPhase2Data;
}

function cleanupRequest(tabId, generation) {
  const entry = activeRequests.get(tabId);
  if (entry && entry.generation === generation) {
    activeRequests.delete(tabId);
  }
}

async function pollForDeepScanBackground(requestId, localRequestId, signal, tabId, url, generation) {
  console.log("Starting phase3 polling:", requestId);
  try {
    const phase2Data = await pollForDeepScan(requestId, localRequestId, signal, tabId, url, BACKGROUND_POLL_MAX_MS);
    
    // Merge backend results with local analysis (running GSB checks too)
    const finalSec = await analyzeLocal(phase2Data.furl || url, phase2Data.t || "", phase2Data.hops || [], false);
    phase2Data.sec = finalSec;
    phase2Data.p2 = "done";
    phase2Data.p3 = "done"; // Mark deep scan visual complete!

    // Check generation
    const entry = activeRequests.get(tabId);
    if (entry && entry.generation === generation && tabId) {
      try {
        console.log("Sending phase3 result to content script");
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
  while (Date.now() - startTime < timeoutMs) {
    if (signal && signal.aborted) throw new Error("AbortError");

    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));

    try {
      const response = await fetch(`${BACKEND_URL}/analyze/deep/${requestId}`, { signal });
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
          const partialSec = await analyzeLocal(data.furl || url, data.t || "", data.hops || [], false);
          data.sec = partialSec;
          data.p2 = "done";

          // Send partial result so UI shows intelligence immediately
          if (tabId) {
            try {
              chrome.tabs.sendMessage(tabId, {
                action: "phase2_result",
                requestId: localRequestId, // Match localRequestId in content script!
                url: url,
                data: data
              });
            } catch (e) {}
          }
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
  }

  throw new Error("Deep scan polling timed out");
}

// -------------------------------------------------------------------------------------
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
