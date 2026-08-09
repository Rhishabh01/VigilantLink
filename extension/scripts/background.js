// Service Worker for API communication — Progressive Two-Phase Architecture
// Phase 1: Instant analysis (POST /analyze) — returned immediately
// Phase 2: Deep scan polling (GET /analyze/deep/{request_id}) — background poll

const DEFAULT_BACKEND_URL = "https://vigilantlink-1.onrender.com";
const EXTENSION_VERSION = chrome.runtime.getManifest().version;


async function getBackendUrl() {
  const data = await chrome.storage.local.get('backendUrl');
  return data.backendUrl || DEFAULT_BACKEND_URL;
}
const POLL_INTERVAL_MS = 1000;
const POLL_TIMEOUT_MS = 15000;
const BACKGROUND_POLL_MAX_MS = 30000;

// Track active requests per tab with generation counter to prevent stale cleanup
const activeRequests = new Map();
const requestGenerations = new Map();

chrome.tabs.onRemoved.addListener((tabId) => {
  requestGenerations.delete(tabId);
  activeRequests.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (request.action === "analyze_link") {
    cancelRequest(tabId);

    const generation = (requestGenerations.get(tabId) || 0) + 1;
    requestGenerations.set(tabId, generation);

    const controller = new AbortController();
    activeRequests.set(tabId, { controller, generation });

    analyzeTwoPhase(request.url, controller.signal, tabId, generation, request.cache_only)
      .then(data => sendResponse({ success: true, data }))
      .catch(error => {
        console.error("VigilantLink analyze error:", error);

        if (error.name === 'AbortError') {
          sendResponse({
            success: false,
            error: 'Request cancelled'
          });
        } else {
          sendResponse({
            success: false,
            error: error?.message || String(error)
          });
        }
      });

    return true; // Async response
  }

  if (request.action === "cancel_analysis") {
    cancelRequest(tabId);
    sendResponse({ success: true });
    return false;
  }

  if (request.action === "get_zoom") {
    if (tabId) {
      chrome.tabs.getZoom(tabId, (zoomFactor) => {
        sendResponse({ zoom: zoomFactor || 1 });
      });
      return true;
    }
    sendResponse({ zoom: 1 });
    return false;
  }

  if (request.action === "resume_deep_scan") {
    const { requestId, url } = request;
    if (!tabId || !requestId || !url) {
      sendResponse({ success: false });
      return false;
    }
    // Cancel any stale poll before starting a fresh one
    cancelRequest(tabId);
    const generation = (requestGenerations.get(tabId) || 0) + 1;
    requestGenerations.set(tabId, generation);
    const controller = new AbortController();
    activeRequests.set(tabId, { controller, generation });
    // Resume phase2 polling only — no phase1 re-run
    pollForDeepScanBackground(requestId, controller.signal, tabId, url, generation);
    sendResponse({ success: true });
    return false;
  }

  if (request.action === "request_preview") {
    const { url } = request;
    if (!url) {
      sendResponse({ success: false });
      return false;
    }
    getBackendUrl().then(backendUrl => {
      fetch(`${backendUrl}/analyze/preview`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Extension-Version": EXTENSION_VERSION
        },
        body: JSON.stringify({ url })
      })
        .then(res => {
          if (!res.ok) throw new Error("Preview failed");
          return res.json();
        })
        .then(data => sendResponse({ success: true, data }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    });
    return true; // Async response
  }

  if (request.action === "get_domain_age") {
    const { url } = request;
    if (!url) {
      sendResponse({ success: false, error: "URL required" });
      return false;
    }
    getBackendUrl().then(backendUrl => {
      fetch(`${backendUrl}/domain-age`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Extension-Version": EXTENSION_VERSION
        },
        body: JSON.stringify({ url })
      })
        .then(res => {
          if (!res.ok) throw new Error("Domain age fetch failed");
          return res.json();
        })
        .then(data => sendResponse(data))
        .catch(err => sendResponse({ success: false, error: err.message }));
    });
    return true; // Async response
  }
});

function cancelRequest(tabId) {
  if (!tabId) return;
  const entry = activeRequests.get(tabId);
  if (entry) {
    entry.controller.abort();
    activeRequests.delete(tabId);
  }
}

async function analyzeTwoPhase(url, signal, tabId, generation, cacheOnly = false) {
  // --- Phase 1: Instant fetch ---

  const backendUrl = await getBackendUrl();
  const phase1Response = await fetch(`${backendUrl}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Extension-Version": EXTENSION_VERSION
    },
    body: JSON.stringify({ url, cache_only: cacheOnly }),
    signal
  });

  if (!phase1Response.ok) {
    const errorText = await phase1Response.text();

    console.error("Backend response status:", phase1Response.status);
    console.error("Backend response body:", errorText);

    // Extract a safe message if possible, otherwise use a generic one
    let safeMessage = "An unexpected error occurred.";
    if (phase1Response.status === 429) {
      safeMessage = "Rate limit exceeded. Please slow down.";
    } else if (phase1Response.status === 400 || phase1Response.status === 403) {
      try {
        const parsed = JSON.parse(errorText);
        if (parsed.detail && typeof parsed.detail === 'string' && parsed.detail.length < 100) {
          safeMessage = parsed.detail;
        }
      } catch (e) {
        // Ignore JSON parse errors for raw text
      }
    }

    throw new Error(safeMessage);
  }

  const phase1Data = await phase1Response.json();

  if (phase1Data.cache_miss) {
    cleanupRequest(tabId, generation);
    return phase1Data;
  }

  // If we got a full cached result (s=2), return instantly
  if (phase1Data.s === 2) {
    cleanupRequest(tabId, generation);
    return phase1Data;
  }

  const requestId = phase1Data.id;

  // START Phase 2 polling immediately in the background!
  // This happens while the UI is still "loading".
  if (requestId) {
    pollForDeepScanBackground(requestId, signal, tabId, url, generation);
  }

  if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

  // Send Phase 1 result to content script
  if (tabId) {
    try {
      chrome.tabs.sendMessage(tabId, {
        action: "phase1_result",
        url: url,
        data: phase1Data
      });
    } catch (e) {
      // Tab may have closed
    }
  }

  return phase1Data;
}

function cleanupRequest(tabId, generation) {
  const entry = activeRequests.get(tabId);
  if (entry && entry.generation === generation) {
    activeRequests.delete(tabId);
  }
}

async function pollForDeepScanBackground(requestId, signal, tabId, url, generation) {

  try {
    const phase2Data = await pollForDeepScan(requestId, signal, tabId, url, BACKGROUND_POLL_MAX_MS);
    // Check generation — but still send if the generation entry was cleaned up
    // (can happen after a disconnect/reconnect). The content script is the
    // authoritative staleness gatekeeper via currentAnalysisUrl / currentRequestId.
    const entry = activeRequests.get(tabId);
    if (entry && entry.generation === generation && tabId) {
      try {

        chrome.tabs.sendMessage(tabId, {
          action: "phase2_result",
          requestId: requestId,   // forward so content.js can gate on it
          url: url,
          data: phase2Data
        });
      } catch (e) {
        // Tab may have closed
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.warn("VigilantLink: Background Phase 2 polling failed", e);
      try {
        chrome.tabs.sendMessage(tabId, {
          action: "phase2_error",
          url: url,
          requestId: requestId,
          error: e.message || "Phase 2 polling failed"
        });
      } catch (e2) {
        // Tab may have closed
      }
    }
  } finally {
    cleanupRequest(tabId, generation);
  }
}

async function pollForDeepScan(requestId, signal, tabId, url, timeoutMs = POLL_TIMEOUT_MS) {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');


    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));

    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

    try {
      const backendUrl = await getBackendUrl();
      const response = await fetch(`${backendUrl}/analyze/deep/${requestId}`, {
        headers: {
          "X-Extension-Version": EXTENSION_VERSION
        },
        signal
      });

      if (response.status === 404 || response.status === 410) {
        throw new Error("Analysis session expired");
      }
      if (!response.ok) continue;

      const data = await response.json();


      if (data.s === 2) {
        if (data.p3 === "pending") {

          // Send partial result so UI shows intelligence immediately
          chrome.tabs.sendMessage(tabId, {
            action: "phase2_result",
            requestId: requestId,
            url: url,
            data: data
          });
          // Continue loop to wait for Phase3
          continue;
        }


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



