// Service Worker for API communication — Progressive Two-Phase Architecture
// Phase 1: Instant analysis (POST /analyze) — returned immediately
// Phase 2: Deep scan polling (GET /analyze/deep/{request_id}) — background poll

const BACKEND_URL = "http://127.0.0.1:8000";
const POLL_INTERVAL_MS = 400;
const POLL_TIMEOUT_MS = 3000;
const BACKGROUND_POLL_MAX_MS = 10000;

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

    analyzeTwoPhase(request.url, controller.signal, tabId, generation)
      .then(data => sendResponse({ success: true, data }))
      .catch(error => {
        if (error.name === 'AbortError') {
          sendResponse({ success: false, error: 'Request cancelled' });
        } else {
          sendResponse({ success: false, error: error.message });
        }
      });

    return true; // Async response
  }

  if (request.action === "cancel_analysis") {
    cancelRequest(tabId);
    sendResponse({ success: true });
    return false;
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

async function analyzeTwoPhase(url, signal, tabId, generation) {
  // --- Phase 1: Instant fetch ---
  const phase1Response = await fetch(`${BACKEND_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal
  });

  if (!phase1Response.ok) {
    throw new Error(`Backend Error: ${phase1Response.statusText}`);
  }

  const phase1Data = await phase1Response.json();

  // If we got a full cached result (s=2), return immediately
  if (phase1Data.s === 2) {
    cleanupRequest(tabId, generation);
    return phase1Data;
  }

  // Send Phase 1 result to content script immediately
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

  const requestId = phase1Data.id;
  if (!requestId) {
    cleanupRequest(tabId, generation);
    return phase1Data;
  }

  // Return Phase 1 data immediately (shows ANALYZING in popup).
  // Poll Phase 2 in background — result arrives via phase2_result message.
  pollForDeepScanBackground(requestId, signal, tabId, url, generation);

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
    const phase2Data = await pollForDeepScan(requestId, signal, BACKGROUND_POLL_MAX_MS);
    // Only send if this generation is still current for this exact URL
    const entry = activeRequests.get(tabId);
    if (entry && entry.generation === generation && tabId) {
      try {
        chrome.tabs.sendMessage(tabId, {
          action: "phase2_result",
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

async function pollForDeepScan(requestId, signal, timeoutMs = POLL_TIMEOUT_MS) {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));

    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

    try {
      const response = await fetch(`${BACKEND_URL}/analyze/deep/${requestId}`, {
        signal
      });

      if (!response.ok) continue;

      const data = await response.json();

      if (data.s === 2) {
        return data;
      }
      // s=0 → keep polling
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      // Network error — keep trying
    }
  }

  throw new Error("Deep scan polling timed out");
}
