// Service Worker for API communication — Progressive Two-Phase Architecture
// Phase 1: Instant analysis (POST /analyze)
// Phase 2: Deep scan polling (GET /analyze/deep/{request_id})

const BACKEND_URL = "http://127.0.0.1:8000";
const POLL_INTERVAL_MS = 400;
const POLL_TIMEOUT_MS = 3000;

// Track active requests per tab for cancellation
const activeRequests = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (request.action === "analyze_link") {
    // Cancel any previous in-flight request for this tab
    cancelRequest(tabId);

    const controller = new AbortController();
    activeRequests.set(tabId, controller);

    analyzeTwoPhase(request.url, controller.signal, tabId)
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
  const controller = activeRequests.get(tabId);
  if (controller) {
    controller.abort();
    activeRequests.delete(tabId);
  }
}

async function analyzeTwoPhase(url, signal, tabId) {
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
    activeRequests.delete(tabId);
    return phase1Data;
  }

  // Send Phase 1 result to content script immediately
  if (tabId) {
    try {
      chrome.tabs.sendMessage(tabId, {
        action: "phase1_result",
        data: phase1Data
      });
    } catch (e) {
      // Tab may have closed
    }
  }

  // --- Phase 2: Poll for deep scan results ---
  const requestId = phase1Data.id;
  if (!requestId) {
    activeRequests.delete(tabId);
    return phase1Data;
  }

  try {
    const phase2Data = await pollForDeepScan(requestId, signal);

    // Send Phase 2 update to content script
    if (tabId) {
      try {
        chrome.tabs.sendMessage(tabId, {
          action: "phase2_result",
          data: phase2Data
        });
      } catch (e) {
        // Tab may have closed
      }
    }

    activeRequests.delete(tabId);
    return phase2Data;
  } catch (e) {
    activeRequests.delete(tabId);
    if (e.name === 'AbortError') throw e;
    // If polling fails, return Phase 1 result (best effort)
    console.warn("VigilantLink: Phase 2 polling failed, using Phase 1 result", e);
    return phase1Data;
  }
}

async function pollForDeepScan(requestId, signal) {
  const startTime = Date.now();

  while (Date.now() - startTime < POLL_TIMEOUT_MS) {
    // Check if cancelled
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

    // Wait before polling
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));

    // Check again after wait
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
      // s=1 + status=pending → keep polling
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      // Network error — keep trying
    }
  }

  // Timeout — return whatever we have
  throw new Error("Deep scan polling timed out");
}
