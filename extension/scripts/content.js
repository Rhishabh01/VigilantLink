// Hover detection with Event Delegation, Debouncing, and Top Layer Z-Index
// Designed for Shadow DOM and AJAX-loaded content

let hoverTimer = null;
let hoverTargetUrl = null;
let closeTimer = null;
let currentPopupContainer = null;
let currentPopupShadowRoot = null;
let currentPopupContent = null;
const HOVER_DELAY_MS = 100;
const ACTIVATION_DELAY_MS = 1500;
let activationTimer = null;
let mutationObserver = null;
const processedLinks = new WeakSet();
let currentAnalysisUrl = null;
let currentRequestId = null;
let requestSequence = 0;
let lastPhase1Result = null;
let freezeTimer = null;
const FREEZE_TIMEOUT_MS = 12000;
let activeAnchor = null;
let lastLocation = location.href;
let spaPatched = false;
let spaInterval = null;
let currentLinkText = null;
let currentLinkDescription = null;

// ── Scan State Machine ─────────────────────────────────────────────────────
// IDLE        : no active scan
// SCANNING    : phase1 request in-flight, skeleton shown
// ANALYZING   : phase1 rendered, polling phase2
// RECONNECTING: phase2 poll failed, retrying after backend reconnect
// FINALIZED   : phase2_result received, final verdict shown
// INTERRUPTED : reconnect timed out, scan could not complete
let scanState = 'IDLE';
let reconnectTimer = null;
let reconnectStartTime = 0;
const MAX_RECONNECT_DURATION_MS = 25000; // 25 s total retry window
const RECONNECT_INTERVAL_MS = 2000; // retry every 2 s

// Debounce utility - prevents excessive function calls
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Throttle utility - ensures minimum time between calls
function throttle(func, limit) {
  let inThrottle;
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

const DEFAULT_SETTINGS = {
  globalEnabled: true,
  disabledSites: ['youtube.com', 'mail.google.com', 'instagram.com', 'linkedin.com']
};

// Check if VigilantLink is enabled for current site
async function isEnabledForSite() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['globalEnabled', 'disabledSites'], (result) => {
      const override = window.sessionStorage.getItem('vigilantlink_override');
      if (override === 'enabled') return resolve(true);
      if (override === 'disabled') return resolve(false);

      const globalEnabled = result.globalEnabled !== false;
      const disabledSites = result.disabledSites !== undefined ? result.disabledSites : DEFAULT_SETTINGS.disabledSites;
      const currentDomain = window.location.hostname;

      if (!globalEnabled) return resolve(false);

      const isSiteDisabled = disabledSites.some(disabledDomain => {
        return currentDomain === disabledDomain || currentDomain.endsWith('.' + disabledDomain);
      });

      if (isSiteDisabled) return resolve(false);

      resolve(true);
    });
  });
}

// Get the effective theme (stored or system default)
async function getTheme() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['theme'], (result) => {
      if (result.theme) return resolve(result.theme);

      // Fallback to system preference
      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      resolve(isDark ? 'dark' : 'light');
    });
  });
}

async function getFixedPhysicalSize() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['fixedPhysicalSize'], (result) => {
      resolve(result.fixedPhysicalSize === true); // default to false (scales with browser)
    });
  });
}

// Watch for theme changes to update active popups
chrome.storage.onChanged.addListener((changes) => {
  if (changes.theme && currentPopupContainer) {
    const newTheme = changes.theme.newValue;
    currentPopupContainer.classList.remove('theme-light', 'theme-dark');
    currentPopupContainer.classList.add(`theme-${newTheme}`);
  }
});

// Initialize MutationObserver for AJAX-loaded and Shadow DOM links
function initializeMutationObserver() {
  if (mutationObserver) return;

  mutationObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Check direct links and nested links
            const links = node.querySelectorAll?.('a') || [];
            if (node.tagName === 'A') {
              attachLinkHoverListener(node);
              processedLinks.add(node);
            }
            links.forEach(link => {
              if (!processedLinks.has(link)) {
                attachLinkHoverListener(link);
                processedLinks.add(link);
              }
            });

            // Try to pierce Shadow DOM boundaries
            try {
              const shadowElements = node.querySelectorAll?.('*') || [];
              shadowElements.forEach(el => {
                if (el.shadowRoot) {
                  const shadowLinks = el.shadowRoot.querySelectorAll('a');
                  shadowLinks.forEach(link => {
                    if (!processedLinks.has(link)) {
                      attachLinkHoverListener(link);
                      processedLinks.add(link);
                    }
                  });
                }
              });
            } catch (e) {
              // Shadow DOM access may be restricted
            }
          }
        });
      }
    });
  });

  mutationObserver.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}

function attachLinkHoverListener(link) {
  link.addEventListener('mouseenter', handleLinkMouseEnter, false);
  link.addEventListener('mouseleave', handleLinkMouseLeave, false);
}

// Main hover handler with debouncing
async function handleLinkMouseEnter(event) {
  // Use event delegation: climb up to find the <a> tag
  let target = event.target;
  while (target && target.tagName !== 'A') {
    target = target.parentElement;
  }

  if (!target || !target.href) return;

  // Only analyze http/https links
  if (!target.href.startsWith('http://') && !target.href.startsWith('https://')) return;

  const enabled = await isEnabledForSite();
  if (!enabled) return;

  const url = target.href;
  const linkText = target.textContent.trim() || target.title || null;
  let linkDesc = target.getAttribute('aria-label') || target.title || null;
  if (linkDesc === linkText) linkDesc = null;

  hoverTargetUrl = url;
  currentLinkText = linkText;
  currentLinkDescription = linkDesc;
  activeAnchor = target;

  if (hoverTimer) clearTimeout(hoverTimer);

  // Debounced hover popup display
  hoverTimer = setTimeout(async () => {
    if (hoverTargetUrl !== url) return;

    const cursorX = event.clientX;
    const cursorY = event.clientY;

    let x = cursorX + 15;
    let y = cursorY + 15;

    const isFixed = await getFixedPhysicalSize();
    let scale = 1;
    let zoom = 1;
    try {
      const response = await Promise.race([
        new Promise(resolve => chrome.runtime.sendMessage({ action: 'get_zoom' }, resolve)),
        new Promise(resolve => setTimeout(() => resolve(null), 500))
      ]);
      if (response && response.zoom) {
        zoom = response.zoom;
      }
    } catch (e) {
      if (window.outerWidth && window.innerWidth) {
        let browserZoom = window.outerWidth / window.innerWidth;
        if (Math.abs(browserZoom - 1) < 0.08) browserZoom = 1;
        if (browserZoom < 0.25) browserZoom = 0.25;
        if (browserZoom > 5) browserZoom = 5;
        zoom = browserZoom;
        console.log(`[VigilantLink] Zoom fallback used. BrowserZoom: ${browserZoom}`);
      }
    }

    if (isFixed) {
      // when fixed: the same size for all zoom levels, locked to 90% of default size
      scale = 0.9 / zoom;
    } else {
      // when unfixed and zoomed in (zoom > 100%), the card size shouldn't change
      if (zoom > 1) {
        scale = 1 / zoom;
      } else {
        scale = 1;
      }
    }

    console.log(`[VigilantLink] isFixed: ${isFixed}, Final Scale: ${scale}`);

    const POPUP_WIDTH = 340 * scale;
    const POPUP_HEIGHT = 410 * scale;

    // Horizontal positioning
    if (x + POPUP_WIDTH > window.innerWidth) {
      // Try to flip to the left of the cursor
      x = cursorX - POPUP_WIDTH - 15;
      if (x < 0) {
        // If it doesn't fit on either side, snap to the right edge
        x = window.innerWidth - POPUP_WIDTH - 10;
        if (x < 10) x = 10;
      }
    }

    // Vertical positioning
    if (y + POPUP_HEIGHT > window.innerHeight) {
      // Try to flip above the cursor
      y = cursorY - POPUP_HEIGHT - 15;
      if (y < 0) {
        // If it doesn't fit above either, snap to the bottom edge
        y = window.innerHeight - POPUP_HEIGHT - 10;
        if (y < 10) y = 10;
      }
    }

    await showLoadingPopup(x, y, scale);

    // Instant Cache Check
    chrome.runtime.sendMessage({ action: 'analyze_link', url, cache_only: true }, (response) => {
      if (hoverTargetUrl !== url) return; // Moved away
      if (response && response.success && !response.data.cache_miss) {

        if (activationTimer) {
          clearTimeout(activationTimer);
          activationTimer = null;
        }

        currentAnalysisUrl = url;
        currentRequestId = response.data.id || null;
        updatePopupWithResult(response.data);
      }
    });


    activationTimer = setTimeout(async () => {
      activationTimer = null; // Mark timer as fired
      if (hoverTargetUrl !== url) return;


      currentAnalysisUrl = url;
      currentRequestId = null;
      const seq = ++requestSequence;

      try {
        chrome.runtime.sendMessage({ action: 'analyze_link', url }, (response) => {
          if (currentAnalysisUrl !== url) return; // Stale response
          if (seq !== requestSequence) return; // Stale sequence
          if (response && response.success) {
            currentRequestId = response.data.id;
            updatePopupWithResult(response.data);
          } else {
            updatePopupWithError(response?.error || 'Unknown error');
          }
        });
      } catch (e) {

      }
    }, ACTIVATION_DELAY_MS);
  }, HOVER_DELAY_MS);
}

function handleLinkMouseLeave(event) {
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }

  if (activationTimer) {

    clearTimeout(activationTimer);
    activationTimer = null;
    // If we were waiting for activation, the scan hasn't started yet.
    // Close the popup since the user moved away.
    closePopup();
  }

  if (!currentAnalysisUrl && !currentRequestId) {
    hoverTargetUrl = null;
    activeAnchor = null;
    ++requestSequence;
    clearFreezeTimer();
    clearReconnectTimer();
    scanState = 'IDLE';
    try {
      chrome.runtime.sendMessage({ action: 'cancel_analysis' });
    } catch (e) { /* context may be invalid */ }
    return;
  }

  // Popup is already visible — preserve currentAnalysisUrl / currentRequestId
  // so that an in-flight phase2_result can still be matched and rendered.
  // closePopup() is the single authoritative site that clears analysis state.
  hoverTargetUrl = null;
  activeAnchor = null;
}

// Global event delegation on document body - catches all link hovers
document.addEventListener('mouseover', handleLinkMouseEnter, { capture: true });
document.addEventListener('mouseout', handleLinkMouseLeave, { capture: true });

// --- Initialization ---
initializeMutationObserver();

// Close popup when switching tabs or minimizing
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    closePopup();
  }
});

// Close popup if moving away from link and popup.
// During active scans (SCANNING / ANALYZING / RECONNECTING), suppress the
// auto-close entirely — the popup must stay alive so it can receive
// phase2_result when the scan or reconnect completes.
document.addEventListener('mousemove', (event) => {
  if (!isPopupValid()) return;

  // Keep popup alive while a scan is in progress
  if (scanState === 'SCANNING' || scanState === 'ANALYZING' || scanState === 'RECONNECTING') {
    if (closeTimer) {
      clearTimeout(closeTimer);
      closeTimer = null;
    }
    return;
  }

  const target = event.target.closest('a');
  const isOverPopup = currentPopupContainer.contains(event.target) ||
    (currentPopupShadowRoot && currentPopupShadowRoot.contains(event.composedPath()[0]));

  if (!target && !isOverPopup) {
    if (!closeTimer) {
      closeTimer = setTimeout(() => {
        closePopup();
      }, 500); // 500ms grace period to move cursor to popup
    }
  } else {
    if (closeTimer) {
      clearTimeout(closeTimer);
      closeTimer = null;
    }
  }
});

document.addEventListener('click', (event) => {
  if (!isPopupValid()) return;
  if (!currentPopupContainer.contains(event.target)) {
    if (currentPopupShadowRoot && currentPopupShadowRoot.contains(event.composedPath()[0])) {
      return;
    }
    closePopup();
  }
});

// Listen for messages from popup and background worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.action === 'settings_updated') {
    closePopup();
  } else if (message.action === 'set_override') {
    window.sessionStorage.setItem('vigilantlink_override', message.enabled ? 'enabled' : 'disabled');
    closePopup();
    sendResponse({ success: true });
  } else if (message.action === 'get_override') {
    sendResponse({ override: window.sessionStorage.getItem('vigilantlink_override') });
  } else if (message.action === 'phase1_result') {
    if (isPopupValid() && currentAnalysisUrl && message.url === currentAnalysisUrl) {
      updatePopupWithResult(message.data);
    }
  } else if (message.action === 'phase2_result') {
    if (!isPopupValid()) return;
    if (!currentAnalysisUrl) return; // Popup was closed; drop result

    const matchesId = currentRequestId !== null && message.requestId === currentRequestId;
    const matchesUrl = currentRequestId === null && message.url === currentAnalysisUrl;

    if (matchesId || matchesUrl) {
      if (matchesUrl && message.requestId) currentRequestId = message.requestId;
      mergeDeepScanResult(message.data);
    }
  } else if (message.action === 'phase2_error') {
    if (isPopupValid() && message.url === currentAnalysisUrl) {
      const idMatch = !currentRequestId || message.requestId === currentRequestId;
      if (idMatch) {
        clearFreezeTimer();
        // Preserve currentRequestId — we need it to resume polling
        if (message.requestId) currentRequestId = message.requestId;
        if (scanState === 'RECONNECTING') {
          // Already retrying — schedule the next attempt
          scheduleNextReconnect();
        } else {
          // First failure — enter recoverable reconnect mode
          enterReconnectingState();
        }
      }
    }
  }
});

function isPopupValid() {
  return currentPopupContainer !== null &&
    currentPopupContainer.isConnected &&
    currentPopupShadowRoot !== null &&
    currentPopupContent !== null;
}

function closePopup() {
  clearFreezeTimer();
  clearReconnectTimer();
  // Single authoritative cleanup site for all analysis state.
  scanState = 'IDLE';
  currentAnalysisUrl = null;
  currentRequestId = null;
  lastPhase1Result = null;
  if (currentPopupContainer) {
    if (currentPopupContainer.isConnected) {
      currentPopupContainer.remove();
    }
    currentPopupContainer = null;
    currentPopupShadowRoot = null;
    currentPopupContent = null;
  }
}

function clearFreezeTimer() {
  if (freezeTimer) {
    clearTimeout(freezeTimer);
    freezeTimer = null;
  }
}

function clearReconnectTimer() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

// ── Reconnect Recovery ─────────────────────────────────────────────────────

function enterReconnectingState() {
  scanState = 'RECONNECTING';
  reconnectStartTime = Date.now();
  showReconnectingUI();
  scheduleNextReconnect();
}

function scheduleNextReconnect() {
  clearReconnectTimer();
  reconnectTimer = setTimeout(attemptReconnectPoll, RECONNECT_INTERVAL_MS);
}

function attemptReconnectPoll() {
  reconnectTimer = null;
  if (!isPopupValid() || scanState !== 'RECONNECTING') return;

  if (Date.now() - reconnectStartTime > MAX_RECONNECT_DURATION_MS) {
    enterInterruptedState();
    return;
  }

  const url = currentAnalysisUrl;
  if (!url) {
    enterInterruptedState();
    return;
  }

  // Use Phase 1 analyze_link to re-establish connectivity and get a fresh ID if the old one died.
  // This ensures that as soon as the backend is back, we resume progress even if state was lost.
  chrome.runtime.sendMessage({ action: 'analyze_link', url }, (response) => {
    // Basic guard: ensure we are still in the same popup and reconnect session
    if (!isPopupValid() || scanState !== 'RECONNECTING' || currentAnalysisUrl !== url) return;

    if (response && response.success) {
      const data = response.data;
      if (data.s === 2) {
        // Result is already cached/complete! Transition to result view.
        finalizeReconnectCard(data);
      } else {
        // Phase 1 succeeded (got ID), move back to ANALYZING and wait for Phase 2.
        // The background script already started polling for data.id in its analyze_link handler.
        currentRequestId = data.id;
        scanState = 'ANALYZING';

        // Update UI to show we are back to analyzing
        const badge = currentPopupShadowRoot.querySelector('.badge');
        const logo = currentPopupShadowRoot.querySelector('.logo');
        if (badge) {
          badge.className = 'badge gray';
          badge.textContent = 'ANALYZING';
        }
        if (logo) {
          logo.textContent = 'VigilantLink: Scanning...';
        }
      }
    } else {
      // Still down or errored, schedule next retry
      scheduleNextReconnect();
    }
  });
}

function showReconnectingUI() {
  if (!isPopupValid()) return;

  const badge = currentPopupShadowRoot.querySelector('.badge');
  const header = currentPopupShadowRoot.querySelector('.header');
  const logo = currentPopupShadowRoot.querySelector('.logo');

  if (badge && header && logo) {
    // Popup already shows phase1 content — update header only
    header.className = 'header loading-header';
    badge.className = 'badge gray';
    badge.textContent = 'Reconnecting…';
    logo.textContent = 'VigilantLink: Waiting for backend…';
  } else {
    // Still in skeleton/loading state — rebuild as a minimal reconnect card
    currentPopupContent.textContent = '';

    const headerDiv = document.createElement('div');
    headerDiv.className = 'header loading-header';
    const logoDiv = document.createElement('div');
    logoDiv.className = 'logo';
    logoDiv.textContent = 'VigilantLink';
    headerDiv.appendChild(logoDiv);
    const badgeDiv = document.createElement('div');
    badgeDiv.className = 'badge gray';
    badgeDiv.textContent = 'Reconnecting…';
    headerDiv.appendChild(badgeDiv);
    currentPopupContent.appendChild(headerDiv);

    const bodyDiv = document.createElement('div');
    bodyDiv.className = 'body';
    const msgDiv = document.createElement('div');
    msgDiv.style.cssText = 'padding:20px 0;text-align:center;color:#888;font-size:13px;font-style:italic;';
    msgDiv.textContent = 'Waiting for backend to reconnect…';
    bodyDiv.appendChild(msgDiv);
    currentPopupContent.appendChild(bodyDiv);
    appendCardFooter();
  }
}

function enterInterruptedState() {
  scanState = 'INTERRUPTED';
  clearReconnectTimer();
  if (!isPopupValid()) return;

  const badge = currentPopupShadowRoot.querySelector('.badge');
  const header = currentPopupShadowRoot.querySelector('.header');
  const logo = currentPopupShadowRoot.querySelector('.logo');

  if (badge && header && logo) {
    header.className = 'header error-header';
    badge.className = 'badge gray';
    badge.textContent = 'Scan Timed Out';
    logo.textContent = 'VigilantLink: Limited Protection';
  } else {
    currentPopupContent.textContent = '';
    const headerDiv = document.createElement('div');
    headerDiv.className = 'header error-header';
    const logoDiv = document.createElement('div');
    logoDiv.className = 'logo';
    logoDiv.textContent = 'VigilantLink: Limited Protection';
    headerDiv.appendChild(logoDiv);
    const badgeDiv = document.createElement('div');
    badgeDiv.className = 'badge gray';
    badgeDiv.textContent = 'Scan Timed Out';
    headerDiv.appendChild(badgeDiv);
    currentPopupContent.appendChild(headerDiv);
  }
}

/**
 * Transitions the reconnect card in-place to the final scan result.
 * Updates the header badge/logo, then replaces the body content with the
 * full result (URL, screenshot, warning, forensics, redirects).
 * This avoids the jarring full-card rebuild that updatePopupWithResult does.
 */
function finalizeReconnectCard(data) {
  if (!isPopupValid()) return;

  const security = data.sec;
  if (!security) return;

  const { furl: final_url, hops: redirect_chain, ss: screenshot_base64,
    t: title, d: description, img: preview_image_url } = data;

  const verdictClass = security.v;
  let verdictText = security.safe ? 'Safe' : 'Suspicious';
  if (verdictClass === 'red') verdictText = 'Dangerous';

  // — 1. Update header in-place —
  const badge = currentPopupShadowRoot.querySelector('.badge');
  const header = currentPopupShadowRoot.querySelector('.header');
  const logo = currentPopupShadowRoot.querySelector('.logo');

  if (header && badge && logo) {
    header.className = `header ${verdictClass}-header`;
    badge.className = `badge ${verdictClass}`;
    badge.textContent = verdictText;
    logo.textContent = `Safety Score: ${100 - security.rs}/100`;
  } else {
    // Reconnect card lost its header nodes somehow — full rebuild
    updatePopupWithResult(data);
    return;
  }

  // — 2. Build a fresh body and swap it in —
  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'body';

  const warningBox = createWarningBox(verdictClass, security.tt);
  if (warningBox) bodyDiv.appendChild(warningBox);

  // Metadata Section (Title & Description) - Always render
  const metaSection = document.createElement('div');
  metaSection.className = 'metadata-section';

  const titleEl = document.createElement('div');
  titleEl.className = 'metadata-title';
  titleEl.textContent = title || currentLinkText || 'No title available';
  metaSection.appendChild(titleEl);

  const descEl = document.createElement('div');
  descEl.className = 'metadata-description';
  descEl.textContent = description || currentLinkDescription || 'No description available for this webpage.';
  if (!description && !currentLinkDescription) {
    descEl.style.fontStyle = 'italic';
  }
  metaSection.appendChild(descEl);

  bodyDiv.appendChild(metaSection);

  if (final_url) {
    const urlDestDiv = createUrlDestSection(final_url, security.da ?? null);
    bodyDiv.appendChild(urlDestDiv);
  }

  const screenshotContainer = document.createElement('div');
  screenshotContainer.className = 'screenshot-container';
  const placeholder = document.createElement('div');
  placeholder.className = 'preview-placeholder';
  const hasImage = !!(data.ss || data.img);
  const isPending = data.s === 1 || data.p3 === 'pending';
  if (isPending && !hasImage) {
    placeholder.textContent = 'Loading visual preview...';
  } else if (!hasImage) {
    placeholder.textContent = 'Visual preview unavailable';
  }
  screenshotContainer.appendChild(placeholder);

  const img = document.createElement('img');
  img.className = 'preview-image';
  img.alt = `Preview of ${final_url}`;
  const displayImage = screenshot_base64 || preview_image_url;
  if (displayImage) {
    img.onload = () => {
      img.classList.add('loaded');
      placeholder.style.opacity = '0';
    };
    img.onerror = () => { };
    img.src = displayImage;
  }
  screenshotContainer.appendChild(img);
  bodyDiv.appendChild(screenshotContainer);

  const infoDiv = document.createElement('div');
  infoDiv.className = 'info';
  let filteredReasons = security.r || [];
  if (verdictClass === 'green') {
    filteredReasons = filteredReasons.filter(r =>
      !r.includes('Uncertainty penalty') && !r.includes('timed out') && !r.includes('Limited security data')
    );
  }
  const forensicSection = createForensicSection(filteredReasons);
  if (forensicSection) infoDiv.appendChild(forensicSection);
  const redirectsSection = createRedirectsSection(redirect_chain);
  if (redirectsSection) infoDiv.appendChild(redirectsSection);
  bodyDiv.appendChild(infoDiv);

  // Swap: remove old body (reconnect message) and insert fresh result body
  const existingBody = currentPopupShadowRoot.querySelector('.body');
  if (existingBody) {
    existingBody.replaceWith(bodyDiv);
  } else {
    currentPopupContent.appendChild(bodyDiv);
  }

  if (final_url) attachPopupEventHandlers(final_url);
}

async function createShadowPopup(x, y, scale = 1) {
  if (currentPopupContainer) {
    closePopup();
  }

  const styleUrl = chrome.runtime.getURL("styles/shadow-styles.css");
  if (!styleUrl) {
    console.error("VigilantLink: Shadow styles not found!");
    return;
  }

  const theme = await getTheme();

  const container = document.createElement("div");
  container.className = `theme-${theme}`;
  // Container positioning
  container.style.position = "fixed";
  container.style.left = `${x}px`;
  container.style.top = `${y}px`;
  container.style.zIndex = "2147483647"; // Max z-index
  container.style.transform = `scale(${scale})`;
  container.style.transformOrigin = "top left";

  // Use closed mode for Zero-Trust isolation from host page JS
  const shadowRoot = container.attachShadow({ mode: "closed" });
  currentPopupShadowRoot = shadowRoot;

  const styleLink = document.createElement("link");
  styleLink.rel = "stylesheet";
  styleLink.href = styleUrl;
  shadowRoot.appendChild(styleLink);

  const content = document.createElement("div");
  content.className = "vigilant-card";
  shadowRoot.appendChild(content);

  document.body.appendChild(container);

  currentPopupContainer = container;
  currentPopupContent = content;
}

function appendCardFooter() {
  if (!currentPopupContent) return;
  const footerDiv = document.createElement('div');
  footerDiv.className = 'card-footer';

  const disclaimer = document.createElement('div');
  disclaimer.className = 'disclaimer-text';
  disclaimer.textContent = 'Scans are advisory and not absolute. Always exercise caution and verify links independently.';
  footerDiv.appendChild(disclaimer);

  currentPopupContent.appendChild(footerDiv);
}

async function showLoadingPopup(x, y, scale = 1) {
  await createShadowPopup(x, y, scale);
  if (!currentPopupContent) return;

  clearFreezeTimer();
  scanState = 'SCANNING';
  freezeTimer = setTimeout(() => {
    // Do NOT finalize the popup while the reconnect mechanism is active.
    if (isPopupValid() && scanState !== 'RECONNECTING' && scanState !== 'FINALIZED' && scanState !== 'INTERRUPTED') {
      if (lastPhase1Result) {
        resolvePhase1AsFinal(lastPhase1Result);
      } else {
        closePopup();
      }
    }
  }, FREEZE_TIMEOUT_MS);

  currentPopupContent.textContent = '';

  const headerDiv = document.createElement('div');
  headerDiv.className = 'header loading-header';

  const logoDiv = document.createElement('div');
  logoDiv.className = 'logo';
  logoDiv.textContent = 'VigilantLink';
  headerDiv.appendChild(logoDiv);

  const badgeDiv = document.createElement('div');
  badgeDiv.className = 'badge gray loading-badge';
  badgeDiv.textContent = 'Analyzing...';
  headerDiv.appendChild(badgeDiv);

  currentPopupContent.appendChild(headerDiv);

  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'body';

  const skeletonText1 = document.createElement('div');
  skeletonText1.className = 'skeleton-text short pulse-anim';
  bodyDiv.appendChild(skeletonText1);

  const skeletonText2 = document.createElement('div');
  skeletonText2.className = 'skeleton-text pulse-anim';
  bodyDiv.appendChild(skeletonText2);

  const skeletonImg = document.createElement('div');
  skeletonImg.className = 'skeleton-img pulse-anim';
  bodyDiv.appendChild(skeletonImg);

  currentPopupContent.appendChild(bodyDiv);
  appendCardFooter();
}

function getBadgeColor(reason) {
  if (reason.includes('Punycode')) return 'red';
  if (reason.includes('Excessive Redirect') || reason.includes('Cross-Domain')) return 'orange';
  if (reason.includes('Typosquatting') || reason.includes('impersonation')) return 'red';
  if (reason.includes('Synergy') || reason.includes('Homograph')) return 'red';
  if (reason.includes('Recently issued') || reason.includes('SSL certificate')) return 'orange';
  if (reason.includes('not encrypted') || reason.includes('HTTP')) return 'orange';
  if (reason.includes('Flagged')) return 'orange';
  return 'gray';
}

function cleanThreatExplanation(reason) {
  const explanations = {
    'Punycode Homograph Attack': 'Punycode domain trick',
    'Typosquatting Detected': 'Possible impersonation attempt',
    'Excessive Redirect Chain': 'Trusted authentication redirect flow detected.',
    'Connection is not encrypted': 'No encryption (HTTP)',
    'Invalid SSL certificate': 'Certificate error',
    'Suspicious Keywords': 'Suspicious content detected',
    'Synergy': 'High-risk combination',
    'Phishing keyword': 'Phishing attempt',
    'CRITICAL: Punycode': 'Punycode domain trick',
    'CRITICAL: Flagged': 'Flagged by security vendors',
    'CRITICAL: VirusTotal': 'Flagged by VirusTotal',
    'Flagged by': 'Flagged by vendors',
    'Recently issued SSL certificate': 'New SSL certificate',
    'Young SSL certificate': 'Young SSL certificate',
    'does not resolve': 'Domain invalid',
    'Suspicious TLD': 'Suspicious domain extension',
    'Uncertainty penalty': 'Limited security data',
  };

  for (const [key, value] of Object.entries(explanations)) {
    if (reason.includes(key)) return value;
  }

  return reason.length > 50 ? reason.substring(0, 47) + '...' : reason;
}

function createWarningBox(verdictClass, threatType) {
  if (verdictClass === 'green' || verdictClass === 'gray') return null;

  const warningBox = document.createElement('div');
  warningBox.className = `warning-box ${verdictClass}`;

  const strong = document.createElement('strong');
  strong.textContent = 'Warning: ';
  warningBox.appendChild(strong);

  const text = document.createTextNode(threatType || 'Potential risk detected');
  warningBox.appendChild(text);

  return warningBox;
}

function createRedirectsSection(redirectChain) {
  if (!redirectChain || redirectChain.length <= 1) return null;

  const maxCompact = 3;
  const showUrls = redirectChain.slice(0, maxCompact).map(r => {
    try { return new URL(r.u).hostname; } catch { return r.u; }
  });
  const hiddenCount = redirectChain.length - maxCompact;
  const compactText = showUrls.join(' → ');

  const redirectsDiv = document.createElement('div');
  redirectsDiv.className = 'redirects';
  redirectsDiv.style.marginTop = '8px';
  redirectsDiv.style.paddingTop = '8px';
  redirectsDiv.style.borderTop = '1px dashed #eee';

  const titleSmall = document.createElement('small');
  titleSmall.style.fontWeight = '600';
  titleSmall.style.color = '#555';
  titleSmall.textContent = 'Redirect Path:';
  redirectsDiv.appendChild(titleSmall);

  const pathDiv = document.createElement('div');
  pathDiv.style.fontSize = '10px';
  pathDiv.style.color = '#666';
  pathDiv.style.marginTop = '4px';
  pathDiv.style.wordBreak = 'break-all';

  const compactSpan = document.createElement('span');
  compactSpan.id = 'redirects-compact';
  compactSpan.textContent = compactText;
  pathDiv.appendChild(compactSpan);

  if (hiddenCount > 0) {
    const moreSpan = document.createElement('span');
    moreSpan.id = 'redirects-more';
    moreSpan.style.cursor = 'pointer';
    moreSpan.style.color = '#0056b3';
    moreSpan.style.marginLeft = '4px';
    moreSpan.textContent = `+${hiddenCount} more`;
    pathDiv.appendChild(moreSpan);

    const fullDiv = document.createElement('div');
    fullDiv.id = 'redirects-full';
    fullDiv.style.display = 'none';
    fullDiv.style.maxHeight = '150px';
    fullDiv.style.overflowY = 'auto';
    fullDiv.style.marginTop = '6px';
    fullDiv.style.padding = '6px 8px';
    fullDiv.style.background = '#f8f9fa';
    fullDiv.style.borderRadius = '4px';
    fullDiv.style.fontSize = '10px';
    fullDiv.style.color = '#666';

    redirectChain.forEach(r => {
      const urlDiv = document.createElement('div');
      urlDiv.style.marginBottom = '3px';
      urlDiv.style.wordBreak = 'break-all';
      const arrow = document.createElement('span');
      arrow.appendChild(document.createTextNode('\u2192 '));
      urlDiv.appendChild(arrow);
      const urlText = document.createTextNode(r.u);
      urlDiv.appendChild(urlText);
      fullDiv.appendChild(urlDiv);
    });

    const toggleBtn = document.createElement('button');
    toggleBtn.id = 'redirects-toggle-btn';
    toggleBtn.style.marginTop = '6px';
    toggleBtn.style.padding = '3px 10px';
    toggleBtn.style.border = '1px solid #ddd';
    toggleBtn.style.borderRadius = '4px';
    toggleBtn.style.background = '#f8f9fa';
    toggleBtn.style.fontSize = '9px';
    toggleBtn.style.cursor = 'pointer';
    toggleBtn.style.color = '#333';
    toggleBtn.style.fontWeight = '600';
    toggleBtn.textContent = 'Show full path';

    redirectsDiv.appendChild(pathDiv);
    redirectsDiv.appendChild(fullDiv);
    redirectsDiv.appendChild(toggleBtn);
  } else {
    redirectsDiv.appendChild(pathDiv);
  }

  return redirectsDiv;
}

function createForensicSection(reasons) {
  if (!reasons || reasons.length === 0) return null;

  const reasonsDiv = document.createElement('div');
  reasonsDiv.className = 'reasons';

  const titleDiv = document.createElement('div');
  titleDiv.className = 'reasons-title';
  titleDiv.textContent = 'Reasons';
  reasonsDiv.appendChild(titleDiv);

  const badgeListDiv = document.createElement('div');
  badgeListDiv.className = 'badge-list';

  reasons.forEach(r => {
    const cleaned = cleanThreatExplanation(r);
    const badge = document.createElement('span');
    badge.className = `forensic-badge ${getBadgeColor(r)}`;
    badge.textContent = cleaned;
    badge.title = r;
    badgeListDiv.appendChild(badge);
  });

  reasonsDiv.appendChild(badgeListDiv);
  return reasonsDiv;
}

function formatDaysToAge(days) {
  if (days === null || days === undefined) return '';
  if (days < 30) return `${Math.max(1, days)}D`;
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  if (years === 0) return months > 0 ? `${months}M` : `${days}D`;
  if (months === 0) return `${years}Y`;
  return `${years}Y ${months}M`;
}

function formatShortAge(rawAge) {
  if (!rawAge || rawAge === 'Unknown' || rawAge === 'Loading...') return '';
  return rawAge
    .replace(/Years?/gi, 'Y')
    .replace(/Months?/gi, 'M')
    .replace(/Days?/gi, 'D')
    .replace(/(\d+)\s+([YMD])/gi, '$1$2')
    .replace(/\s+/g, ' ')
    .trim();
}

function createUrlDestSection(finalUrl, ageDays) {
  const urlDestDiv = document.createElement('div');
  urlDestDiv.className = 'url-dest';

  const destLabel = document.createElement('strong');
  destLabel.textContent = 'Dest: ';
  urlDestDiv.appendChild(destLabel);

  const linkEl = document.createElement('a');
  linkEl.href = finalUrl;
  linkEl.target = '_blank';
  linkEl.rel = 'noopener noreferrer';
  linkEl.title = finalUrl;
  linkEl.textContent = finalUrl;
  urlDestDiv.appendChild(linkEl);

  const copyBtn = document.createElement('span');
  copyBtn.id = 'copy-dest-btn';
  copyBtn.title = 'Copy URL';

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '12');
  svg.setAttribute('height', '12');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.style.pointerEvents = 'none';

  const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  rect.setAttribute('x', '9');
  rect.setAttribute('y', '9');
  rect.setAttribute('width', '13');
  rect.setAttribute('height', '13');
  rect.setAttribute('rx', '2');
  rect.setAttribute('ry', '2');
  svg.appendChild(rect);

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1');
  svg.appendChild(path);

  copyBtn.appendChild(svg);
  urlDestDiv.appendChild(copyBtn);

  const ageEl = document.createElement('span');
  ageEl.className = 'url-dest-age';
  const ageText = formatDaysToAge(ageDays);
  if (ageText) {
    ageEl.textContent = `${ageText} old`;
  } else if (ageDays === null) {
    ageEl.textContent = 'Age: N/A';
  } else {
    ageEl.textContent = 'Scanning...';
  }
  urlDestDiv.appendChild(ageEl);

  return urlDestDiv;
}

function updatePopupWithResult(data) {
  if (!isPopupValid()) return;

  clearFreezeTimer();
  if (data.s === 1) {
    lastPhase1Result = data;
    scanState = 'ANALYZING';
  } else if (data.s === 2) {
    scanState = 'FINALIZED';
  }

  const { url: original_url, furl: final_url, hops: redirect_chain, ss: screenshot_base64, sec: security, t: title, d: description, img: preview_image_url } = data;

  currentPopupContent.textContent = '';

  let verdictClass = security.v;
  let verdictText = security.safe ? 'Safe' : 'Suspicious';
  if (verdictClass === 'red') verdictText = 'Dangerous';

  // Issue 1: Prevent false "Safe" during Phase 1
  if (data.s === 1) {
    verdictClass = 'gray';
    verdictText = 'ANALYZING';
  }

  const headerDiv = document.createElement('div');
  headerDiv.className = `header ${data.s === 1 ? '' : verdictClass + '-header'}`;

  const logoDiv = document.createElement('div');
  logoDiv.className = 'logo';
  logoDiv.textContent = data.s === 1 ? 'VigilantLink: Scanning...' : `Safety Score: ${100 - security.rs}/100`;
  headerDiv.appendChild(logoDiv);

  const badgeDiv = document.createElement('div');
  badgeDiv.className = `badge ${verdictClass}`;
  badgeDiv.textContent = verdictText;
  headerDiv.appendChild(badgeDiv);

  currentPopupContent.appendChild(headerDiv);

  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'body';

  const warningBox = createWarningBox(verdictClass, security.tt);
  if (warningBox) bodyDiv.appendChild(warningBox);

  // Metadata Section (Title & Description) - Always render
  const metaSection = document.createElement('div');
  metaSection.className = 'metadata-section';

  const titleEl = document.createElement('div');
  titleEl.className = 'metadata-title';
  titleEl.textContent = title || currentLinkText || 'No title available';
  metaSection.appendChild(titleEl);

  const descEl = document.createElement('div');
  descEl.className = 'metadata-description';
  descEl.textContent = description || currentLinkDescription || 'No description available for this webpage.';
  if (!description && !currentLinkDescription) {
    descEl.style.fontStyle = 'italic';
  }
  metaSection.appendChild(descEl);

  bodyDiv.appendChild(metaSection);

  if (final_url) {
    const urlDestDiv = createUrlDestSection(final_url, security.da ?? null);
    bodyDiv.appendChild(urlDestDiv);
  }


  const screenshotContainer = document.createElement('div');
  screenshotContainer.className = 'screenshot-container';

  const makePlaceholder = () => {
    const d = document.createElement('div');
    d.className = 'preview-placeholder';
    const hasImage = !!(data.ss || data.img);
    const isPending = data.s === 1 || data.p3 === 'pending';
    if (isPending && !hasImage) {
      d.textContent = 'Loading visual preview...';
    } else if (!hasImage) {
      d.textContent = 'Visual preview unavailable';
    }
    return d;
  };

  const placeholder = makePlaceholder();
  screenshotContainer.appendChild(placeholder);

  const img = document.createElement('img');
  img.className = 'preview-image';
  img.alt = `Preview of ${final_url}`;

  const displayImage = screenshot_base64 || preview_image_url;
  if (displayImage) {
    img.onload = () => {
      img.classList.add('loaded');
      placeholder.style.opacity = '0';
    };
    img.onerror = () => { };
    img.src = displayImage;
  }

  screenshotContainer.appendChild(img);
  bodyDiv.appendChild(screenshotContainer);

  const infoDiv = document.createElement('div');
  infoDiv.className = 'info';

  let filteredReasons = security.r || [];

  // Suppress uncertainty penalty and internal reasons for safe verdicts
  if (verdictClass === 'green') {
    filteredReasons = filteredReasons.filter(r =>
      !r.includes('Uncertainty penalty') &&
      !r.includes('timed out') &&
      !r.includes('Limited security data')
    );
  }

  const forensicSection = createForensicSection(filteredReasons);
  if (forensicSection) infoDiv.appendChild(forensicSection);

  const redirectsSection = createRedirectsSection(redirect_chain);
  if (redirectsSection) infoDiv.appendChild(redirectsSection);

  bodyDiv.appendChild(infoDiv);
  currentPopupContent.appendChild(bodyDiv);
  appendCardFooter();

  attachPopupEventHandlers(final_url);
}

function resolvePhase1AsFinal(data) {
  if (!isPopupValid()) return;
  const sec = data.sec || data.security;
  if (!sec) return;
  const badge = currentPopupShadowRoot.querySelector('.badge');
  const header = currentPopupShadowRoot.querySelector('.header');
  const logo = currentPopupShadowRoot.querySelector('.logo');
  if (!badge || !header || !logo) return;
  let verdictClass = sec.v;
  let verdictText = sec.safe ? 'Safe' : 'Suspicious';
  if (verdictClass === 'red') verdictText = 'Dangerous';
  header.className = `header ${verdictClass}-header`;
  badge.className = `badge ${verdictClass}`;
  badge.textContent = verdictText;
  logo.textContent = `Safety Score: ${100 - sec.rs}/100`;
}

/**
 * Merges Phase 2 deep scan results into the existing popup.
 * Updates badge color, risk score, and forensic details with smooth transitions.
 */
function mergeDeepScanResult(data) {
  if (!isPopupValid()) return;
  clearFreezeTimer();
  clearReconnectTimer();

  const security = data.sec;
  if (!security) return;

  // Capture previous state before updating, so the routing decision below
  // is based on where we were, not where we're going.
  const prevState = scanState;
  scanState = 'FINALIZED';

  // Route based on previous state:
  // ANALYZING / FINALIZED → incremental patch (header + forensics only, body DOM is already full)
  // RECONNECTING → in-card transition (header patch + body swap)
  // anything else → full rebuild (phase1 never rendered a result)
  if (prevState === 'RECONNECTING') {
    finalizeReconnectCard(data);
    return;
  }
  if (prevState !== 'ANALYZING' && prevState !== 'FINALIZED') {
    updatePopupWithResult(data);
    return;
  }

  // --- Incremental patch path (popup already shows phase1 result) ---

  const badge = currentPopupShadowRoot.querySelector('.badge');
  const header = currentPopupShadowRoot.querySelector('.header');
  const logo = currentPopupShadowRoot.querySelector('.logo');

  if (header && badge && logo) {
    const verdictClass = security.v;
    let verdictText = security.safe ? 'Safe' : 'Suspicious';
    if (verdictClass === 'red') verdictText = 'Dangerous';

    // Only update if changed to avoid micro-flicker
    if (badge.textContent !== verdictText) {
      header.className = `header ${verdictClass}-header`;
      badge.className = `badge ${verdictClass}`;
      badge.textContent = verdictText;
      logo.textContent = `Safety Score: ${100 - security.rs}/100`;
    }
  }

  // Update or add warning box
  const body = currentPopupShadowRoot.querySelector('.body');
  if (body) {
    const existingWarning = currentPopupShadowRoot.querySelector('.warning-box');
    const newWarning = createWarningBox(security.v, security.tt);

    // Only patch if warning box changed
    if (existingWarning && newWarning && existingWarning.className !== newWarning.className) {
      existingWarning.replaceWith(newWarning);
    } else if (!existingWarning && newWarning) {
      body.insertBefore(newWarning, body.firstChild);
    } else if (existingWarning && !newWarning) {
      existingWarning.remove();
    }

    // Update or add forensic section
    const existingInfo = currentPopupShadowRoot.querySelector('.info');
    if (existingInfo && security.r && security.r.length > 0) {
      let filteredReasons = security.r;

      // Suppress uncertainty penalty and internal reasons for safe verdicts
      if (security.v === 'green') {
        filteredReasons = security.r.filter(r =>
          !r.includes('Uncertainty penalty') &&
          !r.includes('timed out') &&
          !r.includes('Limited security data')
        );
      }

      // Check if reasons actually changed before wiping the text (prevents flicker on Phase 3)
      const currentBadges = existingInfo.querySelectorAll('.forensic-badge');
      const currentTexts = Array.from(currentBadges).map(b => b.textContent).join('|');
      const newTexts = filteredReasons.join('|');

      if (currentTexts !== newTexts) {
        existingInfo.textContent = '';
        const forensicSection = createForensicSection(filteredReasons);
        if (forensicSection) existingInfo.appendChild(forensicSection);
      }
    }

    // Patch domain age badge once Phase 2 data (with da) arrives
    if (security.da !== undefined) {
      const ageEl = currentPopupShadowRoot.querySelector('.url-dest-age');
      if (ageEl) {
        const ageText = formatDaysToAge(security.da);
        if (ageText) {
          ageEl.textContent = `${ageText} old`;
        } else {
          ageEl.textContent = 'Age: N/A';
        }
      }
    }
  }

  // Update screenshot if Phase 3 provided one
  if (data.ss) {
    const container = currentPopupShadowRoot.querySelector('.screenshot-container');
    if (container) {
      let img = container.querySelector('.preview-image');
      let placeholder = container.querySelector('.preview-placeholder');

      if (!img) {
        img = document.createElement('img');
        img.className = 'preview-image';
        img.alt = 'Site preview';
        container.appendChild(img);
      }

      if (!placeholder) {
        placeholder = document.createElement('div');
        placeholder.className = 'preview-placeholder';
        container.insertBefore(placeholder, container.firstChild);
      }

      if (img.src !== data.ss) {
        if (!img.classList.contains('loaded')) {
          placeholder.textContent = 'Rendering preview...';
        }

        img.onload = () => {
          img.classList.add('loaded');
          placeholder.style.opacity = '0';
          const card = currentPopupShadowRoot?.querySelector('.vigilant-card') || currentPopupContent;
          if (card) console.log(`[VigilantLink] Final card size: ${card.offsetWidth}x${card.offsetHeight}`);
        };
        img.onerror = () => { };
        img.src = data.ss;
      }
    }
  } else {
    const placeholder = currentPopupShadowRoot.querySelector('.preview-placeholder');
    if (placeholder) {
      const hasImage = !!(data.ss || data.img);
      const isPending = data.p3 === 'pending';
      if (isPending && !hasImage) {
        placeholder.textContent = 'Loading visual preview...';
      } else if (!hasImage) {
        placeholder.textContent = 'Visual preview unavailable';
      }
    }
  }
  const card = currentPopupShadowRoot?.querySelector('.vigilant-card') || currentPopupContent;
  if (card) console.log(`[VigilantLink] Card size after Phase 2/3: ${card.offsetWidth}x${card.offsetHeight}`);
}

function attachPopupEventHandlers(finalUrl) {
  const shadowRoot = currentPopupShadowRoot;
  if (!shadowRoot) return;

  shadowRoot.addEventListener('click', async (e) => {
    const copyBtn = e.target.closest('#copy-dest-btn');
    if (copyBtn) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      try {
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(finalUrl);
          const originalSvg = copyBtn.innerHTML;
          copyBtn.textContent = '';
          const successSpan = document.createElement('span');
          successSpan.className = 'copy-status-success';
          successSpan.textContent = '✓';
          copyBtn.appendChild(successSpan);
          setTimeout(() => {
            copyBtn.innerHTML = originalSvg;
          }, 1500);
        } else {
          throw new Error('Clipboard API not available');
        }
      } catch (err) {
        console.error('VigilantLink Copy Error: ', err);
        const originalSvg = copyBtn.innerHTML;
        copyBtn.textContent = '';
        const errorSpan = document.createElement('span');
        errorSpan.className = 'copy-status-error';
        errorSpan.textContent = '✗';
        copyBtn.appendChild(errorSpan);
        setTimeout(() => {
          copyBtn.innerHTML = originalSvg;
        }, 1500);
      }
      return;
    }

    const toggleBtn = e.target.closest('#redirects-toggle-btn');
    const moreLink = e.target.closest('#redirects-more');
    if (toggleBtn || moreLink) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      const fullView = shadowRoot.getElementById('redirects-full');
      const compactView = shadowRoot.getElementById('redirects-compact');
      const moreEl = shadowRoot.getElementById('redirects-more');
      const btn = shadowRoot.getElementById('redirects-toggle-btn');
      if (!fullView) return;

      const isExpanded = fullView.style.display === 'block';
      fullView.style.display = isExpanded ? 'none' : 'block';
      if (compactView) compactView.style.display = isExpanded ? 'inline' : 'none';
      if (moreEl) moreEl.style.display = isExpanded ? 'inline' : 'inline';
      if (btn) btn.textContent = isExpanded ? 'Show full path' : 'Collapse path';
      return;
    }


  });
}

function updatePopupWithError(errorMsg) {
  if (!isPopupValid()) return;
  clearFreezeTimer();
  currentPopupContent.textContent = '';

  const headerDiv = document.createElement('div');
  headerDiv.className = 'header error-header';

  const logoDiv = document.createElement('div');
  logoDiv.className = 'logo';
  logoDiv.textContent = 'VigilantLink';
  headerDiv.appendChild(logoDiv);

  const badgeDiv = document.createElement('div');
  badgeDiv.className = 'badge red';
  badgeDiv.textContent = 'Error';
  headerDiv.appendChild(badgeDiv);

  currentPopupContent.appendChild(headerDiv);

  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'body error-body';

  const p = document.createElement('p');
  p.textContent = 'Failed to analyze link.';
  bodyDiv.appendChild(p);

  const small = document.createElement('small');
  small.textContent = errorMsg;
  bodyDiv.appendChild(small);

  currentPopupContent.appendChild(bodyDiv);
  appendCardFooter();
}

// ============================================================
// SPA Navigation Cleanup
// ============================================================

window.addEventListener('popstate', () => {
  closePopup();
});

window.addEventListener('hashchange', () => {
  closePopup();
});

function patchSpaNavigation() {
  if (spaPatched) return;
  spaPatched = true;
  const origPushState = history.pushState;
  const origReplaceState = history.replaceState;
  history.pushState = function (...args) {
    origPushState.apply(this, args);
    closePopup();
  };
  history.replaceState = function (...args) {
    origReplaceState.apply(this, args);
    closePopup();
  };
}
patchSpaNavigation();

// Lightweight location change watchdog
spaInterval = setInterval(() => {
  const currentUrl = location.href;
  if (currentUrl !== lastLocation) {
    lastLocation = currentUrl;
    closePopup();
  }
}, 1000);


