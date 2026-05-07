// Hover detection with Event Delegation, Debouncing, and Top Layer Z-Index
// Designed for Shadow DOM and AJAX-loaded content

let hoverTimer = null;
let hoverTargetUrl = null;
let closeTimer = null;
let currentPopupContainer = null;
let currentPopupShadowRoot = null;
let currentPopupContent = null;
const HOVER_DELAY_MS = 100;
let mutationObserver = null;
const processedLinks = new WeakSet();
let currentAnalysisUrl = null;

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
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

const DEFAULT_SETTINGS = {
  globalEnabled: true,
  disabledSites: []
};

// Check if VigilantLink is enabled for current site
async function isEnabledForSite() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['globalEnabled', 'disabledSites'], (result) => {
      const override = window.sessionStorage.getItem('vigilantlink_override');
      if (override === 'enabled') return resolve(true);
      if (override === 'disabled') return resolve(false);

      const globalEnabled = result.globalEnabled !== false;
      const disabledSites = result.disabledSites || [];
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
  hoverTargetUrl = url;

  if (hoverTimer) clearTimeout(hoverTimer);

  // Debounced hover popup display
  hoverTimer = setTimeout(async () => {
    if (hoverTargetUrl !== url) return;

    const rect = target.getBoundingClientRect();
    let x = rect.right + 10;
    let y = rect.top;

    const POPUP_WIDTH = 340;
    const POPUP_HEIGHT = 450;

    // Position popup with edge detection
    if (x + POPUP_WIDTH > window.innerWidth) {
      x = rect.left - POPUP_WIDTH - 10;
    }
    if (x < 0) x = 10;

    if (y + POPUP_HEIGHT > window.innerHeight) {
      y = rect.bottom - POPUP_HEIGHT;
    }
    if (y < 0) y = 10;

    showLoadingPopup(x, y);

    currentAnalysisUrl = url;

    try {
      chrome.runtime.sendMessage({ action: 'analyze_link', url }, (response) => {
        if (currentAnalysisUrl !== url) return; // Stale response
        if (response && response.success) {
          updatePopupWithResult(response.data);
        } else {
          updatePopupWithError(response?.error || 'Unknown error');
        }
      });
    } catch (e) {
      console.warn('VigilantLink: Context invalidated. Refresh page.', e);
    }
  }, HOVER_DELAY_MS);
}

function handleLinkMouseLeave(event) {
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
  hoverTargetUrl = null;
  currentAnalysisUrl = null;

  // Cancel in-flight backend request
  try {
    chrome.runtime.sendMessage({ action: 'cancel_analysis' });
  } catch (e) { /* context may be invalid */ }
}

// Global event delegation on document body - catches all link hovers
document.addEventListener('mouseover', handleLinkMouseEnter, { capture: true });
document.addEventListener('mouseout', handleLinkMouseLeave, { capture: true });

// Initialize observer for AJAX and dynamic content
initializeMutationObserver();

// Close popup if moving away from link and popup
document.addEventListener('mousemove', (event) => {
    if (currentPopupContainer) {
        const target = event.target.closest('a');
        const isOverPopup = currentPopupContainer.contains(event.target) ||
            (currentPopupShadowRoot && currentPopupShadowRoot.contains(event.composedPath()[0]));

        if (!target && !isOverPopup) {
            if (!closeTimer) {
                closeTimer = setTimeout(() => {
                    closePopup();
                }, 300);
            }
        } else {
            if (closeTimer) {
                clearTimeout(closeTimer);
                closeTimer = null;
            }
        }
    }
});

document.addEventListener('click', (event) => {
  if (currentPopupContainer && !currentPopupContainer.contains(event.target)) {
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
    // Progressive update: Phase 1 instant result
    if (currentPopupContent && currentAnalysisUrl) {
      updatePopupWithResult(message.data);
    }
  } else if (message.action === 'phase2_result') {
    // Progressive update: Phase 2 deep scan result
    if (currentPopupContent && currentAnalysisUrl) {
      mergeDeepScanResult(message.data);
    }
  }
});

function closePopup() {
    if (currentPopupContainer) {
        currentPopupContainer.remove();
        currentPopupContainer = null;
        currentPopupShadowRoot = null;
        currentPopupContent = null;
    }
}

function createShadowPopup(x, y) {
  closePopup();

  let styleUrl = "";
  try {
      styleUrl = chrome.runtime.getURL("styles/shadow-styles.css");
  } catch (e) {
      console.warn("VigilantLink: Extension context invalidated. Please refresh the page.");
      return;
  }

  const container = document.createElement("div");
  // Container positioning
  container.style.position = "fixed";
  container.style.left = `${x}px`;
  container.style.top = `${y}px`;
  container.style.zIndex = "2147483647"; // Max z-index
   
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

function showLoadingPopup(x, y) {
  createShadowPopup(x, y);
  if (!currentPopupContent) return;

  currentPopupContent.textContent = '';

  const headerDiv = document.createElement('div');
  headerDiv.className = 'header loading-header';

  const logoDiv = document.createElement('div');
  logoDiv.className = 'logo';
  logoDiv.textContent = 'VigilantLink';
  headerDiv.appendChild(logoDiv);

  const badgeDiv = document.createElement('div');
  badgeDiv.className = 'badge gray';
  badgeDiv.textContent = 'Analyzing...';
  headerDiv.appendChild(badgeDiv);

  currentPopupContent.appendChild(headerDiv);

  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'body';

  const skeletonImg = document.createElement('div');
  skeletonImg.className = 'skeleton-img pulse-anim';
  bodyDiv.appendChild(skeletonImg);

  const skeletonText1 = document.createElement('div');
  skeletonText1.className = 'skeleton-text pulse-anim';
  bodyDiv.appendChild(skeletonText1);

  const skeletonText2 = document.createElement('div');
  skeletonText2.className = 'skeleton-text short pulse-anim';
  bodyDiv.appendChild(skeletonText2);

  currentPopupContent.appendChild(bodyDiv);
}

function getBadgeColor(reason) {
  if (reason.includes('Punycode')) return 'red';
  if (reason.includes('Excessive Redirect Chain') || reason.includes('Cross-Domain')) return 'orange';
  if (reason.includes('Typosquatting') || reason.includes('Synergy')) return 'red';
  if (reason.includes('Newly Registered')) return 'orange';
  return 'gray';
}

function createWarningBox(verdictClass, threatType) {
  if (verdictClass === 'green') return null;

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
  pathDiv.style.fontSize = '11px';
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
    fullDiv.style.fontSize = '11px';
    fullDiv.style.color = '#666';

    redirectChain.forEach(r => {
      const urlDiv = document.createElement('div');
      urlDiv.style.marginBottom = '3px';
      urlDiv.style.wordBreak = 'break-all';
      const arrow = document.createElement('span');
      arrow.innerHTML = '&rarr; ';
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
    toggleBtn.style.fontSize = '10px';
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
  titleDiv.textContent = 'Forensic Analysis';
  reasonsDiv.appendChild(titleDiv);

  const badgeListDiv = document.createElement('div');
  badgeListDiv.className = 'badge-list';

  reasons.forEach(r => {
    const badge = document.createElement('span');
    badge.className = `forensic-badge ${getBadgeColor(r)}`;
    badge.textContent = r;
    badgeListDiv.appendChild(badge);
  });

  reasonsDiv.appendChild(badgeListDiv);
  return reasonsDiv;
}

function updatePopupWithResult(data) {
  if (!currentPopupContent) return;

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
  logoDiv.textContent = data.s === 1 ? 'VigilantLink: Scanning...' : `VigilantLink Score: ${security.rs}/100`;
  logoDiv.style.fontSize = '14px';
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

  // Metadata Section (Title & Description)
  if (title || description) {
    const metaSection = document.createElement('div');
    metaSection.className = 'metadata-section';
    
    if (title) {
      const titleEl = document.createElement('div');
      titleEl.className = 'metadata-title';
      titleEl.textContent = title;
      metaSection.appendChild(titleEl);
    }
    
    if (description) {
      const descEl = document.createElement('div');
      descEl.className = 'metadata-description';
      descEl.textContent = description;
      metaSection.appendChild(descEl);
    }
    
    bodyDiv.appendChild(metaSection);
  }

  const urlDestDiv = document.createElement('div');
  urlDestDiv.className = 'url-dest';
  urlDestDiv.style.marginBottom = '8px';
  urlDestDiv.style.fontSize = '11px';
  urlDestDiv.style.color = '#555';
  urlDestDiv.style.display = 'flex';
  urlDestDiv.style.alignItems = 'center';
  urlDestDiv.style.gap = '6px';

  const destLabel = document.createElement('strong');
  destLabel.textContent = 'Dest: ';
  urlDestDiv.appendChild(destLabel);

  const linkEl = document.createElement('a');
  linkEl.href = final_url;
  linkEl.target = '_blank';
  linkEl.rel = 'noopener noreferrer';
  linkEl.title = final_url;
  linkEl.style.whiteSpace = 'nowrap';
  linkEl.style.overflow = 'hidden';
  linkEl.style.textOverflow = 'ellipsis';
  linkEl.style.maxWidth = '210px';
  linkEl.style.display = 'inline-block';
  linkEl.style.verticalAlign = 'middle';
  linkEl.textContent = final_url;
  urlDestDiv.appendChild(linkEl);

  const copyBtn = document.createElement('span');
  copyBtn.id = 'copy-dest-btn';
  copyBtn.style.cursor = 'pointer';
  copyBtn.style.color = '#888';
  copyBtn.style.display = 'flex';
  copyBtn.style.alignItems = 'center';
  copyBtn.style.padding = '2px';
  copyBtn.style.borderRadius = '3px';
  copyBtn.style.transition = 'background 0.2s';
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

  bodyDiv.appendChild(urlDestDiv);

  const screenshotContainer = document.createElement('div');
  screenshotContainer.className = 'screenshot-container';

  const displayImage = screenshot_base64 || preview_image_url;
  if (displayImage) {
    const img = document.createElement('img');
    img.src = displayImage;
    img.alt = `Preview of ${final_url}`;
    screenshotContainer.appendChild(img);
  } else {
    const placeholderDiv = document.createElement('div');
    placeholderDiv.style.display = 'flex';
    placeholderDiv.style.alignItems = 'center';
    placeholderDiv.style.justifyContent = 'center';
    placeholderDiv.style.height = '100%';
    placeholderDiv.style.color = '#888';
    placeholderDiv.style.fontStyle = 'italic';
    placeholderDiv.style.textAlign = 'center';
    placeholderDiv.style.padding = '0 20px';
    placeholderDiv.textContent = 'Image blocked or preview unavailable';
    screenshotContainer.appendChild(placeholderDiv);
  }

  bodyDiv.appendChild(screenshotContainer);

  const infoDiv = document.createElement('div');
  infoDiv.className = 'info';

  const forensicSection = createForensicSection(security.r);
  if (forensicSection) infoDiv.appendChild(forensicSection);

  const redirectsSection = createRedirectsSection(redirect_chain);
  if (redirectsSection) infoDiv.appendChild(redirectsSection);

  bodyDiv.appendChild(infoDiv);
  currentPopupContent.appendChild(bodyDiv);

  attachPopupEventHandlers(final_url);
}

/**
 * Merges Phase 2 deep scan results into the existing popup.
 * Updates badge color, risk score, and forensic details with smooth transitions.
 */
function mergeDeepScanResult(data) {
  if (!currentPopupContent || !currentPopupShadowRoot) return;

  const security = data.sec;
  if (!security) return;

  // Update header badge and color
  const header = currentPopupShadowRoot.querySelector('.header');
  const badge = currentPopupShadowRoot.querySelector('.badge');
  const logo = currentPopupShadowRoot.querySelector('.logo');

  if (header && badge && logo) {
    const verdictClass = security.v;
    let verdictText = security.safe ? 'Safe' : 'Suspicious';
    if (verdictClass === 'red') verdictText = 'Dangerous';

    // Remove old header classes and apply new
    header.className = `header ${verdictClass}-header`;
    badge.className = `badge ${verdictClass}`;
    badge.textContent = verdictText;
    logo.textContent = `VigilantLink Score: ${security.rs}/100`;
  }

  // Update or add warning box
  const body = currentPopupShadowRoot.querySelector('.body');
  if (body) {
    const existingWarning = currentPopupShadowRoot.querySelector('.warning-box');
    const newWarning = createWarningBox(security.v, security.tt);

    if (existingWarning && newWarning) {
      existingWarning.replaceWith(newWarning);
    } else if (!existingWarning && newWarning) {
      body.insertBefore(newWarning, body.firstChild);
    } else if (existingWarning && !newWarning) {
      existingWarning.remove();
    }

    // Update or add forensic section
    const existingInfo = currentPopupShadowRoot.querySelector('.info');
    if (existingInfo && security.r && security.r.length > 0) {
      existingInfo.textContent = '';
      const forensicSection = createForensicSection(security.r);
      if (forensicSection) existingInfo.appendChild(forensicSection);
    }
  }

  // Update screenshot if Phase 3 provided one
  if (data.ss) {
    const container = currentPopupShadowRoot.querySelector('.screenshot-container');
    if (container) {
      container.textContent = '';
      const img = document.createElement('img');
      img.src = data.ss;
      img.alt = 'Site preview';
      container.appendChild(img);
    }
  }
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
          successSpan.style.color = '#28a745';
          successSpan.style.fontSize = '10px';
          successSpan.style.fontWeight = 'bold';
          successSpan.style.margin = '0 2px';
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
        errorSpan.style.color = '#dc3545';
        errorSpan.style.fontSize = '10px';
        errorSpan.style.fontWeight = 'bold';
        errorSpan.style.margin = '0 2px';
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
  if (!currentPopupContent) return;
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
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'settings_updated') {
    closePopup();
  } else if (message.action === 'set_override') {
    window.sessionStorage.setItem('vigilantlink_override', message.enabled ? 'enabled' : 'disabled');
    closePopup();
    sendResponse({ success: true });
  } else if (message.action === 'get_override') {
    sendResponse({ override: window.sessionStorage.getItem('vigilantlink_override') });
  }
});

function closePopup() {
    if (currentPopupContainer) {
        currentPopupContainer.remove();
        currentPopupContainer = null;
        currentPopupShadowRoot = null;
        currentPopupContent = null;
    }
}

function createShadowPopup(x, y) {
  closePopup();

  let styleUrl = '';
  try {
      styleUrl = chrome.runtime.getURL('styles/shadow-styles.css');
  } catch (e) {
      console.warn('VigilantLink: Extension context invalidated. Please refresh the page.');
      return;
  }

  const container = document.createElement('div');
  container.style.position = 'fixed';
  container.style.left = `${x}px`;
  container.style.top = `${y}px`;
  container.style.zIndex = '2147483647';

  const shadowRoot = container.attachShadow({ mode: 'closed' });
  currentPopupShadowRoot = shadowRoot;

  const styleLink = document.createElement('link');
  styleLink.rel = 'stylesheet';
  styleLink.href = styleUrl;
  shadowRoot.appendChild(styleLink);

  const content = document.createElement('div');
  content.className = 'vigilant-card';
  shadowRoot.appendChild(content);

  document.body.appendChild(container);

  currentPopupContainer = container;
  currentPopupContent = content;
}
