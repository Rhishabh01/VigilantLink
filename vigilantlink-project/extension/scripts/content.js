// Hover detection & Shadow DOM isolation

let hoverTimer = null;
let hoverTargetUrl = null;
let closeTimer = null;
let currentPopupContainer = null;
let currentPopupShadowRoot = null;
let currentPopupContent = null;
const HOVER_DELAY_MS = 400;

// Default settings
const DEFAULT_SETTINGS = {
  globalEnabled: true,
  disabledSites: []
};

// Default settings constants
const DEFAULT_GLOBAL_ENABLED = true;
const DEFAULT_DISABLED_SITES = [];

// Check if VigilantLink is enabled for current site
async function isEnabledForSite() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['globalEnabled', 'disabledSites'], (result) => {
      // 1. Check for temporary tab-level override
      const override = window.sessionStorage.getItem('vigilantlink_override');
      if (override === 'enabled') return resolve(true);
      if (override === 'disabled') return resolve(false);

      // 2. Fallback to default persistent setting
      const globalEnabled = result.globalEnabled !== false; // Default to true
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

document.addEventListener("mouseover", async (event) => {
  const target = event.target.closest("a");
  if (!target || !target.href) return;
   
  // Only analyze http/https links
  if (!target.href.startsWith("http://") && !target.href.startsWith("https://")) return;
  
  // Check if enabled for this site
  const enabled = await isEnabledForSite();
  if (!enabled) return;
  
  const url = target.href;
  hoverTargetUrl = url;
   
  if (hoverTimer) clearTimeout(hoverTimer);
   
  hoverTimer = setTimeout(() => {
    if (hoverTargetUrl !== url) return;
      
    const rect = target.getBoundingClientRect();
    let x = rect.right + 10;
    let y = rect.top;
      
    const POPUP_WIDTH = 340;
    const POPUP_HEIGHT = 450;
      
    // If no room on the right, show on the left
    if (x + POPUP_WIDTH > window.innerWidth) x = rect.left - POPUP_WIDTH - 10;
    if (x < 0) x = 10;
      
    // If no room below, flip above the link
    if (y + POPUP_HEIGHT > window.innerHeight) y = rect.bottom - POPUP_HEIGHT;
    if (y < 0) y = 10;

    showLoadingPopup(x, y);
      
    try {
        chrome.runtime.sendMessage({ action: "analyze_link", url }, (response) => {
          if (response && response.success) {
              updatePopupWithResult(response.data);
          } else {
              updatePopupWithError(response?.error || "Unknown error");
          }
        });
    } catch (e) {
        console.warn("VigilantLink: Context invalidated. Refresh page.", e);
    }
  }, HOVER_DELAY_MS);
});

document.addEventListener("mouseout", (event) => {
  const target = event.target.closest("a");
  if (!target) return;
   
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
  hoverTargetUrl = null;
});

// Close popup if moving away from the link and popup
document.addEventListener("mousemove", (event) => {
    if (currentPopupContainer) {
        const target = event.target.closest("a");
        const isOverPopup = currentPopupContainer.contains(event.target) || 
            (currentPopupShadowRoot && currentPopupShadowRoot.contains(event.composedPath()[0]));
        
        if (!target && !isOverPopup) {
            if (!closeTimer) {
                closeTimer = setTimeout(() => {
                    closePopup();
                }, 300); // 300ms hover bridge
            }
        } else {
            if (closeTimer) {
                clearTimeout(closeTimer);
                closeTimer = null;
            }
        }
    }
});

document.addEventListener("click", (event) => {
  if (currentPopupContainer && !currentPopupContainer.contains(event.target)) {
    // Also check if the click originated inside our shadow DOM
    if (currentPopupShadowRoot && currentPopupShadowRoot.contains(event.composedPath()[0])) {
      return;
    }
    closePopup();
  }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'settings_updated') {
    // Close any open popup when settings change
    closePopup();
  } else if (message.action === 'set_override') {
    // Set a temporary override for this tab
    window.sessionStorage.setItem('vigilantlink_override', message.enabled ? 'enabled' : 'disabled');
    closePopup();
    sendResponse({ success: true });
  } else if (message.action === 'get_override') {
    // Send the current override back to the popup
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

  currentPopupContent.innerHTML = `
    <div class="header loading-header">
      <div class="logo">VigilantLink</div>
      <div class="badge gray">Analyzing...</div>
    </div>
    <div class="body">
      <div class="skeleton-img pulse-anim"></div>
      <div class="skeleton-text pulse-anim"></div>
      <div class="skeleton-text short pulse-anim"></div>
    </div>
  `;
}

function getBadgeColor(reason) {
  if (reason.includes("Punycode")) return "red";
  if (reason.includes("Excessive Redirect Chain") || reason.includes("Cross-Domain")) return "orange";
  if (reason.includes("Typosquatting") || reason.includes("Synergy")) return "red";
  if (reason.includes("Newly Registered")) return "orange";
  return "gray";
}

function updatePopupWithResult(data) {
  if (!currentPopupContent) return;
   
  const { original_url, final_url, redirect_chain, screenshot_base64, security } = data;
   
  let verdictClass = security.verdict;
  let verdictText = security.is_safe ? "Safe" : "Suspicious";
  if (verdictClass === "red") verdictText = "Dangerous";
  
  let warningHtml = '';
  if (verdictClass !== "green") {
      warningHtml = `
      <div class="warning-box ${verdictClass}">
          <strong>Warning:</strong> ${security.threat_type || 'Potential risk detected'}
      </div>`;
  }
   
  let redirectsHtml = '';
  if (redirect_chain && redirect_chain.length > 1) {
      const maxCompact = 3;
      const showUrls = redirect_chain.slice(0, maxCompact).map(r => {
          try { return new URL(r.url).hostname; } catch { return r.url; }
      });
      const hiddenCount = redirect_chain.length - maxCompact;
      const compactText = showUrls.join(' → ');
       
      if (hiddenCount > 0) {
          redirectsHtml = `
          <div class="redirects" style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed #eee;">
            <small style="font-weight: 600; color: #555;">Redirect Path:</small>
            <div style="font-size: 11px; color: #666; margin-top: 4px; word-break: break-all;">
                <span id="redirects-compact">${compactText}</span>
                <span id="redirects-more" style="cursor: pointer; color: #0056b3; margin-left: 4px;">+${hiddenCount} more</span>
            </div>
            <div id="redirects-full" style="display: none; max-height: 150px; overflow-y: auto; margin-top: 6px; padding: 6px 8px; background: #f8f9fa; border-radius: 4px; font-size: 11px; color: #666;">
                ${redirect_chain.map(r => `<div style="margin-bottom: 3px; word-break: break-all;">&rarr; ${r.url}</div>`).join('')}
            </div>
            <button id="redirects-toggle-btn" style="margin-top: 6px; padding: 3px 10px; border: 1px solid #ddd; border-radius: 4px; background: #f8f9fa; font-size: 10px; cursor: pointer; color: #333; font-weight: 600;">Show full path</button>
          </div>`;
      } else {
          redirectsHtml = `
          <div class="redirects" style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed #eee;">
            <small style="font-weight: 600; color: #555;">Redirect Path:</small>
            <div style="font-size: 11px; color: #666; margin-top: 4px; word-break: break-all;">
                ${compactText}
            </div>
          </div>`;
      }
  }
  
  let screenshotHtml = '';
  if (screenshot_base64) {
      screenshotHtml = `<img src="${screenshot_base64}" alt="Preview of ${final_url}" />`;
  } else {
      screenshotHtml = `<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #888; font-style: italic; text-align: center; padding: 0 20px;">Image blocked or preview unavailable</div>`;
  }
  
  let forensicHtml = '';
  if (security.reasons && security.reasons.length > 0) {
      forensicHtml = `
      <div class="reasons">
        <div class="reasons-title">Forensic Analysis</div>
        <div class="badge-list">
            ${security.reasons.map(r => `<span class="forensic-badge ${getBadgeColor(r)}">${r}</span>`).join('')}
        </div>
      </div>`;
  }
  
  currentPopupContent.innerHTML = `
    <div class="header ${verdictClass}-header">
      <div class="logo">VigilantLink <span style="font-size: 10px; margin-left: 8px; opacity: 0.8; font-weight: normal;">Score: ${security.risk_score}/100</span></div>
      <div class="badge ${verdictClass}">${verdictText}</div>
    </div>
    <div class="body">
      ${warningHtml}
      <div class="url-dest" style="margin-bottom: 8px; font-size: 11px; color: #555; display: flex; align-items: center; gap: 6px;">
        <strong>Dest:</strong> 
        <a href="${final_url}" title="${final_url}" target="_blank" rel="noopener noreferrer" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 210px; display: inline-block; vertical-align: middle;">${final_url}</a>
        <span id="copy-dest-btn" style="cursor: pointer; color: #888; display: flex; align-items: center; padding: 2px; border-radius: 3px; transition: background 0.2s;" title="Copy URL" onmouseover="this.style.background='#eee'" onmouseout="this.style.background='transparent'">
          <svg style="pointer-events: none;" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </span>
      </div>
      <div class="screenshot-container">
          ${screenshotHtml}
      </div>
      <div class="info">
        ${forensicHtml}
        ${redirectsHtml}
      </div>
    </div>
  `;
  
  const shadowRoot = currentPopupShadowRoot;
  if (!shadowRoot) return;
   
  shadowRoot.addEventListener('click', async (e) => {
      const copyBtn = e.target.closest('#copy-dest-btn');
      if (copyBtn) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
           try {
                // Use navigator.clipboard directly - works in extension contexts
                if (navigator.clipboard) {
                    await navigator.clipboard.writeText(final_url);
                } else {
                    throw new Error("Clipboard API not available");
                }
                const originalHtml = copyBtn.innerHTML;
                copyBtn.innerHTML = `<span style="color: #28a745; font-size: 10px; font-weight: bold; margin: 0 2px;">✓</span>`;
                setTimeout(() => {
                    copyBtn.innerHTML = originalHtml;
                }, 1500);
            } catch (err) {
                console.error("VigilantLink Copy Error: ", err);
                const originalHtml = copyBtn.innerHTML;
                copyBtn.innerHTML = `<span style="color: #dc3545; font-size: 10px; font-weight: bold; margin: 0 2px;">✗</span>`;
                setTimeout(() => {
                    copyBtn.innerHTML = originalHtml;
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
  currentPopupContent.innerHTML = `
    <div class="header error-header">
      <div class="logo">VigilantLink</div>
      <div class="badge red">Error</div>
    </div>
    <div class="body error-body">
      <p>Failed to analyze link.</p>
      <small>${errorMsg}</small>
    </div>
  `;
}
