// Hover detection & Shadow DOM isolation

let hoverTimer = null;
let hoverTargetUrl = null;
let closeTimer = null;
let currentPopupContainer = null;
let currentPopupShadowRoot = null;
let currentPopupContent = null;
const HOVER_DELAY_MS = 400;

document.addEventListener("mouseover", (event) => {
  const target = event.target.closest("a");
  if (!target || !target.href) return;
  
  if (target.href.startsWith("javascript:") || target.href.startsWith("#")) return;

  const url = target.href;
  hoverTargetUrl = url;
  
  if (hoverTimer) clearTimeout(hoverTimer);
  
  hoverTimer = setTimeout(() => {
    if (hoverTargetUrl !== url) return;
    
    const rect = target.getBoundingClientRect();
    let x = rect.right + 10;
    let y = rect.top;
    
    if (x + 350 > window.innerWidth) x = rect.left - 360;
    if (x < 0) x = 10;
    if (y + 300 > window.innerHeight) y = window.innerHeight - 310;
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
  currentPopupContent = content; // Keep reference to modify internal HTML safely
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

function updatePopupWithResult(data) {
  if (!currentPopupContent) return;
  
  const { original_url, final_url, redirect_chain, screenshot_base64, security } = data;
  
  let verdictClass = security.verdict; // 'green', 'yellow', 'red'
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
      redirectsHtml = `
      <div class="redirects" style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed #eee;">
        <small style="font-weight: 600; color: #555;">Redirect Path:</small>
        <div style="font-size: 11px; color: #666; margin-top: 4px; word-break: break-all;">
            ${redirect_chain.map(r => `<div>&rarr; ${r.url}</div>`).join('')}
        </div>
      </div>`;
  }

  let screenshotHtml = '';
  if (screenshot_base64) {
      screenshotHtml = `<img src="${screenshot_base64}" alt="Preview of ${final_url}" />`;
  } else {
      screenshotHtml = `<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #888; font-style: italic; text-align: center; padding: 0 20px;">Image blocked or preview unavailable</div>`;
  }

  function getBadgeColor(reason) {
      if (reason.includes("Punycode")) return "red";
      if (reason.includes("Redirect Velocity") || reason.includes("Cross-Domain")) return "orange";
      if (reason.includes("Typosquatting") || reason.includes("Synergy")) return "red";
      if (reason.includes("Newly Registered")) return "orange";
      return "gray";
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
