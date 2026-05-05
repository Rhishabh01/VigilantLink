// Hover detection & Shadow DOM isolation

let hoverTimer = null;
let currentPopupContainer = null;
let currentPopupContent = null;
const HOVER_DELAY_MS = 500;

document.addEventListener("mouseover", (event) => {
  const target = event.target.closest("a");
  if (!target || !target.href) return;
  
  if (target.href.startsWith("javascript:") || target.href.startsWith("#")) return;

  const url = target.href;
  
  hoverTimer = setTimeout(() => {
    // Determine positioning. Ensure it doesn't go off-screen.
    let x = event.clientX + 15;
    let y = event.clientY + 15;
    
    if (x + 350 > window.innerWidth) x = window.innerWidth - 365;
    if (y + 300 > window.innerHeight) y = event.clientY - 315;

    showLoadingPopup(x, y);
    
    chrome.runtime.sendMessage({ action: "analyze_link", url }, (response) => {
      if (response && response.success) {
        updatePopupWithResult(response.data);
      } else {
        updatePopupWithError(response?.error || "Unknown error");
      }
    });
  }, HOVER_DELAY_MS);
});

document.addEventListener("mouseout", (event) => {
  const target = event.target.closest("a");
  if (!target) return;
  
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
});

// Close popup if moving away from the link and popup
document.addEventListener("mousemove", (event) => {
    if (currentPopupContainer) {
        // Simple logic: if not hovering over a link and not over popup, close after small delay
        const target = event.target.closest("a");
        const isOverPopup = currentPopupContainer.contains(event.target);
        if (!target && !isOverPopup) {
            closePopup();
        }
    }
});

document.addEventListener("click", (event) => {
  if (currentPopupContainer && !currentPopupContainer.contains(event.target)) {
    closePopup();
  }
});

function closePopup() {
    if (currentPopupContainer) {
        currentPopupContainer.remove();
        currentPopupContainer = null;
        currentPopupContent = null;
    }
}

function createShadowPopup(x, y) {
  closePopup();

  const container = document.createElement("div");
  // Container positioning
  container.style.position = "fixed";
  container.style.left = `${x}px`;
  container.style.top = `${y}px`;
  container.style.zIndex = "2147483647"; // Max z-index
  
  // Use closed mode for Zero-Trust isolation from host page JS
  const shadowRoot = container.attachShadow({ mode: "closed" });
  
  const styleLink = document.createElement("link");
  styleLink.rel = "stylesheet";
  styleLink.href = chrome.runtime.getURL("styles/shadow-styles.css");
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
      <div class="redirects">
        <small>Redirects (${redirect_chain.length}):</small>
        <div class="chain">
            ${redirect_chain.map(r => `<span>${r.url}</span>`).join(' &rarr; ')}
        </div>
      </div>`;
  }

  let screenshotHtml = '';
  if (screenshot_base64) {
      screenshotHtml = `<img src="${screenshot_base64}" alt="Preview of ${final_url}" />`;
  } else {
      screenshotHtml = `<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #888; font-style: italic; text-align: center; padding: 0 20px;">Image blocked or preview unavailable</div>`;
  }

  let reasonsHtml = '';
  if (security.reasons && security.reasons.length > 0) {
      reasonsHtml = `
      <div class="reasons" style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed #eee;">
        <strong>Reasons:</strong>
        <ul style="margin: 4px 0 0; padding-left: 16px; font-size: 11px; color: #555;">
            ${security.reasons.map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>`;
  }

  currentPopupContent.innerHTML = `
    <div class="header ${verdictClass}-header">
      <div class="logo">VigilantLink</div>
      <div class="badge ${verdictClass}">${verdictText}</div>
    </div>
    <div class="body">
      ${warningHtml}
      <div class="screenshot-container">
          ${screenshotHtml}
      </div>
      <div class="info">
        <div class="url-dest"><strong>Destination:</strong> ${final_url}</div>
        <div class="risk-score"><strong>Risk Score:</strong> ${security.risk_score} / 100</div>
        ${redirectsHtml}
        ${reasonsHtml}
      </div>
    </div>
  `;
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
