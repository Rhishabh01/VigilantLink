// Senior Frontend Refactor: Unified State Management for VigilantLink Popup
const PRESET_SITES = [
  { name: 'YouTube', domain: 'youtube.com' },
  { name: 'X (Twitter)', domain: 'x.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  { name: 'GitHub', domain: 'github.com' }
];

// Absolute source of truth from chrome.storage.local
async function getSettings() {
  const data = await chrome.storage.local.get(['globalEnabled', 'disabledSites', 'customSites']);
  return {
    globalEnabled: data.globalEnabled !== false, // Default true
    disabledSites: data.disabledSites || [],
    customSites: data.customSites || []
  };
}

// Central UI Synchronization
async function updateToggles() {
  const { globalEnabled, disabledSites, customSites } = await getSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab) return;

  const url = new URL(tab.url);
  const currentHostname = url.hostname;
  const isBrowserPage = url.protocol === 'chrome:' || url.protocol === 'chrome-extension:';

  // 1. Update Current Site Toggle
  const currentDomainEl = document.getElementById('current-domain');
  const siteToggle = document.getElementById('site-toggle');
  const badgeEl = document.getElementById('site-status-badge');
  if (isBrowserPage) {
    currentDomainEl.textContent = 'N/A (Browser Page)';
    siteToggle.disabled = true;
    siteToggle.checked = false;
    if (badgeEl) {
      badgeEl.textContent = 'N/A';
      badgeEl.style.background = 'rgba(255,255,255,0.1)';
      badgeEl.style.color = '#94a3b8';
    }
  } else {
    currentDomainEl.textContent = currentHostname;
    siteToggle.disabled = false;

    // Ask content script for any temporary override
    let tabOverride = null;
    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'get_override' });
      if (response && response.override) tabOverride = response.override;
    } catch (e) {
      // Content script might not be loaded yet
    }

    const isDefaultDisabled = disabledSites.some(d => currentHostname === d || currentHostname.endsWith('.' + d));

    let isCurrentlyDisabled;
    if (tabOverride === 'enabled') isCurrentlyDisabled = false;
    else if (tabOverride === 'disabled') isCurrentlyDisabled = true;
    else isCurrentlyDisabled = isDefaultDisabled;

    siteToggle.checked = !isCurrentlyDisabled;

    // Status text & color
    if (isCurrentlyDisabled) {
      if (badgeEl) {
        badgeEl.textContent = 'DISABLED';
        badgeEl.style.background = 'rgba(239, 68, 68, 0.2)';
        badgeEl.style.color = '#f87171';
      }
    } else {
      if (badgeEl) {
        badgeEl.textContent = 'ACTIVE';
        badgeEl.style.background = 'rgba(16, 185, 129, 0.2)';
        badgeEl.style.color = '#34d399';
      }
    }
  }

  // 2. Update Preset/Quick Toggle List
  renderPresetList(disabledSites);

  // 3. Update Custom Sites List
  renderCustomList(customSites, disabledSites);
}

function renderPresetList(disabledSites) {
  const listEl = document.getElementById('preset-list');
  if (!listEl) return;

  listEl.textContent = '';
  PRESET_SITES.forEach(site => {
    const isEnabled = !disabledSites.includes(site.domain);
    const item = document.createElement('div');
    item.className = 'preset-item';

    const siteName = document.createElement('span');
    siteName.className = 'site-name';
    siteName.textContent = site.name;
    item.appendChild(siteName);

    const labelEl = document.createElement('label');
    labelEl.className = 'toggle';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'site-list-toggle';
    checkbox.dataset.domain = site.domain;
    checkbox.checked = isEnabled;
    labelEl.appendChild(checkbox);

    const sliderSpan = document.createElement('span');
    sliderSpan.className = 'slider';
    labelEl.appendChild(sliderSpan);

    item.appendChild(labelEl);
    listEl.appendChild(item);
  });
}

function renderCustomList(customSites, disabledSites) {
  const listEl = document.getElementById('custom-list');
  if (!listEl) return;

  if (customSites.length === 0) {
    listEl.textContent = '';
    const emptyDiv = document.createElement('div');
    emptyDiv.style.fontSize = '12px';
    emptyDiv.style.color = 'var(--text-muted)';
    emptyDiv.style.textAlign = 'center';
    emptyDiv.style.padding = '20px 10px';
    emptyDiv.style.background = 'var(--glass)';
    emptyDiv.style.borderRadius = '12px';
    emptyDiv.textContent = 'No custom sites added';
    listEl.appendChild(emptyDiv);
    return;
  }

  listEl.textContent = '';
  customSites.forEach((site, index) => {
    const isEnabled = !disabledSites.includes(site.domain);
    const item = document.createElement('div');
    item.className = 'custom-site-item';

    const siteInfoDiv = document.createElement('div');
    siteInfoDiv.className = 'site-info';

    const nameDiv = document.createElement('div');
    nameDiv.className = 'site-name';
    nameDiv.textContent = site.name;
    siteInfoDiv.appendChild(nameDiv);

    const domainDiv = document.createElement('div');
    domainDiv.className = 'site-domain';
    domainDiv.textContent = site.domain;
    siteInfoDiv.appendChild(domainDiv);

    item.appendChild(siteInfoDiv);

    const controlsDiv = document.createElement('div');
    controlsDiv.style.display = 'flex';
    controlsDiv.style.alignItems = 'center';
    controlsDiv.style.gap = '8px';

    const labelEl = document.createElement('label');
    labelEl.className = 'toggle';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'site-list-toggle';
    checkbox.dataset.domain = site.domain;
    checkbox.checked = isEnabled;
    labelEl.appendChild(checkbox);

    const sliderSpan = document.createElement('span');
    sliderSpan.className = 'slider';
    labelEl.appendChild(sliderSpan);

    controlsDiv.appendChild(labelEl);

    const removeBtn = document.createElement('span');
    removeBtn.className = 'remove';
    removeBtn.dataset.index = index;
    removeBtn.title = 'Remove';
    removeBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="3 6 5 6 21 6"></polyline>
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
      </svg>
    `;
    controlsDiv.appendChild(removeBtn);

    item.appendChild(controlsDiv);
    listEl.appendChild(item);
  });
}

// Event Listeners for State Changes
async function handleToggleChange(domain, isEnabled) {
  let { disabledSites } = await getSettings();

  if (isEnabled) {
    // If enabling, remove exact match and any parent domains that might be blocking it
    disabledSites = disabledSites.filter(d => d !== domain && !domain.endsWith('.' + d));
  } else {
    // If disabling, add it
    if (!disabledSites.includes(domain)) disabledSites.push(domain);
  }

  await chrome.storage.local.set({ disabledSites });
  // updateToggles() will be called via storage listener or manually
  notifyTabs();
}

function notifyTabs() {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, { action: 'settings_updated' }).catch(() => { });
    });
  });
}

// DOM Event Delegation
document.addEventListener('change', async (e) => {
  if (e.target.id === 'site-toggle') {
    // Temporary override logic
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      try {
        await chrome.tabs.sendMessage(tab.id, { action: 'set_override', enabled: e.target.checked });
        updateToggles();
      } catch (err) {
        console.error("Could not send override to tab:", err);
      }
    }
  } else if (e.target.classList.contains('site-list-toggle')) {
    const domain = e.target.dataset.domain;
    handleToggleChange(domain, e.target.checked);
  }
});

document.addEventListener('click', async (e) => {
  if (e.target.id === 'show-add-btn') {
    document.getElementById('add-form').style.display = 'flex';
    e.target.style.display = 'none';
  } else if (e.target.id === 'cancel-btn') {
    document.getElementById('add-form').style.display = 'none';
    document.getElementById('show-add-btn').style.display = 'block';
  } else if (e.target.id === 'save-site-btn') {
    const name = document.getElementById('site-name-input').value.trim();
    const domain = document.getElementById('site-domain-input').value.trim()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    if (name && domain) {
      const { customSites } = await getSettings();
      customSites.push({ name, domain });
      await chrome.storage.local.set({ customSites });
      document.getElementById('add-form').style.display = 'none';
      document.getElementById('show-add-btn').style.display = 'block';
      updateToggles();
    }
  } else if (e.target.closest('.remove')) {
    const removeBtn = e.target.closest('.remove');
    const index = parseInt(removeBtn.dataset.index);
    let { customSites, disabledSites } = await getSettings();
    const domain = customSites[index].domain;
    customSites.splice(index, 1);
    disabledSites = disabledSites.filter(d => d !== domain);
    await chrome.storage.local.set({ customSites, disabledSites });
    updateToggles();
  }
});

// React to storage changes immediately (Cross-Toggle Sync)
chrome.storage.onChanged.addListener(() => {
  updateToggles();
});

// Initialization
document.addEventListener('DOMContentLoaded', updateToggles);
