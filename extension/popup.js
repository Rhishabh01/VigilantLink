const PRESET_SITES = [
  { name: 'YouTube', domain: 'youtube.com' },
  { name: 'X (Twitter)', domain: 'x.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  { name: 'GitHub', domain: 'github.com' },
  { name: 'Gmail', domain: 'mail.google.com' },
  { name: 'Google Accounts', domain: 'accounts.google.com' }
];

const DEFAULT_BACKEND_URL = 'https://extension-production-4bd4.up.railway.app';

async function getSettings() {
  const data = await chrome.storage.local.get(['globalEnabled', 'disabledSites', 'customSites', 'hiddenPresets', 'theme', 'siteOrder', 'backendUrl', 'autoAddSite', 'fixedPhysicalSize']);

  // Determine default theme based on system preference
  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';

  return {
    globalEnabled: data.globalEnabled !== false,
    disabledSites: data.disabledSites || [],
    customSites: data.customSites || [],
    hiddenPresets: data.hiddenPresets || [],
    theme: data.theme || systemTheme,
    siteOrder: data.siteOrder || [],
    backendUrl: data.backendUrl || DEFAULT_BACKEND_URL,
    autoAddSite: data.autoAddSite === true,
    fixedPhysicalSize: data.fixedPhysicalSize === true
  };
}

async function initTheme() {
  const { theme } = await getSettings();
  applyTheme(theme);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const moonIcon = document.getElementById('moon-icon');
  const sunIcon = document.getElementById('sun-icon');
  if (theme === 'light') {
    moonIcon.style.display = 'none';
    sunIcon.style.display = 'block';
  } else {
    moonIcon.style.display = 'block';
    sunIcon.style.display = 'none';
  }
}

async function toggleTheme() {
  const { theme } = await getSettings();
  const newTheme = theme === 'light' ? 'dark' : 'light';
  await chrome.storage.local.set({ theme: newTheme });
  applyTheme(newTheme);
}

async function updateToggles() {
  const { globalEnabled, disabledSites, customSites, hiddenPresets, siteOrder } = await getSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  const globalToggle = document.getElementById('global-toggle');
  if (globalToggle) {
    globalToggle.checked = globalEnabled;
  }

  if (!tab) return;

  const url = new URL(tab.url);
  const currentHostname = url.hostname;
  const isBrowserPage = url.protocol === 'chrome:' || url.protocol === 'chrome-extension:';

  const currentDomainEl = document.getElementById('current-domain');
  const siteToggle = document.getElementById('site-toggle');
  const badgeEl = document.getElementById('site-status-badge');

  if (isBrowserPage) {
    if (currentDomainEl) currentDomainEl.textContent = 'N/A (Browser Page)';
    if (siteToggle) {
      siteToggle.disabled = true;
      siteToggle.checked = false;
    }
    if (badgeEl) {
      badgeEl.textContent = 'N/A';
      badgeEl.style.background = 'rgba(255,255,255,0.1)';
      badgeEl.style.color = '#94a3b8';
    }
  } else {
    if (currentDomainEl) currentDomainEl.textContent = currentHostname;
    if (siteToggle) siteToggle.disabled = false;

    let tabOverride = null;
    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'get_override' });
      if (response && response.override) tabOverride = response.override;
    } catch (e) {
    }

    const isDefaultDisabled = !globalEnabled || disabledSites.some(d => currentHostname === d || currentHostname.endsWith('.' + d));

    let isCurrentlyDisabled;
    if (tabOverride === 'enabled') isCurrentlyDisabled = false;
    else if (tabOverride === 'disabled') isCurrentlyDisabled = true;
    else isCurrentlyDisabled = isDefaultDisabled;

    if (siteToggle) siteToggle.checked = !isCurrentlyDisabled;

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

  renderSiteList(disabledSites, customSites, hiddenPresets, siteOrder);
}

function renderSiteList(disabledSites, customSites, hiddenPresets, siteOrder) {
  const listEl = document.getElementById('preset-list');
  if (!listEl) return;

  listEl.textContent = '';

  const presets = PRESET_SITES.filter(site => !hiddenPresets.includes(site.domain)).map(site => ({
    ...site,
    isPreset: true
  }));

  const custom = customSites.map(site => ({
    ...site,
    isPreset: false
  }));

  const allSites = [...presets, ...custom];

  // Sort according to siteOrder
  allSites.sort((a, b) => {
    let idxA = siteOrder.indexOf(a.domain);
    let idxB = siteOrder.indexOf(b.domain);
    if (idxA === -1) idxA = 999;
    if (idxB === -1) idxB = 999;
    return idxA - idxB;
  });

  allSites.forEach(site => {
    const isEnabled = !disabledSites.includes(site.domain);
    const item = document.createElement('div');
    item.className = 'site-item';
    item.draggable = true;
    item.dataset.domain = site.domain;

    // Drag handle
    const dragHandle = document.createElement('div');
    dragHandle.className = 'drag-handle';
    dragHandle.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="9" cy="12" r="1.5"></circle>
        <circle cx="9" cy="5" r="1.5"></circle>
        <circle cx="9" cy="19" r="1.5"></circle>
        <circle cx="15" cy="12" r="1.5"></circle>
        <circle cx="15" cy="5" r="1.5"></circle>
        <circle cx="15" cy="19" r="1.5"></circle>
      </svg>
    `;
    item.appendChild(dragHandle);

    // Left Side: Status & Details
    const leftEl = document.createElement('div');
    leftEl.className = 'site-left';

    const statusEl = document.createElement('div');
    statusEl.className = `site-status-dot ${isEnabled ? 'active' : 'deactive'}`;
    leftEl.appendChild(statusEl);

    const infoEl = document.createElement('div');
    infoEl.className = 'site-info';

    const nameEl = document.createElement('div');
    nameEl.className = 'site-name';
    nameEl.textContent = site.name;
    infoEl.appendChild(nameEl);

    leftEl.appendChild(infoEl);
    item.appendChild(leftEl);

    // Right Side: Controls
    const controlsEl = document.createElement('div');
    controlsEl.className = 'site-controls';

    // Toggle Checkbox
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

    controlsEl.appendChild(labelEl);

    // Remove Button
    const removeBtn = document.createElement('span');
    removeBtn.className = 'remove';
    removeBtn.dataset.domain = site.domain;
    removeBtn.dataset.isPreset = site.isPreset ? 'true' : 'false';
    removeBtn.title = 'Remove';
    removeBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="3 6 5 6 21 6"></polyline>
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
      </svg>
    `;
    controlsEl.appendChild(removeBtn);

    item.appendChild(controlsEl);
    listEl.appendChild(item);
  });
}

async function handleToggleChange(domain, isEnabled) {
  let { disabledSites } = await getSettings();

  if (isEnabled) {
    disabledSites = disabledSites.filter(d => d !== domain && !domain.endsWith('.' + d));
  } else {
    if (!disabledSites.includes(domain)) disabledSites.push(domain);
  }

  await chrome.storage.local.set({ disabledSites });
  notifyTabs();
}

function notifyTabs() {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, { action: 'settings_updated' }).catch(() => { });
    });
  });
}

// Drag and drop event listeners setup on DomContentLoaded
function initDragAndDrop() {
  const listEl = document.getElementById('preset-list');
  if (!listEl) return;

  listEl.addEventListener('dragstart', (e) => {
    const item = e.target.closest('.site-item');
    if (item) {
      item.classList.add('dragging');
      e.dataTransfer.setData('text/plain', item.dataset.domain);
      e.dataTransfer.effectAllowed = 'move';
    }
  });

  listEl.addEventListener('dragend', (e) => {
    const item = e.target.closest('.site-item');
    if (item) {
      item.classList.remove('dragging');
    }
  });

  listEl.addEventListener('dragover', (e) => {
    e.preventDefault();
    const draggingItem = listEl.querySelector('.dragging');
    if (!draggingItem) return;

    const siblings = [...listEl.querySelectorAll('.site-item:not(.dragging)')];
    const nextSibling = siblings.find(sibling => {
      const box = sibling.getBoundingClientRect();
      const offset = e.clientY - box.top - box.height / 2;
      return offset < 0;
    });

    listEl.insertBefore(draggingItem, nextSibling);
  });

  listEl.addEventListener('drop', async (e) => {
    e.preventDefault();
    const itemEls = [...listEl.querySelectorAll('.site-item')];
    const newOrder = itemEls.map(el => el.dataset.domain);
    await chrome.storage.local.set({ siteOrder: newOrder });
  });
}

document.addEventListener('change', async (e) => {
  if (e.target.id === 'global-toggle') {
    await chrome.storage.local.set({ globalEnabled: e.target.checked });
    notifyTabs();
    updateToggles();
  } else if (e.target.id === 'site-toggle') {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      try {
        await chrome.tabs.sendMessage(tab.id, { action: 'set_override', enabled: e.target.checked });
        updateToggles();
      } catch (err) {
        // tab may not have content script yet
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
    (async () => {
      const { autoAddSite } = await getSettings();
      if (autoAddSite) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
          try {
            const url = new URL(tab.url);
            if (url.protocol !== 'chrome:' && url.protocol !== 'chrome-extension:') {
              const hostname = url.hostname;
              const cleanName = hostname.replace(/^www\./, '').replace(/\.[^.]+$/, '');
              document.getElementById('site-name-input').value = cleanName;
              document.getElementById('site-domain-input').value = hostname;
            }
          } catch (e) { /* ignore */ }
        }
      }
    })();
    setTimeout(() => {
      document.getElementById('add-form').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);
  } else if (e.target.id === 'cancel-btn') {
    document.getElementById('add-form').style.display = 'none';
    document.getElementById('show-add-btn').style.display = 'block';
  } else if (e.target.id === 'save-site-btn') {
    const name = document.getElementById('site-name-input').value.trim();
    const domain = document.getElementById('site-domain-input').value.trim()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    // Strict validation to prevent malformed input and potential XSS vectors
    // Name should be alphanumeric with some basic punctuation
    const nameValid = /^[a-zA-Z0-9\s\-_.,()]+$/.test(name) && name.length > 0 && name.length <= 50;
    // Domain should be a valid FQDN
    const domainValid = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(domain);

    if (nameValid && domainValid) {
      const { customSites } = await getSettings();
      // Ensure no exact duplicates
      if (!customSites.find(s => s.domain === domain)) {
        customSites.push({
          name,
          domain
        });
        await chrome.storage.local.set({ customSites });
      }
      document.getElementById('site-name-input').value = '';
      document.getElementById('site-domain-input').value = '';
      document.getElementById('add-form').style.display = 'none';
      document.getElementById('show-add-btn').style.display = 'block';
      updateToggles();
    } else {
      alert("Invalid input: Please provide a valid site name (alphanumeric) and domain (e.g. example.com).");
    }
  } else if (e.target.closest('.remove')) {
    const removeBtn = e.target.closest('.remove');
    const domain = removeBtn.dataset.domain;
    const isPreset = removeBtn.dataset.isPreset === 'true';

    if (!isPreset) {
      let { customSites, disabledSites } = await getSettings();
      customSites = customSites.filter(site => site.domain !== domain);
      disabledSites = disabledSites.filter(d => d !== domain);
      await chrome.storage.local.set({ customSites, disabledSites });
    } else {
      let { hiddenPresets } = await getSettings();
      if (!hiddenPresets.includes(domain)) hiddenPresets.push(domain);
      await chrome.storage.local.set({ hiddenPresets });
    }
    updateToggles();
  } else if (e.target.closest('#theme-toggle')) {
    toggleTheme();
  } else if (e.target.closest('#settings-btn')) {
    showSettingsView();
  } else if (e.target.closest('#back-btn')) {
    hideSettingsView();
  }
});

// ── Settings View Logic ──

async function showSettingsView() {
  document.getElementById('main-view').style.display = 'none';
  document.getElementById('settings-view').style.display = 'flex';
  await loadSettingsData();
}

function hideSettingsView() {
  document.getElementById('settings-view').style.display = 'none';
  document.getElementById('main-view').style.display = 'block';
}

async function loadSettingsData() {
  const settings = await getSettings();

  // Populate auto-add toggle
  const autoAddToggle = document.getElementById('settings-auto-add-toggle');
  if (autoAddToggle) autoAddToggle.checked = settings.autoAddSite;

  const fixedSizeToggle = document.getElementById('settings-fixed-size-toggle');
  if (fixedSizeToggle) fixedSizeToggle.checked = settings.fixedPhysicalSize;

  // Populate hidden presets
  renderHiddenPresets(settings.hiddenPresets);
}

function renderHiddenPresets(hiddenPresets) {
  const container = document.getElementById('presets-restore-list');
  if (!container) return;
  container.innerHTML = '';

  if (hiddenPresets.length === 0) {
    container.innerHTML = '<div style="font-size:11px;color:var(--text-dim);text-align:center;padding:12px 0;font-style:italic;">No deleted presets.</div>';
    return;
  }

  hiddenPresets.forEach(domain => {
    const site = PRESET_SITES.find(s => s.domain === domain) || { name: domain, domain };
    const row = document.createElement('div');
    row.className = 'restore-item';

    const nameEl = document.createElement('span');
    nameEl.className = 'restore-name';
    nameEl.textContent = `${site.name} (${site.domain})`;
    row.appendChild(nameEl);

    const restoreBtn = document.createElement('button');
    restoreBtn.className = 'restore-btn';
    restoreBtn.textContent = 'Restore';
    restoreBtn.addEventListener('click', async () => {
      let { hiddenPresets: current } = await getSettings();
      current = current.filter(d => d !== domain);
      await chrome.storage.local.set({ hiddenPresets: current });
      loadSettingsData();
      updateToggles();
    });
    row.appendChild(restoreBtn);

    container.appendChild(row);
  });
}

// Auto-add toggle handler — only saves the preference.
// The actual auto-fill happens when the user clicks "Add Website".
document.getElementById('settings-auto-add-toggle')?.addEventListener('change', async (e) => {
  await chrome.storage.local.set({ autoAddSite: e.target.checked });
});

document.getElementById('settings-fixed-size-toggle')?.addEventListener('change', async (e) => {
  await chrome.storage.local.set({ fixedPhysicalSize: e.target.checked });
});

document.getElementById('settings-clear-custom-btn')?.addEventListener('click', async () => {
  if (confirm('Clear all custom websites?')) {
    await chrome.storage.local.set({ customSites: [] });
    updateToggles();
  }
});

document.getElementById('settings-reset-all-btn')?.addEventListener('click', async () => {
  if (confirm('Reset all settings to default? This cannot be undone.')) {
    await chrome.storage.local.clear();
    initTheme();
    updateToggles();
    loadSettingsData();
  }
});

chrome.storage.onChanged.addListener(() => {
  updateToggles();
});

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  updateToggles();
  initDragAndDrop();
});
