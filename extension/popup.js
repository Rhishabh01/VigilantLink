const PRESET_SITES = [
  { name: 'YouTube', domain: 'youtube.com' },
  { name: 'X (Twitter)', domain: 'x.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  { name: 'GitHub', domain: 'github.com' }
];

async function getSettings() {
  const data = await chrome.storage.local.get(['globalEnabled', 'disabledSites', 'customSites', 'hiddenPresets', 'theme']);
  
  // Determine default theme based on system preference
  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  
  return {
    globalEnabled: data.globalEnabled !== false,
    disabledSites: data.disabledSites || [],
    customSites: data.customSites || [],
    hiddenPresets: data.hiddenPresets || [],
    theme: data.theme || systemTheme
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
  const { globalEnabled, disabledSites, customSites, hiddenPresets } = await getSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab) return;

  const url = new URL(tab.url);
  const currentHostname = url.hostname;
  const isBrowserPage = url.protocol === 'chrome:' || url.protocol === 'chrome-extension:';

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

    let tabOverride = null;
    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'get_override' });
      if (response && response.override) tabOverride = response.override;
    } catch (e) {
    }

    const isDefaultDisabled = disabledSites.some(d => currentHostname === d || currentHostname.endsWith('.' + d));

    let isCurrentlyDisabled;
    if (tabOverride === 'enabled') isCurrentlyDisabled = false;
    else if (tabOverride === 'disabled') isCurrentlyDisabled = true;
    else isCurrentlyDisabled = isDefaultDisabled;

    siteToggle.checked = !isCurrentlyDisabled;

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

  renderSiteList(disabledSites, customSites, hiddenPresets);
}

function renderSiteList(disabledSites, customSites, hiddenPresets) {
  const listEl = document.getElementById('preset-list');
  if (!listEl) return;

  listEl.textContent = '';

  const availablePresets = PRESET_SITES.filter(site => !hiddenPresets.includes(site.domain));

  availablePresets.forEach(site => {
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

    const removeBtn = document.createElement('span');
    removeBtn.className = 'remove';
    removeBtn.dataset.domain = site.domain;
    removeBtn.title = 'Remove';
    removeBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="3 6 5 6 21 6"></polyline>
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
      </svg>
    `;
    item.appendChild(removeBtn);

    listEl.appendChild(item);
  });

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

document.addEventListener('change', async (e) => {
  if (e.target.id === 'site-toggle') {
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
    const domain = removeBtn.dataset.domain;
    const index = removeBtn.dataset.index;
    if (index !== undefined) {
      let { customSites, disabledSites } = await getSettings();
      const site = customSites[parseInt(index)];
      if (site) {
        customSites.splice(parseInt(index), 1);
        disabledSites = disabledSites.filter(d => d !== site.domain);
        await chrome.storage.local.set({ customSites, disabledSites });
      }
    } else if (domain) {
      let { hiddenPresets } = await getSettings();
      if (!hiddenPresets.includes(domain)) hiddenPresets.push(domain);
      await chrome.storage.local.set({ hiddenPresets });
    }
    updateToggles();
  } else if (e.target.closest('#theme-toggle')) {
    toggleTheme();
  }
});

chrome.storage.onChanged.addListener(() => {
  updateToggles();
});

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  updateToggles();
});
