const PRESET_SITES = [
  { name: 'YouTube', domain: 'youtube.com' },
  { name: 'X (Twitter)', domain: 'x.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  { name: 'GitHub', domain: 'github.com' }
];

const DEFAULT_BACKEND_URL = "https://vigilantlink-1.onrender.com";

async function getSettings() {
  const data = await chrome.storage.local.get(['theme', 'backendUrl', 'hiddenPresets', 'customSites']);
  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';

  return {
    theme: data.theme || systemTheme,
    backendUrl: data.backendUrl || DEFAULT_BACKEND_URL,
    hiddenPresets: data.hiddenPresets || [],
    customSites: data.customSites || []
  };
}

function showToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2500);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const moonIcon = document.getElementById('moon-icon');
  const sunIcon = document.getElementById('sun-icon');
  if (theme === 'light') {
    if (moonIcon) moonIcon.style.display = 'none';
    if (sunIcon) sunIcon.style.display = 'block';
  } else {
    if (moonIcon) moonIcon.style.display = 'block';
    if (sunIcon) sunIcon.style.display = 'none';
  }
}

async function loadSettings() {
  const settings = await getSettings();
  applyTheme(settings.theme);

  renderHiddenPresets(settings.hiddenPresets);
}

function renderHiddenPresets(hiddenPresets) {
  const container = document.getElementById('presets-container');
  if (!container) return;
  container.innerHTML = '';

  if (hiddenPresets.length === 0) {
    container.innerHTML = '<div class="empty-state">No presets are currently deleted.</div>';
    return;
  }

  hiddenPresets.forEach(domain => {
    const site = PRESET_SITES.find(s => s.domain === domain) || { name: domain, domain };
    const row = document.createElement('div');
    row.className = 'preset-item';

    const info = document.createElement('div');
    const nameSpan = document.createElement('span');
    nameSpan.className = 'preset-name';
    nameSpan.style.fontWeight = '600';
    nameSpan.textContent = site.name;

    const domainSpan = document.createElement('span');
    domainSpan.className = 'preset-domain';
    domainSpan.style.fontSize = '11px';
    domainSpan.style.color = 'var(--text-muted)';
    domainSpan.textContent = ` (${site.domain})`;

    info.appendChild(nameSpan);
    info.appendChild(domainSpan);
    row.appendChild(info);

    const restoreBtn = document.createElement('button');
    restoreBtn.className = 'btn btn-secondary';
    restoreBtn.textContent = 'Restore';
    restoreBtn.style.padding = '6px 12px';
    restoreBtn.addEventListener('click', async () => {
      let { hiddenPresets: currentPresets } = await getSettings();
      currentPresets = currentPresets.filter(d => d !== domain);
      await chrome.storage.local.set({ hiddenPresets: currentPresets });
      showToast(`Restored ${site.name}`);
      loadSettings();
    });
    row.appendChild(restoreBtn);

    container.appendChild(row);
  });
}

document.getElementById('theme-toggle')?.addEventListener('click', async () => {
  const { theme } = await getSettings();
  const newTheme = theme === 'light' ? 'dark' : 'light';
  await chrome.storage.local.set({ theme: newTheme });
  applyTheme(newTheme);
});

document.getElementById('clear-custom-btn')?.addEventListener('click', async () => {
  if (confirm('Are you sure you want to clear all custom websites?')) {
    await chrome.storage.local.set({ customSites: [] });
    showToast('Custom websites cleared');
    loadSettings();
  }
});

document.getElementById('reset-all-btn')?.addEventListener('click', async () => {
  if (confirm('Are you sure you want to reset all settings to factory default?')) {
    await chrome.storage.local.clear();
    showToast('All settings reset to default');
    loadSettings();
  }
});

chrome.storage.onChanged.addListener(() => {
  loadSettings();
});

document.addEventListener('DOMContentLoaded', loadSettings);
