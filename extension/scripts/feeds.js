// Local Threat Feeds Engine for VigilantLink
// Downloads and updates PhishTank & URLHaus locally in chrome.storage.local for instant, offline lookups

var TRUSTED_DOMAINS_FEEDS = [
  "google.com", "youtube.com", "github.com", "microsoft.com",
  "cloudflare.com", "discord.com", "linkedin.com", "apple.com"
];

async function lookupLocalFeeds(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  
  const result = await chrome.storage.local.get(['threatFeeds']);
  const feeds = result.threatFeeds || {};
  
  // 1. Direct URL match (exact match, case insensitive)
  const urlMatch = feeds[url.toLowerCase()];
  if (urlMatch) {
    return urlMatch;
  }
  
  // 2. Host match
  const hostMatch = feeds[hostname];
  if (hostMatch) {
    return hostMatch;
  }
  
  // 3. Root domain match
  const parts = hostname.split('.');
  if (parts.length > 2) {
    const rootDomain = parts.slice(-2).join('.');
    const rootMatch = feeds[rootDomain];
    if (rootMatch) return rootMatch;
  }
  
  return null;
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function updateThreatFeeds() {
  console.log("Starting local threat feed updates...");
  
  // Load existing feeds so we merge instead of overwrite
  const result = await chrome.storage.local.get(['threatFeeds']);
  const feeds = result.threatFeeds || {};
  let updatedCount = 0;
  
  // 1. Fetch URLHaus active malware URLs
  try {
    const response = await fetchWithTimeout('https://urlhaus.abuse.ch/downloads/text/', 10000);
    if (response.ok) {
      const text = await response.text();
      const lines = text.split('\n');
      let count = 0;
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          feeds[trimmed.toLowerCase()] = { source: 'URLHaus', type: 'malware' };
          try {
            const u = new URL(trimmed);
            const host = u.hostname.toLowerCase();
            const isTrusted = TRUSTED_DOMAINS_FEEDS.some(d => host === d || host.endsWith('.' + d));
            if (!isTrusted) {
              feeds[host] = { source: 'URLHaus', type: 'malware' };
            }
          } catch(e) {}
          count++;
          if (count > 5000) break; // Keep memory lightweight
        }
      }
      updatedCount += count;
      console.log(`URLHaus feed updated: loaded ${count} entries`);
    }
  } catch (e) {
    console.warn("Failed to update URLHaus feed, failing gracefully:", e);
  }
  
  // 2. Fetch PhishTank active phishing URLs
  try {
    const response = await fetchWithTimeout('https://raw.githubusercontent.com/stamparm/aux/master/phishtank-active.txt', 10000);
    if (response.ok) {
      const text = await response.text();
      const lines = text.split('\n');
      let count = 0;
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          feeds[trimmed.toLowerCase()] = { source: 'PhishTank', type: 'phishing' };
          try {
            const u = new URL(trimmed);
            const host = u.hostname.toLowerCase();
            const isTrusted = TRUSTED_DOMAINS_FEEDS.some(d => host === d || host.endsWith('.' + d));
            if (!isTrusted) {
              feeds[host] = { source: 'PhishTank', type: 'phishing' };
            }
          } catch(e) {}
          count++;
          if (count > 5000) break; // Keep memory lightweight
        }
      }
      updatedCount += count;
      console.log(`PhishTank feed updated: loaded ${count} entries`);
    }
  } catch (e) {
    console.warn("Failed to update PhishTank feed, failing gracefully:", e);
  }
  
  if (updatedCount > 0) {
    await chrome.storage.local.set({ threatFeeds: feeds, lastFeedUpdate: Date.now() });
    console.log("Local threat feeds saved to chrome.storage.local successfully!");
  }
}
