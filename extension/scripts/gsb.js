// Google Safe Browsing Verification for VigilantLink
// Query Safe Browsing API v4 as an optional secondary confirmation engine

var GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
var GSB_API_KEY = "AIzaSyD-Cs9Fwtg5KnmV2_kQSiIoJBBV9pwDpWI"; // Google Cloud key

async function checkGoogleSafeBrowsingLocal(url) {
  if (!GSB_API_KEY) return null;
  
  let normalized = url;
  try {
    const parsed = new URL(url);
    if (!parsed.protocol.startsWith('http')) return null;
    normalized = `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}${parsed.search || ''}`;
  } catch (e) {
    return null;
  }
  
  const payload = {
    client: {
      clientId: "vigilantlink",
      clientVersion: "1.2.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: normalized }]
    }
  };
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);
  
  try {
    const response = await fetch(`${GSB_API_URL}?key=${GSB_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    
    if (!response.ok) {
      console.warn("GSB API status error:", response.status);
      return null;
    }
    
    const data = await response.json();
    if (data.matches && data.matches.length > 0) {
      const matches = data.matches.map(m => m.threatType);
      const priority = ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"];
      for (const p of priority) {
        if (matches.includes(p)) {
          return p;
        }
      }
      return matches[0];
    }
  } catch (e) {
    console.warn("GSB check error, failing gracefully:", e);
  } finally {
    clearTimeout(timeoutId);
  }
  
  return null;
}
