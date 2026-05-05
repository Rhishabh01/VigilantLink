// Service Worker for API communication

async function getBackendUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["backendUrl"], (result) => {
      resolve(result.backendUrl || "http://127.0.0.1:8000/analyze");
    });
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_link") {
    analyzeLink(request.url)
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    
    return true; // Indicates asynchronous response
  }
});

async function analyzeLink(url) {
  try {
    const backendUrl = await getBackendUrl();
    const response = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
      throw new Error(`Backend Error: ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error("VigilantLink Background Error:", error);
    throw error;
  }
}
