let _pageAnalysisCache = new Map()

function cachedPageAnalysis(tabId) {
  return _pageAnalysisCache.get(tabId) || null
}

function cachePageAnalysis(tabId, result) {
  _pageAnalysisCache.set(tabId, result)
  setTimeout(() => _pageAnalysisCache.delete(tabId), 30000)
}

async function analyzePageBehavior(tabId) {
  if (!tabId) return { detected: false, signals: [], reasons: [] }
  const cached = cachedPageAnalysis(tabId)
  if (cached) return cached
  try {
    const result = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const signals = []
        const reasons = []
        const hasHiddenIframes = Array.from(document.querySelectorAll('iframe')).some(
          f => f.style.display === 'none' || f.style.visibility === 'hidden' || f.width <= 1
        )
        if (hasHiddenIframes) {
          signals.push('hidden_iframes')
          reasons.push('Page contains hidden iframes')
        }
        const hasFakeLoginForm = !!document.querySelector(
          'form input[type="password"]'
        ) && !document.querySelector(
          'form[action*="login" i], form[action*="auth" i], form[action*="signin" i]'
        )
        if (hasFakeLoginForm) {
          signals.push('fake_login_form')
          reasons.push('Suspicious login form with non-standard action')
        }
        const hasClipboardListeners = (() => {
          try {
            const proto = window.constructor.prototype
            const desc = Object.getOwnPropertyDescriptor(proto, 'oncopy') ||
                         Object.getOwnPropertyDescriptor(proto, 'onpaste') ||
                         Object.getOwnPropertyDescriptor(proto, 'oncut')
            return !!desc
          } catch { return false }
        })()
        if (hasClipboardListeners) {
          signals.push('clipboard_listeners')
          reasons.push('Page monitors clipboard activity')
        }
        const hasFullscreenOverlay = !!document.querySelector(
          'div[style*="position: fixed"][style*="z-index: 9999"], ' +
          'div[style*="position: fixed"][style*="z-index: 2147483647"]'
        )
        if (hasFullscreenOverlay) {
          signals.push('fullscreen_overlay')
          reasons.push('Suspicious fullscreen overlay detected')
        }
        const hasWalletConnectors = !!document.querySelector(
          '[class*="wallet" i], [id*="wallet" i], [class*="connect" i][class*="wallet" i]'
        )
        if (hasWalletConnectors) {
          signals.push('wallet_connector')
          reasons.push('Cryptocurrency wallet connector detected')
        }
        return { detected: signals.length > 0, signals, reasons }
      },
    }).catch(() => null)
    if (result && result[0] && result[0].result) {
      cachePageAnalysis(tabId, result[0].result)
      return result[0].result
    }
  } catch {}
  return { detected: false, signals: [], reasons: [] }
}
