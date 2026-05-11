# Extension

Chrome Manifest V3 extension. Two scripts handle all runtime behavior: `content.js` (injected into pages) and `background.js` (service worker).

---

## Directory Structure

```
extension/
├── manifest.json          # MV3 manifest — permissions, content scripts, service worker
├── popup.html             # Popup UI shell
├── scripts/
│   ├── background.js      # Service worker — API calls, polling, message routing
│   └── content.js         # Injected — hover detection, popup rendering, UI lifecycle
└── styles/
    └── (popup CSS)
```

---

## Manifest

Key permissions:

```json
{
  "manifest_version": 3,
  "background": { "service_worker": "scripts/background.js" },
  "content_scripts": [{
    "matches": ["http://*/*", "https://*/*"],
    "js": ["scripts/content.js"]
  }],
  "permissions": ["activeTab", "storage", "tabs"]
}
```

The service worker is persistent only while handling messages. It can be suspended by the browser between requests.

---

## background.js

Service worker. Handles all network communication. Never touches the DOM.

### Message Handlers

| `action` | Behavior |
|---|---|
| `analyze_link` | Cancels any existing request, starts `analyzeTwoPhase` |
| `cancel_analysis` | Aborts `AbortController`, cleans up `activeRequests` |
| `resume_deep_scan` | Re-attaches Phase 2 polling without re-running Phase 1 |

### Request Tracking

```js
const activeRequests = new Map();      // tabId → { controller, generation }
const requestGenerations = new Map();  // tabId → generation counter
```

Each new `analyze_link` message increments the generation counter. Stale results from a previous hover are gated by generation comparison before being sent to `content.js`.

Tabs are cleaned up via `chrome.tabs.onRemoved`.

### analyzeTwoPhase

```
POST /analyze
  └─ If s=2 (cached full result) → return immediately
  └─ If s=1 → start pollForDeepScanBackground (fire-and-forget)
            → send phase1_result to content.js
            → return phase1Data
```

Phase 2 polling starts immediately after Phase 1 returns — it does not wait for the popup to open.

### pollForDeepScanBackground

Wraps `pollForDeepScan` and sends the result to `content.js` via `chrome.tabs.sendMessage`:

```js
chrome.tabs.sendMessage(tabId, {
  action: "phase2_result",
  requestId,
  url,
  data: phase2Data
});
```

Generation check ensures stale results from superseded hovers are not forwarded.

### pollForDeepScan

```
while (elapsed < timeoutMs):
  await sleep(POLL_INTERVAL_MS)       // 1000ms
  GET /analyze/deep/{requestId}
  if data.s === 2 → return data       // complete
  if data.s === 0 → continue polling  // not ready
  if 404/410      → throw             // session expired
throw "Deep scan polling timed out"   // after timeoutMs (30s)
```

Abort signals are checked before each sleep and before each fetch. Network errors (non-abort) are swallowed and polling continues until timeout.

---

## content.js

Injected into every http/https page. Handles:

- Link hover detection
- Popup rendering and positioning
- Phase 1 / Phase 2 UI state transitions
- Message receipt from `background.js`

### Hover Detection

A `mouseover` listener on `document` uses event delegation. When the target (or its ancestor) is an `<a>` element with an `href` starting with `http`:

1. A debounce timer fires after a short delay
2. `chrome.runtime.sendMessage({ action: "analyze_link", url })` is sent to `background.js`
3. The popup is rendered in loading state at the link's position

`mouseout` sends `cancel_analysis` and hides the popup.

### Popup Rendering

The popup is a `<div>` injected into the page body. It is not the extension's `popup.html` — that file is for the toolbar icon click.

State transitions:

```
hidden
  └─ hover detected → loading (spinner)
      └─ phase1_result received → phase1 verdict displayed (s=1 badge)
          └─ phase2_result received → final verdict displayed (s=2 badge, screenshot)
          └─ phase2_error / timeout → phase1 result rendered as final
```

### Message Receipt

`chrome.runtime.onMessage` in `content.js` handles:

| `action` | Behavior |
|---|---|
| `phase1_result` | Updates popup with initial heuristic verdict |
| `phase2_result` | Replaces popup content with final verdict + screenshot |
| `phase2_error` | Falls back to Phase 1 result, marks as preliminary |

Staleness is gated by comparing `message.url` and `message.requestId` against the currently active hover state. Messages for superseded URLs are discarded.

### Extension Popup (toolbar icon)

`popup.html` + `popup.js` handle the toolbar icon click. They display the last analyzed result stored in `chrome.storage.session`, or a prompt to hover a link.

---

## Extension Messaging Flow

```
content.js                background.js              FastAPI Backend
    |                           |                           |
    |-- analyze_link(url) ------>|                           |
    |                           |-- POST /analyze ---------->|
    |                           |<-- { s:1, id, sec } ------|
    |                           |                           |
    |<-- phase1_result(data) ----|-- GET /deep/{id} -------->| (polling starts)
    |  [render phase1 verdict]  |<-- { s:0 } ---------------|
    |                           |-- GET /deep/{id} -------->|
    |                           |<-- { s:2, sec, ss } ------|
    |<-- phase2_result(data) ----|                           |
    |  [render final verdict]   |                           |
```

---

## AbortController Usage

Every `analyze_link` call creates a new `AbortController`. The signal is passed to:
- `fetch(POST /analyze, { signal })`
- `fetch(GET /analyze/deep/{id}, { signal })` inside poll loop
- Pre-poll sleep checks via `signal.aborted`

When `cancel_analysis` is received (mouseout), `controller.abort()` is called. The backend screenshot task is shielded with `asyncio.shield()` server-side so it continues completing even after the client disconnects.
