# Architecture

VigilantLink uses a two-phase progressive analysis pipeline. Phase 1 returns within ~500ms. Phase 2 runs in the background and is polled asynchronously by the extension.

---

## System Overview

```mermaid
graph TD
    A[User hovers a link] --> B[content.js — hover detection]
    B --> C[background.js — AbortController created]
    C --> D[POST /analyze — FastAPI]

    D --> E{Redis cache hit?}
    E -- Full hit s=2 --> Z[Return immediately]
    E -- Partial hit s=1 --> F[Re-trigger Phase 2 background task]
    E -- Miss --> G[RequestCollapser.deduplicated_call]

    G --> H[run_phase1]
    H --> H1[trace_url — redirect chain]
    H --> H2[fetch_metadata]
    H --> H3[check_dns]
    H --> H4[run_heuristics — CPU only]
    H1 & H2 & H3 --> H4

    H4 --> I[compute_heuristic_score]
    I --> J[Stage 1 response returned to extension]
    J --> K[asyncio.create_task — _run_phase2_background]

    K --> L[run_external_scans — parallel]
    L --> L1[SSL cert age]
    L --> L3[Google Safe Browsing]
    L --> L4[RDAP domain age]
    L --> L5[PhishTank Match]

    L1 & L3 & L4 --> M[compute_final_score]
    M --> N{needs_screenshot?}
    N -- Yes --> O[BrowserPool.capture_screenshot]
    N -- No --> P[Build stage 2 response]
    O --> P

    P --> Q[redis_cache.set_pending + set_full]
    Q --> R[Extension polls GET /analyze/deep/{id}]
    R --> S[Stage 2 response returned to popup]
```

---

## Request Lifecycle

### Phase 1 — Instant Analysis (target ≤500ms)

1. Extension POSTs `{ url }` to `/analyze`
2. URL is normalized (tracking params stripped, query sorted)
3. Redis is checked — full or partial cache hit returns immediately
4. `RequestCollapser` deduplicates concurrent hovers for the same URL
5. `run_phase1` executes three coroutines in parallel via `asyncio.TaskGroup`:
   - `trace_url` — follows redirects, detects SSL errors, returns hop chain
   - `fetch_metadata` — extracts title, description, OG image, favicon
   - `check_dns` — resolves domain to detect non-existent domains
6. `run_heuristics` runs synchronously on the final URL (pure CPU, <1ms)
7. `compute_heuristic_score` produces an initial risk score
8. Stage 1 JSON is returned to the extension
9. `asyncio.create_task` fires Phase 2 as a background task

### Phase 2 — Deep Scan (background, polled)

1. `run_external_scans` runs three coroutines in parallel via `asyncio.gather`:
   - SSL certificate age via async TLS handshake
   - Google Safe Browsing v4 threatMatches lookup
   - RDAP domain registration age
   - PhishTank offline match (URL and Domain level)
2. `compute_final_score` merges heuristic base score with external signals
3. `needs_screenshot` gatekeeper decides if Playwright capture is justified
4. If triggered: `BrowserPool.capture_screenshot` runs under a semaphore
5. Full stage 2 response is stored in Redis under two keys:
   - `pending:{request_id}` — for poll endpoint (60s TTL)
   - `full:{canonical_url}` — for future cache hits (1h TTL)

### Polling Lifecycle

```
Extension                     Backend
   |                              |
   |-- POST /analyze ------------>|  (Phase 1 response, s=1)
   |<-- { s:1, id, sec, ... } ----|
   |                              |
   |-- GET /analyze/deep/{id} --->|  (poll #1, s=0 if not ready)
   |<-- { s:0, id } --------------|
   |                              |
   |-- GET /analyze/deep/{id} --->|  (poll #2)
   |<-- { s:2, id, sec, ss, ...} -|  (Phase 2 complete)
   |                              |
```

- Poll interval: 1000ms
- Popup timeout: 15000ms
- Background service worker timeout: 30000ms
- On timeout, popup renders Phase 1 result as final

---

## Async Orchestration

### Request Collapsing

If multiple tabs hover the same normalized URL simultaneously, `RequestCollapser` ensures only one `run_phase1` coroutine executes. All other callers await the same `asyncio.Future`. This prevents redundant network calls under load.

### Screenshot Shielding

The screenshot coroutine is wrapped in `asyncio.shield()`:

```python
screenshot_base64 = await asyncio.shield(
    asyncio.wait_for(browser_pool.capture_screenshot(url), timeout=SCREENSHOT_TIMEOUT_S)
)
```

This ensures the screenshot completes even if the user's HTTP request is cancelled (mouse moved away from the link).

### Lazy Browser Initialization

`BrowserPool` does **not** start Chromium at server startup. It initializes on first use. This prevents the Playwright startup cost from blocking Railway health-check requests during deployment.

---

## Security Pipeline

```
URL Input
  └─ normalize_url()         — strip tracking params, sort query
  └─ DNS check               — detect NXDOMAIN
  └─ trace_url()             — follow redirects, detect SSL errors
  └─ run_heuristics()
        ├─ Levenshtein typosquatting detection
        ├─ TLD + keyword synergy check
        ├─ Punycode/homograph detection
        └─ Suspicious keyword scan
  └─ run_external_scans()
        ├─ SSL cert age (notBefore)
        ├─ Google Safe Browsing v4 threatMatches
        ├─ RDAP domain registration date
        └─ PhishTank Offline Match (URL/Domain)
  └─ compute_final_score()
        ├─ Weighted signal aggregation
        ├─ GSB authoritative override
        ├─ Trusted platform dampening
        ├─ Signal synergy bonuses
        └─ Uncertainty penalties (per timed-out source)
  └─ Verdict: green / yellow / red
```
