# Backend

FastAPI application serving two endpoints: a synchronous Phase 1 analysis and an async poll endpoint for Phase 2 results.

---

## Directory Structure

```
backend/
├── app/
│   ├── main.py                    # App setup, endpoints, background task runner
│   ├── models.py                  # Pydantic request models
│   ├── core/
│   │   ├── constants.py           # Thresholds, timeouts, lists (keywords, TLDs, etc.)
│   │   └── logging.py             # Structured logging setup
│   ├── middleware/
│   │   └── rate_limiter.py        # Leaky bucket rate limiter per session
│   └── services/
│       ├── orchestrator.py        # Phase 1/2 execution, scoring logic
│       ├── scanner.py             # Heuristics + external API calls
│       ├── tracer.py              # Redirect chain follower
│       ├── metadata_fetcher.py    # OG/meta tag extractor
│       ├── rdap_client.py         # Domain age via RDAP
│       ├── browser_pool.py        # Playwright screenshot pool
│       ├── redis_cache.py         # Redis-backed persistence
│       ├── cache_manager.py       # In-process TTLCache fallback
│       └── request_collapser.py   # Concurrent request deduplication
├── Dockerfile
├── Procfile
├── requirements.txt
└── run.py
```

---

## Endpoints

### `GET /`
Health indicator. Returns `{ "status": "VigilantLink backend running" }`.

### `POST /analyze`
Phase 1 entry point. Accepts `{ "url": "<string>" }`.

Flow:
1. Rate limiter check (leaky bucket, 10 capacity, 2.0/s leak rate)
2. Scheme validation — rejects non-http/https
3. `normalize_url` — strips tracking params, sorts query, lowercases host
4. Redis full cache check → return immediately if hit
5. Redis partial cache check → re-trigger Phase 2 if Phase 1 cached
6. `RequestCollapser.deduplicated_call` → `run_phase1`
7. Stage 1 response built from Phase 1 result (compact JSON wire format)
8. Partial result stored in Redis
9. `asyncio.create_task(_run_phase2_background(...))` — fire-and-forget
10. Stage 1 response returned

### `GET /analyze/deep/{request_id}`
Phase 2 poll endpoint. Returns `{ "s": 0, "id": request_id }` if not ready, or the full stage 2 response when complete.

### `GET /health`
Returns `{ "status": "ok", "service": "VigilantLink" }`. Used by Railway health checks.

---

## orchestrator.py

Core execution engine. Contains:

| Function | Responsibility |
|---|---|
| `normalize_url` | Canonical form for cache deduplication |
| `check_dns` | Non-blocking DNS resolution via `getaddrinfo` |
| `detect_hosted_phishing` | Detects phishing abuse on trusted hosting platforms |
| `compute_heuristic_score` | Phase 1 scoring — heuristics only, no external data |
| `compute_final_score` | Phase 2 scoring — merges heuristics + external signals |
| `run_phase1` | Parallel trace + metadata + DNS + heuristics |
| `run_phase2` | External scans + final weighted scoring |
| `needs_screenshot` | Gatekeeper: decides if Playwright capture is justified |

### Phase 1 Concurrency

```python
async with asyncio.TaskGroup() as tg:
    trace_task = tg.create_task(trace_url(url))
    meta_task  = tg.create_task(fetch_metadata(url))
    dns_task   = tg.create_task(check_dns(domain))
```

Uses `asyncio.TaskGroup` (Python 3.11+) for structured concurrency. If any task raises, remaining tasks are cancelled.

### Phase 2 Timeout

```python
external = await asyncio.wait_for(run_external_scans(final_url), timeout=3.0)
```

Hard 3-second budget for all external scans combined. On `TimeoutError`, all sources are marked as timed out and uncertainty penalties apply to the score.

---

## scanner.py

Two tiers:

**Tier 1 — CPU heuristics (`run_heuristics`)**
- Levenshtein distance (distance=1) against `HIGH_VALUE_TARGETS` for typosquatting
- TLD + keyword synergy (`SUSPICIOUS_TLDS` × `HIGH_RISK_KEYWORDS`)
- Punycode/homograph detection (`xn--` prefix)
- Suspicious keyword presence in root domain
- Target: <1ms, no network

**Tier 2 — Network lookups (`run_external_scans`)**

```python
results = await asyncio.gather(
    _safe_ssl(), check_phishtank(url), check_openphish(url), _safe_gsb(), _safe_rdap()
)
```

Each sub-call wraps its coroutine in `asyncio.wait_for` with an individual timeout. Failures set a `*_timed_out` flag; they do not raise.

| Source | Timeout | Key returned |
|---|---|---|
| SSL cert age | `SSL_CERT_TIMEOUT_S` | `ssl_cert_age_days` |
| PhishTank | 2.0s | `phishtank_flagged`, `phishtank_timed_out` |
| OpenPhish | 3.0s | `openphish_flagged`, `openphish_timed_out` |
| Google Safe Browsing | `GSB_TIMEOUT_S` | `gsb_threats`, `gsb_threat_type` |
| RDAP | `RDAP_TIMEOUT_S` | `domain_age_days` |

---

## tracer.py

Follows up to 10 redirects with a 2-second hard timeout using `httpx.AsyncClient`. Returns:

```python
{
  "final_url": str,
  "hops": [{ "url": str, "status_code": int }, ...],
  "ssl_error": bool
}
```

SSL errors are detected by inspecting the exception message for `"SSL"` or `"certificate verify failed"`. On timeout or error, the original URL is returned as the only hop with `status_code: 0`.

---

## browser_pool.py

`BrowserPool` manages a single shared Playwright `BrowserContext` with a semaphore gating concurrent screenshot pages.

**Initialization:** Lazy — Chromium does not launch at startup. First call to `capture_screenshot` triggers `start()`. This avoids blocking the event loop during Railway health-check window.

**Launch args:**
```
--disable-gpu --no-sandbox --disable-dev-shm-usage
```

**Screenshot:** JPEG at quality 50, returned as a `data:image/jpeg;base64,...` string. Retried once on failure.

**Caller contract:** Wrap with `asyncio.shield()` to prevent cancellation when the user's HTTP request is aborted.

---

## Cache Architecture

Two implementations exist:

**`redis_cache.py` — Primary (persistent)**

| Key pattern | TTL | Content |
|---|---|---|
| `full:{canonical_url}` | 1 hour | Complete stage 2 response |
| `partial:{canonical_url}` | 30 min | Stage 1 response + `_phase1_raw` |
| `pending:{request_id}` | 60 sec | Stage 2 result awaiting poll |

Redis connection is attempted at startup with a 3-second timeout. On failure, the backend operates in no-cache mode without crashing.

**`cache_manager.py` — Fallback (in-process)**

`cachetools.TTLCache` used when Redis is unavailable. Not shared across workers.

---

## Logging

Configured via `app/core/logging.py`. Log level is controlled by the `LOG_LEVEL` environment variable (default: `INFO` in production).

Prefix tags used throughout:

| Tag | Module |
|---|---|
| `[STARTUP]` | `main.py` lifespan |
| `[PHASE1]` | `orchestrator.py` |
| `[PHASE2]` | `orchestrator.py`, `main.py` |
| `[SCORING]` | `orchestrator.py` |
| `[BROWSER]` | `browser_pool.py` |
| `[PhishTank]` / `[OpenPhish]` | `scanner.py` |
| `[GSB]` | `scanner.py` |
| `[POLL]` | `main.py` |

URLs are truncated to 50 characters in all log statements to avoid leaking full paths in production.

---

## Rate Limiting

`SessionRateLimiter` implements a leaky bucket per session (capacity=10, leak\_rate=2.0/s). Applied to `POST /analyze` only. Returns HTTP 429 when the bucket is full.

---

## Railway Considerations

- Server binds to `${PORT:-8080}` — Railway injects `PORT` at runtime
- Chromium is installed in the Docker image via `playwright install chromium`
- Chromium lazy-start prevents health-check timeouts during cold boot
- Redis connection failure is non-fatal — backend degrades gracefully
- `gunicorn` is available in `requirements.txt` but the default `CMD` uses `uvicorn` directly (single worker is appropriate for async workloads)
