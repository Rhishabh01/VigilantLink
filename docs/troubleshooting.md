# Troubleshooting

---

## Railway Startup Failures

### Service fails health check immediately after deploy

**Cause:** Chromium was previously initialized at startup, blocking the event loop for 3–5 seconds.

**Status:** Fixed. `BrowserPool` now uses lazy initialization — Chromium only starts on first screenshot request.

**If still occurring:** Check Railway logs for `[STARTUP]` lines. If no `[STARTUP] Initialization ready` line appears, the process crashed before the lifespan handler completed. Look for import errors or missing environment variables.

---

### `ModuleNotFoundError` on startup

**Cause:** A dependency is missing from `requirements.txt` or `pip install` failed silently during build.

**Fix:** Check the Railway build logs for pip install errors. Rebuild with cache disabled:

Railway Dashboard → Deployments → Redeploy → clear build cache option.

---

### `PORT` not bound

**Symptom:** Railway shows the service as running but health checks fail.

**Cause:** The server is binding to a hardcoded port instead of `${PORT}`.

**Fix:** Confirm the `CMD` in `Dockerfile` uses `${PORT:-8080}`:

```dockerfile
CMD ["bash", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
```

---

## Playwright / Chromium Issues

### `playwright install chromium` fails during Docker build

**Symptom:** Build exits with a non-zero code during the `RUN playwright install chromium` layer.

**Cause:** Missing system dependencies or network failure fetching the Chromium binary.

**Fix:** Ensure all `apt-get install` packages in the Dockerfile succeed first. The `rm -rf /var/lib/apt/lists/*` at the end of the apt step is important — remove it temporarily to see package errors during debugging.

---

### Chromium fails to launch at runtime

**Symptom:** `[BROWSER] Starting pool` log appears, followed by an error. Screenshots always return `None`.

**Cause:** Missing shared library (e.g., `libgbm1`, `libnss3`).

**Fix:** Run the container interactively and test manually:

```bash
docker run -it vigilantlink-backend bash
playwright install chromium
python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(); print('OK'); b.close()"
```

Missing libraries will be printed as `error while loading shared libraries`.

---

### `--no-sandbox` not set

**Symptom:** Chromium crashes immediately in containerized environment.

**Cause:** Chromium requires `--no-sandbox` when running as root inside a container.

**Status:** Already set in `BrowserPool.start()`. If you have overridden launch args, ensure `--no-sandbox` is included.

---

### Screenshots always `null` in production

**Cause:** `needs_screenshot` gatekeeper returned `False` for all requests, or Chromium is failing silently.

**Check:**
1. Verify `[BROWSER] Launching browser for screenshot` appears in logs
2. If it appears but screenshots are `null`, check for `[BROWSER] Screenshot failed` warnings
3. If the log line never appears, check `needs_screenshot` gatekeeper logic — risk score may be below threshold

---

## Polling Stuck / Popup Never Updates

### Extension shows Phase 1 result indefinitely

**Cause A:** Phase 2 background task crashed before storing a result in Redis.

**Check:** Search Railway logs for `[ERROR] Phase 2 failed`. The fallback handler should have written a stage 2 response anyway. If it did not, it means the `finally` block in `_run_phase2_background` also failed.

**Cause B:** Redis is unavailable, so `set_pending` silently failed.

**Check:** Look for `[STARTUP] Redis connect timed out` or `Redis connection failed`. If present, the poll endpoint has nothing to return.

**Cause C:** The extension's `AbortController` fired before Phase 2 completed (mouse moved).

**Expected behavior:** The popup closes or renders Phase 1 as final. Not a bug.

---

### Poll returns `s=0` indefinitely

**Symptom:** Extension keeps polling, Phase 2 never returns `s=2`.

**Cause:** Phase 2 background task is still running (slow external APIs) or has crashed.

**Fix:** The poll loop in `background.js` times out after 30 seconds and stops. The extension then renders Phase 1 as final. If this happens consistently, check `[PHASE2]` log output for timeout warnings on GSB or RDAP.

---

### `Analysis session expired` error in extension

**Cause:** The `pending:{request_id}` Redis key expired (60s TTL) before the extension started polling. This can happen if the extension was closed and reopened.

**Expected behavior:** The extension catches this error and renders Phase 1 as the final result. Use `resume_deep_scan` message to re-attach to an in-progress poll.

---

## Redis Failures

### Redis connection fails on startup

**Expected behavior:** The backend logs a warning and continues in no-cache mode. All analyses run fresh.

**If Redis is required:** Ensure `REDIS_URL` is set correctly. Railway's Redis plugin sets this automatically. For local development, start Redis locally or use `REDIS_URL=redis://localhost:6379/0`.

---

### Redis runs out of memory

**Cause:** Too many cached results. Default TTLs:
- Full results: 1 hour
- Partial results: 30 min
- Pending: 60 seconds

**Fix:** Reduce `maxsize` values in `RedisCache` or lower TTLs in `constants.py`. Railway's managed Redis instance has a memory limit — set an eviction policy of `allkeys-lru` in Redis config.

---

## Docker Build Failures

### Build hangs at `apt-get install`

**Cause:** Network timeout during package fetch inside the build environment.

**Fix:** Retry the build. If consistently failing, pin to specific package versions or use a different base image mirror.

---

### `pip install` fails for `playwright`

**Cause:** `playwright==1.43.0` requires Python 3.8+. Confirm `FROM python:3.11-slim` is used.

---

## Timeout Handling

### Phase 1 taking > 500ms

**Likely cause:** `trace_url` is following a slow redirect chain. Hard timeout is 2 seconds.

**Check:** Look for `Redirect tracing timed out` in logs. The original URL is used as fallback.

**Secondary cause:** `fetch_metadata` timing out. Metadata fetch failures are non-fatal — `has_metadata` is set to `False` and a +10 penalty applies.

---

### Phase 2 always timing out (entire 3s budget)

**Cause:** All three external scans are timing out. Common in networks with strict outbound filtering.

**Check:** Confirm outbound HTTPS to these hosts is allowed:
- `safebrowsing.googleapis.com`
- RDAP servers (varies by registrar)

---

## Async Task Failures

### `asyncio.TaskGroup` raises `ExceptionGroup`

**Context:** `run_phase1` uses `asyncio.TaskGroup`. If any task raises, the group cancels remaining tasks and raises `ExceptionGroup`.

**Fix:** Individual tasks (`trace_url`, `fetch_metadata`, `check_dns`) should catch their own exceptions and return safe defaults. If you add tasks to the group, ensure they handle exceptions internally.

---

### `asyncio.shield()` not protecting screenshot

**Symptom:** Screenshot is interrupted when the user moves the mouse away.

**Cause:** `asyncio.shield` must wrap the `wait_for`, not just the inner coroutine.

**Correct usage** (already implemented):
```python
await asyncio.shield(
    asyncio.wait_for(browser_pool.capture_screenshot(url), timeout=SCREENSHOT_TIMEOUT_S)
)
```

If the outer `wait_for` is removed, `shield` has no effect on the timeout behavior.

---

## Common Production Issues

| Symptom | Likely cause | Check |
|---|---|---|
| All scores = 0, verdict always green | GSB API key missing | `[GSB]` logs — key not set |
| Domain age always treated as unknown | RDAP timeouts | `[PHASE2] RDAP timeout` in logs |
| Extension popup never opens | Content script not injected | Verify `host_permissions` in `manifest.json` covers the page domain |
| CORS errors in browser console | `ALLOWED_ORIGIN` mismatch | Set `EXTENSION_ID` env var to match installed extension ID |
| Phase 2 never triggers | Phase 1 score below Phase 2 threshold | Expected — only suspicious URLs trigger deep scan |
| Railway deploy succeeds but 502 on all requests | Wrong `PORT` binding | Confirm `CMD` uses `${PORT}` not a hardcoded value |
