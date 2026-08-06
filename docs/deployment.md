# Deployment

---

## Render (Production)

### Prerequisites

- A Render account
- GitHub repository connected to Render
- A Redis instance (Render Redis or external provider like Upstash)

### Steps

1. Push the repository to GitHub
2. In Render, create a new **Web Service** and connect the repository
3. Under **Build & Deploy**, set the **Root Directory** to `backend/`
4. Set the **Runtime** to `Docker`
5. Create a Redis instance on Render (or use an external Redis provider) and copy its connection string
6. Set environment variables in the Web Service settings (see below)
7. Deploy — Render will automatically build and run the service using the `Dockerfile`

Render injects `PORT` at runtime. The `CMD` in the Dockerfile uses `${PORT:-8080}`.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | Yes | GSB v4 API key |
| `REDIS_URL` | Yes | Redis connection string |
| `LOG_LEVEL` | No | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `EXTENSION_ID` | No | Chrome extension ID for origin validation (relaxed in current code) |

Copy `backend/.env.example` to `backend/.env` for local development.

---

## Docker

### Build

```bash
cd backend
docker build -t vigilantlink-backend .
```

### Run

```bash
docker run -p 8080:8080 \
  -e GOOGLE_SAFE_BROWSING_API_KEY=your_key \
  -e REDIS_URL=redis://host.docker.internal:6379/0 \
  vigilantlink-backend
```

### Dockerfile Breakdown

```dockerfile
FROM python:3.11-slim

# System deps for Chromium headless
RUN apt-get install -y wget curl gnupg fonts-liberation \
    libasound2 libatk-bridge2.0-0 libcups2 libdbus-1-3 libdrm2 \
    libgbm1 libgtk-3-0 libnspr4 libnss3 libvulkan1 \
    libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 \
    libxshmfence1 libglu1-mesa xdg-utils

RUN pip install -r requirements.txt
RUN playwright install chromium

CMD ["bash", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
```

The Chromium system dependencies must be present before `playwright install chromium`. Missing any will cause a runtime crash when the browser pool first activates.

---

## Procfile

```
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Used when deploying on platforms that read `Procfile` directly (e.g., Heroku-style). Render uses the `Dockerfile` by default when the Docker runtime environment is selected.

---

## Local Development

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
playwright install chromium

cp .env.example .env
# Fill in API keys in .env

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend will run in no-cache mode if Redis is not available locally. This is non-fatal.

---

## Playwright Setup

Playwright requires Chromium to be installed separately after pip install:

```bash
playwright install chromium
```

In Docker, this is handled by the `RUN playwright install chromium` layer. On Render, when deployed as a Docker Web Service, the Dockerfile handles it automatically.

If Chromium fails to launch at runtime (typically missing system libraries), the screenshot phase will fail gracefully and Phase 2 will complete without a screenshot. The scoring pipeline is unaffected.

---

## Production Logging

Set `LOG_LEVEL=INFO` in production (the default). Use `LOG_LEVEL=DEBUG` only during local debugging — debug mode logs every poll request and internal scoring step, which floods Render logs.

URL values in logs are truncated to 50 characters:
```python
logger.info(f"[PHASE2] Deep scan complete for {canonical_url[:50]}...")
```

Redis connection failures and Phase 2 exceptions are logged at `WARNING`/`ERROR` level and include enough context to diagnose without exposing full URLs.

---

## Crash Recovery

### Redis unavailable

The backend starts in no-cache mode. All requests run fresh Phase 1 + Phase 2 analyses. Performance degrades (no deduplication or caching) but the service remains functional.

### Chromium crash / browser pool failure

`BrowserPool.capture_screenshot` catches exceptions and returns `None`. The stage 2 response is built without a screenshot. The scoring verdict is unaffected.

### Phase 2 task failure

`_run_phase2_background` wraps `run_phase2` in a try/except. On failure, it builds a fallback stage 2 response from Phase 1 data with `s=2`. The poll endpoint returns this fallback so the extension does not hang.

### External API timeout

Each external scan (PhishTank, OpenPhish, GSB, RDAP, SSL) has an individual timeout. Timeouts set a `*_timed_out` flag and return safe defaults. The orchestrator applies uncertainty penalties based on timeout count and heuristic context.

---

## Scaling Notes

- The server runs a single async uvicorn worker. This is intentional for an async FastAPI app — multiple workers would each hold their own `BrowserPool` and Redis connection, increasing Chromium memory usage significantly.
- The `BrowserPool` semaphore (`MAX_CONCURRENT_SCREENSHOTS`) limits concurrent browser pages. Tune this constant in `constants.py` based on available memory (each page uses ~100–150MB).
- `RequestCollapser` handles burst traffic for the same URL — concurrent hovers deduplicate to one backend call.
- For higher throughput, deploy multiple Render web services behind a load balancer and use a shared Redis instance for cross-instance caching.
