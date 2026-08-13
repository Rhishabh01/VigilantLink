import asyncio
import os
import secrets
import sys
import time

import httpx

# Load .env for local development (Render sets env vars natively)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from datetime import datetime, timezone

from .utils.url_validator import resolve_and_validate

from .core.logging import setup_logging, get_logger

from .models import AnalyzeRequest
from .services.orchestrator import (
    run_phase1, run_phase2, generate_request_id, normalize_url, needs_screenshot,
)
from .services.browser_pool import browser_pool
from .services.redis_cache import RedisCache
from .services.request_collapser import request_collapser
from .middleware.rate_limiter import SessionRateLimiter
from .core.constants import SCREENSHOT_TIMEOUT_S

# Standardized Logging
setup_logging()
logger = get_logger("VigilantLink")

# ============================================================
# Globals
# ============================================================

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_cache = RedisCache(redis_url=REDIS_URL)
rate_limiter = SessionRateLimiter(capacity=10, leak_rate=2.0, redis_cache=redis_cache, prefix="main")
polling_rate_limiter = SessionRateLimiter(capacity=60, leak_rate=2.0, redis_cache=redis_cache, prefix="poll")

# Keep-alive configuration (prevents Render free-tier spin-down)
KEEP_ALIVE_URL = os.getenv("KEEP_ALIVE_URL", "").strip()
KEEP_ALIVE_INTERVAL_S = int(os.getenv("KEEP_ALIVE_INTERVAL_S", "300"))  # default 5 min
# How often to log countdown progress between pings (seconds)
_KA_LOG_INTERVAL = 120  # every 2 minutes


async def _keep_alive_loop() -> None:
    """Periodically ping the /health endpoint to prevent Render spin-down.

    Only runs when KEEP_ALIVE_URL is configured (production). Pings every
    KEEP_ALIVE_INTERVAL_S seconds (default 300 = 5 min). Render free-tier
    spins down after ~15 min of inactivity, so 5 min keeps a safe margin.

    Flow:
      1. Immediate verification ping on startup (no delay).
      2. Countdown logs every _KA_LOG_INTERVAL seconds for visibility.
      3. Repeat indefinitely.
    """
    ping_count = 0
    fail_streak = 0
    health_url = f"{KEEP_ALIVE_URL}/health"
    logger.info(
        f"[KEEP-ALIVE] ⏱️  Timer started — pinging {health_url} "
        f"every {KEEP_ALIVE_INTERVAL_S}s ({KEEP_ALIVE_INTERVAL_S // 60}min)"
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            # ── Ping ────────────────────────────────────────────────
            ping_count += 1
            t0 = time.monotonic()
            try:
                resp = await client.get(health_url)
                elapsed_ms = (time.monotonic() - t0) * 1000
                fail_streak = 0
                logger.info(
                    f"[KEEP-ALIVE] ✅ Ping #{ping_count} OK — "
                    f"status={resp.status_code}, took {elapsed_ms:.0f}ms"
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t0) * 1000
                fail_streak += 1
                logger.error(
                    f"[KEEP-ALIVE] ❌ Ping #{ping_count} FAILED — "
                    f"{type(exc).__name__}: {exc} "
                    f"(fail streak: {fail_streak}, took {elapsed_ms:.0f}ms)"
                )

            # ── Wait with countdown logs ────────────────────────────
            remaining = KEEP_ALIVE_INTERVAL_S
            while remaining > 0:
                sleep_chunk = min(_KA_LOG_INTERVAL, remaining)
                await asyncio.sleep(sleep_chunk)
                remaining -= sleep_chunk
                if remaining > 0:
                    logger.info(
                        f"[KEEP-ALIVE] ⏳ Next ping in {remaining}s "
                        f"({remaining // 60}m {remaining % 60}s)"
                    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────
    # NOTE: Chromium (BrowserPool) is intentionally NOT started here.
    # Launching a browser at startup blocks the event loop for several
    # seconds, causing Render/health-check timeouts before the server
    # is ready. Instead, browser_pool.start() is called lazily inside
    # capture_screenshot() on first use.
    t0 = time.monotonic()
    logger.info("[STARTUP] Connecting to Redis...")
    try:
        await asyncio.wait_for(redis_cache.connect(), timeout=3.0)
        # In dev mode, flush stale cache on startup so schema changes take effect immediately
        if os.getenv("ENVIRONMENT", "development").lower() != "production":
            if redis_cache._is_connected and redis_cache._redis:
                await redis_cache._redis.flushdb()
                logger.info("[STARTUP] Dev mode — Redis cache flushed (stale entries cleared)")
    except asyncio.TimeoutError:
        logger.warning("[STARTUP] Redis connect timed out — running in no-cache mode")
    except Exception as e:
        logger.warning(f"[STARTUP] Redis connection failed — no-cache mode: {e}")


    # Start keep-alive background task only in production
    keep_alive_task = None
    is_production = os.getenv("ENVIRONMENT", "development").lower() == "production"
    if KEEP_ALIVE_URL and is_production:
        keep_alive_task = asyncio.create_task(_keep_alive_loop())
        logger.info(f"[STARTUP] Keep-alive enabled — pinging {KEEP_ALIVE_URL} every {KEEP_ALIVE_INTERVAL_S}s")
    elif KEEP_ALIVE_URL and not is_production:
        logger.info("[STARTUP] KEEP_ALIVE_URL set but ENVIRONMENT != 'production' — keep-alive suppressed for local dev")
    else:
        logger.info("[STARTUP] KEEP_ALIVE_URL not set — keep-alive disabled")

    logger.info(f"[STARTUP] Initialization ready in {time.monotonic() - t0:.2f}s")
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────
    if keep_alive_task:
        keep_alive_task.cancel()
        try:
            await keep_alive_task
        except asyncio.CancelledError:
            logger.info("[KEEP-ALIVE] Task cancelled")
    await browser_pool.stop()
    await redis_cache.close()

# ============================================================
# App Setup
# ============================================================

app = FastAPI(title="VigilantLink Security API", lifespan=lifespan)

@app.get("/")
async def root():
    return {"status": "VigilantLink backend running"}

DEV_MODE = os.getenv("DEV_MODE", "").lower() in ("true", "1", "yes")

def _build_allowed_origins() -> list:
    """Build CORS origin allowlist from environment variables."""
    origins = []
    allowed_ids_str = os.getenv("ALLOWED_EXTENSION_IDS") or os.getenv("EXTENSIONS_IDS") or os.getenv("EXTENSION_ID") or ""
    allowed_ids = [ext_id.strip() for ext_id in allowed_ids_str.split(",") if ext_id.strip()]
    for ext_id in allowed_ids:
        origins.append(f"chrome-extension://{ext_id}")
    if DEV_MODE:
        origins.extend(["http://localhost:8000", "http://127.0.0.1:8000"])
    return origins

def is_allowed_origin(origin: Optional[str]) -> bool:
    if DEV_MODE:
        return True
    if not origin:
        return False

    allowed_ids_str = os.getenv("ALLOWED_EXTENSION_IDS") or os.getenv("EXTENSIONS_IDS") or os.getenv("EXTENSION_ID") or ""
    allowed_ids = [ext_id.strip() for ext_id in allowed_ids_str.split(",") if ext_id.strip()]
    allowed_origins = {f"chrome-extension://{ext_id}" for ext_id in allowed_ids}

    return origin in allowed_origins

MIN_EXTENSION_VERSION = os.getenv("MIN_EXTENSION_VERSION", "2.0.0")

def parse_version(version_str: str) -> tuple:
    try:
        parts = [int(x) for x in version_str.split(".") if x.strip().isdigit()]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except Exception:
        return (0, 0, 0)

def is_version_allowed(version_str: Optional[str]) -> bool:
    if DEV_MODE:
        return True
    if not version_str:
        return False
    return parse_version(version_str) >= parse_version(MIN_EXTENSION_VERSION)

@app.middleware("http")
async def verify_origin_and_version_middleware(request: Request, call_next):
    path = request.url.path
    if path == "/analyze" or path == "/analyze/preview" or path.startswith("/analyze/deep/"):
        # 1. Verify Origin (only for POST requests)
        if path in ("/analyze", "/analyze/preview"):
            origin = request.headers.get("origin")
            if not is_allowed_origin(origin):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden Access: Restricted to official VigilantLink Extension."}
                )
        
        # 2. Verify Version
        client_version = request.headers.get("x-extension-version")
        if not is_version_allowed(client_version):
            return JSONResponse(
                status_code=403,
                content={"detail": "Visit the extension store to get the updated version."}
            )
            
    return await call_next(request)

# Build CORS allowlist from environment. In production, only chrome-extension://
# origins are allowed. This replaces the insecure allow_origins=["*"] +
# allow_credentials=True combination, which would let any origin make
# credentialed requests to the API.
_cors_origins = _build_allowed_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins if _cors_origins else [],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ============================================================
# Phase 1: Instant Analysis (≤500ms)
# ============================================================

@app.post("/analyze")
async def analyze_link(request: Request, body: AnalyzeRequest) -> dict:
    try:
        """
        Phase 1: Returns instant heuristic + metadata results.
        Kicks off Phase 2 deep scan in the background.

        Features:
          - Leaky Bucket rate limiting per session
          - Request collapsing (deduplicate concurrent hovers)
          - Redis cache with soft-TTL
        """
        # Rate limit check
        await rate_limiter.check(request)

        url_str = str(body.url)

        # Reject non-http/https schemes
        parsed = urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scheme: {parsed.scheme}. Only http/https URLs are supported."
            )

        # SSRF protection: block requests to private/reserved IP ranges
        is_safe, _, ssrf_reason = resolve_and_validate(url_str)
        if not is_safe:
            raise HTTPException(
                status_code=400,
                detail=f"URL blocked: {ssrf_reason}"
            )

        # Normalize URL for cache deduplication
        canonical = normalize_url(url_str)

        # Check Redis full cache first — return complete result instantly
        cached_full = await redis_cache.get_full(canonical)
        if cached_full:
            logger.info(f"[RESULT] Full cache hit")
            return cached_full

        # Check partial cache — return stage 1 instantly + re-trigger phase 2
        cached_partial = await redis_cache.get_partial(canonical)
        if cached_partial:
            request_id = cached_partial.get("request_id", generate_request_id())
            # Check if deep scan already completed
            pending = await redis_cache.get_pending(request_id)
            if pending:
                return pending
            # Re-trigger phase 2 in background
            phase1_raw = cached_partial.get("_phase1_raw")
            if phase1_raw is None:
                # Stale cache from old extension version — re-run Phase 1
                logger.info(f"[PHASE1] Re-running for stale cache entry")
                phase1_raw = await run_phase1(url_str)
            asyncio.create_task(
                _run_phase2_background(request_id, canonical, phase1_raw)
            )
            return cached_partial

        if body.cache_only:
            return {"cache_miss": True}

        # --- Fresh analysis (request-collapsed) ---
        phase1 = await request_collapser.deduplicated_call(
            canonical,
            lambda: run_phase1(url_str),
        )

        request_id = secrets.token_hex(12)

        # Build stage 1 response
        metadata = phase1.get("metadata") or {}
        sec = phase1["security"]
        
        stage1_response: Dict[str, Any] = {
            "s": 1,
            "id": request_id,
            "url": url_str,
            "furl": phase1["final_url"],
            "hops": [{"u": h["url"], "c": h["status_code"]} for h in phase1["hops"]],
            "t": metadata.get("title"),
            "d": metadata.get("description"),
            "img": metadata.get("image_url"),
            "fav": metadata.get("favicon_url"),
            "ss": None,
            "sec": {
                "safe": sec["is_safe"],
                "v": sec["verdict"],
                "rs": sec["risk_score"],
                "tt": sec["threat_type"],
                "vf": sec["vendor_flags"],
                "tv": sec["total_vendors"],
                "age": sec.get("ssl_cert_age_days"),
                "sr": sec["suspicious_redirects"],
                "ts": sec["typosquatting_detected"],
                "da": sec.get("da"),
                "r": sec["reasons"],
            },
            "ms": phase1["duration_ms"],
        }

        # Cache partial result
        await redis_cache.set_partial(canonical, {**stage1_response, "_phase1_raw": phase1})

        # Determine if we need to trigger Phase 2 deep scan
        # Gated to reduce backend compute/Render usage. Safe links bypass deep analysis.
        needs_deep_scan = False
        if not sec["is_safe"] or sec["verdict"] != "green":
            needs_deep_scan = True
        elif sec["risk_score"] >= 20: # Threshold for early warning
            needs_deep_scan = True
        elif sec["suspicious_redirects"]:
            needs_deep_scan = True
        elif sec.get("typosquatting_detected", False):
            needs_deep_scan = True

        if needs_deep_scan:
            # Fire-and-forget Phase 2 in background for suspicious/dangerous links
            if len(background_tasks) >= MAX_BACKGROUND_TASKS:
                logger.warning(f"[PHASE2] Background task limit ({MAX_BACKGROUND_TASKS}) reached, skipping deep scan for {request_id}")
                
                # Mark as complete immediately so frontend doesn't hang polling
                # Ensure we run this async operation correctly without blocking
                stage2_bypass = {
                    "s": 2,
                    "id": request_id,
                    "url": url_str,
                    "furl": phase1.get("final_url", url_str),
                    "hops": [{"u": h["url"], "c": h["status_code"]} for h in phase1.get("hops", [])],
                    "t": metadata.get("title"),
                    "d": metadata.get("description"),
                    "img": metadata.get("image_url"),
                    "fav": metadata.get("favicon_url"),
                    "ss": None,
                    "p3": "skipped (server load)",
                    "sec": stage1_response["sec"],
                    "ms": phase1["duration_ms"],
                }
                asyncio.create_task(redis_cache.set_pending(request_id, stage2_bypass))
            else:
                task = asyncio.create_task(_run_phase2_background(request_id, canonical, phase1))
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)
            logger.info(f"Phase 1 complete in {phase1['duration_ms']}ms (id={request_id}). Deep scan triggered.")
        else:
            # Safe link: bypass deep analysis and Playwright to save resources.
            # Mark as complete in Redis so frontend polling terminates immediately.
            stage2_bypass = {
                "s": 2,
                "id": request_id,
                "url": url_str,
                "furl": phase1["final_url"],
                "hops": [{"u": h["url"], "c": h["status_code"]} for h in phase1["hops"]],
                "t": metadata.get("title"),
                "d": metadata.get("description"),
                "img": metadata.get("image_url"),
                "fav": metadata.get("favicon_url"),
                "ss": None,
                "p3": "done",
                "sec": stage1_response["sec"],
                "ms": phase1["duration_ms"],
            }
            # Set pending immediately so background poller resolves
            await redis_cache.set_pending(request_id, stage2_bypass)
            # Cache the full safe result to skip phase 1 entirely on next hover
            await redis_cache.set_full(canonical, stage2_bypass)
            logger.info(f"Phase 1 complete in {phase1['duration_ms']}ms (id={request_id}). Safe link - bypassed Phase 2.")

        return stage1_response

    except Exception as e:
        logger.exception(f"[ERROR] Analyze failed: {str(e)}")
        raise



# ============================================================
# Phase 2: Deep Scan (polled by extension)
# ============================================================

@app.get("/analyze/deep/{request_id}")
async def get_deep_result(request_id: str, request: Request) -> dict:
    """
    Poll endpoint for Phase 2 deep scan results.
    """
    await polling_rate_limiter.check(request)
    
    result = await redis_cache.get_pending(request_id)
    if result:
        # Reduced noise: only log if we actually found something to return
        logger.debug(f"[POLL] Deep result ready for {request_id}")
        return result
    
    return {"s": 0, "id": request_id}


# Global set to hold strong references to background tasks to prevent GC.
# Capped at 100 to prevent unbounded accumulation under extreme load.
MAX_BACKGROUND_TASKS = 100
background_tasks = set()

async def _run_phase2_background(
    request_id: str, canonical_url: str, phase1: Dict[str, Any]
) -> None:
    """
    Background task: runs Phase 2 deep scans and stores result for polling.
    """
    logger.info(f"[PHASE2] Background scan started: {request_id}")
    stage2_response = None
    screenshot_base64 = None
    phase2 = None
    
    try:
        # 1. Run Phase 2 Intelligence
        phase2 = await run_phase2(canonical_url, phase1)

        metadata = phase1.get("metadata")
        final_url = phase1["final_url"]
        risk_score = phase2["security"]["risk_score"]
        sec2 = phase2["security"]

        # 2. Build and Cache Phase 2 result IMMEDIATELY (Intelligence only)
        stage2_response = {
            "s": 2,
            "id": request_id,
            "url": canonical_url,
            "furl": final_url,
            "hops": [{"u": h["url"], "c": h["status_code"]} for h in phase1["hops"]],
            "t": (metadata or {}).get("title"),
            "d": (metadata or {}).get("description"),
            "img": (metadata or {}).get("image_url"),
            "fav": (metadata or {}).get("favicon_url"),
            "ss": None, # Screenshot not ready yet
            "p3": "pending", # Flag indicating Phase 3 is still running
            "sec": {
                "safe": sec2["is_safe"],
                "v": sec2["verdict"],
                "rs": sec2["risk_score"],
                "tt": sec2["threat_type"],
                "vf": sec2["vendor_flags"],
                "tv": sec2["total_vendors"],
                "age": sec2.get("ssl_cert_age_days"),
                "da": sec2.get("domain_age_days"),
                "sr": sec2["suspicious_redirects"],
                "ts": sec2["typosquatting_detected"],
                "r": sec2["reasons"],
                "gsb": sec2.get("gsb_matched", False),
                "gsbt": sec2.get("gsb_threat_type", None),
            },
            "ms": phase1["duration_ms"] + phase2["duration_ms"],
        }

        # Cache intelligence result
        await redis_cache.set_full(canonical_url, stage2_response)
        await redis_cache.set_pending(request_id, stage2_response)
        logger.info(f"[CACHE] Phase 2 result stored (id={request_id})")

        # 3. Run Phase 3: Risk-adaptive screenshot capture
        # Safe (green)   → no Playwright, no automatic screenshot (uses OG metadata or manual button)
        # Suspicious (yellow)  → screenshot allowed
        # Dangerous (red) → screenshot always captured
        screenshot_base64: Optional[str] = None
        ssl_age = phase2["security"].get("ssl_cert_age_days")
        vendor_flags = phase2["security"].get("vendor_flags", 0)
        redirect_depth = len(phase1.get("hops", []))

        if needs_screenshot(metadata, risk_score, ssl_age, vendor_flags, redirect_depth):
            logger.info(f"[PHASE2] Launching browser for screenshot (id={request_id})...")
            try:
                screenshot_base64 = await asyncio.shield(
                    asyncio.wait_for(
                        browser_pool.capture_screenshot(final_url),
                        timeout=SCREENSHOT_TIMEOUT_S,
                    )
                )

                if screenshot_base64:
                    stage2_response["ss"] = screenshot_base64
                    await redis_cache.set_full(canonical_url, stage2_response)
                    logger.info(f"[CACHE] Phase 3 cache upgraded with screenshot for {request_id}")
                else:
                    logger.debug(f"[PHASE2] Screenshot capture returned empty")
            except Exception as e:
                logger.warning(f"[PHASE2] Screenshot failed: {e}")

        stage2_response["p3"] = "done"
        await redis_cache.set_pending(request_id, stage2_response)

        logger.info(f"[PHASE2] Deep scan complete (id={request_id})...")
        
    except Exception as e:
        logger.exception(f"[PHASE2] Background scan failed for {request_id}: {e}")
        
        # Build failure fallback so polling doesn't hang — use Phase 1 data
        sec1 = phase1.get("security", {})
        metadata = phase1.get("metadata") or {}
        stage2_response = {
            "s": 2,
            "id": request_id,
            "url": canonical_url,
            "furl": phase1.get("final_url", canonical_url),
            "hops": [{"u": h["url"], "c": h["status_code"]} for h in phase1.get("hops", [])],
            "t": metadata.get("title"),
            "d": metadata.get("description"),
            "img": metadata.get("image_url"),
            "fav": metadata.get("favicon_url"),
            "ss": None,
            "p3": "done",
            "sec": {
                "safe": sec1.get("is_safe", True),
                "v": sec1.get("verdict", "green"),
                "rs": sec1.get("risk_score", 0),
                "tt": sec1.get("threat_type"),
                "vf": sec1.get("vendor_flags", 0),
                "tv": sec1.get("total_vendors", 0),
                "age": sec1.get("ssl_cert_age_days"),
                "sr": sec1.get("suspicious_redirects", False),
                "ts": sec1.get("typosquatting_detected", False),
                "r": sec1.get("reasons", []) + ["Deep scan unavailable — showing preliminary result"],
                "gsb": False,
                "gsbt": None,
            },
            "ms": phase1.get("duration_ms", 0),
        }
    finally:
        if stage2_response:
            logger.debug(f"[PHASE2] Saving result to pending: {request_id}")
            await redis_cache.set_pending(request_id, stage2_response)
            
        # Aggressive memory release for heavy background tasks
        stage2_response = None
        screenshot_base64 = None
        phase2 = None
        phase1 = None



# ============================================================
# Manual Preview
# ============================================================

@app.post("/analyze/preview")
async def request_preview(request: Request, body: AnalyzeRequest) -> dict:
    await rate_limiter.check(request)
    url_str = str(body.url)
    canonical = normalize_url(url_str)
    
    logger.info(f"[PREVIEW] Manual preview requested...")
    try:
        # Check cache early to find the final URL to speed up Playwright
        cached_full = await redis_cache.get_full(canonical)
        target_url = cached_full.get("furl") if cached_full else url_str
        if not target_url:
            target_url = url_str

        screenshot_base64 = await asyncio.shield(
            asyncio.wait_for(
                browser_pool.capture_screenshot(target_url),
                timeout=SCREENSHOT_TIMEOUT_S,
            )
        )
    except Exception as e:
        logger.error(f"[PREVIEW] Failed to capture screenshot: {e}")
        screenshot_base64 = None

    if screenshot_base64:
        # We might not have had cached_full earlier if Phase 2 was still running
        if not cached_full:
            cached_full = await redis_cache.get_full(canonical)
            
        if cached_full:
            cached_full["ss"] = screenshot_base64
            await redis_cache.set_full(canonical, cached_full)
            req_id = cached_full.get("id")
            if req_id:
                await redis_cache.set_pending(req_id, cached_full)
                
    return {"ss": screenshot_base64}


# ============================================================
# Health Check
# ============================================================

@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "ok",
        "service": "VigilantLink Backend",
        "version": MIN_EXTENSION_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ============================================================
# Domain Age Endpoint
# ============================================================
from .routers import domain_age_router
app.include_router(domain_age_router.router)

