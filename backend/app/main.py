import asyncio
import os
import sys
import time
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from .core.logging import setup_logging, get_logger

from .models import AnalyzeRequest
from .services.orchestrator import (
    run_phase1, run_phase2, generate_request_id, normalize_url, needs_screenshot,
)
from .services.scanner import start_phishtank_sync, stop_phishtank_sync
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
rate_limiter = SessionRateLimiter(capacity=10, leak_rate=2.0)



@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────
    # NOTE: Chromium (BrowserPool) is intentionally NOT started here.
    # Launching a browser at startup blocks the event loop for several
    # seconds, causing Railway/health-check timeouts before the server
    # is ready. Instead, browser_pool.start() is called lazily inside
    # capture_screenshot() on first use.
    t0 = time.monotonic()
    start_phishtank_sync()
    logger.info("[STARTUP] Connecting to Redis...")
    try:
        await asyncio.wait_for(redis_cache.connect(), timeout=3.0)
    except asyncio.TimeoutError:
        logger.warning("[STARTUP] Redis connect timed out — running in no-cache mode")
    except Exception as e:
        logger.warning(f"[STARTUP] Redis connection failed — no-cache mode: {e}")
    logger.info(f"[STARTUP] Initialization ready in {time.monotonic() - t0:.2f}s")
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────
    stop_phishtank_sync()
    await browser_pool.stop()
    await redis_cache.close()

# ============================================================
# App Setup
# ============================================================

app = FastAPI(title="VigilantLink Security API", lifespan=lifespan)

@app.get("/")
async def root():
    return {"status": "VigilantLink backend running"}

# Origin validation (relaxed for local dev)
ALLOWED_EXTENSION_ID = os.getenv("EXTENSION_ID", "[MY_EXTENSION_ID]")
ALLOWED_ORIGIN = f"chrome-extension://{ALLOWED_EXTENSION_ID}"

def is_allowed_origin(origin: str) -> bool:
    # Relaxed for local development
    return True

@app.middleware("http")
async def verify_origin_middleware(request: Request, call_next):
    if request.url.path == "/analyze":
        origin = request.headers.get("origin")
        if not is_allowed_origin(origin):
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: Access restricted to official Chrome Extension."}
            )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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

        # Normalize URL for cache deduplication
        canonical = normalize_url(url_str)

        # Check Redis full cache first — return complete result instantly
        cached_full = await redis_cache.get_full(canonical)
        if cached_full:
            logger.info(f"[RESULT] Full cache hit: {canonical[:50]}...")
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
                logger.info(f"[PHASE1] Re-running for stale cache entry: {canonical[:50]}...")
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

        request_id = generate_request_id()

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
                "age": sec.get("ssl_cert_age_days"),
                "sr": sec["suspicious_redirects"],
                "ts": sec["typosquatting_detected"],
                "r": sec["reasons"],
                "ptu": sec.get("pt_url_match", False),
                "ptd": sec.get("pt_domain_match", False),
            },
            "ms": phase1["duration_ms"],
        }

        # Cache partial result
        await redis_cache.set_partial(canonical, {**stage1_response, "_phase1_raw": phase1})

        # Fire-and-forget Phase 2 in background
        asyncio.create_task(_run_phase2_background(request_id, canonical, phase1))

        logger.info(f"Phase 1 complete for {url_str} in {phase1['duration_ms']}ms (id={request_id})")
        return stage1_response

    except Exception as e:
        logger.exception(f"[ERROR] Analyze failed: {str(e)}")
        raise



# ============================================================
# Phase 2: Deep Scan (polled by extension)
# ============================================================

@app.get("/analyze/deep/{request_id}")
async def get_deep_result(request_id: str) -> dict:
    """
    Poll endpoint for Phase 2 deep scan results.
    """
    result = await redis_cache.get_pending(request_id)
    if result:
        # Reduced noise: only log if we actually found something to return
        logger.debug(f"[POLL] Deep result ready for {request_id}")
        return result
    
    return {"s": 0, "id": request_id}


async def _run_phase2_background(
    request_id: str, canonical_url: str, phase1: Dict[str, Any]
) -> None:
    """
    Background task: runs Phase 2 deep scans and stores result for polling.
    """
    logger.info(f"[PHASE2] Background scan started: {request_id}")
    stage2_response = None
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
                "age": sec2.get("ssl_cert_age_days"),
                "sr": sec2["suspicious_redirects"],
                "ts": sec2["typosquatting_detected"],
                "r": sec2["reasons"],
                "gsb": sec2.get("gsb_matched", False),
                "gsbt": sec2.get("gsb_threat_type", None),
                "ptu": sec2.get("pt_url_match", False),
                "ptd": sec2.get("pt_domain_match", False),
            },
            "ms": phase1["duration_ms"] + phase2["duration_ms"],
        }

        # Cache intelligence result
        await redis_cache.set_full(canonical_url, stage2_response)
        await redis_cache.set_pending(request_id, stage2_response)
        logger.info(f"[CACHE] Phase 2 result stored for {canonical_url[:50]} (id={request_id})")

        # 3. Run Phase 3: Compulsory screenshot
        screenshot_base64: Optional[str] = None
        ssl_age = phase2["security"].get("ssl_cert_age_days")
        redirect_depth = len(phase1.get("hops", []))

        if needs_screenshot(metadata, risk_score, ssl_age, redirect_depth):
            logger.info(f"[PHASE2] Launching browser for compulsory screenshot: {final_url[:50]}...")
            try:
                screenshot_base64 = await asyncio.shield(
                    asyncio.wait_for(
                        browser_pool.capture_screenshot(final_url),
                        timeout=SCREENSHOT_TIMEOUT_S,
                    )
                )
                
                # Update status regardless of success to signal polling can stop
                stage2_response["p3"] = "done"

                if screenshot_base64:
                    # Upgrade the cache entry with the screenshot
                    stage2_response["ss"] = screenshot_base64
                    await redis_cache.set_full(canonical_url, stage2_response)
                    await redis_cache.set_pending(request_id, stage2_response)
                    logger.info(f"[CACHE] Phase 3 cache upgraded with screenshot for {request_id}")
                else:
                    logger.debug(f"[PHASE2] Screenshot capture returned empty")
                    # Still need to update pending status so pollers stop
                    await redis_cache.set_pending(request_id, stage2_response)
            except Exception as e:
                logger.warning(f"[PHASE2] Screenshot failed: {e}")
                stage2_response["p3"] = "done"
                await redis_cache.set_pending(request_id, stage2_response)

        logger.info(f"[PHASE2] Deep scan complete for {canonical_url[:50]}...")

    except Exception as e:
        logger.exception(f"[ERROR] Phase 2 failed: {str(e)}")
        
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
                "age": sec1.get("ssl_cert_age_days"),
                "sr": sec1.get("suspicious_redirects", False),
                "ts": sec1.get("typosquatting_detected", False),
                "r": sec1.get("reasons", []) + ["Deep scan unavailable — showing preliminary result"],
                "gsb": False,
                "gsbt": None,
                "ptu": False,
                "ptd": False,
            },
            "ms": phase1.get("duration_ms", 0),
        }
    finally:
        if stage2_response:
            logger.debug(f"[PHASE2] Saving result to pending: {request_id}")
            await redis_cache.set_pending(request_id, stage2_response)



# ============================================================
# Health Check
# ============================================================

@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "service": "VigilantLink"}
