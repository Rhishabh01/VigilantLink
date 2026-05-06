import asyncio
import logging
import sys
import warnings
import os
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Fix for Windows ProactorEventLoop requirement for Playwright/Subprocesses
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Suppress noisy Windows connection reset errors
def suppress_connection_reset():
    if sys.platform == 'win32':
        warnings.filterwarnings('ignore', category=ResourceWarning)
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)

suppress_connection_reset()

from .models import AnalyzeRequest, ProgressiveResponse, RedirectHop, SecurityReport
from .services.orchestrator import run_phase1, run_phase2, generate_request_id, needs_screenshot
from .services.browser_pool import browser_pool
from .services.cache_manager import cache_manager
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ============================================================
# App Setup
# ============================================================

app = FastAPI(title="VigilantLink Security API")

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
# Lifecycle
# ============================================================

@app.on_event("startup")
async def startup_event():
    await browser_pool.start()

@app.on_event("shutdown")
async def shutdown_event():
    await browser_pool.stop()

# ============================================================
# Phase 1: Instant Analysis (≤500ms)
# ============================================================

@app.post("/analyze")
async def analyze_link(request: AnalyzeRequest):
    """
    Phase 1: Returns instant heuristic + metadata results.
    Kicks off Phase 2 deep scan in the background.
    
    If a full cached result exists, returns it immediately (stage=2).
    """
    url_str = str(request.url)

    # Reject non-http/https schemes
    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported scheme: {parsed.scheme}. Only http/https URLs are supported."
        )

    # Check full cache first — return complete result instantly
    cached_full = cache_manager.get(url_str)
    if cached_full:
        logger.info(f"Full cache hit for {url_str}")
        return cached_full

    # Check partial cache — return stage 1 instantly + re-trigger phase 2
    cached_partial = cache_manager.get_partial(url_str)
    if cached_partial:
        request_id = cached_partial.get("request_id", generate_request_id())
        # Check if deep scan already completed
        pending = cache_manager.get_pending(request_id)
        if pending:
            return pending
        # Re-trigger phase 2 in background
        asyncio.create_task(
            _run_phase2_background(request_id, url_str, cached_partial.get("_phase1_raw"))
        )
        return cached_partial

    # --- Fresh analysis ---
    request_id = generate_request_id()

    try:
        phase1 = await run_phase1(url_str)
    except Exception as e:
        logger.error(f"Phase 1 failed for {url_str}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Build stage 1 response
    metadata = phase1.get("metadata")
    stage1_response = {
        "stage": 1,
        "request_id": request_id,
        "original_url": url_str,
        "final_url": phase1["final_url"],
        "redirect_chain": phase1["hops"],
        "title": metadata.get("title") if metadata else None,
        "description": metadata.get("description") if metadata else None,
        "preview_image_url": metadata.get("image_url") if metadata else None,
        "favicon_url": metadata.get("favicon_url") if metadata else None,
        "screenshot_base64": None,
        "security": phase1["security"],
        "duration_ms": phase1["duration_ms"],
    }

    # Cache partial result
    cache_manager.set_partial(url_str, {**stage1_response, "_phase1_raw": phase1})

    # Fire-and-forget Phase 2 in background
    asyncio.create_task(_run_phase2_background(request_id, url_str, phase1))

    logger.info(f"Phase 1 complete for {url_str} in {phase1['duration_ms']}ms (id={request_id})")
    return stage1_response


# ============================================================
# Phase 2: Deep Scan (polled by extension)
# ============================================================

@app.get("/analyze/deep/{request_id}")
async def get_deep_result(request_id: str):
    """
    Poll endpoint for Phase 2 deep scan results.
    Returns stage=1 + status=pending if not yet complete.
    Returns stage=2 with full security data when ready.
    """
    result = cache_manager.get_pending(request_id)
    if result:
        return result
    return {"stage": 1, "status": "pending", "request_id": request_id}


async def _run_phase2_background(request_id: str, url_str: str, phase1: dict):
    """
    Background task: runs Phase 2 deep scans and stores result for polling.
    Also triggers Phase 3 screenshot if needed.
    """
    try:
        phase2 = await run_phase2(url_str, phase1)

        metadata = phase1.get("metadata")
        final_url = phase1["final_url"]

        # Phase 3: Conditional screenshot
        screenshot_base64 = None
        risk_score = phase2["security"]["risk_score"]
        if needs_screenshot(metadata, risk_score):
            try:
                screenshot_base64 = await asyncio.wait_for(
                    browser_pool.capture_screenshot(final_url),
                    timeout=5.0
                )
            except Exception as e:
                logger.warning(f"Phase 3 screenshot failed for {final_url}: {e}")

        # Build complete stage 2 response
        stage2_response = {
            "stage": 2,
            "request_id": request_id,
            "original_url": url_str,
            "final_url": final_url,
            "redirect_chain": phase1["hops"],
            "title": metadata.get("title") if metadata else None,
            "description": metadata.get("description") if metadata else None,
            "preview_image_url": metadata.get("image_url") if metadata else None,
            "favicon_url": metadata.get("favicon_url") if metadata else None,
            "screenshot_base64": screenshot_base64,
            "security": phase2["security"],
            "duration_ms": phase2["duration_ms"],
        }

        # Store in pending cache (for polling) and full cache (for re-hover)
        cache_manager.set_pending(request_id, stage2_response)
        cache_manager.set(url_str, stage2_response)

        logger.info(
            f"Phase 2 complete for {url_str} in {phase2['duration_ms']}ms "
            f"(score={risk_score}, verdict={phase2['security']['verdict']})"
        )

    except Exception as e:
        logger.error(f"Phase 2 background task failed for {url_str}: {e}")
        # Store a fallback result so polling doesn't hang forever
        cache_manager.set_pending(request_id, {
            "stage": 2,
            "request_id": request_id,
            "original_url": url_str,
            "final_url": phase1.get("final_url", url_str),
            "redirect_chain": phase1.get("hops", []),
            "title": None,
            "description": None,
            "preview_image_url": None,
            "favicon_url": None,
            "screenshot_base64": None,
            "security": phase1.get("security", {
                "is_safe": True, "verdict": "green", "risk_score": 0,
                "reasons": ["Deep scan failed — showing heuristic result only"],
                "vendor_flags": 0, "total_vendors": 0, "domain_age_days": None,
                "suspicious_redirects": False, "typosquatting_detected": False,
                "threat_type": None,
            }),
            "duration_ms": 0,
        })


# ============================================================
# Health Check
# ============================================================

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "VigilantLink"}
