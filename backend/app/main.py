import asyncio
import logging
import sys
import warnings
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

# Fix for Windows ProactorEventLoop requirement for Playwright/Subprocesses
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Suppress noisy Windows connection reset errors
def suppress_connection_reset():
    if sys.platform == 'win32':
        warnings.filterwarnings('ignore', category=ResourceWarning)
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)

suppress_connection_reset()

from .models import AnalyzeRequest, AnalyzeResponse, RedirectHop, SecurityReport
from .services.browser_pool import browser_pool
from .services.tracer import trace_url
from .services.scanner import scan_url, SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS
from .services.cache_manager import cache_manager
from urllib.parse import urlparse
from app.core.constants import (
    VERDICT_RED_THRESHOLD, VERDICT_YELLOW_THRESHOLD, PUNYCODE_MIN_SCORE,
    BRAND_PENALTY_SCORE, SYNERGY_PENALTY_SCORE, REDIRECT_CHAIN_MAJOR_PENALTY,
    REDIRECT_CHAIN_MINOR_PENALTY, VENDOR_FLAG_PENALTY, NEWLY_REGISTERED_PENALTY,
    RECENTLY_REGISTERED_PENALTY, TYPOSQUATTING_PENALTY, NEWLY_REGISTERED_DAYS,
    RECENTLY_REGISTERED_DAYS, MAX_REDIRECT_HOPS_FREE, SEVERE_VENDOR_FLAGS_THRESHOLD,
    DEFAULT_DOMAIN_AGE_DAYS, TOTAL_VENDORS_COUNT
)

logger = logging.getLogger(__name__)

def calculate_risk_score(hops, scan_data, final_url):
    risk_score = 0
    reasons = []
    
    # 1. Brand Protection (Levenshtein) Rule - STRICT
    if scan_data.get("brand_penalty_reason"):
        risk_score += BRAND_PENALTY_SCORE
        reasons.append(scan_data.get("brand_penalty_reason"))
    
    # 2. Homograph 'Kill-Switch' - STRICT OVERRIDE
    punycode_detected = scan_data.get("punycode_detected", False)
    if punycode_detected or "xn--" in final_url or any("xn--" in hop["url"] for hop in hops):
        # Set minimum score
        risk_score = max(risk_score, PUNYCODE_MIN_SCORE)
        if "Punycode" not in str(reasons):
            reasons.append(f"SEVERE: Punycode Homograph Attack Detected (Minimum Score: {PUNYCODE_MIN_SCORE})")
    
    # 3. Synergy Check (TLD + Keywords) - STRICT
    if scan_data.get("synergy_detected"):
        risk_score += SYNERGY_PENALTY_SCORE
        reasons.append(scan_data.get("synergy_reason", "High-Risk TLD & Keyword Synergy (Phishing Pattern)"))
    
    # 4. Punycode/Homograph Detector (legacy check)
    punycode_found = "xn--" in final_url or any("xn--" in hop["url"] for hop in hops)
    if punycode_found and not punycode_detected:
        risk_score = max(risk_score, PUNYCODE_MIN_SCORE)
        reasons.append(f"SEVERE: Punycode Homograph Attack Detected (Minimum Score: {PUNYCODE_MIN_SCORE})")
    
    # 5. Redirect Chain Analysis
    if len(hops) > MAX_REDIRECT_HOPS_FREE:
        redirect_score = 0
        for i in range(MAX_REDIRECT_HOPS_FREE, len(hops)):
            prev_domain = urlparse(hops[i-1]["url"]).netloc
            curr_domain = urlparse(hops[i]["url"]).netloc
            if prev_domain != curr_domain:
                redirect_score += REDIRECT_CHAIN_MAJOR_PENALTY
            else:
                redirect_score += REDIRECT_CHAIN_MINOR_PENALTY
        risk_score += redirect_score
        if redirect_score > 0:
            reasons.append(f"Excessive Redirect Chain (+{redirect_score})")
    
    # 6. Security Vendor Flags
    vendor_flags = scan_data.get("vendor_flags", 0)
    if vendor_flags > 0:
        risk_score += VENDOR_FLAG_PENALTY
        reasons.append(f"Flagged by {vendor_flags} Security Vendors")
    
    # 7. Domain Age Scoring
    domain_age_days = scan_data.get("domain_age_days", DEFAULT_DOMAIN_AGE_DAYS)
    if domain_age_days < NEWLY_REGISTERED_DAYS:
        risk_score += NEWLY_REGISTERED_PENALTY
        reasons.append(f"Newly Registered Domain (<{NEWLY_REGISTERED_DAYS} days)")
    elif domain_age_days <= RECENTLY_REGISTERED_DAYS:
        risk_score += RECENTLY_REGISTERED_PENALTY
        reasons.append(f"Recently Registered Domain (<{RECENTLY_REGISTERED_DAYS} days)")
    
    # 8. Existing typosquatting detection from scanner
    if scan_data.get("typosquatting_detected") and not scan_data.get("brand_penalty_reason"):
        risk_score += TYPOSQUATTING_PENALTY
        reasons.append("Typosquatting Detected (High Value Target)")
    
    # Cap the score at 100
    capped_score = min(risk_score, 100)
    
    # Verdict Mapper
    is_safe = True
    verdict = "green"
    
    # Security Vendor 'SEVERE' Override - STRICT
    if vendor_flags > SEVERE_VENDOR_FLAGS_THRESHOLD:
        # Force MALICIOUS (red) and score to 99
        is_safe = False
        verdict = "red"
        capped_score = 99
        reasons.append(f"SEVERE OVERRIDE: Flagged by {vendor_flags} Security Vendors (>{SEVERE_VENDOR_FLAGS_THRESHOLD}) - Forced Score: 99")
    elif capped_score >= VERDICT_RED_THRESHOLD:
        is_safe = False
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        is_safe = False
        verdict = "yellow"
    
    return capped_score, verdict, is_safe, reasons

app = FastAPI(title="VigilantLink Security API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_EXTENSION_ID = os.getenv("EXTENSION_ID", "[MY_EXTENSION_ID]")
ALLOWED_ORIGIN = f"chrome-extension://{ALLOWED_EXTENSION_ID}"

def is_allowed_origin(origin: str) -> bool:
    if not origin:
        return False
    return origin == ALLOWED_ORIGIN

@app.middleware("http")
async def verify_origin_middleware(request: Request, call_next):
    # Only enforce on /analyze endpoint or API routes
    if request.url.path == "/analyze":
        origin = request.headers.get("origin")
        if not is_allowed_origin(origin):
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: Access to this API is restricted to the official Chrome Extension."}
            )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await browser_pool.start()

@app.on_event("shutdown")
async def shutdown_event():
    await browser_pool.stop()

@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("5/minute")
async def analyze_link(request: Request, payload: AnalyzeRequest):
    url_str = str(payload.url)

    # Reject non-http/https schemes (mailto:, tel:, file:, etc.)
    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail=f"Unsupported scheme: {parsed.scheme}. Only http/https URLs are supported.")

    # 1. Check Cache
    cached_result = cache_manager.get(url_str)
    if cached_result:
        return cached_result

    try:
        # 2. Trace Redirects
        trace_result = await trace_url(url_str)
        final_url = trace_result["final_url"]
        hops = trace_result["hops"]

        # 3. Security Scan with fallback for resilience
        try:
            scan_data = await asyncio.wait_for(
                scan_url(final_url),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger = logging.getLogger(__name__)
            logger.warning(f"Security scan timed out for {final_url}, using fallback data")
            scan_data = {
                "domain_age_days": DEFAULT_DOMAIN_AGE_DAYS,
                "typosquatting_detected": False,
                "threat_type": None,
                "vendor_flags": 0,
                "total_vendors": TOTAL_VENDORS_COUNT
            }
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Security scan failed for {final_url}: {e}, using fallback data")
            scan_data = {
                "domain_age_days": DEFAULT_DOMAIN_AGE_DAYS,
                "typosquatting_detected": False,
                "threat_type": None,
                "vendor_flags": 0,
                "total_vendors": TOTAL_VENDORS_COUNT
            }

        # --- Weighted Risk Scorer ---
        risk_score, verdict, is_safe, reasons = calculate_risk_score(hops, scan_data, final_url)

        security_report = SecurityReport(
            is_safe=is_safe,
            verdict=verdict,
            threat_type=scan_data.get("threat_type"),
            vendor_flags=scan_data.get("vendor_flags", 0),
            total_vendors=scan_data.get("total_vendors", TOTAL_VENDORS_COUNT),
            domain_age_days=scan_data.get("domain_age_days"),
            risk_score=risk_score,
            suspicious_redirects=len(hops) > MAX_REDIRECT_HOPS_FREE,
            typosquatting_detected=scan_data.get("typosquatting_detected", False),
            reasons=reasons
        )

        # 4. Capture Screenshot via Browser Pool
        screenshot_base64 = await browser_pool.capture_screenshot(final_url)

        response = AnalyzeResponse(
            original_url=url_str,
            final_url=final_url,
            redirect_chain=[RedirectHop(**hop) for hop in hops],
            screenshot_base64=screenshot_base64,
            security=security_report
        )

        # 5. Save to Cache
        cache_manager.set(url_str, response.model_dump())

        return response

    except Exception as e:
        logger.error(f"Analysis failed for {url_str}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Analysis Error")
