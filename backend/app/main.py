import asyncio
import logging
import sys
import warnings
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

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
from .services.metadata_fetcher import fetch_metadata
from .services.browser_pool import browser_pool
from .services.tracer import trace_url
from .services.scanner import scan_url, SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS
from .services.cache_manager import cache_manager
from urllib.parse import urlparse
from .core.constants import (
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
        risk_score += 50
        reasons.append(scan_data.get("brand_penalty_reason"))
    
    # 2. Homograph 'Kill-Switch' - STRICT OVERRIDE
    punycode_detected = scan_data.get("punycode_detected", False)
    if punycode_detected or "xn--" in final_url or any("xn--" in hop["url"] for hop in hops):
        # Set minimum score of 75 - this is almost exclusively deception
        risk_score = max(risk_score, 75)
        if "Punycode" not in str(reasons):
            reasons.append("CRITICAL: Punycode Homograph Attack Detected (Minimum Score: 75)")
    
    # 3. Synergy Check (TLD + Keywords) - STRICT
    if scan_data.get("synergy_detected"):
        risk_score += 40
        reasons.append(scan_data.get("synergy_reason", "High-Risk TLD & Keyword Synergy (Phishing Pattern)"))
    
    # 4. Punycode/Homograph Detector (legacy check)
    punycode_found = "xn--" in final_url or any("xn--" in hop["url"] for hop in hops)
    if punycode_found and not punycode_detected:
        risk_score = max(risk_score, 75)
        reasons.append("CRITICAL: Punycode Homograph Attack Detected (Minimum Score: 75)")
    
    # 5. Redirect Chain Analysis (first 2 hops are free)
    if len(hops) > 3:
        redirect_score = 0
        for i in range(3, len(hops)):
            prev_domain = urlparse(hops[i-1]["url"]).netloc
            curr_domain = urlparse(hops[i]["url"]).netloc
            if prev_domain != curr_domain:
                redirect_score += 20
            else:
                redirect_score += 5
        risk_score += redirect_score
        if redirect_score > 0:
            reasons.append(f"Excessive Redirect Chain (+{redirect_score})")
    
    # 6. VirusTotal Flags (Ignore 1 flag as it's often a false positive)
    vendor_flags = scan_data.get("vendor_flags", 0)
    if vendor_flags >= 2:
        risk_score += 40
        reasons.append(f"Flagged by {vendor_flags} Security Vendors")
    
    # 7. Domain Age Scoring
    domain_age_days = scan_data.get("domain_age_days", 3000)
    if domain_age_days < 14:
        risk_score += 40
        reasons.append("Newly Registered Domain (<14 days)")
    elif domain_age_days <= 90:
        risk_score += 20
        reasons.append("Recently Registered Domain (<90 days)")
    
    # 8. Existing typosquatting detection from scanner
    if scan_data.get("typosquatting_detected") and not scan_data.get("brand_penalty_reason"):
        risk_score += 50
        reasons.append("Typosquatting Detected (High Value Target)")
    
    # Cap the score at 100
    capped_score = min(risk_score, 100)
    
    # Verdict Mapper
    is_safe = True
    verdict = "green"
    
    # VirusTotal 'Critical' Override - STRICT
    if vendor_flags > 5:
        # Force MALICIOUS (red) and score to 99
        is_safe = False
        verdict = "red"
        capped_score = 99
        reasons.append(f"CRITICAL OVERRIDE: VirusTotal flagged by {vendor_flags} vendors (>5) - Forced Score: 99")
    elif capped_score >= 71:
        is_safe = False
        verdict = "red"
    elif capped_score >= 36:
        is_safe = False
        verdict = "yellow"
    
    return capped_score, verdict, is_safe, reasons

app = FastAPI(title="VigilantLink Security API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
async def analyze_link(request: AnalyzeRequest):
    url_str = str(request.url)

    # Reject non-http/https schemes (mailto:, tel:, file:, etc.)
    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail=f"Unsupported scheme: {parsed.scheme}. Only http/https URLs are supported.")

    # 1. Check Cache
    cached_result = cache_manager.get(url_str)
    if cached_result:
        return cached_result

    import time
    start_time = time.time()
    
    try:
        # 2 & 3. Trace Redirects and Fetch Metadata in Parallel
        # Note: We speculative fetch metadata on the original URL while tracing.
        # If the final URL is different, we'll have the trace data soon.
        print(f"DEBUG: Starting Parallel Trace & Meta for {url_str}")
        trace_task = trace_url(url_str)
        meta_task = fetch_metadata(url_str) # Speculative fetch
        
        trace_result, metadata = await asyncio.gather(trace_task, meta_task)
        
        final_url = trace_result["final_url"]
        hops = trace_result["hops"]
        
        # If redirects were significant (domain change), re-fetch metadata for the final URL
        if urlparse(url_str).netloc != urlparse(final_url).netloc:
            print("DEBUG: Domain changed during redirect, re-fetching metadata...")
            metadata = await fetch_metadata(final_url)
        
        # 4. Security Scan & Screenshot
        parallel_start = time.time()
        async def safe_scan():
            try:
                return await asyncio.wait_for(scan_url(final_url), timeout=8.0)
            except Exception as e:
                logger.warning(f"Security scan failed or timed out: {e}")
                return {
                    "domain_age_days": DEFAULT_DOMAIN_AGE_DAYS,
                    "typosquatting_detected": False,
                    "threat_type": None,
                    "vendor_flags": 0,
                    "total_vendors": TOTAL_VENDORS_COUNT
                }

        scan_task = safe_scan()
        
        screenshot_base64 = ""
        if not metadata or not metadata.get("image_url"):
            print("DEBUG: No metadata image, falling back to screenshot...")
            screenshot_task = browser_pool.capture_screenshot(final_url)
            scan_data, screenshot_base64 = await asyncio.gather(scan_task, screenshot_task)
        else:
            print("DEBUG: Using metadata image, skipping screenshot.")
            scan_data = await scan_task
            
        parallel_duration = time.time() - parallel_start
        print(f"DEBUG: Parallel stage (scan+shot) took {parallel_duration:.2f}s")

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

        response = AnalyzeResponse(
            original_url=url_str,
            final_url=final_url,
            redirect_chain=[RedirectHop(**hop) for hop in hops],
            screenshot_base64=screenshot_base64,
            security=security_report,
            title=metadata.get("title") if metadata else None,
            description=metadata.get("description") if metadata else None,
            preview_image_url=metadata.get("image_url") if metadata else None
        )

        # 5. Save to Cache
        cache_manager.set(url_str, response.model_dump())

        total_duration = time.time() - start_time
        print(f"DEBUG: Total analysis for {url_str} took {total_duration:.2f}s")
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
