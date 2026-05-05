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
from .services.browser_pool import browser_pool
from .services.tracer import trace_url
from .services.scanner import scan_url, SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS
from .services.cache_manager import cache_manager
from urllib.parse import urlparse

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
    
    # 6. VirusTotal Flags
    vendor_flags = scan_data.get("vendor_flags", 0)
    if vendor_flags > 0:
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
                "domain_age_days": 3000,
                "typosquatting_detected": False,
                "threat_type": None,
                "vendor_flags": 0,
                "total_vendors": 70
            }
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Security scan failed for {final_url}: {e}, using fallback data")
            scan_data = {
                "domain_age_days": 3000,
                "typosquatting_detected": False,
                "threat_type": None,
                "vendor_flags": 0,
                "total_vendors": 70
            }

        # --- Weighted Risk Scorer ---
        risk_score, verdict, is_safe, reasons = calculate_risk_score(hops, scan_data, final_url)

        security_report = SecurityReport(
            is_safe=is_safe,
            verdict=verdict,
            threat_type=scan_data.get("threat_type"),
            vendor_flags=scan_data.get("vendor_flags", 0),
            total_vendors=scan_data.get("total_vendors", 70),
            domain_age_days=scan_data.get("domain_age_days"),
            risk_score=risk_score,
            suspicious_redirects=len(hops) > 3,
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
        raise HTTPException(status_code=500, detail=str(e))
