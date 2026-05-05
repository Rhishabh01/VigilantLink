import asyncio
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Fix for Windows ProactorEventLoop requirement for Playwright/Subprocesses
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from .models import AnalyzeRequest, AnalyzeResponse, RedirectHop, SecurityReport
from .services.browser_pool import browser_pool
from .services.tracer import trace_url
from .services.scanner import scan_url, SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS
from .services.cache_manager import cache_manager
from urllib.parse import urlparse

def calculate_risk_score(hops, scan_data, final_url):
    risk_score = 0
    reasons = []
    
    # 1. Punycode/Homograph Detector
    punycode_found = "xn--" in final_url or any("xn--" in hop["url"] for hop in hops)
    if punycode_found:
        risk_score += 60
        reasons.append("Deceptive Identity (Punycode Homograph Attack)")
        
    # 2. Redirect Velocity Logic
    if len(hops) > 1:
        redirect_penalty = 0
        for i in range(1, len(hops)):
            prev_domain = urlparse(hops[i-1]["url"]).netloc
            curr_domain = urlparse(hops[i]["url"]).netloc
            if prev_domain != curr_domain:
                redirect_penalty += 30
            else:
                redirect_penalty += 15
        risk_score += redirect_penalty
        if redirect_penalty > 0:
            reasons.append(f"High Redirect Velocity (+{redirect_penalty} penalty)")
                
    # 3. Compound Heuristics
    parsed_final = urlparse(final_url)
    domain_parts = parsed_final.netloc.split('.')
    tld = f".{domain_parts[-1]}".lower() if len(domain_parts) > 0 else ""
    path_lower = parsed_final.path.lower()
    
    if tld in SUSPICIOUS_TLDS and any(kw in path_lower for kw in HIGH_RISK_KEYWORDS):
        risk_score += 50
        reasons.append("High-Risk TLD & Keyword Synergy")
        
    # Existing heuristics from scan_data
    if scan_data.get("domain_age_days", 3000) < 30:
        risk_score += 30
        reasons.append("Newly Registered Domain (<30 days)")
        
    if scan_data.get("typosquatting_detected"):
        risk_score += 50
        reasons.append("Typosquatting Detected (High Value Target)")
    elif scan_data.get("threat_type") == "Suspicious Keywords in Domain":
        risk_score += 25
        reasons.append("Suspicious Keywords in Domain")
        
    capped_score = min(risk_score, 100)
    
    # Verdict Mapper
    is_safe = True
    verdict = "green"
    if capped_score >= 66:
        is_safe = False
        verdict = "red"
    elif capped_score >= 36:
        is_safe = False
        verdict = "yellow"
        
    return capped_score, verdict, is_safe, reasons

app = FastAPI(title="VigilantLink Security API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to extension ID
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
    
    # 1. Check Cache
    cached_result = cache_manager.get(url_str)
    if cached_result:
        return cached_result
    
    try:
        # 2. Trace Redirects
        trace_result = await trace_url(url_str)
        final_url = trace_result["final_url"]
        hops = trace_result["hops"]
        
        # 3. Security Scan
        scan_data = await scan_url(final_url)
        
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
