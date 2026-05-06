"""
Orchestrator: Tiered parallel execution engine for VigilantLink.

Phase 1 (≤500ms): URL parsing + heuristics + redirect trace + metadata fetch
Phase 2 (~2s):     VirusTotal + WHOIS domain age → final risk score
Phase 3 (optional): Playwright screenshot fallback (background enrichment)
"""

import asyncio
import time
import uuid
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from .tracer import trace_url
from .metadata_fetcher import fetch_metadata
from .scanner import run_heuristics, run_external_scans
from .browser_pool import browser_pool
from .cache_manager import cache_manager
from ..core.constants import (
    VERDICT_RED_THRESHOLD, VERDICT_YELLOW_THRESHOLD, PUNYCODE_MIN_SCORE,
    MAX_REDIRECT_HOPS_FREE, SEVERE_VENDOR_FLAGS_THRESHOLD,
    DEFAULT_DOMAIN_AGE_DAYS, TOTAL_VENDORS_COUNT
)

logger = logging.getLogger(__name__)


def generate_request_id() -> str:
    return uuid.uuid4().hex[:12]


def compute_heuristic_score(heuristics: Dict, hops: list, final_url: str) -> tuple:
    """
    Compute risk score using ONLY heuristic data (no external APIs).
    Returns (score, verdict, is_safe, reasons).
    Used for Phase 1 instant response.
    """
    risk_score = 0
    reasons = []

    # 1. Brand Protection (Levenshtein)
    if heuristics.get("brand_penalty_reason"):
        risk_score += 50
        reasons.append(heuristics["brand_penalty_reason"])

    # 2. Homograph / Punycode detection
    punycode_detected = heuristics.get("punycode_detected", False)
    if punycode_detected or "xn--" in final_url or any("xn--" in hop["url"] for hop in hops):
        risk_score = max(risk_score, PUNYCODE_MIN_SCORE)
        if "Punycode" not in str(reasons):
            reasons.append("CRITICAL: Punycode Homograph Attack Detected")

    # 3. Synergy Check (TLD + Keywords)
    if heuristics.get("synergy_detected"):
        risk_score += 40
        reasons.append(heuristics.get("synergy_reason", "High-Risk TLD & Keyword Synergy"))

    # 4. Redirect chain analysis
    if len(hops) > MAX_REDIRECT_HOPS_FREE:
        redirect_score = 0
        for i in range(MAX_REDIRECT_HOPS_FREE, len(hops)):
            prev_domain = urlparse(hops[i - 1]["url"]).netloc
            curr_domain = urlparse(hops[i]["url"]).netloc
            if prev_domain != curr_domain:
                redirect_score += 20
            else:
                redirect_score += 5
        risk_score += redirect_score
        if redirect_score > 0:
            reasons.append(f"Excessive Redirect Chain (+{redirect_score})")

    # 5. Typosquatting (without brand penalty overlap)
    if heuristics.get("typosquatting_detected") and not heuristics.get("brand_penalty_reason"):
        risk_score += 50
        reasons.append("Typosquatting Detected (High Value Target)")

    capped_score = min(risk_score, 100)

    is_safe = True
    verdict = "green"
    if capped_score >= VERDICT_RED_THRESHOLD:
        is_safe = False
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        is_safe = False
        verdict = "yellow"

    return capped_score, verdict, is_safe, reasons


def compute_final_score(heuristics: Dict, external: Dict, hops: list, final_url: str) -> tuple:
    """
    Compute the full risk score combining heuristics + external scan data.
    Returns (score, verdict, is_safe, reasons).
    Used for Phase 2 complete response.
    """
    # Start with heuristic score
    risk_score, _, _, reasons = compute_heuristic_score(heuristics, hops, final_url)

    # 6. VirusTotal Flags (ignore 1 flag — common false positive)
    vendor_flags = external.get("vendor_flags", 0)
    if vendor_flags >= 2:
        risk_score += 40
        reasons.append(f"Flagged by {vendor_flags} Security Vendors")

    # 7. Domain Age
    domain_age_days = external.get("domain_age_days", DEFAULT_DOMAIN_AGE_DAYS)
    if domain_age_days < 14:
        risk_score += 40
        reasons.append("Newly Registered Domain (<14 days)")
    elif domain_age_days <= 90:
        risk_score += 20
        reasons.append("Recently Registered Domain (<90 days)")

    capped_score = min(risk_score, 100)

    is_safe = True
    verdict = "green"

    # VirusTotal critical override
    if vendor_flags > SEVERE_VENDOR_FLAGS_THRESHOLD:
        is_safe = False
        verdict = "red"
        capped_score = 99
        reasons.append(f"CRITICAL: VirusTotal flagged by {vendor_flags} vendors (>{SEVERE_VENDOR_FLAGS_THRESHOLD})")
    elif capped_score >= VERDICT_RED_THRESHOLD:
        is_safe = False
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        is_safe = False
        verdict = "yellow"

    return capped_score, verdict, is_safe, reasons


async def run_phase1(url: str) -> Dict[str, Any]:
    """
    Phase 1: Instant analysis (target ≤500ms).
    Runs redirect trace, metadata fetch, and CPU heuristics in parallel.
    """
    start = time.time()

    # Run trace + metadata in parallel; heuristics are instant CPU
    trace_task = trace_url(url)
    meta_task = fetch_metadata(url)

    trace_result, metadata = await asyncio.gather(trace_task, meta_task)

    final_url = trace_result["final_url"]
    hops = trace_result["hops"]

    # If domain changed during redirect, re-fetch metadata for final URL
    if urlparse(url).netloc != urlparse(final_url).netloc:
        logger.info(f"Domain changed during redirect, re-fetching metadata for {final_url}")
        metadata = await fetch_metadata(final_url)

    # CPU heuristics — instant
    heuristics = run_heuristics(final_url)

    # Compute initial score (heuristics only)
    risk_score, verdict, is_safe, reasons = compute_heuristic_score(heuristics, hops, final_url)

    # Determine threat type from heuristics
    threat_type = None
    if heuristics.get("brand_penalty_reason"):
        threat_type = "Typosquatting Detected"
    elif heuristics.get("synergy_detected"):
        threat_type = heuristics.get("synergy_reason")
    elif heuristics.get("punycode_detected"):
        threat_type = "Punycode Homograph Attack"
    elif heuristics.get("has_suspicious_keywords"):
        threat_type = "Suspicious Keywords in Domain"

    duration_ms = int((time.time() - start) * 1000)

    return {
        "final_url": final_url,
        "hops": hops,
        "metadata": metadata,
        "heuristics": heuristics,
        "security": {
            "is_safe": is_safe,
            "verdict": verdict,
            "threat_type": threat_type,
            "vendor_flags": 0,
            "total_vendors": 0,
            "domain_age_days": None,
            "risk_score": risk_score,
            "suspicious_redirects": len(hops) > MAX_REDIRECT_HOPS_FREE,
            "typosquatting_detected": heuristics.get("typosquatting_detected", False),
            "reasons": reasons,
        },
        "duration_ms": duration_ms,
    }


async def run_phase2(url: str, phase1_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Phase 2: Deep scan (target ≤2s).
    Runs VirusTotal + WHOIS in parallel. Computes final risk score.
    """
    start = time.time()

    final_url = phase1_result["final_url"]
    hops = phase1_result["hops"]
    heuristics = phase1_result["heuristics"]
    root_domain = heuristics.get("root_domain", urlparse(final_url).netloc)

    try:
        external = await asyncio.wait_for(
            run_external_scans(root_domain),
            timeout=3.0  # Hard limit for entire Phase 2
        )
    except asyncio.TimeoutError:
        logger.warning(f"Phase 2 external scans timed out for {root_domain}")
        external = {
            "domain_age_days": DEFAULT_DOMAIN_AGE_DAYS,
            "vendor_flags": 0,
            "total_vendors": TOTAL_VENDORS_COUNT,
            "threat_type": None,
        }

    # Compute final score
    risk_score, verdict, is_safe, reasons = compute_final_score(
        heuristics, external, hops, final_url
    )

    # Determine threat type (external threats override heuristic-only threats)
    threat_type = phase1_result["security"].get("threat_type")
    if external.get("threat_type"):
        threat_type = external["threat_type"]

    duration_ms = int((time.time() - start) * 1000)

    return {
        "security": {
            "is_safe": is_safe,
            "verdict": verdict,
            "threat_type": threat_type,
            "vendor_flags": external.get("vendor_flags", 0),
            "total_vendors": external.get("total_vendors", TOTAL_VENDORS_COUNT),
            "domain_age_days": external.get("domain_age_days"),
            "risk_score": risk_score,
            "suspicious_redirects": len(hops) > MAX_REDIRECT_HOPS_FREE,
            "typosquatting_detected": heuristics.get("typosquatting_detected", False),
            "reasons": reasons,
        },
        "duration_ms": duration_ms,
    }


def needs_screenshot(metadata: Optional[Dict], risk_score: int) -> bool:
    """Determine if a screenshot is needed (Phase 3 trigger)."""
    has_image = metadata and metadata.get("image_url")
    is_suspicious = risk_score >= VERDICT_YELLOW_THRESHOLD
    return not has_image or is_suspicious
