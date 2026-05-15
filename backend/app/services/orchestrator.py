"""
Orchestrator: Deterministic tiered execution engine for VigilantLink.

Phase 1 (≤500ms): URL parsing + heuristics + redirect trace + metadata fetch
Phase 2 (~2s):     RDAP + GSB → final weighted risk score
Phase 3 (optional): Playwright screenshot (shielded, semaphore-gated)

Key patterns:
  - asyncio.TaskGroup for structured concurrency (Python 3.11+)
  - Request collapsing via RequestCollapser (deduplicate concurrent hovers)
  - asyncio.shield() for Phase 3 so screenshots survive request cancellation
  - Uncertainty penalty when external sources timeout
  - URL normalization for cache deduplication
"""

import asyncio
import logging
import socket
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .tracer import trace_url
from .metadata_fetcher import fetch_metadata
from .scanner import run_heuristics, run_external_scans
from ..core.constants import (
    VERDICT_RED_THRESHOLD, VERDICT_YELLOW_THRESHOLD, PUNYCODE_MIN_SCORE,
    MAX_REDIRECT_HOPS_FREE, TRUSTED_PLATFORM_CAP,
    DEFAULT_DOMAIN_AGE_DAYS,
    BRAND_PENALTY_SCORE, SYNERGY_PENALTY_SCORE, TYPOSQUATTING_PENALTY,
    REDIRECT_CHAIN_MAJOR_PENALTY, REDIRECT_CHAIN_MINOR_PENALTY,
    SSL_CERT_VERY_NEW_PENALTY, SSL_CERT_NEW_PENALTY, SSL_CERT_RECENT_PENALTY, SSL_CERT_YOUNG_PENALTY,
    SSL_CERT_VERY_NEW_DAYS, SSL_CERT_NEW_DAYS, SSL_CERT_RECENT_DAYS, SSL_CERT_YOUNG_DAYS,
    NEWLY_REGISTERED_DAYS, NEWLY_REGISTERED_PENALTY,
    RECENTLY_REGISTERED_DAYS, RECENTLY_REGISTERED_PENALTY,
    WEIGHT_HEURISTIC, WEIGHT_SSL_AGE, WEIGHT_REDIRECT_DEPTH, WEIGHT_RDAP_AGE,
    UNCERTAINTY_PENALTY, TRACKING_PARAMS, PHISHING_KEYWORDS,
    TRUSTED_HOSTING_DOMAINS, TRUSTED_PLATFORMS, SUSPICIOUS_TLDS,
    DECEPTIVE_QUERY_PARAMS, SUSPICIOUS_HOSTED_PATHS, WEAK_SIGNAL_PATTERNS,
    GSB_THREAT_MIN_SCORES, PHISHTANK_URL_PENALTY, PHISHTANK_DOMAIN_PENALTY,
)
from ..core.logging import get_logger

logger = get_logger("VigilantLink")


# ============================================================
# Utilities
# ============================================================

def generate_request_id() -> str:
    return uuid.uuid4().hex[:12]

async def check_dns(domain: str) -> bool:
    """Non-blocking DNS resolution check."""
    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        return True
    except Exception:
        return False

def normalize_url(raw: str) -> str:
    """
    Canonical URL form for cache deduplication.
    - Lowercase scheme + host
    - Strip trailing slash (keep root /)
    - Sort query params
    - Strip tracking params (utm_*, fbclid, gclid, etc.)
    - Strip fragment
    """
    p = urlparse(raw)
    qs = parse_qs(p.query, keep_blank_values=True)
    # Remove tracking parameters (prefix match for utm_)
    filtered = {
        k: v for k, v in qs.items() 
        if k.lower() not in TRACKING_PARAMS and not k.lower().startswith("utm_")
    }
    sorted_qs = urlencode(sorted(filtered.items()), doseq=True)
    return urlunparse((
        p.scheme.lower(),
        p.netloc.lower(),
        p.path.rstrip("/") or "/",
        p.params,
        sorted_qs,
        "",  # strip fragment for normalization
    ))


# ============================================================
# Hosted Phishing Detection
# ============================================================

def detect_hosted_phishing(
    final_url: str,
    hops: List[Dict[str, Any]],
    metadata: Optional[Dict[str, Any]],
    has_phishing_keywords: bool,
) -> Dict[str, Any]:
    """
    Detects phishing abuse on trusted hosting platforms.
    Checks for suspicious paths, deceptive redirect params,
    and redirect chains that end on trusted platforms.
    """
    signals = {
        "active": False,
        "suspicious_path": False,
        "deceptive_param": False,
        "redirect_chain_suspicious": False,
        "corroboration_count": 0,
    }

    domain_lower = urlparse(final_url).netloc.lower()
    is_hosting = any(
        domain_lower == d or domain_lower.endswith(f".{d}")
        for d in TRUSTED_HOSTING_DOMAINS
    )
    if not is_hosting:
        return signals

    path_lower = urlparse(final_url).path.lower()

    for sp in SUSPICIOUS_HOSTED_PATHS:
        if path_lower.startswith(sp):
            signals["suspicious_path"] = True
            break

    parsed_qs = parse_qs(urlparse(final_url).query)
    for param in DECEPTIVE_QUERY_PARAMS:
        if param in parsed_qs:
            val = parsed_qs[param][0]
            if val and not any(
                trusted in val for trusted in TRUSTED_PLATFORMS
            ):
                signals["deceptive_param"] = True
                signals["deceptive_param_name"] = param
                signals["redirect_target"] = val
                break

    if hops and len(hops) > 1:
        for hop in hops[:-1]:
            hop_domain = urlparse(hop["url"]).netloc
            is_trusted_hop = any(
                hop_domain == d or hop_domain.endswith(f".{d}")
                for d in list(TRUSTED_PLATFORMS) + TRUSTED_HOSTING_DOMAINS
            )
            if not is_trusted_hop:
                signals["redirect_chain_suspicious"] = True
                break

    count = 0
    if signals["suspicious_path"]:
        count += 1
    if signals["deceptive_param"]:
        count += 1
    if signals["redirect_chain_suspicious"]:
        count += 1
    if has_phishing_keywords:
        count += 1
    signals["corroboration_count"] = count
    signals["active"] = count >= 1

    return signals


# ============================================================
# Scoring: Weighted formula S = Σ(wi · ci) + U
# ============================================================

def _apply_uncertainty(
    base_score: int,
    ssl_uncertain: bool,
    rdap_uncertain: bool = False,
    gsb_uncertain: bool = False,
    is_suspicious: bool = False,
) -> Tuple[int, int, int]:
    """
    Revised uncertainty penalty logic for 3 external sources.
    Returns (total_score, ssl_penalty, security_penalty).
    """
    ssl_penalty = 0
    security_penalty = 0
    
    # SSL timeout: +2 only if site already shows suspicious signs
    if ssl_uncertain and (is_suspicious or base_score >= VERDICT_YELLOW_THRESHOLD):
        ssl_penalty = 2
        
    # Security sources (GSB/RDAP): +5 each only if multiple fail OR heuristics exist OR near threshold
    if gsb_uncertain or rdap_uncertain:
        timeout_count = sum([gsb_uncertain, rdap_uncertain])
        near_threshold = base_score >= (VERDICT_YELLOW_THRESHOLD - 5)
        
        if timeout_count >= 2 or is_suspicious or near_threshold:
            if gsb_uncertain: security_penalty += 5
            if rdap_uncertain: security_penalty += 5
            
    return min(base_score + ssl_penalty + security_penalty, 100), ssl_penalty, security_penalty


def compute_heuristic_score(
    heuristics: Dict[str, Any],
    hops: List[Dict[str, Any]],
    final_url: str,
    dns_resolves: bool,
    has_metadata: bool,
    metadata: Optional[Dict[str, Any]] = None,
    ssl_error: bool = False,
) -> Tuple[int, str, bool, List[str]]:
    """
    Phase 1 Preliminary Score — uses ONLY local CPU heuristics.
    User sees this within 500ms of hover. No external API data.

    Returns (score, verdict, is_safe, reasons).
    """
    risk_score: int = 0
    reasons: List[str] = []

    # NEW: DNS Failure (CRITICAL)
    if not dns_resolves:
        risk_score += 40
        reasons.append("Domain does not resolve (suspicious)")

    # NEW: Trusted platform detection (used to dampen weak signals)
    domain_lower = urlparse(final_url).netloc.lower()
    is_trusted_platform = any(
        domain_lower == d or domain_lower.endswith(f".{d}")
        for d in TRUSTED_PLATFORMS
    )

    # Metadata Availability
    if not has_metadata and not is_trusted_platform:
        risk_score += 10
        reasons.append("Limited metadata available (Suspicious or obscure site)")

    # NEW: Suspicious TLD Detection
    for tld in SUSPICIOUS_TLDS:
        tld_ext = tld if tld.startswith('.') else f".{tld}"
        if domain_lower.endswith(tld_ext):
            risk_score += 15
            reasons.append(f"Suspicious TLD: {tld_ext}")
            break

    # NEW: HTTPS & Certificate Signal
    parsed_final = urlparse(final_url)
    if parsed_final.scheme == "http":
        risk_score += 20
        reasons.append("Connection is not encrypted (HTTP)")
    
    if ssl_error:
        risk_score += 30
        reasons.append("Invalid SSL certificate")

    # NEW: Phishing Intent Detection (Keywords)
    found_keywords = []
    content_to_check = [parsed_final.path.lower()]
    if metadata:
        if metadata.get("title"):
            content_to_check.append(metadata["title"].lower())
        if metadata.get("description"):
            content_to_check.append(metadata["description"].lower())
            
    for kw in PHISHING_KEYWORDS:
        if any(kw in text for text in content_to_check):
            found_keywords.append(kw)
    
    if found_keywords:
        risk_score += 25
        reasons.append(f"Phishing keyword(s) detected: {', '.join(found_keywords[:3])}")
        
        # Synergy: Keyword + Suspicious TLD/Typosquatting
        is_suspicious_domain = any(domain_lower.endswith(tld if tld.startswith('.') else f".{tld}") for tld in SUSPICIOUS_TLDS)
        if is_suspicious_domain or heuristics.get("typosquatting_detected"):
            risk_score += 30
            reasons.append("High-Risk Synergy: Phishing keyword on suspicious/impersonated domain")

    # Signal 1: Brand impersonation (Levenshtein distance = 1)
    if heuristics.get("brand_penalty_reason"):
        risk_score += round(WEIGHT_HEURISTIC * BRAND_PENALTY_SCORE)
        reasons.append(heuristics["brand_penalty_reason"])

    # Signal 2: Punycode / Homograph (hard floor)
    punycode_detected = heuristics.get("punycode_detected", False)
    if punycode_detected or "xn--" in final_url or any("xn--" in hop["url"] for hop in hops):
        risk_score = max(risk_score, PUNYCODE_MIN_SCORE)
        if "Punycode" not in str(reasons):
            reasons.append("CRITICAL: Punycode Homograph Attack Detected")

    # Signal 3: TLD + Keyword synergy
    if heuristics.get("synergy_detected"):
        risk_score += round(WEIGHT_HEURISTIC * SYNERGY_PENALTY_SCORE)
        reasons.append(heuristics.get("synergy_reason", "High-Risk TLD & Keyword Synergy"))

    # Signal 4: Redirect chain depth
    if len(hops) > MAX_REDIRECT_HOPS_FREE:
        redirect_score = 0
        for i in range(MAX_REDIRECT_HOPS_FREE, len(hops)):
            prev_domain = urlparse(hops[i - 1]["url"]).netloc
            curr_domain = urlparse(hops[i]["url"]).netloc
            if prev_domain != curr_domain:
                redirect_score += round(WEIGHT_REDIRECT_DEPTH * REDIRECT_CHAIN_MAJOR_PENALTY)
            else:
                redirect_score += round(WEIGHT_REDIRECT_DEPTH * REDIRECT_CHAIN_MINOR_PENALTY)
        risk_score += redirect_score
        if redirect_score > 0:
            reasons.append(f"Excessive Redirect Chain (+{redirect_score})")

    # Signal 5: Typosquatting (without brand penalty overlap)
    if heuristics.get("typosquatting_detected") and not heuristics.get("brand_penalty_reason"):
        risk_score += round(WEIGHT_HEURISTIC * TYPOSQUATTING_PENALTY)
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


def compute_final_score(
    heuristics: Dict[str, Any],
    external: Dict[str, Any],
    hops: List[Dict[str, Any]],
    final_url: str,
    dns_resolves: bool,
    has_metadata: bool,
    metadata: Optional[Dict[str, Any]] = None,
    ssl_error: bool = False,
) -> Tuple[int, str, bool, List[str]]:
    """
    Phase 2 Final Score — heuristics + RDAP + GSB + uncertainty penalty.

    Returns (score, verdict, is_safe, reasons).
    """
    # Start with heuristic base score
    risk_score, _, _, reasons = compute_heuristic_score(
        heuristics, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error
    )
    logger.debug(f"[SCORING] {final_url[:50]}... - Initial base score: {risk_score}")

    gsb_threats = external.get("gsb_threats", [])

    # NEW: Detect trusted platform early — used to dampen domain-level leakage
    domain_lower = urlparse(final_url).netloc.lower()
    is_trusted_platform = any(
        domain_lower == d or domain_lower.endswith(f".{d}")
        for d in TRUSTED_PLATFORMS
    )

    # Phishing keyword detection in URL + metadata (used by multiple downstream checks)
    has_phishing_keywords = False
    content_to_check = [urlparse(final_url).path.lower(), urlparse(final_url).query.lower()]
    if metadata:
        if metadata.get("title"): content_to_check.append(metadata["title"].lower())
        if metadata.get("description"): content_to_check.append(metadata["description"].lower())
    if any(kw in text for kw in PHISHING_KEYWORDS for text in content_to_check):
        has_phishing_keywords = True

    # NEW: Trusted-Domain Abuse Detection
    is_trusted_hosting = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_HOSTING_DOMAINS)
    logger.info(f"[SCORING] {final_url[:50]}... - is_trusted_hosting={is_trusted_hosting}, has_phishing_keywords={has_phishing_keywords}")
    if is_trusted_hosting and has_phishing_keywords:
        old_score = risk_score
        if risk_score < 50:
            risk_score = 50
        reasons.append("Suspicious content hosted on trusted platform")
        risk_score = max(risk_score, VERDICT_YELLOW_THRESHOLD + 1)
        logger.info(f"[SCORING] Trusted host escalation: {old_score} -> {risk_score}")

    # Hosted phishing escalation with corroboration
    hosted_signals = detect_hosted_phishing(
        final_url, hops, metadata, has_phishing_keywords
    )
    if hosted_signals.get("active"):
        if hosted_signals.get("suspicious_path"):
            reasons.append("Suspicious authentication path on trusted hosting")
        if hosted_signals.get("deceptive_param"):
            target = hosted_signals.get("redirect_target", "unknown")
            reasons.append(f"Deceptive redirect parameter ({hosted_signals['deceptive_param_name']}) to {target}")
        if hosted_signals.get("redirect_chain_suspicious"):
            reasons.append("Redirect chain passes through untrusted domain before trusted landing")
        
        old_score = risk_score
        if risk_score < 55:
            risk_score = 55
        risk_score = max(risk_score, VERDICT_YELLOW_THRESHOLD + 5)
        logger.info(f"[SCORING] Hosted phishing active: {old_score} -> {risk_score}")

    # Phase 2 Signal: SSL Certificate age
    cert_age = external.get("ssl_cert_age_days")

    if cert_age is not None:
        ssl_age_penalty = 0
        if cert_age < SSL_CERT_VERY_NEW_DAYS:
            ssl_age_penalty = SSL_CERT_VERY_NEW_PENALTY
        elif cert_age < SSL_CERT_NEW_DAYS:
            ssl_age_penalty = SSL_CERT_NEW_PENALTY
        elif cert_age < SSL_CERT_RECENT_DAYS:
            ssl_age_penalty = SSL_CERT_RECENT_PENALTY
        elif cert_age < SSL_CERT_YOUNG_DAYS:
            ssl_age_penalty = SSL_CERT_YOUNG_PENALTY
            
        if ssl_age_penalty > 0:
            is_risky = (
                heuristics.get("typosquatting_detected") or 
                heuristics.get("punycode_detected") or 
                heuristics.get("synergy_detected") or
                heuristics.get("has_suspicious_keywords") or
                has_phishing_keywords or
                bool(gsb_threats) or
                external.get("pt_url_match", False) or
                external.get("pt_domain_match", False)
            )
            
            final_penalty = round(WEIGHT_SSL_AGE * ssl_age_penalty)
            if not is_risky:
                final_penalty = min(final_penalty, 5)
            
            risk_score += final_penalty
            
            if cert_age < SSL_CERT_RECENT_DAYS:
                reasons.append(f"Recently issued SSL certificate (<{cert_age + 1} days)")
            else:
                reasons.append(f"Young SSL certificate ({cert_age} days old)")

    # Phase 2 Signal: Domain Age (RDAP)
    domain_age = external.get("domain_age_days")
    if domain_age is not None:
        rdap_penalty = 0
        if domain_age < NEWLY_REGISTERED_DAYS:
            rdap_penalty = NEWLY_REGISTERED_PENALTY
        elif domain_age < RECENTLY_REGISTERED_DAYS:
            rdap_penalty = RECENTLY_REGISTERED_PENALTY
            
        if rdap_penalty > 0:
            is_risky = (
                heuristics.get("typosquatting_detected") or 
                heuristics.get("punycode_detected") or 
                heuristics.get("synergy_detected") or
                heuristics.get("has_suspicious_keywords") or
                has_phishing_keywords or
                bool(gsb_threats) or
                external.get("pt_url_match", False) or
                external.get("pt_domain_match", False)
            )
            
            final_p = round(WEIGHT_RDAP_AGE * rdap_penalty)
            if not is_risky:
                final_p = min(final_p, 5)
                logger.info(f"[SCORING] Capping RDAP penalty for {final_url[:30]}... (is_risky=False)")
            
            risk_score += final_p
            if domain_age < NEWLY_REGISTERED_DAYS:
                reasons.append(f"Newly registered domain (<{domain_age + 1} days)")
                # High-Sensitivity Synergy: New Domain + Phishing Keywords
                if has_phishing_keywords or heuristics.get("has_suspicious_keywords"):
                    risk_score += 30
                    reasons.append("CRITICAL Synergy: Phishing intent on newly registered domain")
            else:
                reasons.append(f"Recent domain registration ({domain_age} days ago)")
                
                


    logger.debug(f"[SCORING] {final_url[:50]}... - Heuristic base score: {risk_score}")
            
    # Uncertainty penalty for timed-out sources
    ssl_uncertain = external.get("ssl_timed_out", False)
    gsb_uncertain = external.get("gsb_timed_out", False)
    rdap_uncertain = external.get("rdap_uncertain", False)
    
    is_susp_heur = (
        heuristics.get("typosquatting_detected") or 
        heuristics.get("punycode_detected") or 
        heuristics.get("synergy_detected") or
        heuristics.get("has_suspicious_keywords")
    )
    
    risk_score, p_ssl, p_sec = _apply_uncertainty(
        risk_score, ssl_uncertain, rdap_uncertain, gsb_uncertain, is_susp_heur
    )
    
    # Store uncertainty info for filtered reason display
    uncertainty_info = None
    if p_ssl > 0 or p_sec > 0:
        timed_out_count = sum([ssl_uncertain, gsb_uncertain, rdap_uncertain])
        uncertainty_info = (timed_out_count, p_ssl + p_sec)

    # Google Safe Browsing Scoring
    gsb_threat_type = external.get("gsb_threat_type")
    logger.info(f"[SCORING] {final_url[:50]}... - GSB matches: {gsb_threats}, selected type: {gsb_threat_type}")
    if gsb_threats and gsb_threat_type:
        min_score = GSB_THREAT_MIN_SCORES.get(gsb_threat_type, 90)
        old_score = risk_score
        risk_score = max(risk_score, min_score)
        reasons.append(f"CRITICAL: Flagged by Google Safe Browsing ({', '.join(gsb_threats)})")
        logger.info(f"[SCORING] GSB escalation: {old_score} -> {risk_score} (type={gsb_threat_type})")

    pt_url_match = external.get("pt_url_match", False)
    pt_domain_match = external.get("pt_domain_match", False)

    if pt_url_match:
        risk_score = max(risk_score, PHISHTANK_URL_PENALTY)
        reasons.append("CRITICAL: Known phishing URL (PhishTank)")
        logger.debug(f"[SCORING] {final_url[:50]}... - After PhishTank URL match: {risk_score}")
    elif pt_domain_match:
        risk_score = max(risk_score, PHISHTANK_DOMAIN_PENALTY)
        reasons.append("WARNING: Known phishing infrastructure (PhishTank)")
        logger.debug(f"[SCORING] {final_url[:50]}... - After PhishTank Domain match: {risk_score}")

    # Trusted platform calibration: dampen weak/noisy signals
    if is_trusted_platform:
        has_strong_signals = (
            bool(gsb_threats) or
            pt_url_match or
            len(hops) > MAX_REDIRECT_HOPS_FREE or
            heuristics.get("punycode_detected", False) or
            heuristics.get("brand_penalty_reason") is not None or
            hosted_signals.get("active", False)
        )
        logger.info(f"[SCORING] Trusted platform detected. has_strong_signals={has_strong_signals}")
        if not has_strong_signals:
            old_score = risk_score
            risk_score = min(risk_score, TRUSTED_PLATFORM_CAP)
            logger.info(f"[SCORING] Applying trusted platform cap: {old_score} -> {risk_score}")
            reasons = [
                r for r in reasons
                if not any(p.lower() in r.lower() for p in WEAK_SIGNAL_PATTERNS)
            ]
        else:
            logger.info(f"[SCORING] Bypassing trusted platform cap due to strong signals")

    capped_score = min(risk_score, 100)
    logger.info(f"[SCORING] Final capped_score: {capped_score}")

    is_safe = True
    verdict = "green"

    if capped_score >= VERDICT_RED_THRESHOLD:
        is_safe = False
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        is_safe = False
        verdict = "yellow"

    # Issue 2: Only show uncertainty reason if justified by risk or high timeout count
    if uncertainty_info:
        timed_out_count, penalty = uncertainty_info
        is_suspicious_heuristics = (
            heuristics.get("typosquatting_detected") or 
            heuristics.get("punycode_detected") or 
            heuristics.get("synergy_detected") or
            heuristics.get("has_suspicious_keywords")
        )
        # Issue 2: Strictly hide uncertainty from safe (green) verdicts
        show_uncertainty = (
            verdict != "green" and (
                timed_out_count >= 2 or
                bool(gsb_threats) or
                is_suspicious_heuristics
            )
        )
        if show_uncertainty:
            reasons.append(f"Uncertainty penalty (+{penalty}): {timed_out_count}/4 sources timed out")

    logger.debug(f"[SCORING] {final_url[:50]}... - Final Verdict: {verdict}, Safe: {is_safe}, Final Score: {capped_score}")
    return capped_score, verdict, is_safe, reasons


# ============================================================
# Phase 1: Instant Analysis (≤500ms)
# ============================================================

async def run_phase1(url: str) -> Dict[str, Any]:
    """
    Phase 1: Instant analysis (target ≤500ms).
    Runs redirect trace, metadata fetch, and CPU heuristics in parallel.
    Uses asyncio.TaskGroup for structured concurrency.
    """
    start = time.monotonic()

    # Run trace + metadata + dns in parallel
    domain_to_check = urlparse(url).netloc
    if ':' in domain_to_check:
        domain_to_check = domain_to_check.split(':')[0]
        
    async with asyncio.TaskGroup() as tg:
        trace_task = tg.create_task(trace_url(url))
        meta_task = tg.create_task(fetch_metadata(url))
        dns_task = tg.create_task(check_dns(domain_to_check))

    trace_result = trace_task.result()
    metadata = meta_task.result()
    dns_resolves = dns_task.result()

    final_url = trace_result["final_url"]
    hops = trace_result["hops"]

    # If domain changed during redirect, re-fetch metadata for final URL
    final_domain = urlparse(final_url).netloc
    if ':' in final_domain:
        final_domain = final_domain.split(':')[0]
        
    if domain_to_check != final_domain:
        logger.debug(f"[PHASE1] Domain changed during redirect, re-fetching metadata for {final_domain}")
        async with asyncio.TaskGroup() as tg2:
            meta_task2 = tg2.create_task(fetch_metadata(final_url))
            dns_task2 = tg2.create_task(check_dns(final_domain))
        metadata = meta_task2.result()
        dns_resolves = dns_task2.result()
        
    has_metadata = metadata is not None

    # CPU heuristics — instant
    heuristics = run_heuristics(final_url)

    # Compute initial score (heuristics only — preliminary)
    risk_score, verdict, is_safe, reasons = compute_heuristic_score(
        heuristics, hops, final_url, dns_resolves, has_metadata, 
        metadata=metadata, ssl_error=trace_result.get("ssl_error", False)
    )

    # Determine threat type from heuristics
    threat_type: Optional[str] = None
    if heuristics.get("brand_penalty_reason"):
        threat_type = "Typosquatting Detected"
    elif heuristics.get("synergy_detected"):
        threat_type = heuristics.get("synergy_reason")
    elif heuristics.get("punycode_detected"):
        threat_type = "Punycode Homograph Attack"
    elif heuristics.get("has_suspicious_keywords"):
        threat_type = "Suspicious Keywords in Domain"

    duration_ms = int((time.monotonic() - start) * 1000)

    return {
        "final_url": final_url,
        "hops": hops,
        "metadata": metadata,
        "heuristics": heuristics,
        "dns_resolves": dns_resolves,
        "has_metadata": has_metadata,
        "security": {
            "is_safe": is_safe,
            "verdict": verdict,
            "threat_type": threat_type,
            "ssl_cert_age_days": None,
            "risk_score": risk_score,
            "suspicious_redirects": len(hops) > MAX_REDIRECT_HOPS_FREE,
            "typosquatting_detected": heuristics.get("typosquatting_detected", False),
            "ssl_error": trace_result.get("ssl_error", False),
            "reasons": reasons,
        },
        "duration_ms": duration_ms,
    }


# ============================================================
# Phase 2: Deep Scan (≤2s budget)
# ============================================================

async def run_phase2(url: str, phase1_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Phase 2: Deep scan (target ≤2s total).
    Runs RDAP + GSB in parallel. Computes final weighted risk score.
    Includes uncertainty penalty for timed-out sources.
    """
    start = time.monotonic()

    final_url = phase1_result["final_url"]
    hops = phase1_result["hops"]
    heuristics = phase1_result["heuristics"]
    root_domain = heuristics.get("root_domain", urlparse(final_url).netloc)

    try:
        external = await asyncio.wait_for(
            run_external_scans(final_url),
            timeout=3.0  # Hard limit for entire Phase 2
        )
    except asyncio.TimeoutError:
        logger.warning(f"[PHASE2] External scans timed out for {root_domain}")
        external = {
            "ssl_cert_age_days": None,
            "domain_age_days": None,
            "threat_type": None,
            "gsb_threats": [],
            "gsb_matched": False,
            "gsb_threat_type": None,
            "popularity_rank": None,
            "ssl_timed_out": True,
            "gsb_timed_out": True,
            "rdap_timed_out": True,
            "cf_timed_out": True,
        }

    # Concise structured logging for timeouts - use debug level to reduce noise
    if external.get("ssl_timed_out"):
        logger.debug(f"[PHASE2] SSL cert age timeout: {root_domain}")
    if external.get("gsb_timed_out"):
        logger.debug(f"[PHASE2] GSB timeout: {root_domain}")
    if external.get("rdap_timed_out"):
        logger.debug(f"[PHASE2] RDAP timeout: {root_domain}")

    # Compute final weighted score with uncertainty
    risk_score, verdict, is_safe, reasons = compute_final_score(
        heuristics, external, hops, final_url,
        phase1_result.get("dns_resolves", True),
        phase1_result.get("has_metadata", True),
        metadata=phase1_result.get("metadata"),
        ssl_error=phase1_result["security"].get("ssl_error", False)
    )

    # Determine threat type (external threats override heuristic-only threats)
    threat_type = phase1_result["security"].get("threat_type")
    if external.get("gsb_threat_type"):
        threat_type = external["gsb_threat_type"]
    elif external.get("threat_type"):
        threat_type = external["threat_type"]

    duration_ms = int((time.monotonic() - start) * 1000)

    return {
        "security": {
            "is_safe": is_safe,
            "verdict": verdict,
            "threat_type": threat_type,
            "ssl_cert_age_days": external.get("ssl_cert_age_days"),
            "risk_score": risk_score,
            "suspicious_redirects": len(hops) > MAX_REDIRECT_HOPS_FREE,
            "typosquatting_detected": heuristics.get("typosquatting_detected", False),
            "ssl_error": phase1_result["security"].get("ssl_error", False),
            "reasons": reasons,
            "gsb_matched": external.get("gsb_matched", False),
            "gsb_threat_type": external.get("gsb_threat_type"),
            "pt_url_match": external.get("pt_url_match", False),
            "pt_domain_match": external.get("pt_domain_match", False),
        },
        "duration_ms": duration_ms,
    }


# ============================================================
# Phase 3: Screenshot Gatekeeper
# ============================================================

def needs_screenshot(
    metadata: Optional[Dict[str, Any]],
    risk_score: int,
    ssl_cert_age_days: Optional[int] = None,
    redirect_depth: int = 0,
) -> bool:
    """
    Phase 3 gatekeeper. Now updated to be COMPULSORY for all scans.
    """
    return True
