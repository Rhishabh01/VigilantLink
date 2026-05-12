"""
Orchestrator: Deterministic tiered execution engine for VigilantLink.

Phase 1 (≤500ms): URL parsing + heuristics + redirect trace + metadata fetch
Phase 2 (~2s):     RDAP + VirusTotal → final weighted risk score
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
    MAX_REDIRECT_HOPS_FREE, SEVERE_VENDOR_FLAGS_THRESHOLD,
    VT_LOW_CONFIDENCE_THRESHOLD, CORROBORATION_MIN_VENDOR_FLAGS, TRUSTED_PLATFORM_CAP,
    DEFAULT_DOMAIN_AGE_DAYS, TOTAL_VENDORS_COUNT,
    BRAND_PENALTY_SCORE, SYNERGY_PENALTY_SCORE, TYPOSQUATTING_PENALTY,
    REDIRECT_CHAIN_MAJOR_PENALTY, REDIRECT_CHAIN_MINOR_PENALTY,
    VENDOR_FLAG_PENALTY,
    SSL_CERT_VERY_NEW_PENALTY, SSL_CERT_NEW_PENALTY, SSL_CERT_RECENT_PENALTY, SSL_CERT_YOUNG_PENALTY,
    SSL_CERT_VERY_NEW_DAYS, SSL_CERT_NEW_DAYS, SSL_CERT_RECENT_DAYS, SSL_CERT_YOUNG_DAYS,
    NEWLY_REGISTERED_DAYS, NEWLY_REGISTERED_PENALTY,
    RECENTLY_REGISTERED_DAYS, RECENTLY_REGISTERED_PENALTY,
    WEIGHT_HEURISTIC, WEIGHT_SSL_AGE, WEIGHT_VT, WEIGHT_REDIRECT_DEPTH, WEIGHT_RDAP_AGE,
    UNCERTAINTY_PENALTY, TRACKING_PARAMS, PHISHING_KEYWORDS,
    TRUSTED_HOSTING_DOMAINS, TRUSTED_PLATFORMS, SUSPICIOUS_TLDS,
    DECEPTIVE_QUERY_PARAMS, SUSPICIOUS_HOSTED_PATHS, WEAK_SIGNAL_PATTERNS,
    GSB_THREAT_MIN_SCORES,
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
    # Remove tracking parameters
    filtered = {k: v for k, v in qs.items() if k.lower() not in TRACKING_PARAMS}
    sorted_qs = urlencode(sorted(filtered.items()), doseq=True)
    return urlunparse((
        p.scheme.lower(),
        p.netloc.lower(),
        p.path.rstrip("/") or "/",
        p.params,
        sorted_qs,
        "",  # strip fragment
    ))


# ============================================================
# Hosted Phishing Detection
# ============================================================

def detect_hosted_phishing(
    final_url: str,
    hops: List[Dict[str, Any]],
    metadata: Optional[Dict[str, Any]],
    vendor_flags: int,
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
    if vendor_flags >= 1:
        count += 1
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


async def should_run_phase2(phase1_result: Dict[str, Any], redis_cache: Any, source_domain: Optional[str] = None) -> bool:
    """
    Gatekeeper for Phase 2 (external APIs).
    Returns True if the URL is suspicious enough to warrant hitting external quotas.
    
    Conditions for skipping Phase 2:
    - Verdict is NOT 'red' (Phase 1 score < 65)
    - Domain is in TRUSTED_PLATFORMS OR in the dynamic Redis Top Domains set
    - OR Final URL matches the source_domain (Internal redirect trust)
    - No critical heuristic signals (Punycode, Typosquatting, etc.)
    """
    sec = phase1_result["security"]
    heuristics = phase1_result["heuristics"]
    final_url = phase1_result["final_url"]
    
    # 1. If Phase 1 already flagged it as dangerous (Red), run Phase 2 to get full data
    if sec["verdict"] == "red":
        return True
        
    # 2. Check if it's a trusted platform (Static + Dynamic)
    parsed_final = urlparse(final_url)
    domain_lower = parsed_final.netloc.lower()
    if ':' in domain_lower:
        domain_lower = domain_lower.split(':')[0]
        
    # Check for same-domain redirect trust
    if source_domain and (domain_lower == source_domain or domain_lower.endswith('.' + source_domain)):
        logger.info(f"[GATEKEEPER] Internal redirect trust: {domain_lower} matches source {source_domain}")
        return False

    is_trusted_static = any(
        domain_lower == d or domain_lower.endswith(f".{d}")
        for d in TRUSTED_PLATFORMS
    )
    
    # Dynamic check via Redis (O(1) set lookup)
    is_trusted_dynamic = False
    if not is_trusted_static and redis_cache:
        is_trusted_dynamic = await redis_cache.is_top_domain(domain_lower)
        if is_trusted_dynamic:
            logger.info(f"[GATEKEEPER] Dynamic match: {domain_lower} is a top traffic domain.")
    
    is_trusted = is_trusted_static or is_trusted_dynamic
    
    # 3. Check for high-risk signals from heuristics
    has_risk_signals = (
        heuristics.get("typosquatting_detected") or
        heuristics.get("punycode_detected") or
        heuristics.get("synergy_detected") or
        sec["suspicious_redirects"] or
        sec["ssl_error"]
    )
    
    # Gatekeeping logic:
    # Skip Phase 2 if it's a trusted domain AND has a relatively low heuristic score AND no risk signals
    if is_trusted and sec["risk_score"] < VERDICT_RED_THRESHOLD and not has_risk_signals:
        logger.info(f"[GATEKEEPER] Skipping Phase 2 for trusted/top domain: {domain_lower}")
        return False
        
    # Always run for untrusted or suspicious domains
    return True


# ============================================================
# Scoring: Weighted formula S = Σ(wi · ci) + U
# ============================================================

def _apply_uncertainty(
    base_score: int,
    ssl_uncertain: bool,
    vt_uncertain: bool,
    rdap_uncertain: bool = False,
    gsb_uncertain: bool = False,
    is_suspicious: bool = False,
) -> Tuple[int, int, int]:
    """
    Revised uncertainty penalty logic for 4 external sources.
    Returns (total_score, ssl_penalty, security_penalty).
    """
    ssl_penalty = 0
    security_penalty = 0
    
    # SSL timeout: +2 only if site already shows suspicious signs
    if ssl_uncertain and (is_suspicious or base_score >= VERDICT_YELLOW_THRESHOLD):
        ssl_penalty = 2
        
    # Security sources (VT/GSB/RDAP): +5 each only if multiple fail OR heuristics exist OR near threshold
    if vt_uncertain or gsb_uncertain or rdap_uncertain:
        timeout_count = sum([vt_uncertain, gsb_uncertain, rdap_uncertain])
        near_threshold = base_score >= (VERDICT_YELLOW_THRESHOLD - 5)
        
        if timeout_count >= 2 or is_suspicious or near_threshold:
            if vt_uncertain: security_penalty += 5
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
        risk_score += 10
        reasons.append(f"Phishing keyword(s) detected: {', '.join(found_keywords[:3])}")
        
        # Synergy: Keyword + Suspicious/New Domain
        # (New domain check happens in Phase 2, but suspicious TLD is Phase 1)
        is_suspicious_domain = any(domain_lower.endswith(tld if tld.startswith('.') else f".{tld}") for tld in SUSPICIOUS_TLDS)
        if is_suspicious_domain or heuristics.get("typosquatting_detected"):
            risk_score += 15
            reasons.append("Synergy: Phishing keyword on suspicious domain")

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
    Phase 2 Final Score — heuristics + RDAP + VirusTotal + uncertainty penalty.

    Returns (score, verdict, is_safe, reasons).
    """
    # Start with heuristic base score
    risk_score, _, _, reasons = compute_heuristic_score(
        heuristics, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error
    )
    logger.debug(f"[SCORING] {final_url[:50]}... - Initial base score: {risk_score}")

    # Phase 2 Signal: VirusTotal flags
    vendor_flags = external.get("vendor_flags", 0)
    gsb_threats = external.get("gsb_threats", [])

    # NEW: Detect trusted platform early — used to dampen VT domain-level leakage
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

    # Low-confidence VT suppression: vendor_flags < threshold + no corroboration = zero contribution
    has_vt_corroboration = (
        bool(gsb_threats) or
        has_phishing_keywords or
        vendor_flags >= CORROBORATION_MIN_VENDOR_FLAGS
    )

    if vendor_flags >= 1:
        if vendor_flags < VT_LOW_CONFIDENCE_THRESHOLD and not has_vt_corroboration:
            vt_penalty = 0
        elif is_trusted_platform and vendor_flags < 3:
            vt_penalty = 0
        else:
            vt_penalty = min(10 * vendor_flags, 40)
        if vt_penalty > 0:
            risk_score += round(WEIGHT_VT * vt_penalty)
            reasons.append(f"Flagged by {vendor_flags} security vendor(s)")

    # NEW: Trusted-Domain Abuse Detection
    is_trusted_hosting = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_HOSTING_DOMAINS)

    if is_trusted_hosting and (vendor_flags >= 1 or has_phishing_keywords):
        if risk_score < 50:
            risk_score = 50
        reasons.append("Suspicious content hosted on trusted platform")
        risk_score = max(risk_score, VERDICT_YELLOW_THRESHOLD + 1)

    # Hosted phishing escalation with corroboration
    hosted_signals = detect_hosted_phishing(
        final_url, hops, metadata, vendor_flags, has_phishing_keywords
    )
    if hosted_signals.get("active"):
        if hosted_signals.get("suspicious_path"):
            reasons.append("Suspicious authentication path on trusted hosting")
        if hosted_signals.get("deceptive_param"):
            target = hosted_signals.get("redirect_target", "unknown")
            reasons.append(f"Deceptive redirect parameter ({hosted_signals['deceptive_param_name']}) to {target}")
        if hosted_signals.get("redirect_chain_suspicious"):
            reasons.append("Redirect chain passes through untrusted domain before trusted landing")
        if risk_score < 55:
            risk_score = 55
        risk_score = max(risk_score, VERDICT_YELLOW_THRESHOLD + 5)

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
                vendor_flags >= 1 or
                bool(gsb_threats)
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
            risk_score += round(WEIGHT_RDAP_AGE * rdap_penalty)
            if domain_age < NEWLY_REGISTERED_DAYS:
                reasons.append(f"Newly registered domain (<{domain_age + 1} days)")
            else:
                reasons.append(f"Recent domain registration ({domain_age} days ago)")
                
            # Synergy: New Domain + VT flags (even 1)
            if domain_age < NEWLY_REGISTERED_DAYS and vendor_flags >= 1:
                risk_score = max(risk_score, 60)
                reasons.append("Synergy: New domain flagged by security vendor")

    logger.debug(f"[SCORING] {final_url[:50]}... - Heuristic base score: {risk_score}")
            
    # Uncertainty penalty for timed-out sources
    ssl_uncertain = external.get("ssl_timed_out", False)
    vt_uncertain = external.get("vt_timed_out", False)
    gsb_uncertain = external.get("gsb_timed_out", False)
    rdap_uncertain = external.get("rdap_uncertain", False)
    
    is_susp_heur = (
        heuristics.get("typosquatting_detected") or 
        heuristics.get("punycode_detected") or 
        heuristics.get("synergy_detected") or
        heuristics.get("has_suspicious_keywords")
    )
    
    risk_score, p_ssl, p_sec = _apply_uncertainty(
        risk_score, ssl_uncertain, vt_uncertain, rdap_uncertain, gsb_uncertain, is_susp_heur
    )
    
    # Store uncertainty info for filtered reason display
    uncertainty_info = None
    if p_ssl > 0 or p_sec > 0:
        timed_out_count = sum([ssl_uncertain, vt_uncertain, gsb_uncertain, rdap_uncertain])
        uncertainty_info = (timed_out_count, p_ssl + p_sec)

    # Google Safe Browsing Scoring
    gsb_threat_type = external.get("gsb_threat_type")
    logger.debug(f"[SCORING] {final_url[:50]}... - GSB result: matched={bool(gsb_threats)}, type={gsb_threat_type}")
    if gsb_threats and gsb_threat_type:
        min_score = GSB_THREAT_MIN_SCORES.get(gsb_threat_type, 90)
        risk_score = max(risk_score, min_score)
        reasons.append(f"CRITICAL: Flagged by Google Safe Browsing ({', '.join(gsb_threats)})")
        logger.debug(f"[SCORING] {final_url[:50]}... - After GSB override: {risk_score}")

    # Trusted platform calibration: dampen weak/noisy signals
    if is_trusted_platform:
        has_strong_signals = (
            vendor_flags >= 3 or
            bool(gsb_threats) or
            len(hops) > MAX_REDIRECT_HOPS_FREE or
            heuristics.get("punycode_detected", False) or
            heuristics.get("brand_penalty_reason") is not None or
            hosted_signals.get("active", False)
        )
        if not has_strong_signals:
            risk_score = min(risk_score, TRUSTED_PLATFORM_CAP)
            reasons = [
                r for r in reasons
                if not any(p.lower() in r.lower() for p in WEAK_SIGNAL_PATTERNS)
            ]

    capped_score = min(risk_score, 100)
    logger.debug(f"[SCORING] {final_url[:50]}... - After trusted platform cap: {capped_score} (Is Trusted Platform: {is_trusted_platform})")

    is_safe = True
    verdict = "green"

    # VirusTotal critical override (softened for trusted platforms without corroboration)
    if vendor_flags > SEVERE_VENDOR_FLAGS_THRESHOLD:
        has_corroboration = bool(gsb_threats) or has_phishing_keywords or len(hops) > MAX_REDIRECT_HOPS_FREE
        if is_trusted_platform and not has_corroboration:
            capped_score = min(capped_score, VERDICT_RED_THRESHOLD - 1)
        else:
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
                vendor_flags >= 1 or
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
            "vendor_flags": 0,
            "total_vendors": 0,
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
    Runs RDAP + VirusTotal in parallel. Computes final weighted risk score.
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
            "vendor_flags": 0,
            "total_vendors": TOTAL_VENDORS_COUNT,
            "threat_type": None,
            "gsb_threats": [],
            "gsb_matched": False,
            "gsb_threat_type": None,
            "popularity_rank": None,
            "ssl_timed_out": True,
            "vt_timed_out": True,
            "gsb_timed_out": True,
            "rdap_timed_out": True,
            "cf_timed_out": True,
        }

    # Concise structured logging for timeouts - use debug level to reduce noise
    if external.get("ssl_timed_out"):
        logger.debug(f"[PHASE2] SSL cert age timeout: {root_domain}")
    if external.get("vt_timed_out"):
        logger.debug(f"[PHASE2] VT timeout: {root_domain}")
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
            "vendor_flags": external.get("vendor_flags", 0),
            "total_vendors": external.get("total_vendors", TOTAL_VENDORS_COUNT),
            "ssl_cert_age_days": external.get("ssl_cert_age_days"),
            "risk_score": risk_score,
            "suspicious_redirects": len(hops) > MAX_REDIRECT_HOPS_FREE,
            "typosquatting_detected": heuristics.get("typosquatting_detected", False),
            "ssl_error": phase1_result["security"].get("ssl_error", False),
            "reasons": reasons,
            "gsb_matched": external.get("gsb_matched", False),
            "gsb_threat_type": external.get("gsb_threat_type"),
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
    vendor_flags: int = 0,
    redirect_depth: int = 0,
) -> bool:
    """
    Phase 3 gatekeeper. Returns True only when visual evidence is justified.

    Conditions (any triggers screenshot):
      1. risk_score >= 70 (high risk)
      2. risk_score >= 40 AND domain < 90 days (medium risk + new domain)
      3. vendor_flags >= 2 AND no OG image (flagged, no preview)
      4. redirect_depth > 3 AND domain < 90 days (chain landing on fresh domain)
    """
    has_image = metadata is not None and metadata.get("image_url") is not None
    is_new = ssl_cert_age_days is not None and ssl_cert_age_days < 90

    if risk_score >= 70:
        return True
    if risk_score >= 40 and ssl_cert_age_days is not None and ssl_cert_age_days < 90:
        return True
    if vendor_flags >= 2 and not has_image:
        return True
    if redirect_depth > MAX_REDIRECT_HOPS_FREE and ssl_cert_age_days is not None and ssl_cert_age_days < 90:
        return True
    # Fallback: metadata fetch failed entirely — try screenshot for visual preview
    if metadata is None:
        return True
    # Fallback: metadata exists but has no OG image — try screenshot for visual preview
    if metadata is not None and not has_image:
        return True

    return False
