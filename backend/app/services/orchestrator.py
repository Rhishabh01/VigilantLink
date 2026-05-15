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
# Scoring: Correlation Engine
# ============================================================
======# ============================================================
# Signal Intelligence & Correlation Engine
# ============================================================

def _extract_signals(
    heuristics: Dict[str, Any],
    external: Dict[str, Any],
    hops: List[Dict[str, Any]],
    final_url: str,
    dns_resolves: bool,
    has_metadata: bool,
    metadata: Optional[Dict[str, Any]] = None,
    ssl_error: bool = False,
) -> Dict[str, Any]:
    """
    Extracts and categorizes signals from all available data sources.
    """
    parsed_final = urlparse(final_url)
    domain_lower = parsed_final.netloc.lower()
    path_lower = parsed_final.path.lower()
    
    # Infrastructure Signals
    domain_age = external.get("domain_age_days")
    ssl_age = external.get("ssl_cert_age_days")
    
    is_new_domain = domain_age is not None and domain_age < RECENTLY_REGISTERED_DAYS
    is_very_new_domain = domain_age is not None and domain_age < NEWLY_REGISTERED_DAYS
    is_new_ssl = ssl_age is not None and ssl_age < SSL_CERT_RECENT_DAYS
    is_very_new_ssl = ssl_age is not None and ssl_age < SSL_CERT_NEW_DAYS
    
    is_suspicious_tld = any(domain_lower.endswith(tld if tld.startswith('.') else f".{tld}") for tld in SUSPICIOUS_TLDS)
    is_punycode = heuristics.get("punycode_detected", False) or "xn--" in final_url
    
    # Behavioral Signals
    num_hops = len(hops)
    has_redirect_chain = num_hops > 1
    is_excessive_redirects = num_hops > MAX_REDIRECT_HOPS_FREE
    
    # Cross-domain check
    is_cross_domain = False
    if has_redirect_chain:
        start_domain = urlparse(hops[0]["url"]).netloc.lower()
        is_cross_domain = start_domain != domain_lower

    # Shortener check
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrandly.com"}
    is_shortened = any(urlparse(hop["url"]).netloc.lower() in shorteners for hop in hops)

    # Phishing Signals
    found_keywords = []
    content_to_check = [path_lower, parsed_final.query.lower()]
    if metadata:
        if metadata.get("title"): content_to_check.append(metadata["title"].lower())
        if metadata.get("description"): content_to_check.append(metadata["description"].lower())
            
    for kw in PHISHING_KEYWORDS:
        if any(kw in text for text in content_to_check):
            found_keywords.append(kw)
    
    is_impersonation = heuristics.get("brand_penalty_reason") is not None or heuristics.get("typosquatting_detected", False)
    
    is_suspicious_path = any(path_lower.startswith(sp) for sp in SUSPICIOUS_HOSTED_PATHS)
    
    is_trusted_hosting = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_HOSTING_DOMAINS)
    is_trusted_platform = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_PLATFORMS)

    # Intelligence Signals
    gsb_threats = external.get("gsb_threats", [])
    pt_url_match = external.get("pt_url_match", False)
    pt_domain_match = external.get("pt_domain_match", False)

    return {
        "infra": {
            "new_domain": is_new_domain,
            "very_new_domain": is_very_new_domain,
            "new_ssl": is_new_ssl,
            "very_new_ssl": is_very_new_ssl,
            "suspicious_tld": is_suspicious_tld,
            "punycode": is_punycode,
            "dns_failed": not dns_resolves,
            "ssl_error": ssl_error,
            "domain_age": domain_age,
            "ssl_age": ssl_age,
        },
        "behavior": {
            "redirect_chain": has_redirect_chain,
            "excessive_redirects": is_excessive_redirects,
            "cross_domain": is_cross_domain,
            "shortened": is_shortened,
            "num_hops": num_hops,
        },
        "phishing": {
            "keywords": found_keywords,
            "impersonation": is_impersonation,
            "suspicious_path": is_suspicious_path,
            "trusted_hosting": is_trusted_hosting,
            "trusted_platform": is_trusted_platform,
            "no_metadata": not has_metadata and not is_trusted_platform,
        },
        "intel": {
            "gsb_threats": gsb_threats,
            "gsb_hit": bool(gsb_threats),
            "pt_url_hit": pt_url_match,
            "pt_domain_hit": pt_domain_match,
            "gsb_threat_type": external.get("gsb_threat_type"),
        }
    }

def _evaluate_correlations(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates signals against correlation rules.
    Returns a list of matched rules with scores and reasons.
    """
    matches = []
    infra = signals["infra"]
    behavior = signals["behavior"]
    phish = signals["phishing"]
    intel = signals["intel"]

    # Rule: Fresh Phishing Infrastructure
    if (infra["new_domain"] or infra["new_ssl"] or infra["suspicious_tld"]) and phish["keywords"]:
        matches.append({
            "id": "fresh_phishing_infra",
            "score": 65 if infra["very_new_domain"] or infra["very_new_ssl"] else 45,
            "reason": "Fresh infrastructure combined with phishing behavior",
            "confidence": "strong" if infra["very_new_domain"] else "moderate"
        })

    # Rule: Hosted Phishing
    if phish["trusted_hosting"] and (phish["keywords"] or phish["suspicious_path"]):
        score = 55
        if behavior["redirect_chain"]: score += 15
        matches.append({
            "id": "hosted_phishing",
            "score": score,
            "reason": "Suspicious content or auth path hosted on trusted platform",
            "confidence": "strong" if score > 60 else "moderate"
        })

    # Rule: Credential Harvesting / Impersonation
    if phish["impersonation"]:
        score = 65
        if phish["keywords"] or behavior["redirect_chain"]:
            score += 20
        matches.append({
            "id": "credential_harvesting",
            "score": score,
            "reason": "Brand impersonation combined with suspicious behavior",
            "confidence": "critical" if score >= 85 else "strong"
        })

    # Rule: Redirect Cloaking
    if behavior["shortened"] and behavior["excessive_redirects"] and behavior["cross_domain"]:
        matches.append({
            "id": "redirect_cloaking",
            "score": 50,
            "reason": "URL shortener and excessive redirects used to cloak destination",
            "confidence": "moderate"
        })

    # Rule: Punycode / Homograph Attack (Critical)
    if infra["punycode"]:
        matches.append({
            "id": "homograph_attack",
            "score": 85,
            "reason": "Punycode homograph attack detected (impersonated domain)",
            "confidence": "critical"
        })

    # Rule: Infrastructure Weakness (Low Confidence)
    if not any(m["id"] in ["fresh_phishing_infra", "homograph_attack"] for m in matches):
        if infra["very_new_domain"] or infra["very_new_ssl"]:
            matches.append({
                "id": "new_infra_only",
                "score": 25,
                "reason": "Recently registered domain or SSL certificate",
                "confidence": "weak"
            })
        elif infra["suspicious_tld"]:
            matches.append({
                "id": "suspicious_tld_only",
                "score": 15,
                "reason": "Site uses a TLD commonly associated with phishing",
                "confidence": "weak"
            })

    # Rule: Behavioral Suspicion (Low Confidence)
    if not any(m["id"] == "redirect_cloaking" for m in matches):
        if behavior["excessive_redirects"]:
            matches.append({
                "id": "excessive_redirects_only",
                "score": 20,
                "reason": "Excessive redirect chain detected",
                "confidence": "weak"
            })

    # Rule: Phishing Intent (Low Confidence)
    if not any(m["id"] in ["fresh_phishing_infra", "hosted_phishing", "credential_harvesting"] for m in matches):
        if phish["keywords"]:
            matches.append({
                "id": "phishing_keywords_only",
                "score": 20,
                "reason": f"Phishing-related keywords detected: {', '.join(phish['keywords'][:2])}",
                "confidence": "weak"
            })

    # Rule: Connection Security
    if infra["ssl_error"]:
        matches.append({
            "id": "ssl_error",
            "score": 30,
            "reason": "Invalid or expired SSL certificate",
            "confidence": "moderate"
        })
    elif infra["dns_failed"]:
        matches.append({
            "id": "dns_failure",
            "score": 40,
            "reason": "Domain does not resolve to an active server",
            "confidence": "moderate"
        })

    return matches

def _apply_intelligence_overrides(risk_score: int, intel: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Applies overrides for high-confidence intelligence signals (GSB, PhishTank).
    """
    reasons = []
    
    if intel["gsb_hit"]:
        gsb_type = intel["gsb_threat_type"]
        min_score = GSB_THREAT_MIN_SCORES.get(gsb_type, 90)
        risk_score = max(risk_score, min_score)
        reasons.append(f"CRITICAL: Flagged by Google Safe Browsing ({', '.join(intel['gsb_threats'])})")
    
    if intel["pt_url_hit"]:
        risk_score = max(risk_score, PHISHTANK_URL_PENALTY)
        reasons.append("CRITICAL: Confirmed phishing URL in PhishTank database")
    elif intel["pt_domain_hit"]:
        risk_score = max(risk_score, PHISHTANK_DOMAIN_PENALTY)
        reasons.append("WARNING: Known phishing infrastructure (PhishTank)")
        
    return risk_score, reasons

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
    Refactored Phase 1 Score using correlation signals.
    """
    # Extract available signals (external data will be empty/defaults for Phase 1)
    signals = _extract_signals(
        heuristics, {}, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error
    )
    
    # Evaluate correlations
    matches = _evaluate_correlations(signals)
    
    # Calculate score based on strongest correlation
    if not matches:
        risk_score = 0
        reasons = []
    else:
        # Use max score for primary signal + small additive for others
        matches.sort(key=lambda x: x["score"], reverse=True)
        risk_score = matches[0]["score"]
        
        # Add slight weight for additional suspicious signals (max +10 total)
        if len(matches) > 1:
            additional_weight = min(len(matches) - 1, 2) * 5
            risk_score += additional_weight
            
        reasons = [m["reason"] for m in matches[:3]]

    # Trusted platform dampening for uncorroborated signals
    if signals["phishing"]["trusted_platform"]:
        has_strong_match = any(m["confidence"] in ["strong", "critical"] for m in matches)
        if not has_strong_match:
            risk_score = min(risk_score, TRUSTED_PLATFORM_CAP)
            # Filter weak reasons for trusted platforms
            reasons = [r for r in reasons if not any(p.lower() in r.lower() for p in WEAK_SIGNAL_PATTERNS)]

    capped_score = min(risk_score, 100)
    verdict = "green"
    if capped_score >= VERDICT_RED_THRESHOLD:
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        verdict = "yellow"
        
    return capped_score, verdict, capped_score < VERDICT_YELLOW_THRESHOLD, reasons

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
    Refactored Phase 2 Final Score using correlation + intelligence.
    """
    # Extract all signals
    signals = _extract_signals(
        heuristics, external, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error
    )
    
    # Evaluate correlations
    matches = _evaluate_correlations(signals)
    
    # Calculate base correlation score
    if not matches:
        risk_score = 0
        reasons = []
    else:
        matches.sort(key=lambda x: x["score"], reverse=True)
        risk_score = matches[0]["score"]
        if len(matches) > 1:
            additional_weight = min(len(matches) - 1, 2) * 5
            risk_score += additional_weight
        reasons = [m["reason"] for m in matches[:3]]

    # Apply Intelligence Overrides (GSB / PhishTank)
    risk_score, intel_reasons = _apply_intelligence_overrides(risk_score, signals["intel"])
    reasons = intel_reasons + reasons

    # Apply uncertainty penalty for timed-out sources
    ssl_uncertain = external.get("ssl_timed_out", False)
    gsb_uncertain = external.get("gsb_timed_out", False)
    rdap_uncertain = external.get("rdap_uncertain", False)
    
    # Uncertainty only if site already shows suspicion or multiple timeouts
    timeout_count = sum([ssl_uncertain, gsb_uncertain, rdap_uncertain])
    if timeout_count >= 2 or risk_score >= (VERDICT_YELLOW_THRESHOLD - 5):
        penalty = 0
        if ssl_uncertain: penalty += 2
        if gsb_uncertain: penalty += 5
        if rdap_uncertain: penalty += 5
        
        if penalty > 0:
            risk_score = min(risk_score + penalty, 100)
            if timeout_count >= 2:
                reasons.append(f"Limited security data ({timeout_count}/3 sources timed out)")

    # Final verdict determination
    capped_score = min(risk_score, 100)
    verdict = "green"
    if capped_score >= VERDICT_RED_THRESHOLD:
        verdict = "red"
    elif capped_score >= VERDICT_YELLOW_THRESHOLD:
        verdict = "yellow"

    # Trusted platform final check
    if signals["phishing"]["trusted_platform"]:
        has_strong_intel = signals["intel"]["gsb_hit"] or signals["intel"]["pt_url_hit"]
        has_strong_match = any(m["confidence"] in ["strong", "critical"] for m in matches)
        if not (has_strong_intel or has_strong_match):
            risk_score = min(risk_score, TRUSTED_PLATFORM_CAP)
            verdict = "green"
            reasons = [r for r in reasons if not any(p.lower() in r.lower() for p in WEAK_SIGNAL_PATTERNS)]

    return min(risk_score, 100), verdict, verdict == "green", reasons


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

    # Determine threat type from intelligent reasons
    threat_type: Optional[str] = None
    if not is_safe and reasons:
        threat_type = reasons[0]

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
    # Determine threat type from intelligent reasons
    threat_type: Optional[str] = None
    if not is_safe and reasons:
        threat_type = reasons[0]

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
