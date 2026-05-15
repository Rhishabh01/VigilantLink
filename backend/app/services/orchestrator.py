"""
Orchestrator: Deterministic tiered execution engine for VigilantLink.

Phase 1 (≤500ms): URL parsing + heuristics + redirect trace + metadata fetch
Phase 2 (~2s):     RDAP + GSB → correlation-based risk score
Phase 3 (optional): Playwright screenshot (shielded, semaphore-gated)

Key patterns:
  - asyncio.TaskGroup for structured concurrency (Python 3.11+)
  - Request collapsing via RequestCollapser (deduplicate concurrent hovers)
  - asyncio.shield() for Phase 3 so screenshots survive request cancellation
  - Signal correlation engine for pattern-based detection
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
    VERDICT_RED_THRESHOLD, VERDICT_YELLOW_THRESHOLD, WEAK_SIGNAL_MAX_SCORE,
    PUNYCODE_MIN_SCORE,
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
        "",
    ))


# ============================================================
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
    """Extracts and categorizes signals from all available data sources."""
    parsed_final = urlparse(final_url)
    domain_lower = parsed_final.netloc.lower()
    path_lower = parsed_final.path.lower()
    
    domain_age = external.get("domain_age_days")
    ssl_age = external.get("ssl_cert_age_days")
    is_suspicious_tld = any(domain_lower.endswith(tld if tld.startswith('.') else f".{tld}") for tld in SUSPICIOUS_TLDS)
    is_punycode = heuristics.get("punycode_detected", False) or "xn--" in final_url
    
    num_hops = len(hops)
    is_cross_domain = False
    if num_hops > 1:
        is_cross_domain = urlparse(hops[0]["url"]).netloc.lower() != domain_lower

    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrandly.com", "shorturl.at", "tiny.cc"}
    is_shortened = any(urlparse(hop["url"]).netloc.lower() in shorteners for hop in hops)

    found_keywords = []
    content_to_check = [path_lower, parsed_final.query.lower()]
    if metadata:
        if metadata.get("title"): content_to_check.append(metadata["title"].lower())
        if metadata.get("description"): content_to_check.append(metadata["description"].lower())
    for kw in PHISHING_KEYWORDS:
        if any(kw in text for text in content_to_check):
            found_keywords.append(kw)
    
    imp_detected = heuristics.get("typosquatting_detected", False)
    imp_severity = heuristics.get("impersonation_severity", "none")
    imp_brand = heuristics.get("impersonation_brand")
    imp_technique = heuristics.get("impersonation_technique")
    imp_contextual_confidence = heuristics.get("impersonation_contextual_confidence", 0.0)
    
    is_suspicious_path = any(path_lower.startswith(sp) for sp in SUSPICIOUS_HOSTED_PATHS)
    is_trusted_hosting = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_HOSTING_DOMAINS)
    is_trusted_platform = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in TRUSTED_PLATFORMS)

    return {
        "infra": {
            "new_domain": domain_age is not None and domain_age < RECENTLY_REGISTERED_DAYS,
            "very_new_domain": domain_age is not None and domain_age < NEWLY_REGISTERED_DAYS,
            "new_ssl": ssl_age is not None and ssl_age < SSL_CERT_RECENT_DAYS,
            "very_new_ssl": ssl_age is not None and ssl_age < SSL_CERT_NEW_DAYS,
            "suspicious_tld": is_suspicious_tld,
            "punycode": is_punycode,
            "dns_failed": not dns_resolves,
            "ssl_error": ssl_error,
            "http_only": parsed_final.scheme == "http",
        },
        "behavior": {
            "redirect_chain": num_hops > 1,
            "excessive_redirects": num_hops > MAX_REDIRECT_HOPS_FREE,
            "cross_domain": is_cross_domain,
            "shortened": is_shortened,
            "num_hops": num_hops,
        },
        "phishing": {
            "keywords": found_keywords,
            "impersonation": imp_detected,
            "imp_severity": imp_severity,
            "imp_brand": imp_brand,
            "imp_technique": imp_technique,
            "imp_contextual_confidence": imp_contextual_confidence,
            "suspicious_path": is_suspicious_path,
            "trusted_hosting": is_trusted_hosting,
            "trusted_platform": is_trusted_platform,
            "no_metadata": not has_metadata and not is_trusted_platform,
            "synergy": heuristics.get("synergy_detected", False),
            "synergy_reason": heuristics.get("synergy_reason"),
            "has_suspicious_keywords": heuristics.get("has_suspicious_keywords", False),
        },
        "intel": {
            "gsb_threats": external.get("gsb_threats", []),
            "gsb_hit": bool(external.get("gsb_threats", [])),
            "pt_url_hit": external.get("pt_url_match", False),
            "pt_domain_hit": external.get("pt_domain_match", False),
            "gsb_threat_type": external.get("gsb_threat_type"),
        }
    }


def _evaluate_correlations(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates signals against correlation rules using a strict signal hierarchy.

    STRONG signals can independently escalate to yellow/red verdicts:
      - impersonation WITH contextual phishing confidence (>= 0.5)
      - punycode homograph
      - TLD + keyword synergy
      - fresh phishing infrastructure (new domain + phishing keywords)
      - hosted phishing (trusted hosting + phishing path/keywords)
      - redirect cloaking (shortener + cross-domain)

    WEAK signals amplify suspicion but NEVER independently create yellow/red:
      - low-confidence impersonation (< 0.5)
      - new domain / new SSL alone
      - suspicious TLD alone
      - excessive redirects alone
      - phishing keywords alone (no other context)
      - SSL errors, DNS failures, HTTP-only
      - no metadata
    """
    matches = []
    infra = signals["infra"]
    behavior = signals["behavior"]
    phish = signals["phishing"]

    has_infra_concern = infra["new_domain"] or infra["new_ssl"] or infra["suspicious_tld"]
    has_keywords = bool(phish["keywords"])
    has_behavior = behavior["excessive_redirects"] or behavior["cross_domain"]

    imp_confidence = phish.get("imp_contextual_confidence", 0.0)

    # ================================================================
    # STRONG SIGNALS — can independently produce yellow/red verdicts
    # ================================================================

    # --- CRITICAL: High-Confidence Impersonation ---
    if phish["impersonation"] and imp_confidence >= 0.5:
        brand = phish["imp_brand"] or "unknown"
        base = 70 if imp_confidence >= 0.7 else 55
        if has_keywords: base += 10
        if has_behavior: base += 5
        if has_infra_concern: base += 5
        matches.append({
            "id": "impersonation",
            "score": min(base, 95),
            "reason": phish.get("brand_penalty_reason") or f"Brand impersonation targeting {brand}",
            "confidence": "critical" if base >= 80 else "strong",
            "strong": True,
        })

    # --- CRITICAL: Punycode Homograph ---
    if infra["punycode"]:
        matches.append({
            "id": "homograph_attack",
            "score": 85,
            "reason": "Punycode homograph attack detected",
            "confidence": "critical",
            "strong": True,
        })

    # --- STRONG: TLD + Keyword Synergy ---
    if phish["synergy"]:
        matches.append({
            "id": "tld_keyword_synergy",
            "score": 55,
            "reason": phish["synergy_reason"] or "Suspicious TLD combined with phishing keywords in domain",
            "confidence": "strong",
            "strong": True,
        })

    # --- STRONG: Fresh Phishing Infrastructure (new infra + keywords) ---
    if has_infra_concern and has_keywords:
        already_imp = any(m["id"] == "impersonation" for m in matches)
        if not already_imp:
            very_fresh = infra["very_new_domain"] or infra["very_new_ssl"]
            score = 55 if very_fresh else 42
            if has_behavior: score += 10
            matches.append({
                "id": "fresh_phishing_infra",
                "score": min(score, 75),
                "reason": "Fresh infrastructure combined with credential harvesting indicators",
                "confidence": "strong",
                "strong": True,
            })

    # --- STRONG: Hosted Phishing ---
    if phish["trusted_hosting"] and (has_keywords or phish["suspicious_path"]):
        score = 50
        if phish["suspicious_path"] and has_keywords: score = 65
        if behavior["redirect_chain"]: score += 10
        matches.append({
            "id": "hosted_phishing",
            "score": min(score, 80),
            "reason": "Phishing content or credential-stealing path on trusted hosting platform",
            "confidence": "strong" if score >= 60 else "moderate",
            "strong": True,
        })

    # --- STRONG: Redirect Cloaking ---
    if behavior["shortened"] and behavior["cross_domain"]:
        score = 45
        if behavior["excessive_redirects"]: score += 10
        if has_keywords: score += 10
        matches.append({
            "id": "redirect_cloaking",
            "score": min(score, 65),
            "reason": "URL shortener with cross-domain redirects used to disguise destination",
            "confidence": "strong" if score >= 55 else "moderate",
            "strong": True,
        })

    # ================================================================
    # WEAK / AMPLIFYING SIGNALS — never independently produce yellow/red
    # ================================================================

    # Weak: Low-confidence impersonation (edit distance / similarity only)
    if phish["impersonation"] and imp_confidence < 0.5:
        brand = phish["imp_brand"] or "unknown"
        matches.append({
            "id": "low_confidence_impersonation",
            "score": 15,
            "reason": f"Domain visually similar to {brand}",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: New infrastructure without phishing behavior
    if infra["very_new_domain"] or infra["very_new_ssl"]:
        matches.append({
            "id": "new_infra_only",
            "score": 12,
            "reason": "Recently registered domain or SSL certificate",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: Suspicious TLD alone
    if infra["suspicious_tld"]:
        matches.append({
            "id": "suspicious_tld_only",
            "score": 8,
            "reason": "TLD commonly associated with abuse",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: Excessive redirects (non-shortened)
    if behavior["excessive_redirects"] and not behavior["shortened"]:
        matches.append({
            "id": "excessive_redirects_only",
            "score": 12,
            "reason": "Excessive redirect chain detected",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: Phishing keywords without other strong signals
    if has_keywords and not phish["trusted_hosting"]:
        matches.append({
            "id": "phishing_keywords_only",
            "score": 10,
            "reason": f"Phishing-related keywords: {', '.join(phish['keywords'][:3])}",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: SSL certificate error
    if infra["ssl_error"]:
        score = 15 if has_keywords else 8
        matches.append({
            "id": "ssl_error",
            "score": score,
            "reason": "Invalid SSL certificate" + (" with phishing indicators" if has_keywords else ""),
            "confidence": "weak",
            "strong": False,
        })

    # Weak: DNS resolution failure
    if infra["dns_failed"]:
        matches.append({
            "id": "dns_failure",
            "score": 20,
            "reason": "Domain does not resolve to an active server",
            "confidence": "weak",
            "strong": False,
        })

    # Weak: HTTP-only connection
    if infra["http_only"] and not phish["trusted_platform"]:
        score = 10 if has_keywords else 5
        matches.append({
            "id": "no_encryption",
            "score": score,
            "reason": "Unencrypted connection" + (" serving login/auth content" if has_keywords else ""),
            "confidence": "weak",
            "strong": False,
        })

    # Weak: No metadata
    if phish["no_metadata"]:
        matches.append({
            "id": "no_metadata",
            "score": 5,
            "reason": "No metadata available from site",
            "confidence": "weak",
            "strong": False,
        })

    return matches


def _compute_correlation_score(matches: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Compute score from correlation matches using strongest-signal-first.
    Weak-signal-only results are capped below WEAK_SIGNAL_MAX_SCORE to
    prevent isolated weak infrastructure signals from producing yellow/red.
    """
    if not matches:
        return 0, []

    has_strong = any(m.get("strong", False) for m in matches)

    matches.sort(key=lambda x: x["score"], reverse=True)

    if has_strong:
        risk_score = matches[0]["score"]
        # Weak signals amplify strong ones with diminishing weight
        for i, m in enumerate(matches[1:4], 1):
            weight = 5 if m.get("strong", False) else 3
            risk_score += weight
    else:
        # Weak signals only — capped below yellow threshold
        risk_score = matches[0]["score"]
        for i, m in enumerate(matches[1:3], 1):
            risk_score += 2
        risk_score = min(risk_score, WEAK_SIGNAL_MAX_SCORE)

    reasons = [m["reason"] for m in matches[:4]]
    return min(risk_score, 100), reasons


def _apply_intelligence_overrides(risk_score: int, intel: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Applies overrides for high-confidence intelligence signals (GSB, PhishTank)."""
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


def _apply_trusted_dampening(
    risk_score: int, verdict: str, reasons: List[str],
    signals: Dict[str, Any], matches: List[Dict[str, Any]],
) -> Tuple[int, str, List[str]]:
    """
    Trusted platform dampening — ONLY suppresses weak/isolated signals.
    NEVER suppresses strong correlations, impersonation, intel hits, or hosted phishing.
    """
    if not signals["phishing"]["trusted_platform"]:
        return risk_score, verdict, reasons

    # These ALWAYS bypass dampening
    bypass_ids = {"impersonation", "homograph_attack", "hosted_phishing",
                  "tld_keyword_synergy", "fresh_phishing_infra", "redirect_cloaking"}
    has_bypass = any(m["id"] in bypass_ids for m in matches)
    has_strong = any(m["confidence"] in ("strong", "critical") for m in matches)
    has_intel = signals["intel"]["gsb_hit"] or signals["intel"]["pt_url_hit"]

    if has_bypass or has_strong or has_intel:
        return risk_score, verdict, reasons

    # Only dampen weak/isolated signals on trusted platforms
    risk_score = min(risk_score, TRUSTED_PLATFORM_CAP)
    verdict = "green"
    reasons = [r for r in reasons if not any(p.lower() in r.lower() for p in WEAK_SIGNAL_PATTERNS)]
    return risk_score, verdict, reasons


def _make_verdict(score: int) -> Tuple[str, bool]:
    if score >= VERDICT_RED_THRESHOLD:
        return "red", False
    elif score >= VERDICT_YELLOW_THRESHOLD:
        return "yellow", False
    return "green", True


# ============================================================
# Unified Scoring — Used by BOTH Phase 1 and Phase 2
# ============================================================

def compute_heuristic_score(
    heuristics: Dict[str, Any],
    hops: List[Dict[str, Any]],
    final_url: str,
    dns_resolves: bool,
    has_metadata: bool,
    metadata: Optional[Dict[str, Any]] = None,
    ssl_error: bool = False,
) -> Tuple[int, str, bool, List[str]]:
    """Phase 1 Score — correlation-based, no external data."""
    signals = _extract_signals(heuristics, {}, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error)
    matches = _evaluate_correlations(signals)
    risk_score, reasons = _compute_correlation_score(matches)

    # Trusted platform dampening
    risk_score, verdict_override, reasons = _apply_trusted_dampening(
        risk_score, "", reasons, signals, matches
    )

    score = min(risk_score, 100)
    verdict, is_safe = _make_verdict(score)
    if verdict_override:
        verdict = verdict_override
        is_safe = verdict == "green"

    return score, verdict, is_safe, reasons


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
    """Phase 2 Final Score — same correlation engine + intelligence + uncertainty."""
    signals = _extract_signals(heuristics, external, hops, final_url, dns_resolves, has_metadata, metadata, ssl_error)
    matches = _evaluate_correlations(signals)
    risk_score, reasons = _compute_correlation_score(matches)

    # Intelligence overrides (GSB / PhishTank)
    risk_score, intel_reasons = _apply_intelligence_overrides(risk_score, signals["intel"])
    reasons = intel_reasons + reasons

    # Uncertainty penalty
    ssl_uncertain = external.get("ssl_timed_out", False)
    gsb_uncertain = external.get("gsb_timed_out", False)
    rdap_uncertain = external.get("rdap_uncertain", False)
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

    score = min(risk_score, 100)
    verdict, is_safe = _make_verdict(score)

    # Trusted platform dampening
    score, verdict, reasons = _apply_trusted_dampening(score, verdict, reasons, signals, matches)
    is_safe = verdict == "green"

    return score, verdict, is_safe, reasons


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
    heuristics = run_heuristics(final_url)

    risk_score, verdict, is_safe, reasons = compute_heuristic_score(
        heuristics, hops, final_url, dns_resolves, has_metadata, 
        metadata=metadata, ssl_error=trace_result.get("ssl_error", False)
    )

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
            timeout=3.0
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

    if external.get("ssl_timed_out"):
        logger.debug(f"[PHASE2] SSL cert age timeout: {root_domain}")
    if external.get("gsb_timed_out"):
        logger.debug(f"[PHASE2] GSB timeout: {root_domain}")
    if external.get("rdap_timed_out"):
        logger.debug(f"[PHASE2] RDAP timeout: {root_domain}")

    risk_score, verdict, is_safe, reasons = compute_final_score(
        heuristics, external, hops, final_url,
        phase1_result.get("dns_resolves", True),
        phase1_result.get("has_metadata", True),
        metadata=phase1_result.get("metadata"),
        ssl_error=phase1_result["security"].get("ssl_error", False)
    )

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
