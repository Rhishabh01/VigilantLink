"""
Scanner: Heuristic analysis engine + external scan orchestration.

Tier 1 (CPU): Pure heuristics — typosquatting, punycode, TLD/keyword synergy.
Tier 2 (Network): RDAP + VirusTotal in parallel (asyncwhois removed).
"""

import asyncio
import logging
import os
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..core.constants import (
    HIGH_RISK_KEYWORDS, HIGH_VALUE_TARGETS, SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS, DEFAULT_DOMAIN_AGE_DAYS, TOTAL_VENDORS_COUNT,
    GSB_API_URL, GSB_THREAT_TYPES, GSB_THREAT_PRIORITY, GSB_TIMEOUT_S,
)
from .rdap_client import fetch_domain_age_rdap

logger = logging.getLogger(__name__)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# ============================================================
# TIER 1: Pure CPU heuristics — instant, no network calls
# ============================================================

def run_heuristics(url: str) -> Dict[str, Any]:
    """
    Pure CPU heuristic analysis. No network calls.
    Runs typosquatting detection, punycode check, TLD/keyword synergy.
    Target: <1ms execution time.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    if ':' in domain:
        domain = domain.split(':')[0]

    parts = domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = domain

    # Brand Protection (Levenshtein)
    typosquatting_detected = False
    brand_penalty_reason = None
    for target in HIGH_VALUE_TARGETS:
        target_domain = f"{target}.com" if '.' not in target else target
        if root_domain == target_domain:
            continue
        dist = levenshtein_distance(root_domain, target_domain)
        if dist == 1:
            typosquatting_detected = True
            brand_penalty_reason = f"Potential Typosquatting detected (Levenshtein distance 1 from {target})"
            break

    # Synergy Check (TLD + Keywords)
    synergy_detected = False
    synergy_reason = None
    tld = f".{parts[-1]}" if parts else ""
    if tld in SUSPICIOUS_TLDS and any(kw in domain for kw in HIGH_RISK_KEYWORDS):
        synergy_detected = True
        synergy_reason = "High-Risk TLD & Keyword Synergy (Phishing Pattern)"

    # Punycode / Homograph detection
    punycode_detected = "xn--" in domain

    # Suspicious keywords in domain
    has_suspicious_keywords = (
        any(kw in root_domain for kw in SUSPICIOUS_KEYWORDS)
        and root_domain not in [f"{t}.com" for t in HIGH_VALUE_TARGETS]
    )

    return {
        "typosquatting_detected": typosquatting_detected,
        "brand_penalty_reason": brand_penalty_reason,
        "synergy_detected": synergy_detected,
        "synergy_reason": synergy_reason,
        "punycode_detected": punycode_detected,
        "has_suspicious_keywords": has_suspicious_keywords,
        "root_domain": root_domain,
        "domain": domain,
    }


# ============================================================
# TIER 2: External network lookups — async, non-blocking
# ============================================================

async def fetch_virustotal_flags(domain: str) -> Tuple[int, int]:
    """
    Fetches vendor flags from VirusTotal API v3.
    Returns (malicious_flags, total_vendors).
    Timeout: 1.5s — fast-fail to avoid blocking.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return 0, 70

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    try:
        timeout = httpx.Timeout(1.5)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit hit for {domain}")
                return 0, 70

            if response.status_code != 200:
                logger.warning(f"VirusTotal API returned {response.status_code} for {domain}")
                return 0, 70

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return (malicious + suspicious), total

    except httpx.TimeoutException:
        logger.warning(f"VirusTotal request timed out for {domain}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            logger.warning(f"VirusTotal rate limit hit for {domain}")
        else:
            logger.error(f"VirusTotal HTTP error for {domain}: {e}")
    except Exception as e:
        logger.error(f"VirusTotal fetch failed for {domain}: {e}")

    return 0, 70


def _normalize_gsb_url(target: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


async def check_google_safe_browsing(url: str) -> List[str]:
    """Check a URL against Google Safe Browsing v4 threatMatches."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    normalized = _normalize_gsb_url(url)
    if not api_key or not normalized:
        return []

    payload = {
        "client": {
            "clientId": "vigilantlink",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": GSB_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized}],
        },
    }

    try:
        timeout = httpx.Timeout(GSB_TIMEOUT_S)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                GSB_API_URL,
                params={"key": api_key},
                json=payload,
            )

            if response.status_code == 429:
                logger.warning(f"Google Safe Browsing rate limit hit for {normalized}")
                return []

            if response.status_code != 200:
                logger.warning(f"Google Safe Browsing API returned {response.status_code} for {normalized}")
                return []

            data = response.json()
            matches = data.get("matches", [])
            threats = [match.get("threatType") for match in matches if match.get("threatType") in GSB_THREAT_TYPES]
            return list(dict.fromkeys([t for t in threats if t]))

    except httpx.TimeoutException:
        logger.warning(f"Google Safe Browsing request timed out for {normalized}")
    except Exception as e:
        logger.warning(f"Google Safe Browsing check failed for {normalized}: {e}")

    return []


async def run_external_scans(domain: str) -> Dict[str, Any]:
    """
    Tier 2: Run RDAP + VirusTotal + GSB in parallel.
    'domain' can be a hostname or a full URL.
    """
    parsed = urllib.parse.urlparse(domain)
    if parsed.scheme and parsed.netloc:
        target_domain = parsed.netloc.split(':')[0]
        gsb_url = urllib.parse.urlunparse(parsed)
    else:
        target_domain = domain
        gsb_url = f"http://{domain}"

    parts = target_domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = target_domain

    rdap_timed_out = False
    vt_timed_out = False
    gsb_timed_out = False

    async def _safe_rdap() -> int:
        nonlocal rdap_timed_out
        try:
            return await asyncio.wait_for(
                fetch_domain_age_rdap(root_domain), timeout=0.8
            )
        except asyncio.TimeoutError:
            rdap_timed_out = True
            return DEFAULT_DOMAIN_AGE_DAYS
        except Exception as e:
            logger.warning(f"RDAP fallback for {root_domain}: {e}")
            return DEFAULT_DOMAIN_AGE_DAYS

    async def _safe_vt() -> Tuple[int, int]:
        nonlocal vt_timed_out
        try:
            return await asyncio.wait_for(
                fetch_virustotal_flags(target_domain), timeout=2.0
            )
        except asyncio.TimeoutError:
            vt_timed_out = True
            return 0, TOTAL_VENDORS_COUNT

    async def _safe_gsb() -> List[str]:
        nonlocal gsb_timed_out
        try:
            return await asyncio.wait_for(
                check_google_safe_browsing(gsb_url), timeout=GSB_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            gsb_timed_out = True
            return []

    age_days, vt_results, gsb_results = await asyncio.gather(
        _safe_rdap(), _safe_vt(), _safe_gsb()
    )
    vendor_flags, total_vendors = vt_results

    gsb_threat_type: Optional[str] = None
    if gsb_results:
        for threat in GSB_THREAT_PRIORITY:
            if threat in gsb_results:
                gsb_threat_type = threat
                break

    threat_type: Optional[str] = None
    if gsb_threat_type:
        threat_type = gsb_threat_type
    elif vendor_flags >= 2:
        threat_type = f"Flagged by {vendor_flags} Security Vendors"
    elif age_days < 30:
        threat_type = "Newly Registered Domain"

    return {
        "domain_age_days": age_days,
        "vendor_flags": vendor_flags,
        "total_vendors": total_vendors,
        "threat_type": threat_type,
        "gsb_threats": gsb_results,
        "gsb_matched": bool(gsb_results),
        "gsb_threat_type": gsb_threat_type,
        "rdap_timed_out": rdap_timed_out,
        "vt_timed_out": vt_timed_out,
        "gsb_timed_out": gsb_timed_out,
    }


# Legacy combined function (kept for backward compatibility)
async def scan_url(url: str) -> Dict[str, Any]:
    """Combined scan — runs heuristics + external scans together."""
    heuristics = run_heuristics(url)
    external = await run_external_scans(heuristics["root_domain"])

    # Merge threat_type: heuristic threats take priority
    threat_type = external.get("threat_type")
    if heuristics.get("brand_penalty_reason"):
        threat_type = "Typosquatting Detected (High Value Target)"
    elif heuristics.get("synergy_detected"):
        threat_type = heuristics["synergy_reason"]
    elif heuristics.get("has_suspicious_keywords"):
        threat_type = threat_type or "Suspicious Keywords in Domain"

    return {
        **heuristics,
        **external,
        "threat_type": threat_type,
    }
