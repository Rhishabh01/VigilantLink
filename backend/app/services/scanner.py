"""
Scanner: Heuristic analysis engine + external scan orchestration.

Tier 1 (CPU): Pure heuristics — typosquatting, punycode, TLD/keyword synergy.
Tier 2 (Network): RDAP + GSB in parallel (asyncwhois removed).
"""

import asyncio
import logging
import os
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..core.constants import (
    HIGH_RISK_KEYWORDS, HIGH_VALUE_TARGETS, SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS, DEFAULT_DOMAIN_AGE_DAYS,
    GSB_API_URL, GSB_THREAT_TYPES, GSB_THREAT_PRIORITY, GSB_TIMEOUT_S,
    SSL_CERT_TIMEOUT_S, RDAP_TIMEOUT_S, NEWLY_REGISTERED_DAYS,
    RECENTLY_REGISTERED_DAYS, PHISHTANK_FEED_URL, PHISHTANK_REFRESH_INTERVAL_S
)
from .rdap_client import fetch_domain_age_rdap
from ..core.logging import get_logger

logger = get_logger("VigilantLink")


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

async def fetch_ssl_cert_age(hostname: str) -> Optional[int]:
    """
    Asynchronously fetches SSL certificate 'notBefore' date and computes age in days.
    Uses asyncio.open_connection for a non-blocking TLS handshake.
    """
    try:
        context = ssl.create_default_context()
        # Fully async connection + TLS handshake
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=context, server_hostname=hostname),
            timeout=SSL_CERT_TIMEOUT_S
        )
        
        cert = writer.get_extra_info('peercert')
        writer.close()
        await writer.wait_closed()
        
        if not cert or 'notBefore' not in cert:
            return None
            
        # Format: 'May 15 00:00:00 2024 GMT'
        issued_date_str = cert['notBefore']
        # Parse and ensure UTC
        issued_date = datetime.strptime(issued_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - issued_date).days
        return max(0, age_days)
    except Exception:
        # Fail gracefully: SSL issues are not always malicious
        return None

# ============================================================
# TIER 2: External network lookups — async, non-blocking
# ============================================================

_phishtank_urls = set()
_phishtank_domains = set()
_phishtank_task = None

async def sync_phishtank_feed() -> None:
    """Background task to periodically fetch and update the PhishTank feed."""
    global _phishtank_urls, _phishtank_domains
    while True:
        try:
            logger.info("[PHISHTANK] Starting feed sync...")
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, headers={"User-Agent": "phishtank/vigilantlink"}) as client:
                response = await client.get(PHISHTANK_FEED_URL)
                if response.status_code == 200:
                    data = response.json()
                    new_urls = set()
                    new_domains = set()
                    for entry in data:
                        url = entry.get("url")
                        if url:
                            norm_url = _normalize_gsb_url(url)
                            if norm_url:
                                new_urls.add(norm_url)
                                parsed = urllib.parse.urlparse(norm_url)
                                new_domains.add(parsed.netloc)
                    
                    _phishtank_urls = new_urls
                    _phishtank_domains = new_domains
                    logger.info(f"[PHISHTANK] Synced {len(_phishtank_urls)} URLs and {len(_phishtank_domains)} domains.")
                else:
                    logger.warning(f"[PHISHTANK] Failed to fetch feed, status {response.status_code}")
        except Exception as e:
            logger.error(f"[PHISHTANK] Sync error: {e}")
            
        await asyncio.sleep(PHISHTANK_REFRESH_INTERVAL_S)

def start_phishtank_sync() -> None:
    global _phishtank_task
    if _phishtank_task is None:
        _phishtank_task = asyncio.create_task(sync_phishtank_feed())

def stop_phishtank_sync() -> None:
    global _phishtank_task
    if _phishtank_task:
        _phishtank_task.cancel()
        _phishtank_task = None

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
                logger.warning(f"[GSB] Rate limit hit")
                return []

            if response.status_code != 200:
                logger.debug(f"[GSB] API returned {response.status_code}")
                return []

            data = response.json()
            matches = data.get("matches", [])
            threats = [match.get("threatType") for match in matches if match.get("threatType") in GSB_THREAT_TYPES]
            return list(dict.fromkeys([t for t in threats if t]))

    except httpx.TimeoutException:
        logger.debug(f"[GSB] Request timed out")
    except Exception as e:
        logger.error(f"[GSB] Check failed: {e}")

    return []


async def run_external_scans(domain: str) -> Dict[str, Any]:
    """
    Tier 2: Run RDAP + GSB in parallel.
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

    ssl_timed_out = False
    gsb_timed_out = False
    rdap_timed_out = False
 
    async def _safe_ssl() -> Optional[int]:
        nonlocal ssl_timed_out
        try:
            return await asyncio.wait_for(
                fetch_ssl_cert_age(target_domain), timeout=SSL_CERT_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            ssl_timed_out = True
            logger.warning(f"SSL cert age timeout: {target_domain}")
            return None
        except Exception as e:
            logger.debug(f"SSL cert age failed for {target_domain}: {e}")
            return None

    async def _safe_gsb() -> List[str]:
        nonlocal gsb_timed_out
        try:
            return await asyncio.wait_for(
                check_google_safe_browsing(gsb_url), timeout=GSB_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            gsb_timed_out = True
            return []

    async def _safe_rdap() -> int:
        nonlocal rdap_timed_out
        try:
            return await asyncio.wait_for(
                fetch_domain_age_rdap(root_domain), timeout=RDAP_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            rdap_timed_out = True
            return DEFAULT_DOMAIN_AGE_DAYS

 
    results = await asyncio.gather(
        _safe_ssl(), _safe_gsb(), _safe_rdap()
    )
    cert_age, gsb_results, domain_age = results
 
    norm_url = _normalize_gsb_url(gsb_url)
    pt_url_match = norm_url in _phishtank_urls if norm_url else False
    pt_domain_match = target_domain in _phishtank_domains

    gsb_threat_type: Optional[str] = None
    if gsb_results:
        for threat in GSB_THREAT_PRIORITY:
            if threat in gsb_results:
                gsb_threat_type = threat
                break
 
    threat_type: Optional[str] = None
    if gsb_threat_type:
        threat_type = gsb_threat_type
    elif cert_age is not None and cert_age < 7:
        threat_type = "Recently Issued SSL Certificate"
    elif domain_age < NEWLY_REGISTERED_DAYS:
        threat_type = "Newly Registered Domain"
 
    return {
        "ssl_cert_age_days": cert_age,
        "domain_age_days": domain_age,
        "threat_type": threat_type,
        "gsb_threats": gsb_results,
        "gsb_matched": bool(gsb_results),
        "gsb_threat_type": gsb_threat_type,
        "rdap_timed_out": rdap_timed_out,
        "pt_url_match": pt_url_match,
        "pt_domain_match": pt_domain_match,
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
