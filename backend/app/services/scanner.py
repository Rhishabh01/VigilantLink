"""
Scanner: Heuristic analysis engine + external scan orchestration.

Tier 1 (CPU): Pure heuristics — typosquatting, punycode, TLD/keyword synergy.
Tier 2 (Network): RDAP + VirusTotal in parallel (asyncwhois removed).
"""

import asyncio
import os
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..core.constants import (
    HIGH_RISK_KEYWORDS, HIGH_VALUE_TARGETS, SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS, DEFAULT_DOMAIN_AGE_DAYS,
    GSB_API_URL, GSB_THREAT_TYPES, GSB_THREAT_PRIORITY, GSB_TIMEOUT_S,
    SSL_CERT_TIMEOUT_S, RDAP_TIMEOUT_S, NEWLY_REGISTERED_DAYS,
    RECENTLY_REGISTERED_DAYS,
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

# Module-level variables for OpenPhish feed caching
_openphish_cache: Optional[List[str]] = None
_openphish_cache_expiry: Optional[datetime] = None
_openphish_lock = asyncio.Lock()


def _normalize_openphish_url(url: str) -> str:
    """
    Normalize URL for comparison: lowercase, strip www., strip trailing slash.
    """
    u = url.lower().strip().rstrip('/')
    if u.startswith("www."):
        u = u[4:]
    u = u.replace("://www.", "://")
    return u


async def check_openphish(url: str) -> bool:
    """
    Check if URL is in OpenPhish community feed.
    Cache in memory with a 12-hour TTL. Thread-safe using asyncio.Lock.
    """
    global _openphish_cache, _openphish_cache_expiry
    now = datetime.now(timezone.utc)

    # Use lock to prevent simultaneous fetch attempts on cache miss
    async with _openphish_lock:
        cache_valid = (
            _openphish_cache is not None
            and _openphish_cache_expiry is not None
            and now < _openphish_cache_expiry
        )

        if not cache_valid:
            try:
                timeout = httpx.Timeout(3.0)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get("https://openphish.com/feed.txt")
                    if response.status_code == 200:
                        lines = [line.strip() for line in response.text.splitlines() if line.strip()]
                        _openphish_cache = [_normalize_openphish_url(line) for line in lines]
                        _openphish_cache_expiry = now + timedelta(hours=12)
                        logger.debug(f"[OpenPhish] Cache refreshed with {len(_openphish_cache)} URLs")
                    else:
                        logger.warning(f"[OpenPhish] Failed to fetch feed (status {response.status_code})")
            except Exception as e:
                logger.warning(f"[OpenPhish] Failed to fetch feed: {e}")

        # Check target URL against cache (either newly fetched or old cached fallback)
        if _openphish_cache is not None:
            normalized_target = _normalize_openphish_url(url)
            return normalized_target in _openphish_cache

    return False


async def check_phishtank(url: str) -> bool:
    """
    Check if URL is flagged as phishing by PhishTank.
    POST to https://checkurl.phishtank.com/checkurl/
    Body: url=ENCODED_URL&format=json&app_key=
    Timeout: 2.0 seconds.
    """
    try:
        timeout = httpx.Timeout(2.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json", "app_key": ""}
            )
            if response.status_code != 200:
                logger.debug(f"[PhishTank] API returned {response.status_code}")
                return False

            data = response.json()
            if "results" not in data or not isinstance(data["results"], dict):
                logger.warning(f"[PhishTank] Unexpected response format for {url[:30]}...")
                return False

            results = data["results"]
            in_database = results.get("in_database", False)
            valid = results.get("valid", False)
            return bool(in_database and valid)
    except httpx.TimeoutException:
        logger.debug(f"[PhishTank] Request timed out for {url[:30]}...")
    except Exception as e:
        logger.debug(f"[PhishTank] Check failed: {e}")
    return False


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
            "clientVersion": "2.0.0",
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
    Tier 2: Run SSL, GSB, RDAP, PhishTank, and OpenPhish in parallel.
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
    phishtank_timed_out = False
    openphish_timed_out = False
 
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

    async def _safe_phishtank() -> bool:
        nonlocal phishtank_timed_out
        try:
            return await asyncio.wait_for(
                check_phishtank(gsb_url), timeout=2.0
            )
        except asyncio.TimeoutError:
            phishtank_timed_out = True
            return False
        except Exception as e:
            logger.debug(f"PhishTank check failed for {gsb_url}: {e}")
            return False

    async def _safe_openphish() -> bool:
        nonlocal openphish_timed_out
        try:
            return await asyncio.wait_for(
                check_openphish(gsb_url), timeout=3.0
            )
        except asyncio.TimeoutError:
            openphish_timed_out = True
            return False
        except Exception as e:
            logger.debug(f"OpenPhish check failed for {gsb_url}: {e}")
            return False

    results = await asyncio.gather(
        _safe_ssl(), _safe_gsb(), _safe_rdap(), _safe_phishtank(), _safe_openphish()
    )
    cert_age, gsb_results, domain_age, phishtank_flagged, openphish_flagged = results
 
    gsb_threat_type: Optional[str] = None
    if gsb_results:
        for threat in GSB_THREAT_PRIORITY:
            if threat in gsb_results:
                gsb_threat_type = threat
                break
 
    threat_type: Optional[str] = None
    if gsb_threat_type:
        threat_type = gsb_threat_type
    elif phishtank_flagged:
        threat_type = "Confirmed Phishing (PhishTank)"
    elif openphish_flagged:
        threat_type = "Active Phishing Campaign (OpenPhish)"
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
        "ssl_timed_out": ssl_timed_out,
        "gsb_timed_out": gsb_timed_out,
        "phishtank_flagged": phishtank_flagged,
        "openphish_flagged": openphish_flagged,
        "phishtank_timed_out": phishtank_timed_out,
        "openphish_timed_out": openphish_timed_out,
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

    merged = {
        **heuristics,
        **external,
        "threat_type": threat_type,
    }
    merged.pop("vendor_flags", None)
    merged.pop("total_vendors", None)
    return merged
