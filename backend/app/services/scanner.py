import os
import urllib.parse
from typing import Dict, Any, Tuple
import datetime
import httpx
import asyncwhois
import logging
import asyncio

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = ['.top', '.xyz', '.biz', '.zip']
HIGH_RISK_KEYWORDS = ['verify', 'login', 'bank', 'secure', 'account']
HIGH_VALUE_TARGETS = ['google', 'amazon', 'paypal', 'github', 'microsoft', 'apple']
SUSPICIOUS_KEYWORDS = ["free", "login", "update", "verify", "secure", "account"]

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
# TIER 2: External network lookups — async, slower
# ============================================================

async def get_domain_age(domain: str) -> int:
    """
    Real WHOIS logic using asyncwhois.
    Returns the age of the domain in days.
    Timeout: 1.5s — fast-fail on slow registrars.
    """
    try:
        try:
            _, parsed_dict = await asyncio.wait_for(
                asyncwhois.aio_whois(domain),
                timeout=1.5
            )
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS lookup timed out for {domain}")
            return 3000

        creation_date = parsed_dict.get('created') or parsed_dict.get('creation_date')
        if not creation_date:
            return 3000

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, str):
            logger.warning(f"WHOIS returned string date for {domain}, cannot parse reliably")
            return 3000

        if isinstance(creation_date, datetime.datetime):
            now = datetime.datetime.now(datetime.timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)

            age_timedelta = now - creation_date
            return max(0, age_timedelta.days)

    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    return 3000

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


async def run_external_scans(domain: str) -> Dict[str, Any]:
    """
    Tier 2: Run WHOIS + VirusTotal in parallel.
    Returns external scan data for risk scoring.
    """
    age_days, vt_results = await asyncio.gather(
        get_domain_age(domain),
        fetch_virustotal_flags(domain)
    )
    vendor_flags, total_vendors = vt_results

    # Determine threat type from external data
    threat_type = None
    if vendor_flags >= 2:
        threat_type = f"Flagged by {vendor_flags} Security Vendors"
    elif age_days < 30:
        threat_type = "Newly Registered Domain"

    return {
        "domain_age_days": age_days,
        "vendor_flags": vendor_flags,
        "total_vendors": total_vendors,
        "threat_type": threat_type,
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
