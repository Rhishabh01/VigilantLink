import os
import urllib.parse
from typing import Dict, Any, Tuple
import datetime
import httpx
import asyncwhois
import logging
import asyncio

from app.core.constants import (
    SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS, HIGH_VALUE_TARGETS, SUSPICIOUS_KEYWORDS,
    NEW_DOMAIN_THRESHOLD_DAYS, DEFAULT_DOMAIN_AGE_DAYS, TOTAL_VENDORS_COUNT
)

logger = logging.getLogger(__name__)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings using iterative Wagner-Fischer."""
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

async def get_domain_age(domain: str) -> int:
    """
    Real WHOIS logic using asyncwhois with 3-second timeout.
    Returns the age of the domain in days.
    """
    try:
        try:
            _, parsed_dict = await asyncio.wait_for(
                asyncwhois.aio_whois(domain),
                timeout=3.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS lookup timed out for {domain}")
            return DEFAULT_DOMAIN_AGE_DAYS

        creation_date = parsed_dict.get('created') or parsed_dict.get('creation_date')
        if not creation_date:
            return DEFAULT_DOMAIN_AGE_DAYS

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, str):
            logger.warning(f"WHOIS returned string date for {domain}, cannot parse reliably")
            return DEFAULT_DOMAIN_AGE_DAYS

        if isinstance(creation_date, datetime.datetime):
            now = datetime.datetime.now(datetime.timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)

            age_timedelta = now - creation_date
            return max(0, age_timedelta.days)

    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    return DEFAULT_DOMAIN_AGE_DAYS

async def fetch_security_vendor_flags(domain: str) -> Tuple[int, int]:
    """
    Fetches vendor flags from VirusTotal API v3 with 3-second timeout.
    Returns (malicious_flags, total_vendors).
    Handles rate limits (429) by returning 0 flags.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return 0, TOTAL_VENDORS_COUNT

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    try:
        timeout = httpx.Timeout(3.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 429:
                logger.warning(f"Security Vendor rate limit hit for {domain}")
                return 0, TOTAL_VENDORS_COUNT

            if response.status_code != 200:
                logger.warning(f"Security Vendor API returned {response.status_code} for {domain}")
                return 0, TOTAL_VENDORS_COUNT

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return (malicious + suspicious), total

    except httpx.TimeoutException:
        logger.warning(f"Security Vendor request timed out for {domain}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            logger.warning(f"Security Vendor rate limit hit for {domain}")
        else:
            logger.error(f"Security Vendor HTTP error for {domain}: {e}")
    except Exception as e:
        logger.error(f"Security Vendor fetch failed for {domain}: {e}")

    return 0, TOTAL_VENDORS_COUNT

async def scan_url(url: str) -> Dict[str, Any]:
    """
    Scans the URL for typosquatting, age, and suspicious keywords.
    Uses concurrent calls for WHOIS and VirusTotal.
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
    
    age_days, vt_results = await asyncio.gather(
        get_domain_age(root_domain),
        fetch_security_vendor_flags(root_domain)
    )
    vendor_flags, total_vendors = vt_results
    
    # Brand Protection (Levenshtein) Rule
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
    path_lower = parsed.path.lower()
    if tld in SUSPICIOUS_TLDS and any(kw in domain for kw in HIGH_RISK_KEYWORDS):
        synergy_detected = True
        synergy_reason = f"High-Risk TLD & Keyword Synergy (Phishing Pattern)"
    
    # Check for homograph/Punycode
    punycode_detected = "xn--" in domain or "xn--" in domain
    
    threat_type = None
    if vendor_flags > 0:
        threat_type = f"Flagged by {vendor_flags} Security Vendors"
    elif typosquatting_detected:
        threat_type = "Typosquatting Detected (High Value Target)"
    elif synergy_detected:
        threat_type = synergy_reason
    elif any(keyword in root_domain for keyword in SUSPICIOUS_KEYWORDS) and root_domain not in [f"{t}.com" for t in HIGH_VALUE_TARGETS]:
        threat_type = "Suspicious Keywords in Domain"
    elif age_days < NEW_DOMAIN_THRESHOLD_DAYS:
        threat_type = "Newly Registered Domain"
    
    return {
        "domain_age_days": age_days,
        "typosquatting_detected": typosquatting_detected,
        "brand_penalty_reason": brand_penalty_reason,
        "synergy_detected": synergy_detected,
        "synergy_reason": synergy_reason,
        "punycode_detected": punycode_detected,
        "threat_type": threat_type,
        "vendor_flags": vendor_flags,
        "total_vendors": total_vendors
    }
