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
HIGH_RISK_KEYWORDS = ['verify', 'login', 'bank', 'secure']

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

async def get_domain_age(domain: str) -> int:
    """
    Real WHOIS logic using asyncwhois. 
    Returns the age of the domain in days.
    """
    try:
        _, parsed_dict = await asyncwhois.aio_whois(domain)
        creation_date = parsed_dict.get('created')
        if not creation_date:
            return 3000 # Assume mature if we can't find it
            
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, str):
            return 3000 
            
        if isinstance(creation_date, datetime.datetime):
            now = datetime.datetime.now(datetime.timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
                
            age_timedelta = now - creation_date
            return max(0, age_timedelta.days)
            
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        
    return 3000 # Default to mature domain if WHOIS fails

async def fetch_virustotal_flags(domain: str) -> Tuple[int, int]:
    """
    Fetches vendor flags from VirusTotal API v3.
    Returns (malicious_flags, total_vendors).
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return 0, 70 # Default dummy values if no key is provided
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                return (malicious + suspicious), total
            else:
                logger.warning(f"VirusTotal API returned {response.status_code} for {domain}")
    except Exception as e:
        logger.error(f"VirusTotal fetch failed for {domain}: {e}")
        
    return 0, 70

async def scan_url(url: str) -> Dict[str, Any]:
    """
    Scans the URL for typosquatting, age, and suspicious keywords.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    # Strip port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Simple root domain extraction (e.g., www.amazon.com -> amazon.com)
    parts = domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = domain

    # Await both external API calls concurrently
    age_days, vt_results = await asyncio.gather(
        get_domain_age(root_domain),
        fetch_virustotal_flags(root_domain)
    )
    vendor_flags, total_vendors = vt_results
    
    high_value_targets = ["google.com", "amazon.com", "microsoft.com", "apple.com", "facebook.com", "paypal.com"]
    
    typosquatting_detected = False
    for target in high_value_targets:
        if root_domain == target:
            continue # Real domain
        dist = levenshtein_distance(root_domain, target)
        if dist == 1: # Distance of 1 (e.g. amäzon.com)
            typosquatting_detected = True
            break
            
    suspicious_keywords = ["free", "login", "update", "verify", "secure", "account"]
    
    threat_type = None
    if vendor_flags > 0:
        threat_type = f"Flagged by {vendor_flags} Security Vendors"
    elif typosquatting_detected:
        threat_type = "Typosquatting Detected (High Value Target)"
    elif any(keyword in root_domain for keyword in suspicious_keywords) and root_domain not in high_value_targets:
        threat_type = "Suspicious Keywords in Domain"
    elif age_days < 30:
        threat_type = "Newly Registered Domain"
        
    return {
        "domain_age_days": age_days,
        "typosquatting_detected": typosquatting_detected,
        "threat_type": threat_type,
        "vendor_flags": vendor_flags,
        "total_vendors": total_vendors
    }
