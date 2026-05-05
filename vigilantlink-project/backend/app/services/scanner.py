import os
import urllib.parse
from typing import Dict, Any

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

def get_domain_age(domain: str) -> int:
    """
    Mock WHOIS logic. 
    Returns the age of the domain in days.
    (Can be swapped for a real WHOIS API/library later).
    """
    # For demonstration, flag .xyz or domains with 'test' as young
    if domain.endswith('.xyz') or 'test' in domain:
        return 5 # Young domain
    return 3000 # Mature domain

async def scan_url(url: str) -> Dict[str, Any]:
    """
    Scans the URL for typosquatting, age, and suspicious keywords.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    
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

    age_days = get_domain_age(root_domain)
    
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
    if typosquatting_detected:
        threat_type = "Typosquatting Detected (High Value Target)"
    elif any(keyword in root_domain for keyword in suspicious_keywords) and root_domain not in high_value_targets:
        threat_type = "Suspicious Keywords in Domain"
    elif age_days < 30:
        threat_type = "Newly Registered Domain"
        
    return {
        "domain_age_days": age_days,
        "typosquatting_detected": typosquatting_detected,
        "threat_type": threat_type,
        "vendor_flags": 0,
        "total_vendors": 70
    }
