"""
Domain Age Service: Lookup creation date via RDAP/WHOIS and calculate domain age.
"""

import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import logging
import httpx

logger = logging.getLogger(__name__)

RDAP_URL_TEMPLATE = "https://rdap.org/domain/{domain}"

def extract_registered_domain(url_or_domain: str) -> str:
    """Extract registered domain from URL or domain string."""
    cleaned = url_or_domain.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        host = parsed.netloc or parsed.path
    else:
        host = cleaned.split('/')[0]
    
    # Strip port if present
    host = host.split(':')[0].lower()
    
    # Handle subdomains (basic extraction for common TLDs)
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    
    # Handle common 2-part TLDs like co.uk, com.au, org.uk, net.au, etc.
    two_part_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.in", "net.in", "org.in", "gen.in", "firm.in"}
    potential_tld = f"{parts[-2]}.{parts[-1]}"
    if potential_tld in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{potential_tld}"
    
    return f"{parts[-2]}.{parts[-1]}"


def format_age_string(days: int, reg_date: Optional[datetime.datetime] = None) -> str:
    """
    Format age in Days/Months/Years.
    Examples:
        12 Days
        8 Months
        3 Years 2 Months
        10 Years
    """
    if days < 30:
        return f"{max(1, days)} Days"
    
    if reg_date is not None:
        now = datetime.datetime.now(datetime.timezone.utc)
        # Calculate years and months from date
        years = now.year - reg_date.year
        months = now.month - reg_date.month
        if now.day < reg_date.day:
            months -= 1
        if months < 0:
            years -= 1
            months += 12
        
        years = max(0, years)
        months = max(0, months)
    else:
        years = days // 365
        rem_days = days % 365
        months = rem_days // 30

    if years == 0:
        return f"{months} Months" if months > 0 else f"{days} Days"
    elif months == 0:
        return f"{years} Years"
    else:
        return f"{years} Years {months} Months"


def get_risk_label(days: int) -> Dict[str, str]:
    """
    Risk Labels:
    Age < 30 days: Newly Registered Domain
    30–180 days: Very New Domain
    180–365 days: Young Domain
    More than 1 year: Trusted Domain
    """
    if days < 30:
        return {
            "label": "Newly Registered Domain",
            "color": "red"
        }
    elif 30 <= days <= 180:
        return {
            "label": "Very New Domain",
            "color": "orange"
        }
    elif 180 < days <= 365:
        return {
            "label": "Young Domain",
            "color": "yellow"
        }
    else:
        return {
            "label": "Trusted Domain",
            "color": "green"
        }


async def get_domain_age_info(url_or_domain: str) -> Dict[str, Any]:
    """
    Extract domain, fetch RDAP registration date, calculate age and risk level.
    """
    domain = extract_registered_domain(url_or_domain)
    
    reg_date: Optional[datetime.datetime] = None
    days: int = 3000 # Default fallback if lookup fails (assume old/established)
    
    rdap_url = RDAP_URL_TEMPLATE.format(domain=domain)
    
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.get(rdap_url, follow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        date_str = event.get("eventDate", "")
                        if date_str:
                            reg_date = datetime.datetime.fromisoformat(
                                date_str.replace("Z", "+00:00")
                            )
                            now = datetime.datetime.now(datetime.timezone.utc)
                            days = max(0, (now - reg_date).days)
                            break
    except Exception as e:
        logger.warning(f"Domain age RDAP lookup failed for {domain}: {e}")

    age_str = format_age_string(days, reg_date)
    risk_info = get_risk_label(days)

    return {
        "domain": domain,
        "days": days,
        "age_string": age_str,
        "risk_label": risk_info["label"],
        "risk_color": risk_info["color"]
    }
