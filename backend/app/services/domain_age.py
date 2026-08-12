"""
Domain Age Service: Lookup creation date via RDAP/WHOIS and calculate domain age.
"""

import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import logging
import httpx

logger = logging.getLogger(__name__)

from .rdap_client import fetch_domain_age_rdap, extract_root_domain as extract_registered_domain


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
    Extract domain, fetch RDAP registration date via multi-endpoint RDAP client, calculate age and risk level.
    """
    domain = extract_registered_domain(url_or_domain)
    days_opt = await fetch_domain_age_rdap(domain)

    if days_opt is not None:
        days = days_opt
        age_str = format_age_string(days)
        risk_info = get_risk_label(days)
    else:
        days = None
        age_str = "N/A"
        risk_info = {"label": "Unknown", "color": "gray"}

    return {
        "domain": domain,
        "days": days,
        "age_string": age_str,
        "risk_label": risk_info["label"],
        "risk_color": risk_info["color"]
    }
