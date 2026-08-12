"""
RDAP Client: HTTP/JSON-based domain age lookup.

Replaces the blocking asyncwhois WHOIS client.
RDAP is the IETF-standardized replacement (RFC 7482) — pure HTTP, no raw sockets.
"""

import datetime
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

RDAP_TIMEOUT_S = 5.0

# Secondary authoritative RDAP servers by top-level domain
TLD_RDAP_ENDPOINTS = {
    "com": "https://rdap.verisign.com/com/v1/domain/{domain}",
    "net": "https://rdap.verisign.com/net/v1/domain/{domain}",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/{domain}",
    "info": "https://rdap.afilias.net/rdap/domain/{domain}",
}


async def fetch_domain_age_rdap(domain: str) -> int:
    """
    Fetch domain registration date via RDAP (HTTP/JSON).
    Tries rdap.org first, then falls back to direct authoritative registry endpoints.
    """
    tld = domain.split(".")[-1].lower() if "." in domain else ""
    urls = [f"https://rdap.org/domain/{domain}"]
    if tld in TLD_RDAP_ENDPOINTS:
        urls.append(TLD_RDAP_ENDPOINTS[tld].format(domain=domain))

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    async with httpx.AsyncClient(timeout=httpx.Timeout(RDAP_TIMEOUT_S), follow_redirects=True, headers=headers) as client:
        for url in urls:
            try:
                resp = await client.get(url)
                if resp.status_code == 404:
                    logger.info(f"RDAP 404 for {domain} at {url} (assuming old domain)")
                    return 3000

                if resp.status_code != 200:
                    continue

                data = resp.json()

                # Search events array for registration or creation
                events = data.get("events", [])
                for event in events:
                    action = event.get("eventAction", "").lower()
                    if action in ("registration", "created"):
                        date_str = event.get("eventDate", "")
                        if date_str:
                            # Parse ISO timestamp
                            clean_date = date_str.replace("Z", "+00:00")
                            reg_date = datetime.datetime.fromisoformat(clean_date)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            return max(0, (now - reg_date).days)

                logger.info(f"RDAP response received for {domain} but no registration date found.")
                return 3000

            except httpx.TimeoutException:
                logger.warning(f"RDAP timeout for {domain} at {url}")
                continue
            except Exception as e:
                logger.warning(f"RDAP error for {domain} at {url}: {e}")
                continue

    # Default fallback if all endpoints failed or timed out
    return 3000
