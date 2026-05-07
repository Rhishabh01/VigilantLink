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

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
RDAP_TIMEOUT_S = 0.8  # Hard budget — enforced here AND by caller


async def fetch_domain_age_rdap(domain: str) -> int:
    """
    Fetch domain registration date via RDAP (HTTP/JSON).

    Returns:
        Age in days. Returns 3000 (assume old) on failure/not-found.

    Raises:
        asyncio.TimeoutError: If request exceeds RDAP_TIMEOUT_S.
            Caller must handle this to apply uncertainty penalty.
    """
    url = RDAP_BOOTSTRAP_URL.format(domain=domain)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(RDAP_TIMEOUT_S)) as client:
            resp = await client.get(url, follow_redirects=True)

            if resp.status_code == 404:
                # Domain not in RDAP = likely legacy/old domain
                logger.info(f"RDAP: domain {domain} not found (assuming old)")
                return 3000

            resp.raise_for_status()
            data = resp.json()

            # RDAP events array: find "registration" event
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    date_str = event.get("eventDate", "")
                    reg_date = datetime.datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")
                    )
                    now = datetime.datetime.now(datetime.timezone.utc)
                    return max(0, (now - reg_date).days)

            # No registration event found
            logger.info(f"RDAP: no registration event for {domain}")
            return 3000

    except httpx.TimeoutException:
        logger.warning(f"RDAP timeout for {domain}")
        raise  # Propagate — caller applies uncertainty penalty

    except Exception as e:
        logger.warning(f"RDAP failed for {domain}: {e}")
        return 3000
