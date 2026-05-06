"""
Cloudflare Radar API: Domain popularity and category enrichment.

Used as supplementary signal alongside RDAP for domain reputation.
Free tier: 10k requests/day.
"""

import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

CF_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar/entities/domains"
CF_TIMEOUT_S = 0.8  # Same budget as RDAP — must not exceed Phase 2 window


async def fetch_domain_popularity(domain: str) -> Optional[Dict[str, Any]]:
    """
    Fetch domain rank and category from Cloudflare Radar.

    Returns:
        Dict with 'rank' (int, lower = more popular) and 'category' (str),
        or None if unavailable.
    """
    token = os.getenv("CLOUDFLARE_API_TOKEN")
    if not token:
        return None

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(CF_TIMEOUT_S)) as client:
            resp = await client.get(
                CF_RADAR_BASE,
                params={"domain": domain},
                headers={"Authorization": f"Bearer {token}"},
            )

            if resp.status_code != 200:
                logger.warning(f"Cloudflare Radar returned {resp.status_code} for {domain}")
                return None

            data = resp.json()
            result = data.get("result", {})
            return {
                "rank": result.get("rank"),
                "category": result.get("category"),
            }

    except httpx.TimeoutException:
        logger.warning(f"Cloudflare Radar timeout for {domain}")
        return None
    except Exception as e:
        logger.warning(f"Cloudflare Radar failed for {domain}: {e}")
        return None
