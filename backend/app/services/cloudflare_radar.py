"""
Cloudflare Radar: Domain popularity and category lookup.
Used to distinguish popular domains from obscure ones.
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CLOUDFLARE_RADAR_API = "https://api.cloudflare.com/client/v4/radar/ranking/domain/"
# We use the free/public ranking API which doesn't strictly require an API key for low volume,
# but can use one if available.

async def fetch_domain_popularity(domain: str) -> Optional[int]:
    """
    Fetch domain popularity rank from Cloudflare Radar.
    Returns: Rank (1 to 1,000,000). None if not in top 1M or error.
    """
    # Cloudflare Radar API requires a token for higher limits
    token = os.getenv("CLOUDFLARE_RADAR_TOKEN")
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    try:
        # Use a very short timeout for popularity signal
        async with httpx.AsyncClient(timeout=1.0) as client:
            resp = await client.get(f"{CLOUDFLARE_RADAR_API}{domain}", headers=headers)
            
            if resp.status_code == 404:
                return None
                
            if resp.status_code != 200:
                return None
                
            data = resp.json()
            # The API returns an array of ranks for different timeframes
            ranks = data.get("result", {}).get("top", [])
            if ranks:
                # Return the first rank (usually the most recent)
                return ranks[0].get("rank")
                
    except Exception as e:
        logger.debug(f"Cloudflare Radar failed for {domain}: {e}")
        
    return None
