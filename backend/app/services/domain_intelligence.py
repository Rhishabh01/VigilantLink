import httpx
import asyncio
from typing import List, Optional
from ..core.logging import get_logger

logger = get_logger("DomainIntelligence")

# Public mirror for the Top domains (aggregates Cloudflare, Ahrefs, Umbrella)
TOP_DOMAINS_URL = "https://raw.githubusercontent.com/danielmiessler/top-domains/main/topdomains.txt"

async def refresh_top_domains_task(redis_cache) -> bool:
    """
    Background task to download and update the top domains list in Redis.
    Target: Top 10,000 high-traffic domains.
    """
    logger.info("[STARTUP] Refreshing Top Domains list...")
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(TOP_DOMAINS_URL)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch top domains: HTTP {response.status_code}")
                return False
                
            # Filter and normalize domains
            lines = response.text.splitlines()
            domains = []
            for line in lines:
                domain = line.strip().lower()
                if domain and "." in domain:
                    domains.append(domain)
            
            if not domains:
                logger.warning("Fetched top domains list is empty.")
                return False
                
            await redis_cache.set_top_domains(domains)
            logger.info(f"Successfully loaded {len(domains)} top domains into Redis.")
            return True
            
    except Exception as e:
        logger.error(f"Error during top domains refresh: {e}")
        return False

async def run_periodic_refresh(redis_cache, interval_hours: int = 24):
    """Loop that refreshes the list every X hours."""
    while True:
        await refresh_top_domains_task(redis_cache)
        await asyncio.sleep(interval_hours * 3600)
