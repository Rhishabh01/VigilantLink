import httpx
from typing import Dict, Any
import logging
from app.utils.security import is_safe_url

logger = logging.getLogger(__name__)

async def trace_url(url: str) -> Dict[str, Any]:
    """
    Follows redirects to find the final URL.
    Returns the redirect chain and the final URL.
    """
    if not await is_safe_url(url):
        raise ValueError('Access to internal network prohibited')

    hops = []
    current_url = url
    
    # We use a custom client to capture intermediate hops
    try:
        async with httpx.AsyncClient(follow_redirects=True, max_redirects=10, timeout=10.0) as client:
            # We use GET. HEAD is safer, but some sites reject HEAD requests.
            response = await client.get(current_url)
            
            # Reconstruct the hop history
            for history_response in response.history:
                hops.append({
                    "url": str(history_response.url),
                    "status_code": history_response.status_code
                })
            
            # Add the final destination
            hops.append({
                "url": str(response.url),
                "status_code": response.status_code
            })
            
            return {
                "final_url": str(response.url),
                "hops": hops
            }
            
    except httpx.HTTPError as e:
        logger.error(f"Tracing failed for {url}: {e}")
        # If trace fails, fallback to the original URL
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}]
        }
