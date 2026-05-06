import httpx
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

async def trace_url(url: str) -> Dict[str, Any]:
    """
    Follows redirects to find the final URL.
    Returns the redirect chain and the final URL.
    Hard timeout: 2 seconds — must not block Phase 1.
    """
    hops = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=10,
            timeout=httpx.Timeout(2.0)
        ) as client:
            response = await client.get(url)

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

    except httpx.TimeoutException:
        logger.warning(f"Redirect tracing timed out for {url}, using original URL")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}]
        }
    except httpx.HTTPError as e:
        logger.error(f"Tracing failed for {url}: {e}")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}]
        }
