import httpx
from typing import Dict, Any
from urllib.parse import urlparse

from ..core.logging import get_logger
from ..utils.url_validator import resolve_and_validate, validate_redirect_target

logger = get_logger("VigilantLink")

async def trace_url(url: str) -> Dict[str, Any]:
    """
    Follows redirects to find the final URL.
    Returns the redirect chain, the final URL, and if there's an SSL error.
    Hard timeout: 2 seconds — must not block Phase 1.

    SSRF Protection:
      - Pre-validates the initial URL's resolved IP before connecting.
      - Re-validates every redirect hop via event_hooks to block redirect-based SSRF.
    """
    hops = []

    # Pre-validate initial URL before any outbound connection
    is_safe, _, reason = resolve_and_validate(url)
    if not is_safe:
        logger.warning(f"[SSRF] Blocked trace_url for {url[:80]}: {reason}")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}],
            "ssl_error": False,
            "ssrf_blocked": True,
        }

    from ..utils.url_validator import is_ip_blocked

    async def _check_redirect(response: httpx.Response) -> None:
        """Event hook: re-validate each redirect destination and connection peername to prevent SSRF/DNS Rebinding."""
        # 1. Connection-level Peer IP verification (defends against DNS Rebinding)
        stream = response.extensions.get("network_stream")
        if stream:
            sock = stream.get_extra_info("socket")
            if sock:
                try:
                    peer_ip, _ = sock.getpeername()
                    if is_ip_blocked(peer_ip):
                        raise httpx.ConnectError(
                            f"SSRF/DNS Rebinding: connection to private IP blocked ({peer_ip})",
                            request=response.request,
                        )
                except OSError:
                    pass  # Socket might be closed/unreadable

        # 2. Redirect URL verification
        if response.is_redirect:
            next_url = response.headers.get("location", "")
            if next_url:
                # Resolve relative redirects
                next_url = str(response.url.join(next_url))
                if not validate_redirect_target(next_url):
                    raise httpx.TooManyRedirects(
                        f"SSRF: redirect to private IP blocked ({next_url[:80]})",
                        request=response.request,
                    )

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=10,
            timeout=httpx.Timeout(2.0),
            event_hooks={"response": [_check_redirect]},
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
                "hops": hops,
                "ssl_error": False
            }

    except httpx.TooManyRedirects as e:
        if "SSRF" in str(e):
            logger.warning(f"[SSRF] Redirect chain blocked for {url[:80]}: {e}")
            return {
                "final_url": url,
                "hops": [{"url": url, "status_code": 0}],
                "ssl_error": False,
                "ssrf_blocked": True,
            }
        logger.warning(f"Too many redirects for {url[:80]}")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}],
            "ssl_error": False
        }
    except httpx.TimeoutException:
        logger.warning(f"Redirect tracing timed out for {url[:80]}, using original URL")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}],
            "ssl_error": False
        }
    except httpx.ConnectError as e:
        logger.warning(f"Connection error (possible SSL) for {url[:80]}: {e}")
        # Check if it's an SSL error
        is_ssl = "SSL" in str(e) or "certificate verify failed" in str(e)
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}],
            "ssl_error": is_ssl
        }
    except httpx.HTTPError as e:
        logger.error(f"Tracing failed for {url[:80]}: {e}")
        return {
            "final_url": url,
            "hops": [{"url": url, "status_code": 0}],
            "ssl_error": False
        }
