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

    from ..utils.url_validator import is_ip_blocked, resolve_and_validate

    async def _check_ssrf(response: httpx.Response) -> None:
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
                    pass

        # 2. Redirect destination verification
        if response.is_redirect:
            next_url = response.headers.get("location", "")
            if next_url:
                next_url = str(response.url.join(next_url))
                is_safe, _, reason = resolve_and_validate(next_url)
                if not is_safe:
                    raise httpx.ConnectError(
                        f"SSRF: redirect to private IP blocked ({next_url[:80]}): {reason}",
                        request=response.request,
                    )

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(RDAP_TIMEOUT_S),
            event_hooks={"response": [_check_ssrf]}
        ) as client:
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
