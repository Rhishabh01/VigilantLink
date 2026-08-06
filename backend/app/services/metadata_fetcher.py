import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from ..core.logging import get_logger
from ..utils.url_validator import resolve_and_validate

logger = get_logger("VigilantLink")

async def fetch_metadata(url: str):
    """
    Fast metadata extraction using raw HTTP requests.
    Attempts to find Open Graph tags and standard meta tags.
    Includes lightweight retry on failure.

    SSRF Protection:
      - Pre-validates URL's resolved IP before any outbound connection.
    """
    # SSRF check before any outbound request
    is_safe, _, reason = resolve_and_validate(url)
    if not is_safe:
        logger.warning(f"[SSRF] Blocked metadata fetch for {url[:80]}: {reason}")
        return None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    from ..utils.url_validator import is_ip_blocked

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

    async def _try_fetch():
        async with httpx.AsyncClient(
            follow_redirects=True, 
            timeout=3.0,
            event_hooks={"response": [_check_ssrf]}
        ) as client:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    return None

                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    return None

                content = b""
                async for chunk in response.aiter_bytes(chunk_size=1024):
                    content += chunk
                    if len(content) > 65536:
                        break

                html = content.decode("utf-8", errors="ignore")
                soup = BeautifulSoup(html, "html.parser")

                title = (
                    soup.find("meta", attrs={"property": "og:title"}) or
                    soup.find("meta", attrs={"name": "twitter:title"}) or
                    soup.title
                )
                if title:
                    title = title.get("content", title.string) if hasattr(title, "get") else title.string

                description = (
                    soup.find("meta", attrs={"property": "og:description"}) or
                    soup.find("meta", attrs={"name": "twitter:description"}) or
                    soup.find("meta", attrs={"name": "description"})
                )
                if description:
                    description = description.get("content", "")

                image = (
                    soup.find("meta", attrs={"property": "og:image"}) or
                    soup.find("meta", attrs={"name": "twitter:image"}) or
                    soup.find("link", attrs={"rel": "image_src"})
                )
                if image:
                    image_url = image.get("content", "") or image.get("href", "")
                    if image_url:
                        image_url = urljoin(url, image_url)
                else:
                    image_url = None

                favicon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
                favicon_url = None
                if favicon:
                    favicon_url = urljoin(url, favicon.get("href", ""))

                if not title and not description and not image_url:
                    return None

                return {
                    "title": title.strip() if title else None,
                    "description": description.strip() if description else None,
                    "image_url": image_url,
                    "favicon_url": favicon_url,
                }

    for attempt in range(2):
        try:
            result = await _try_fetch()
            if result is not None:
                return result
        except Exception as e:
            if attempt == 0:
                logger.debug(f"[METADATA] Fetch attempt 1 failed for {url[:50]}...: {e}. Retrying...")
            else:
                logger.debug(f"[METADATA] Fetch failed for {url[:50]}...: {e}")
                return None

    return None
