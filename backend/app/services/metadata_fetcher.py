import httpx
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

async def fetch_metadata(url: str):
    """
    Fast metadata extraction using raw HTTP requests.
    Attempts to find Open Graph tags and standard meta tags.
    Includes lightweight retry on failure.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    async def _try_fetch():
        async with httpx.AsyncClient(follow_redirects=True, timeout=3.0) as client:
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
                logger.warning(f"Metadata fetch attempt 1 failed for {url}: {e}. Retrying...")
            else:
                logger.warning(f"Metadata fetch failed for {url}: {e}")
                return None

    return None
