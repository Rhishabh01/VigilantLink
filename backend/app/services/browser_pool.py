"""
Browser Pool: Semaphore-gated Playwright screenshot capture.

Resource Management:
  - Semaphore(MAX_CONCURRENT_SCREENSHOTS) prevents OOM from too many browser pages.
  - Callers should wrap with asyncio.shield() so screenshots complete
    even if the user's HTTP request is cancelled (mouse moved away).
"""

import asyncio
import base64
import logging
from typing import Optional

from playwright.async_api import async_playwright, Browser, BrowserContext

from ..core.constants import MAX_CONCURRENT_SCREENSHOTS

logger = logging.getLogger(__name__)

PAGE_TIMEOUT_MS: int = 7000
RENDER_WAIT_MS: int = 200


class BrowserPool:
    """
    Semaphore-gated Playwright pool.
    At most MAX_CONCURRENT_SCREENSHOTS pages open simultaneously.
    """

    def __init__(self) -> None:
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCREENSHOTS)
        self._started: bool = False

    async def start(self) -> None:
        if self._started:
            return
        logger.info(f"Starting BrowserPool (max_concurrent={MAX_CONCURRENT_SCREENSHOTS})")
        self._playwright = await async_playwright().start()
        # Launch chromium; args optimized for performance/isolation in Docker
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
        )
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
            bypass_csp=True,  # Useful for strictly rendering visually
        )
        self._started = True

    async def stop(self) -> None:
        logger.info("Stopping BrowserPool...")
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._started = False

    async def capture_screenshot(self, url: str) -> Optional[str]:
        """
        Semaphore-gated screenshot capture.

        Blocks if MAX_CONCURRENT_SCREENSHOTS pages are already in use.
        Returns base64-encoded JPEG string, or None on failure.

        IMPORTANT: Caller should wrap with asyncio.shield() to prevent
        cancellation when the user's request is aborted.
        """
        if not self._context:
            raise RuntimeError("BrowserPool not started")

        async with self._semaphore:
            page = await self._context.new_page()
            try:
                # Navigate with a timeout to avoid hanging on bad sites
                try:
                    await page.goto(
                        url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded"
                    )
                except Exception as e:
                    logger.warning(
                        f"Navigation issue or timeout for {url}: {e}. "
                        "Capturing whatever loaded."
                    )

                # Wait a brief moment to allow dynamic content (React/Vue) to render
                await page.wait_for_timeout(RENDER_WAIT_MS)

                # Capture screenshot as JPEG for smaller payload
                screenshot_bytes = await page.screenshot(type="jpeg", quality=50)
                base64_img = base64.b64encode(screenshot_bytes).decode("utf-8")
                return f"data:image/jpeg;base64,{base64_img}"

            except Exception as e:
                logger.error(f"Screenshot completely failed for {url}: {e}")
                return None
            finally:
                await page.close()


browser_pool = BrowserPool()
