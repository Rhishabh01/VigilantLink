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
RENDER_WAIT_MS: int = 500

SCREENSHOT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


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
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
        )
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
            bypass_csp=True,
            user_agent=SCREENSHOT_USER_AGENT,
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

    async def _capture_one(self, url: str) -> Optional[str]:
        page = await self._context.new_page()
        try:
            try:
                await page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded")
            except Exception as e:
                logger.warning(
                    f"Navigation issue or timeout for {url}: {e}. "
                    "Capturing whatever loaded."
                )
            await page.wait_for_timeout(RENDER_WAIT_MS)
            screenshot_bytes = await page.screenshot(type="jpeg", quality=50)
            return f"data:image/jpeg;base64,{base64.b64encode(screenshot_bytes).decode('utf-8')}"
        finally:
            await page.close()

    async def capture_screenshot(self, url: str) -> Optional[str]:
        """
        Semaphore-gated screenshot capture with lightweight retry.

        Blocks if MAX_CONCURRENT_SCREENSHOTS pages are already in use.
        Returns base64-encoded JPEG string, or None on failure.

        IMPORTANT: Caller should wrap with asyncio.shield() to prevent
        cancellation when the user's request is aborted.
        """
        if not self._context:
            raise RuntimeError("BrowserPool not started")

        async with self._semaphore:
            for attempt in range(2):
                try:
                    result = await self._capture_one(url)
                    if result is not None:
                        return result
                except Exception as e:
                    if attempt == 0:
                        logger.warning(f"Screenshot attempt 1 failed for {url}: {e}. Retrying...")
                    else:
                        logger.warning(f"Screenshot failed for {url}: {e}")
                        return None
            return None


browser_pool = BrowserPool()
