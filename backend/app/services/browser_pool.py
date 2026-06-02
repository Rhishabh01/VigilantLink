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
from ..core.logging import get_logger
from ..utils.url_validator import resolve_and_validate

logger = get_logger("VigilantLink")

PAGE_TIMEOUT_MS: int = 15000
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
        self._lifecycle_lock = asyncio.Lock()
        self._screenshot_count = 0
        self._active_pages = 0
        self.MAX_SCREENSHOTS_BEFORE_RESTART = 40

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._started:
                return
            logger.info(f"[BROWSER] Starting pool (max_concurrent={MAX_CONCURRENT_SCREENSHOTS})")
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-gpu", 
                    "--no-sandbox", 
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-background-timer-throttling",
                    "--disable-backgrounding-occluded-windows",
                    "--disable-renderer-backgrounding",
                    "--js-flags=--max-old-space-size=256"
                ],
            )
            self._context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                device_scale_factor=1,
                # bypass_csp=True is required for screenshot capture.
                # Many websites use Content Security Policy headers that block
                # inline styles/scripts injected by Playwright during rendering,
                # which produces blank or broken screenshots. Since this browser
                # context is headless, isolated, and only used to render pages
                # for visual capture (never for user sessions or authentication),
                # the security impact is minimal.
                bypass_csp=True,
                user_agent=SCREENSHOT_USER_AGENT,
            )
            self._started = True
            self._screenshot_count = 0

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            if not self._started:
                return
            logger.info("[BROWSER] Stopping pool to release memory...")
            try:
                if self._context:
                    await self._context.close()
                if self._browser:
                    await self._browser.close()
                if self._playwright:
                    await self._playwright.stop()
            except Exception as e:
                logger.error(f"[BROWSER] Error during cleanup: {e}")
            finally:
                self._started = False
                self._context = None
                self._browser = None
                self._playwright = None

    async def _capture_one(self, url: str) -> Optional[str]:
        page = None
        try:
            page = await self._context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)
            
            try:
                await page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded")
            except Exception as e:
                logger.debug(
                    f"[BROWSER] Navigation issue for {url[:50]}...: {e}. "
                    "Capturing whatever loaded."
                )
            
            await page.wait_for_timeout(RENDER_WAIT_MS)
            screenshot_bytes = await page.screenshot(type="jpeg", quality=40)
            return f"data:image/jpeg;base64,{base64.b64encode(screenshot_bytes).decode('utf-8')}"
        finally:
            if page:
                try:
                    await page.close()
                except Exception as e:
                    logger.error(f"[BROWSER] Leaked page failed to close: {e}")

    async def capture_screenshot(self, url: str) -> Optional[str]:
        """
        Semaphore-gated screenshot capture with lightweight retry.

        Blocks if MAX_CONCURRENT_SCREENSHOTS pages are already in use.
        Returns base64-encoded JPEG string, or None on failure.

        IMPORTANT: Caller should wrap with asyncio.shield() to prevent
        cancellation when the user's request is aborted.
        """
        # Lazy-start: initialise Chromium on first use rather than at
        # server startup (which would block the event loop for several
        # seconds and cause Railway health-check timeouts).
        if not self._started:
            await self.start()

        if not self._context:
            raise RuntimeError("BrowserPool failed to start")

        # SSRF protection: validate URL before navigating browser
        is_safe, _, reason = resolve_and_validate(url)
        if not is_safe:
            logger.warning(f"[SSRF] Blocked screenshot for {url[:80]}: {reason}")
            return None

        async with self._semaphore:
            self._active_pages += 1
            logger.info(f"[BROWSER] Active pages: {self._active_pages}/{MAX_CONCURRENT_SCREENSHOTS}. Queued screenshots: {self._screenshot_count}/{self.MAX_SCREENSHOTS_BEFORE_RESTART}")
            try:
                for attempt in range(2):
                    try:
                        result = await asyncio.wait_for(self._capture_one(url), timeout=PAGE_TIMEOUT_MS / 1000 + 2.0)
                        if result is not None:
                            return result
                    except asyncio.TimeoutError:
                        logger.error(f"[BROWSER] Absolute timeout capturing {url[:50]}...")
                        return None
                    except Exception as e:
                        if attempt == 0:
                            logger.warning(f"[BROWSER] Screenshot attempt 1 failed for {url[:50]}...: {e}. Retrying...")
                        else:
                            logger.error(f"[BROWSER] Screenshot failed for {url[:50]}...: {e}")
                            return None
                return None
            finally:
                self._active_pages -= 1
                self._screenshot_count += 1
                
                # Browser Recycling Strategy to prevent RAM bloat
                if self._active_pages == 0 and self._screenshot_count >= self.MAX_SCREENSHOTS_BEFORE_RESTART:
                    logger.info("[BROWSER] Memory threshold reached. Recycling Chromium instance...")
                    asyncio.create_task(self._recycle_browser())

    async def _recycle_browser(self):
        """Reboots Chromium completely to purge RAM accumulation."""
        await self.stop()
        await self.start()


browser_pool = BrowserPool()
