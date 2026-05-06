from playwright.async_api import async_playwright, Browser, BrowserContext
import base64
import logging

logger = logging.getLogger(__name__)

class BrowserPool:
    def __init__(self):
        self.playwright = None
        self.browser: Browser = None
        self.context: BrowserContext = None

    async def start(self):
        logger.info("Starting Playwright Browser Pool...")
        self.playwright = await async_playwright().start()
        # Launch chromium; args optimized for performance/isolation in Docker
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )
        self.context = await self.browser.new_context(
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
            bypass_csp=True # Useful for strictly rendering visually
        )

    async def stop(self):
        logger.info("Stopping Playwright Browser Pool...")
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def capture_screenshot(self, url: str) -> str:
        if not self.context:
            raise RuntimeError("Browser pool is not initialized")
        
        page = await self.context.new_page()
        try:
            # Navigate with a timeout to avoid hanging on bad sites
            await page.goto(url, timeout=7000, wait_until="domcontentloaded")
        except Exception as e:
            logger.warning(f"Navigation issue or timeout for {url}: {e}. Capturing whatever loaded.")
            
        try:
            # Wait a brief moment to allow dynamic content (React/Vue) to render
            await page.wait_for_timeout(200)
            
            # Capture screenshot as JPEG for smaller payload
            screenshot_bytes = await page.screenshot(type="jpeg", quality=50)
            
            base64_img = base64.b64encode(screenshot_bytes).decode('utf-8')
            return f"data:image/jpeg;base64,{base64_img}"
        except Exception as e:
            logger.error(f"Screenshot completely failed for {url}: {e}")
            return "" # Return empty if screenshot fails but analysis continues
        finally:
            await page.close()

browser_pool = BrowserPool()
