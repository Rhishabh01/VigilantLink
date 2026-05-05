from playwright.async_api import async_playwright, Browser, BrowserContext
import base64
import logging
import io
from PIL import Image
from app.utils.security import is_safe_url

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
            args=["--disable-gpu", "--disable-dev-shm-usage"]
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
        if not await is_safe_url(url):
            raise ValueError('Access to internal network prohibited')

        if not self.context:
            raise RuntimeError("Browser pool is not initialized")
        
        page = await self.context.new_page()
        try:
            # Navigate with a timeout to avoid hanging on bad sites
            await page.goto(url, timeout=10000, wait_until="domcontentloaded")
        except Exception as e:
            logger.warning(f"Navigation issue or timeout for {url}: {e}. Capturing whatever loaded.")
            
        try:
            # Wait a brief moment to allow dynamic content (React/Vue) to render
            await page.wait_for_timeout(500)
            
            # Capture raw screenshot
            screenshot_bytes = await page.screenshot()
            
            # Process with Pillow: max width 800px, JPEG quality 60
            img = Image.open(io.BytesIO(screenshot_bytes))
            
            # Convert RGBA to RGB if needed (screenshot might be PNG/RGBA)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
                
            if img.width > 800:
                ratio = 800 / float(img.width)
                new_height = int(float(img.height) * float(ratio))
                img = img.resize((800, new_height), Image.Resampling.LANCZOS)
                
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=60)
            compressed_bytes = buffer.getvalue()
            
            base64_img = base64.b64encode(compressed_bytes).decode('utf-8')
            return f"data:image/jpeg;base64,{base64_img}"
        except Exception as e:
            logger.error(f"Screenshot completely failed for {url}: {e}")
            return "" # Return empty if screenshot fails but analysis continues
        finally:
            await page.close()

browser_pool = BrowserPool()
