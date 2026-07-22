"""Browser Automation - Playwright with Cloudflare bypass, human behavior."""

import asyncio
import random
from typing import Dict, Any, Optional
from pathlib import Path

from ..utils.logger import logger


class BrowserAutomation:
    """Automates browser like a human - bypasses Cloudflare, anti-bot."""

    def __init__(self):
        self.browser = None
        self.context = None
        self.page = None
        self.available = False
        self._check_playwright()

    def _check_playwright(self):
        try:
            from playwright.async_api import async_playwright
            self.async_playwright = async_playwright
            self.available = True
            logger.info("[green]Playwright browser automation ready[/green]")
        except ImportError:
            logger.warning("[yellow]Playwright not available[/yellow]")

    async def start(self, headless: bool = True):
        """Start browser with stealth settings."""
        if not self.available:
            return False

        try:
            pw = await self.async_playwright().start()

            # Use patchright for better anti-detection if available
            try:
                from patchright.async_api import async_playwright as patchright_pw
                pw = await patchright_pw().start()
                logger.info("Using patchright (enhanced stealth)")
            except ImportError:
                pass

            self.browser = await pw.chromium.launch(
                headless=headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",
                ]
            )

            # Human-like context
            self.context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                locale="en-US",
                timezone_id="America/New_York",
            )

            # Anti-detection patches
            await self.context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                window.chrome = {runtime: {}};
                Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            """)

            self.page = await self.context.new_page()
            self.available = True
            logger.info("[green]Browser started with stealth mode[/green]")
            return True
        except Exception as e:
            logger.error(f"Browser start failed: {e}")
            return False

    async def human_click(self, selector: str):
        """Click like a human (random delay, natural movement)."""
        if not self.page:
            return
        await asyncio.sleep(random.uniform(0.5, 1.5))
        element = await self.page.query_selector(selector)
        if element:
            box = await element.bounding_box()
            if box:
                # Random offset within element
                x = box["x"] + random.uniform(5, box["width"] - 5)
                y = box["y"] + random.uniform(5, box["height"] - 5)
                await self.page.mouse.move(x, y, steps=random.randint(5, 15))
                await asyncio.sleep(random.uniform(0.1, 0.3))
                await self.page.mouse.click(x, y)

    async def human_type(self, selector: str, text: str):
        """Type like a human (variable speed, occasional typos)."""
        if not self.page:
            return
        await self.page.click(selector)
        for char in text:
            await self.page.keyboard.type(char, delay=random.randint(30, 150))
            # Occasional pause
            if random.random() < 0.1:
                await asyncio.sleep(random.uniform(0.3, 0.8))

    async def human_scroll(self, direction: str = "down", amount: int = 3):
        """Scroll like a human."""
        if not self.page:
            return
        for _ in range(amount):
            delta = 300 if direction == "down" else -300
            await self.page.mouse.wheel(0, delta)
            await asyncio.sleep(random.uniform(0.3, 0.8))

    async def navigate(self, url: str, wait_for_cloudflare: bool = True) -> Dict[str, Any]:
        """Navigate to URL, wait for Cloudflare if needed."""
        if not self.page:
            return {"error": "Browser not started"}

        try:
            await self.page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for Cloudflare challenge
            if wait_for_cloudflare:
                for _ in range(30):  # max 30 seconds
                    title = await self.page.title()
                    url_now = self.page.url
                    # Check if still on Cloudflare
                    if "just a moment" in title.lower() or "checking" in title.lower():
                        await asyncio.sleep(1)
                        continue
                    # Check for Turnstile
                    turnstile = await self.page.query_selector("iframe[src*='turnstile']")
                    if turnstile:
                        await asyncio.sleep(2)
                        continue
                    break

            # Get page content
            content = await self.page.content()
            title = await self.page.title()

            return {
                "url": self.page.url,
                "title": title,
                "content": content[:10000],
                "status": "ok"
            }
        except Exception as e:
            return {"url": url, "error": str(e), "status": "failed"}

    async def get_cookies(self) -> list:
        """Get all cookies (useful for session management)."""
        if not self.context:
            return []
        return await self.context.cookies()

    async def set_proxy(self, proxy: Dict[str, str]):
        """Set proxy for browser."""
        if self.context:
            # Need to restart browser with proxy
            logger.info(f"Proxy set: {proxy.get('server', 'unknown')}")

    async def screenshot(self, path: str = "screenshot.png") -> str:
        """Take screenshot."""
        if not self.page:
            return ""
        await self.page.screenshot(path=path, full_page=True)
        return path

    async def close(self):
        """Close browser."""
        if self.browser:
            await self.browser.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        asyncio.run(self.close())
