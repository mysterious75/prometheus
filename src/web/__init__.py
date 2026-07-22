"""Web Fetcher - Anti-bot web access using Hound MCP."""

import asyncio
from typing import Dict, Any, Optional
from pathlib import Path

from ..utils.logger import logger


class WebFetcher:
    """Anti-bot web fetcher using Hound MCP. Free, no API keys."""

    def __init__(self):
        self.hound = None
        self._init_hound()

    def _init_hound(self):
        """Initialize Hound MCP client."""
        try:
            from hound_mcp.tools import web_fetch, web_search, web_crawl, web_screenshot
            self.web_fetch = web_fetch
            self.web_search = web_search
            self.web_crawl = web_crawl
            self.web_screenshot = web_screenshot
            self.available = True
            logger.info("[green]Hound MCP initialized (anti-bot fetcher)[/green]")
        except ImportError:
            self.available = False
            logger.warning("[yellow]Hound MCP not available, using fallback[/yellow]")
        except Exception as e:
            self.available = False
            logger.warning(f"[yellow]Hound init failed: {e}[/yellow]")

    async def fetch(self, url: str) -> Dict[str, Any]:
        """Fetch a URL with anti-bot protection."""
        if self.available:
            try:
                result = await self.web_fetch(url=url)
                return {"url": url, "content": result, "source": "hound", "status": "ok"}
            except Exception as e:
                logger.warning(f"Hound fetch failed: {e}")

        # Fallback: httpx with stealth headers
        return await self._fallback_fetch(url)

    async def search(self, query: str, num_results: int = 5) -> Dict[str, Any]:
        """Search the web using 10 keyless backends."""
        if self.available:
            try:
                result = await self.web_search(query=query, num_results=num_results)
                return {"query": query, "results": result, "source": "hound"}
            except Exception as e:
                logger.warning(f"Hound search failed: {e}")

        return await self._fallback_search(query, num_results)

    async def crawl(self, url: str, max_pages: int = 10) -> Dict[str, Any]:
        """Crawl a site (best-first walk, same domain)."""
        if self.available:
            try:
                result = await self.web_crawl(url=url, max_pages=max_pages)
                return {"url": url, "pages": result, "source": "hound"}
            except Exception as e:
                logger.warning(f"Hound crawl failed: {e}")

        return {"url": url, "pages": [], "source": "fallback", "error": "Crawl not available"}

    async def screenshot(self, url: str) -> Dict[str, Any]:
        """Take anti-bot screenshot."""
        if self.available:
            try:
                result = await self.web_screenshot(url=url)
                return {"url": url, "screenshot": result, "source": "hound"}
            except Exception as e:
                logger.warning(f"Hound screenshot failed: {e}")

        return {"url": url, "screenshot": None, "source": "fallback", "error": "Screenshot not available"}

    async def _fallback_fetch(self, url: str) -> Dict[str, Any]:
        """Fallback fetch with stealth headers."""
        import httpx
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
                resp = await client.get(url, headers=headers)
                return {
                    "url": url,
                    "content": resp.text[:5000],
                    "status_code": resp.status_code,
                    "source": "httpx_stealth",
                    "status": "ok"
                }
        except Exception as e:
            return {"url": url, "content": "", "source": "fallback", "error": str(e), "status": "failed"}

    async def _fallback_search(self, query: str, num: int = 5) -> Dict[str, Any]:
        """Fallback search using DuckDuckGo."""
        import httpx
        url = f"https://html.duckduckgo.com/html/?q={query}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
                resp = await client.get(url, headers=headers)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                results = []
                for r in soup.select(".result")[:num]:
                    title = r.select_one(".result__a")
                    snippet = r.select_one(".result__snippet")
                    if title:
                        results.append({
                            "title": title.get_text(strip=True),
                            "url": title.get("href", ""),
                            "snippet": snippet.get_text(strip=True) if snippet else ""
                        })
                return {"query": query, "results": results, "source": "duckduckgo"}
        except Exception as e:
            return {"query": query, "results": [], "source": "fallback", "error": str(e)}

    def fetch_sync(self, url: str) -> Dict[str, Any]:
        """Synchronous fetch wrapper."""
        return asyncio.run(self.fetch(url))

    def search_sync(self, query: str, num: int = 5) -> Dict[str, Any]:
        """Synchronous search wrapper."""
        return asyncio.run(self.search(query, num))
