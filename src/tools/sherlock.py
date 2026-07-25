"""Sherlock Wrapper — username OSINT across 400+ platforms.

Falls back to HTTP-based username checking if sherlock binary is not installed.
"""

import time
import re
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class UsernameOSINT(BaseTool):
    """Wrapper around sherlock for username enumeration."""

    name = "sherlock"
    binary = "sherlock"
    description = "Username search across 400+ social platforms"

    # Fallback: top platforms with reliable profile detection
    FALLBACK_PLATFORMS = {
        "github": "https://github.com/{username}",
        "twitter": "https://x.com/{username}",
        "instagram": "https://www.instagram.com/{username}/",
        "reddit": "https://www.reddit.com/user/{username}",
        "youtube": "https://www.youtube.com/@{username}",
        "tiktok": "https://www.tiktok.com/@{username}",
        "linkedin": "https://www.linkedin.com/in/{username}",
        "medium": "https://medium.com/@{username}",
        "devto": "https://dev.to/{username}",
        "gitlab": "https://gitlab.com/{username}",
        "stackoverflow": "https://stackoverflow.com/users/?tab=Accounts&SearchTerm={username}",
        "hackerone": "https://hackerone.com/{username}",
        "bugcrowd": "https://bugcrowd.com/{username}",
        "tryhackme": "https://tryhackme.com/p/{username}",
        "hackthebox": "https://app.hackthebox.com/users/{username}",
        "keybase": "https://keybase.io/{username}",
        "twitch": "https://www.twitch.tv/{username}",
        "pinterest": "https://www.pinterest.com/{username}/",
        "telegram": "https://t.me/{username}",
        "discord": "https://discord.com/{username}",
    }

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Search for a username across platforms."""
        username = target.strip()

        if not self.installed:
            return self._fallback_scan(username)

        cmd = ["sherlock", username, "--print-found", "--timeout", "10"]

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 120))
        duration = time.time() - start

        findings = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if "[" in line and "+" in line:
                    # sherlock output format: [+] username: https://...
                    match = re.search(r'\[\+\]\s*(?:\w+):\s*(https?://\S+)', line)
                    if match:
                        url = match.group(1)
                        platform = url.split("//")[1].split("/")[0].split(".")[0]
                        findings.append({
                            "type": "username_found",
                            "platform": platform,
                            "url": url,
                            "username": username,
                        })

        return ToolResult(
            tool=self.name,
            target=username,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, username: str) -> ToolResult:
        """Fallback: check top platforms via HTTP."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=username,
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings = []
        start = time.time()
        client = httpx.Client(
            follow_redirects=True, timeout=8, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )

        for platform, url_template in self.FALLBACK_PLATFORMS.items():
            url = url_template.format(username=username)
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Filter out false positives
                    if any(fp in body for fp in ["not found", "doesn't exist", "page not found", "404"]):
                        continue
                    findings.append({
                        "type": "username_found",
                        "platform": platform,
                        "url": url,
                        "username": username,
                    })
            except Exception:
                continue

        duration = time.time() - start
        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=username,
            success=True,
            findings=findings,
            duration=duration,
        )
