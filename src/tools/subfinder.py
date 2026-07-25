"""Subfinder Wrapper — passive subdomain enumeration by ProjectDiscovery.

Falls back to crt.sh + DNS brute force if subfinder binary is not installed.
"""

import json
import time
import socket
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class SubdomainEnumerator(BaseTool):
    """Wrapper around subfinder for passive subdomain enumeration."""

    name = "subfinder"
    binary = "subfinder"
    description = "Passive subdomain enumeration (40+ sources)"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Enumerate subdomains for a target domain."""
        if not self.installed:
            return self._fallback_scan(target)

        cmd = [
            "subfinder",
            "-d", target,
            "-silent",
            "-all",  # use all sources
        ]
        if kwargs.get("recursive"):
            cmd.append("-recursive")

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 120))
        duration = time.time() - start

        subdomains = []
        if result.returncode == 0 and result.stdout:
            subdomains = [
                line.strip() for line in result.stdout.strip().split("\n")
                if line.strip()
            ]

        findings = [{"type": "subdomain", "value": sub} for sub in subdomains]

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, domain: str) -> ToolResult:
        """Fallback: crt.sh certificate transparency + common subdomain brute force."""
        import httpx

        subdomains = set()
        start = time.time()

        # Method 1: crt.sh certificate transparency
        try:
            client = httpx.Client(timeout=15, verify=False)
            resp = client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")

        # Method 2: Common subdomain brute force via DNS
        common = [
            "www", "mail", "ftp", "smtp", "api", "dev", "staging", "test",
            "admin", "beta", "app", "cdn", "blog", "shop", "portal", "vpn",
            "webmail", "cpanel", "ns1", "ns2", "mx", "docs", "git", "jenkins",
            "grafana", "kibana", "dashboard", "status", "monitor", "backup",
            "old", "new", "static", "media", "img", "images", "assets",
        ]
        for sub in common:
            try:
                hostname = f"{sub}.{domain}"
                socket.setdefaulttimeout(2)
                ip = socket.gethostbyname(hostname)
                subdomains.add(hostname)
            except (socket.gaierror, socket.timeout):
                pass

        duration = time.time() - start
        findings = [{"type": "subdomain", "value": sub} for sub in sorted(subdomains)]

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=domain,
            success=True,
            findings=findings,
            duration=duration,
        )
