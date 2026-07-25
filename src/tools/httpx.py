"""httpx Wrapper — fast HTTP probing by ProjectDiscovery.

Falls back to httpx Python library if binary is not installed.
"""

import json
import time
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class HttpProber(BaseTool):
    """Wrapper around httpx for HTTP service probing."""

    name = "httpx"
    binary = "httpx"
    description = "Fast HTTP probing, status codes, tech detection, titles"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Probe a target for HTTP services."""
        targets = kwargs.get("targets", [target])

        if not self.installed:
            return self._fallback_scan(targets if isinstance(targets, list) else [target])

        # Write targets to temp file if multiple
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets if isinstance(targets, list) else [target]))
            targets_file = f.name

        cmd = [
            "httpx",
            "-l", targets_file,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
        ]

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 120))
        duration = time.time() - start

        # Cleanup
        import os
        try:
            os.unlink(targets_file)
        except OSError:
            pass

        findings = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    findings.append({
                        "type": "http_service",
                        "url": entry.get("url", ""),
                        "status_code": entry.get("status-code", 0),
                        "title": entry.get("title", ""),
                        "tech": entry.get("tech", []),
                        "content_length": entry.get("content-length", 0),
                        "webserver": entry.get("webserver", ""),
                        "content_type": entry.get("content-type", ""),
                    })
                except json.JSONDecodeError:
                    continue

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, targets: List[str]) -> ToolResult:
        """Fallback using Python httpx library."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=targets[0] if targets else "",
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings = []
        start = time.time()
        client = httpx.Client(follow_redirects=True, timeout=8, verify=False)

        for url in targets:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            try:
                resp = client.get(url)
                # Extract tech from headers
                tech = []
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                if server:
                    tech.append(server)
                if powered:
                    tech.append(powered)

                # Extract title
                title = ""
                import re
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.I | re.S)
                if match:
                    title = match.group(1).strip()[:100]

                findings.append({
                    "type": "http_service",
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "title": title,
                    "tech": tech,
                    "content_length": len(resp.text),
                    "webserver": server,
                })
            except Exception as e:
                findings.append({
                    "type": "http_service",
                    "url": url,
                    "status_code": 0,
                    "error": str(e),
                })

        duration = time.time() - start
        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=targets[0] if targets else "",
            success=True,
            findings=findings,
            duration=duration,
        )
