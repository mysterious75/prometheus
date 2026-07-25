"""Nuclei Wrapper — template-based vulnerability scanner by ProjectDiscovery.

Falls back to built-in HTTP checks if nuclei binary is not installed.
"""

import json
import time
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class NucleiScanner(BaseTool):
    """Wrapper around the nuclei vulnerability scanner."""

    name = "nuclei"
    binary = "nuclei"
    description = "Template-based vulnerability scanner (12,000+ YAML templates)"

    def scan(
        self,
        target: str,
        severity: str = "critical,high,medium",
        templates: Optional[str] = None,
        tags: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        """Run nuclei against a target."""
        if not self.installed:
            return self._fallback_scan(target)

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-json",
            "-silent",
            "-no-color",
        ]
        if templates:
            cmd.extend(["-t", templates])
        if tags:
            cmd.extend(["-tags", tags])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        duration = time.time() - start

        findings = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    findings.append({
                        "type": entry.get("info", {}).get("name", "Unknown"),
                        "severity": entry.get("info", {}).get("severity", "info").upper(),
                        "url": entry.get("matched-at", target),
                        "template": entry.get("template-id", ""),
                        "description": entry.get("info", {}).get("description", ""),
                        "reference": entry.get("info", {}).get("reference", []),
                        "matcher_name": entry.get("matcher-name", ""),
                        "extracted": entry.get("extracted-results", []),
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

    def _fallback_scan(self, target: str) -> ToolResult:
        """Built-in HTTP checks when nuclei is not installed."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings = []
        start = time.time()

        # Check common sensitive paths
        sensitive_paths = [
            ("/.env", "Environment file exposed", "HIGH"),
            ("/.git/config", "Git repository exposed", "HIGH"),
            ("/robots.txt", "Robots.txt disclosure", "INFO"),
            ("/.htaccess", "Htaccess file exposed", "MEDIUM"),
            ("/server-status", "Server status page", "MEDIUM"),
            ("/phpinfo.php", "PHP info exposed", "MEDIUM"),
            ("/wp-admin/", "WordPress admin accessible", "MEDIUM"),
            ("/admin/", "Admin panel accessible", "MEDIUM"),
            ("/api-docs", "API documentation exposed", "LOW"),
            ("/swagger.json", "Swagger spec exposed", "LOW"),
            ("/graphql", "GraphQL endpoint exposed", "LOW"),
            ("/.DS_Store", "DS_Store file exposed", "LOW"),
            ("/backup.sql", "Database backup exposed", "CRITICAL"),
            ("/sitemap.xml", "Sitemap disclosure", "INFO"),
        ]

        base = target.rstrip("/")
        client = httpx.Client(follow_redirects=True, timeout=8, verify=False)

        for path, desc, severity in sensitive_paths:
            try:
                resp = client.get(f"{base}{path}")
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Extra validation: check for actual content, not just error pages
                    body_lower = resp.text.lower()
                    if any(fp in body_lower for fp in ["404", "not found", "error"]):
                        continue
                    findings.append({
                        "type": "Information Disclosure",
                        "severity": severity,
                        "url": f"{base}{path}",
                        "description": desc,
                        "evidence": resp.text[:200],
                        "status_code": resp.status_code,
                    })
            except Exception:
                continue

        # Check security headers
        try:
            resp = client.get(base)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            missing_headers = []
            for h in [
                "x-frame-options", "x-content-type-options",
                "strict-transport-security", "content-security-policy",
                "x-xss-protection", "referrer-policy",
            ]:
                if h not in headers:
                    missing_headers.append(h)
            if missing_headers:
                findings.append({
                    "type": "Missing Security Headers",
                    "severity": "LOW",
                    "url": base,
                    "description": f"Missing headers: {', '.join(missing_headers)}",
                    "missing": missing_headers,
                })
        except Exception:
            pass

        duration = time.time() - start
        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )
