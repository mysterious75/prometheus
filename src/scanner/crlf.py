"""CRLF Injection Scanner — detects HTTP header injection vulnerabilities.

Tests for:
- Response splitting via CRLF injection
- Log injection
- Header injection in redirects
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse, quote

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from .base import BaseScanner
from ..core.transport import ssl_verify


# CRLF payloads
CRLF_PAYLOADS = [
    ("%0d%0aInjected-Header: test", "Basic CRLF"),
    ("%0aInjected-Header: test", "LF only"),
    ("%0dInjected-Header: test", "CR only"),
    ("%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + XSS"),
    ("%5cr%5cnInjected-Header: test", "Encoded CRLF"),
    ("%E5%98%8D%E5%98%8AInjected-Header: test", "Unicode CRLF"),
    ("\r\nInjected-Header: test", "Raw CRLF"),
    ("%0d%0aLocation: http://evil.com", "CRLF redirect"),
    ("%0d%0aSet-Cookie: injected=true", "CRLF cookie injection"),
    ("%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>", "Full response split"),
]


class CRLFInjectionScanner(BaseScanner):
    """Detects CRLF injection vulnerabilities."""

    NAME = "crlf_injection"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for CRLF injection vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=ssl_verify(), timeout=self.timeout, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            # Get baseline
            self.limiter.wait(host)
            try:
                baseline = client.get(url)
                baseline_headers = set(k.lower() for k in baseline.headers.keys())
            except Exception:
                baseline_headers = set()

            # Test each CRLF payload in various injection points
            injection_points = [
                "url",      # In URL path
                "param",    # In query parameter
                "redirect", # In redirect parameter
            ]

            # Find parameters that might be injectable
            params_to_test = []
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        name = param.split("=")[0]
                        params_to_test.append(name)

            # Add common redirect parameters
            for rp in ["redirect", "url", "next", "return", "returnTo", "return_url",
                        "redirect_uri", "callback", "goto", "to", "link", "continue"]:
                if rp not in params_to_test:
                    params_to_test.append(rp)

            for payload, description in CRLF_PAYLOADS:
                # Test in URL path
                test_url = url.rstrip("/") + "/" + payload
                self.limiter.wait(host)
                try:
                    resp = client.get(test_url)
                    finding = self._check_crlf(resp, baseline_headers, payload, description, test_url, "URL path")
                    if finding:
                        findings.append(finding)
                except Exception:
                    pass

                # Test in query parameters
                for param in params_to_test[:5]:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={payload}"
                    self.limiter.wait(host)
                    try:
                        resp = client.get(test_url)
                        finding = self._check_crlf(resp, baseline_headers, payload, description, test_url, f"param:{param}")
                        if finding:
                            findings.append(finding)
                    except Exception:
                        pass

        finally:
            client.close()

        logger.info(f"CRLF injection scan: {len(findings)} findings")
        return findings

    def _check_crlf(self, resp, baseline_headers: set, payload: str, description: str, url: str, location: str) -> Finding:
        """Check if CRLF injection succeeded."""
        resp_headers = set(k.lower() for k in resp.headers.keys())

        # Check for injected header
        new_headers = resp_headers - baseline_headers
        if "injected-header" in new_headers:
            return Finding(
                vuln_type="CRLF Injection",
                title=f"CRLF injection: {description} ({location})",
                severity="HIGH",
                url=url,
                method="GET",
                payload=payload,
                evidence=f"Injected header 'Injected-Header' found in response",
                description=f"CRLF injection via {location}. Response splitting possible.",
                remediation="Sanitize user input. Remove CR/LF characters from all output.",
                cvss=7.5, cwe="CWE-93",
                tool=self.NAME, verified=True, confidence="HIGH",
                request=f'curl -k -i "{url}"',
            )

        # Check for XSS via CRLF
        if resp.status_code == 200:
            body = resp.text[:1000]
            if "<script>alert(1)</script>" in body:
                return Finding(
                    vuln_type="CRLF Injection",
                    title=f"CRLF + XSS via {location}: {description}",
                    severity="CRITICAL",
                    url=url,
                    method="GET",
                    payload=payload,
                    evidence="XSS payload reflected via CRLF injection",
                    description=f"CRLF injection allows XSS via response splitting in {location}.",
                    remediation="Sanitize input. Never allow CR/LF in HTTP headers or redirects.",
                    cvss=9.1, cwe="CWE-93",
                    tool=self.NAME, verified=True, confidence="HIGH",
                )

        # Check for redirect injection
        location_header = resp.headers.get("location", "")
        if "evil.com" in location_header or "Injected" in location_header:
            return Finding(
                vuln_type="CRLF Injection",
                title=f"CRLF redirect injection via {location}",
                severity="HIGH",
                url=url,
                method="GET",
                payload=payload,
                evidence=f"Location header: {location_header}",
                description=f"CRLF injection modifies redirect Location header via {location}.",
                remediation="Validate redirect URLs. Remove CR/LF from Location headers.",
                cvss=7.5, cwe="CWE-93",
                tool=self.NAME, verified=True, confidence="HIGH",
            )

        return None


__all__ = ["CRLFInjectionScanner"]
