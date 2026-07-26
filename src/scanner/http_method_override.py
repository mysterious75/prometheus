"""HTTP Method Override Scanner — tests for method-based access control bypasses.

Tests:
- X-HTTP-Method-Override header
- X-Method-Override header
- _method query parameter
- HTTP method cycling (PUT/PATCH/DELETE/OPTIONS/TRACE)
- Method override via query string
"""

from __future__ import annotations

from typing import List, Dict
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# Override headers to test
OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "GET"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Method-Override", "GET"),
    ("X-Method-Override", "PUT"),
    ("X-HTTP-Method", "GET"),
    ("X-HTTP-Method", "DELETE"),
    ("X-Original-Method", "GET"),
    ("X-Rewrite-Method", "GET"),
]

# Query parameter overrides
OVERRIDE_PARAMS = [
    "_method",
    "method",
    "_http_method",
    "httpMethod",
    "_action",
]

# Methods to cycle through
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT"]


class HttpMethodOverrideScanner:
    """Tests for HTTP method override vulnerabilities."""

    NAME = "http_method_override"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for HTTP method override vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=True, timeout=self.timeout, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

        try:
            # Get baseline
            self.limiter.wait(host)
            try:
                baseline = client.get(url)
                baseline_status = baseline.status_code
                baseline_len = len(baseline.content)
                baseline_body = baseline.text[:500]
            except Exception:
                baseline_status = 0
                baseline_len = 0
                baseline_body = ""

            # Test 1: Override headers on blocked request
            for header_name, header_value in OVERRIDE_HEADERS:
                self.limiter.wait(host)
                try:
                    resp = client.get(url, headers={header_name: header_value})
                    if self._is_different_response(resp, baseline_status, baseline_len, baseline_body):
                        findings.append(Finding(
                            vuln_type="HTTP Method Override",
                            title=f"Method override via {header_name}: {header_value}",
                            severity="HIGH" if baseline_status in (401, 403) else "MEDIUM",
                            url=url,
                            method="GET",
                            payload=f"{header_name}: {header_value}",
                            evidence=f"Status: {baseline_status}→{resp.status_code}, Size: {baseline_len}→{len(resp.content)}B",
                            description=f"Header {header_name}: {header_value} bypasses access control.",
                            remediation="Ignore method override headers. Enforce access control on actual HTTP method.",
                            cvss=7.5, cwe="CWE-287",
                            tool=self.NAME, verified=True, confidence="HIGH",
                            request=f'curl -k -H "{header_name}: {header_value}" "{url}"',
                        ))
                except Exception:
                    pass

            # Test 2: Query parameter method override
            for param in OVERRIDE_PARAMS:
                for method in ["GET", "PUT", "DELETE"]:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={method}"
                    self.limiter.wait(host)
                    try:
                        resp = client.get(test_url)
                        if self._is_different_response(resp, baseline_status, baseline_len, baseline_body):
                            findings.append(Finding(
                                vuln_type="HTTP Method Override",
                                title=f"Method override via ?{param}={method}",
                                severity="HIGH",
                                url=test_url,
                                method="GET",
                                payload=f"{param}={method}",
                                evidence=f"Status: {baseline_status}→{resp.status_code}",
                                description=f"Query parameter {param}={method} overrides HTTP method.",
                                remediation="Remove method override support. Use actual HTTP methods.",
                                cvss=7.5, cwe="CWE-287",
                                tool=self.NAME, verified=True, confidence="HIGH",
                            ))
                    except Exception:
                        pass

            # Test 3: HTTP method cycling
            for method in METHODS:
                if method == "GET":
                    continue
                self.limiter.wait(host)
                try:
                    resp = client.request(method, url)
                    if resp.status_code not in (401, 403, 405, 404, 501):
                        if baseline_status in (401, 403) and resp.status_code == 200:
                            findings.append(Finding(
                                vuln_type="HTTP Method Override",
                                title=f"HTTP {method} bypasses access control",
                                severity="HIGH",
                                url=url,
                                method=method,
                                evidence=f"GET returned {baseline_status}, {method} returned {resp.status_code}",
                                description=f"HTTP {method} method bypasses access control that blocks GET.",
                                remediation="Enforce access control on all HTTP methods.",
                                cvss=7.5, cwe="CWE-287",
                                tool=self.NAME, verified=True, confidence="HIGH",
                                request=f'curl -k -X {method} "{url}"',
                            ))
                except Exception:
                    pass

            # Test 4: Combined — override header + different base method
            for method in ["POST", "PUT", "PATCH"]:
                for header_name, header_value in OVERRIDE_HEADERS[:3]:
                    self.limiter.wait(host)
                    try:
                        resp = client.request(method, url, headers={header_name: header_value})
                        if self._is_different_response(resp, baseline_status, baseline_len, baseline_body):
                            findings.append(Finding(
                                vuln_type="HTTP Method Override",
                                title=f"{method} + {header_name}: {header_value} bypass",
                                severity="HIGH",
                                url=url,
                                method=method,
                                payload=f"{header_name}: {header_value}",
                                evidence=f"Status: {baseline_status}→{resp.status_code}",
                                description=f"HTTP {method} with {header_name}: {header_value} bypasses access control.",
                                remediation="Ignore method override headers. Validate actual HTTP method.",
                                cvss=7.5, cwe="CWE-287",
                                tool=self.NAME, verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

        finally:
            client.close()

        logger.info(f"HTTP method override scan: {len(findings)} findings")
        return findings

    def _is_different_response(self, resp, baseline_status: int, baseline_len: int, baseline_body: str) -> bool:
        """Check if response differs from baseline in a meaningful way."""
        status = resp.status_code
        content_len = len(resp.content)

        # Status changed from blocked to allowed
        if baseline_status in (401, 403) and status not in (401, 403, 0, 405, 404, 501):
            return True

        # Same status but significantly different content
        if baseline_status == status and baseline_len > 0:
            if content_len > baseline_len * 1.5 or content_len < baseline_len * 0.5:
                if content_len > 100:
                    return True

        return False


__all__ = ["HttpMethodOverrideScanner"]
