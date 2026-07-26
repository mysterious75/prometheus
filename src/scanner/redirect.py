"""Redirect Scanner — open redirect detection."""

from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .findings import Finding
from ..core.ratelimit import get_limiter


class RedirectScanner:
    """Tests for open redirect vulnerabilities."""

    NAME = "redirect"

    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "///evil.com",
        "https://evil.com%00.target.com",
        "javascript:alert(1)",
        "//evil.com/%2f..",
        "/%09/evil.com",
        "/evil.com/..;/",
    ]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test for open redirect."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"url": "https://example.com", "redirect": "https://example.com",
                          "next": "https://example.com", "return": "https://example.com",
                          "returnTo": "https://example.com", "dest": "https://example.com"}

        client = httpx.Client(follow_redirects=False, timeout=10, verify=True)

        for param_name in test_params:
            for payload in self.PAYLOADS:
                test_params_copy = dict(test_params)
                test_params_copy[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)
                    location = resp.headers.get("Location", "")

                    if resp.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in location or payload in location:
                            findings.append(Finding(
                                vuln_type="Open Redirect",
                                title=f"Open redirect via parameter '{param_name}'",
                                severity="MEDIUM",
                                url=url,
                                parameter=param_name,
                                method="GET",
                                payload=payload,
                                evidence=f"Redirect to: {location}",
                                description=f"Parameter '{param_name}' allows redirect to external domains.",
                                remediation="Validate redirect URLs against a whitelist of allowed domains.",
                                cvss=6.1,
                                cwe="CWE-601",
                                tool=self.NAME,
                                verified=True,
                                confidence="HIGH",
                            ))
                            return findings

                except Exception:
                    continue

        return findings
