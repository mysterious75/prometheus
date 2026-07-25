"""XSS Scanner — context-aware reflected XSS detection.

VALIDATION: Payload must be reflected AND unencoded in executable context.
"""

import re
from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .findings import Finding
from ..core.ratelimit import get_limiter


class XSSScanner:
    """Cross-Site Scripting scanner with context-aware detection."""

    NAME = "xss"

    # Context-specific payloads
    PAYLOADS = [
        # HTML context
        ('<script>alert(1)</script>', 'HTML', 'script tag injection'),
        ('<img src=x onerror=alert(1)>', 'HTML', 'event handler injection'),
        ('<svg onload=alert(1)>', 'HTML', 'SVG event injection'),
        ('<body onload=alert(1)>', 'HTML', 'body event injection'),
        # Attribute context
        ('" onfocus=alert(1) autofocus="', 'ATTR', 'attribute breakout'),
        ("' onfocus=alert(1) autofocus='", 'ATTR', 'single quote breakout'),
        # JS context
        ("'-alert(1)-'", 'JS', 'JS string breakout'),
        ('"-alert(1)-"', 'JS', 'JS double quote breakout'),
        ('</script><script>alert(1)</script>', 'JS', 'script tag close'),
    ]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Scan a URL for reflected XSS."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"q": "test"}

        client = httpx.Client(follow_redirects=True, timeout=10, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})

        # Get baseline
        try:
            self.limiter.wait(parsed.netloc)
            baseline = client.get(url)
        except Exception:
            return []

        for param_name in test_params:
            for payload, context, desc in self.PAYLOADS:
                test_params_copy = dict(test_params)
                test_params_copy[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)
                    body = resp.text

                    # Check if payload is reflected unencoded
                    if payload in body:
                        # Validate: check it's in an executable context
                        if self._is_executable_context(body, payload, context):
                            # Confirm: try a canary to rule out WAF/encoding
                            canary = payload.replace("alert(1)", "document.domain")
                            test_params_copy[param_name] = canary
                            canary_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))
                            canary_resp = client.get(canary_url)

                            if canary in canary_resp.text:
                                findings.append(Finding(
                                    vuln_type="Cross-Site Scripting (XSS)",
                                    title=f"Reflected XSS in parameter '{param_name}' ({context} context)",
                                    severity="HIGH",
                                    url=url,
                                    parameter=param_name,
                                    method="GET",
                                    payload=payload,
                                    evidence=f"Payload reflected unencoded in {context} context",
                                    description=f"Reflected XSS vulnerability. {desc}. Payload is reflected without sanitization.",
                                    remediation="Implement output encoding (HTML entity, JS escape, URL encode). Add Content-Security-Policy header.",
                                    cvss=6.1,
                                    cwe="CWE-79",
                                    tool=self.NAME,
                                    verified=True,
                                    confidence="HIGH",
                                ))
                                return findings  # One per param

                except Exception:
                    continue

        return findings

    def _is_executable_context(self, body: str, payload: str, context: str) -> bool:
        """Check if the reflected payload is in an executable context."""
        idx = body.find(payload)
        if idx == -1:
            return False

        surrounding = body[max(0, idx-100):idx+len(payload)+100]

        if context == "HTML":
            # Check it's not inside a comment or non-executable tag
            if "<!--" in surrounding and "-->" in surrounding:
                return False
            if "<textarea" in surrounding.lower():
                return False
            return True

        elif context == "ATTR":
            # Check it's inside an attribute
            return '="' in surrounding or "='" in surrounding

        elif context == "JS":
            # Check it's inside a script tag
            return "<script" in surrounding.lower()

        return True
