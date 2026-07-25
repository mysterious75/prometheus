"""SSTI Scanner — Server-Side Template Injection detection."""

from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .findings import Finding
from ..core.ratelimit import get_limiter


class SSTIScanner:
    """Tests for Server-Side Template Injection."""

    NAME = "ssti"

    PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig/Mustache"),
        ("${7*7}", "49", "FreeMarker/Mako"),
        ("<%= 7*7 %>", "49", "ERB/JSP"),
        ("#{7*7}", "49", "Slim/Ruby"),
        ("{{config}}", "SECRET", "Jinja2 config disclosure"),
        ("{{self.__class__.__mro__[1].__subclasses__()}}", "__subclasses__", "Jinja2 class enumeration"),
    ]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test for SSTI."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"name": "test", "input": "test"}

        client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

        for param_name in test_params:
            for payload, indicator, engine in self.PAYLOADS:
                test_params_copy = dict(test_params)
                test_params_copy[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)
                    body = resp.text

                    if indicator in body and payload not in body:
                        # Mathematical expression was evaluated
                        findings.append(Finding(
                            vuln_type="Server-Side Template Injection (SSTI)",
                            title=f"SSTI via parameter '{param_name}' — {engine}",
                            severity="CRITICAL",
                            url=url,
                            parameter=param_name,
                            method="GET",
                            payload=payload,
                            evidence=f"Template expression evaluated: '{payload}' → '{indicator}'",
                            description=f"SSTI in {engine} template engine. Can lead to Remote Code Execution.",
                            remediation="Never pass user input to template engine. Use sandboxed templates.",
                            cvss=9.8,
                            cwe="CWE-1336",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))
                        return findings

                except Exception:
                    continue

        return findings
