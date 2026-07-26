"""Headers Scanner — security header analysis."""

from typing import List
from .findings import Finding


class HeadersScanner:
    """Checks for missing or misconfigured security headers."""

    NAME = "headers"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "description": "HSTS header missing — allows protocol downgrade attacks",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
            "cvss": 7.5,
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "description": "CSP header missing — allows XSS and data injection",
            "remediation": "Implement Content-Security-Policy with restrictive directives",
            "cvss": 6.1,
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "X-Frame-Options missing — allows clickjacking",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
            "cvss": 4.3,
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "X-Content-Type-Options missing — allows MIME sniffing",
            "remediation": "Add 'X-Content-Type-Options: nosniff'",
            "cvss": 3.1,
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Referrer-Policy missing — may leak sensitive URL data",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
            "cvss": 2.6,
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Permissions-Policy missing — browser features unrestricted",
            "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'",
            "cvss": 2.6,
        },
    }

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Check security headers on a URL."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=10, verify=True)

        try:
            resp = client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header_name, info in self.SECURITY_HEADERS.items():
                if header_name.lower() not in headers:
                    findings.append(Finding(
                        vuln_type="Missing Security Header",
                        title=f"Missing {header_name}",
                        severity=info["severity"],
                        url=url,
                        description=info["description"],
                        remediation=info["remediation"],
                        cvss=info["cvss"],
                        cwe="CWE-693",
                        tool=self.NAME,
                        verified=True,
                        confidence="CONFIRMED",
                    ))

            # Check for information-leaking headers
            leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            for h in leaky_headers:
                if h.lower() in headers:
                    findings.append(Finding(
                        vuln_type="Information Disclosure",
                        title=f"Server information leaked via {h} header",
                        severity="LOW",
                        url=url,
                        evidence=f"{h}: {headers[h.lower()]}",
                        description=f"The {h} header reveals server technology: {headers[h.lower()]}",
                        remediation=f"Remove the {h} header from responses.",
                        cvss=2.6,
                        cwe="CWE-200",
                        tool=self.NAME,
                        verified=True,
                        confidence="CONFIRMED",
                    ))

        except Exception:
            pass

        return findings
