"""CORS Scanner — Cross-Origin Resource Sharing misconfiguration."""

from typing import List
from .findings import Finding


class CORSScanner:
    """Tests for CORS misconfigurations."""

    NAME = "cors"

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Test CORS configuration."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=10, verify=True)

        # Test origins
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://example.com.evil.com",  # subdomain bypass
        ]

        for origin in test_origins:
            try:
                resp = client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    findings.append(Finding(
                        vuln_type="CORS Misconfiguration",
                        title="Wildcard CORS origin with no credentials restriction",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"Access-Control-Allow-Origin: *",
                        description="CORS allows all origins. Sensitive data may be leaked to any website.",
                        remediation="Restrict CORS to specific trusted origins.",
                        cvss=5.3,
                        cwe="CWE-942",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                    ))
                    break

                if acao == origin and origin not in ("null",):
                    if acac.lower() == "true":
                        findings.append(Finding(
                            vuln_type="CORS Misconfiguration",
                            title=f"CORS allows arbitrary origin '{origin}' with credentials",
                            severity="HIGH",
                            url=url,
                            evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            description="CORS reflects arbitrary origin with credentials. Attacker can steal authenticated user data.",
                            remediation="Validate origin against whitelist. Never reflect arbitrary origins with credentials.",
                            cvss=8.1,
                            cwe="CWE-346",
                            tool=self.NAME,
                            verified=True,
                            confidence="CONFIRMED",
                        ))
                        break

                if acao == "null" and origin == "null":
                    findings.append(Finding(
                        vuln_type="CORS Misconfiguration",
                        title="CORS allows 'null' origin",
                        severity="MEDIUM",
                        url=url,
                        evidence="Access-Control-Allow-Origin: null",
                        description="CORS allows null origin. Sandboxed iframes can access this resource.",
                        remediation="Do not allow 'null' as a CORS origin.",
                        cvss=6.5,
                        cwe="CWE-346",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                    ))

            except Exception:
                continue

        return findings
