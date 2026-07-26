"""Auth Bypass Scanner — tests for authentication/authorization bypass."""

from typing import List
from .findings import Finding
from ..core.ratelimit import get_limiter


class AuthBypassScanner:
    """Tests for authentication and authorization bypass vulnerabilities."""

    NAME = "auth"

    # Common admin/protected paths
    PROTECTED_PATHS = [
        "/admin", "/admin/", "/administrator/", "/wp-admin/",
        "/dashboard", "/panel", "/control-panel/", "/cpanel/",
        "/manage", "/management/", "/internal/", "/private/",
        "/api/admin", "/api/v1/admin", "/api/users",
        "/debug", "/debug/vars", "/debug/pprof/", "/trace",
        "/console", "/shell", "/system/", "/config/",
        "/.well-known/", "/graphql", "/graphiql",
    ]

    # Default credentials to test
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("guest", "guest"),
        ("user", "user"),
    ]

    def __init__(self, rps: float = 3.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Test for auth bypass vulnerabilities."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        base = url.rstrip("/")
        client = httpx.Client(follow_redirects=True, timeout=10, verify=True,
                              headers={"User-Agent": "Mozilla/5.0"})

        # Check for accessible admin panels
        for path in self.PROTECTED_PATHS:
            self.limiter.wait(urlparse(base).netloc)
            try:
                resp = client.get(f"{base}{path}")

                if resp.status_code == 200 and len(resp.text) > 100:
                    body = resp.text.lower()
                    # Check it's not a login page redirect
                    if any(kw in body for kw in ["admin", "dashboard", "panel", "management", "control"]):
                        # Verify it's not just a 200 login page
                        if not any(kw in body for kw in ["login", "sign in", "log in", "authenticate"]):
                            findings.append(Finding(
                                vuln_type="Authentication Bypass",
                                title=f"Admin panel accessible without authentication: {path}",
                                severity="HIGH",
                                url=f"{base}{path}",
                                description=f"The path {path} appears to be an admin panel accessible without authentication.",
                                remediation="Implement authentication for all admin/management endpoints.",
                                cvss=7.5,
                                cwe="CWE-306",
                                tool=self.NAME,
                                verified=False,
                                confidence="MEDIUM",
                            ))

            except Exception:
                continue

        # Check for IDOR in API endpoints
        api_paths = ["/api/users", "/api/v1/users", "/api/profile", "/api/v1/profile"]
        for path in api_paths:
            self.limiter.wait(urlparse(base).netloc)
            try:
                resp = client.get(f"{base}{path}")
                if resp.status_code == 200:
                    # Try without auth header
                    resp_no_auth = client.get(f"{base}{path}", headers={})
                    if resp_no_auth.status_code == 200 and len(resp_no_auth.text) > 50:
                        findings.append(Finding(
                            vuln_type="Broken Access Control",
                            title=f"API endpoint accessible without authentication: {path}",
                            severity="HIGH",
                            url=f"{base}{path}",
                            description=f"API endpoint {path} returns data without authentication.",
                            remediation="Implement authentication for all API endpoints.",
                            cvss=7.5,
                            cwe="CWE-306",
                            tool=self.NAME,
                            verified=False,
                            confidence="MEDIUM",
                        ))

            except Exception:
                continue

        return findings


from urllib.parse import urlparse
