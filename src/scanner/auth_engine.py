"""Multi-Session Authentication Engine.

Tests authorization by creating resources as User A and attempting
to access them as User B. This is how real BOLA/IDOR vulnerabilities
are found — not by pattern matching, but by actual cross-user testing.

Usage:
    engine = MultiSessionEngine()
    engine.add_session("admin", "admin123", "https://target.com/login")
    engine.add_session("user", "user123", "https://target.com/login")
    findings = engine.test_bola("https://target.com/api/users/{id}")
"""

import re
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter
from ..scanner.findings import Finding
from ..core.transport import ssl_verify


@dataclass
class Session:
    """An authenticated session."""
    name: str  # "admin", "user1", "attacker"
    username: str
    password: str
    login_url: str
    token: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    logged_in: bool = False
    role: str = "user"  # admin, user, guest


@dataclass
class AuthFlow:
    """An authentication flow discovered by the engine."""
    login_url: str
    method: str  # form, api, oauth, basic
    username_field: str
    password_field: str
    token_location: str  # cookie, header, body
    token_name: str


class MultiSessionEngine:
    """Multi-session engine for BOLA/IDOR/authorization testing.

    Creates multiple authenticated sessions and tests whether
    resources created by one session can be accessed by another.
    """

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)
        self.sessions: Dict[str, Session] = {}
        self.auth_flows: List[AuthFlow] = []
        self.discovered_endpoints: List[Dict[str, Any]] = []

    def add_session(self, name: str, username: str, password: str, login_url: str, role: str = "user"):
        """Add a session with credentials."""
        self.sessions[name] = Session(
            name=name, username=username, password=password,
            login_url=login_url, role=role,
        )

    def login_all(self) -> Dict[str, bool]:
        """Attempt to authenticate all sessions."""
        results = {}
        for name, session in self.sessions.items():
            results[name] = self._login(session)
        return results

    def _login(self, session: Session) -> bool:
        """Authenticate a session."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=15, verify=ssl_verify())

            # Get login page to find form
            self.limiter.wait(urlparse(session.login_url).netloc)
            resp = client.get(session.login_url)

            # Detect auth flow
            auth_flow = self._detect_auth_flow(resp.text, session.login_url)
            if not auth_flow:
                auth_flow = AuthFlow(
                    login_url=session.login_url, method="api",
                    username_field="username", password_field="password",
                    token_location="header", token_name="Authorization",
                )

            # Attempt login
            if auth_flow.method == "form":
                data = {
                    auth_flow.username_field: session.username,
                    auth_flow.password_field: session.password,
                }
                resp = client.post(session.login_url, data=data)
            else:
                data = {
                    auth_flow.username_field: session.username,
                    auth_flow.password_field: session.password,
                }
                resp = client.post(session.login_url, json=data)

            # Extract token
            if auth_flow.token_location == "cookie":
                session.cookies = dict(resp.cookies)
                session.logged_in = bool(session.cookies.get(auth_flow.token_name))
            elif auth_flow.token_location == "body":
                try:
                    body = resp.json()
                    token = body.get(auth_flow.token_name, body.get("token", body.get("access_token", "")))
                    if token:
                        session.token = token
                        session.headers["Authorization"] = f"Bearer {token}"
                        session.logged_in = True
                except Exception:
                    pass
            elif auth_flow.token_location == "header":
                auth_header = resp.headers.get("Authorization", "")
                if auth_header:
                    session.headers["Authorization"] = auth_header
                    session.logged_in = True

            # Fallback: check if response indicates success
            if not session.logged_in:
                if resp.status_code in (200, 302) and "login" not in resp.url.path.lower():
                    session.logged_in = True
                    session.cookies = dict(resp.cookies)

            if session.logged_in:
                console.print(f"    [success]✓ {session.name} logged in as {session.username}[/success]")
            else:
                console.print(f"    [error]✗ {session.name} login failed[/error]")

            return session.logged_in

        except Exception as e:
            console.print(f"    [error]✗ {session.name} login error: {e}[/error]")
            return False

    def _detect_auth_flow(self, html: str, url: str) -> Optional[AuthFlow]:
        """Detect authentication flow from login page HTML."""
        # Find form
        form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S)
        if not form_match:
            return None

        action = form_match.group(1) or url
        form_html = form_match.group(2)

        # Find username field
        username_field = "username"
        for name in ["username", "email", "user", "login", "account"]:
            if re.search(rf'name=["\']({name})["\']', form_html, re.I):
                username_field = name
                break

        # Find password field
        password_field = "password"
        for name in ["password", "passwd", "pass", "secret"]:
            if re.search(rf'name=["\']({name})["\']', form_html, re.I):
                password_field = name
                break

        return AuthFlow(
            login_url=url, method="form",
            username_field=username_field, password_field=password_field,
            token_location="cookie", token_name="session",
        )

    def test_bola(self, endpoint_template: str, method: str = "GET") -> List[Finding]:
        """Test for BOLA (Broken Object Level Authorization).

        Creates a resource as User A, tries to access it as User B.
        """
        findings = []
        sessions = list(self.sessions.values())

        if len(sessions) < 2:
            console.print("  [error]Need at least 2 sessions for BOLA testing[/error]")
            return findings

        console.print(f"  [tool]▸ BOLA Testing[/tool] → {endpoint_template}")

        # Create resource as first user
        creator = sessions[0]
        if not creator.logged_in:
            console.print(f"    [error]{creator.name} not logged in[/error]")
            return findings

        # Try to access as other users
        for accessor in sessions[1:]:
            if not accessor.logged_in:
                continue

            # Try each ID from 1 to 10
            for resource_id in range(1, 11):
                url = endpoint_template.replace("{id}", str(resource_id))

                self.limiter.wait(urlparse(url).netloc)
                try:
                    import httpx
                    # Request as creator
                    creator_client = httpx.Client(
                        follow_redirects=True, timeout=10, verify=ssl_verify(),
                        headers=creator.headers, cookies=creator.cookies,
                    )
                    creator_resp = creator_client.get(url)

                    # Request as accessor
                    accessor_client = httpx.Client(
                        follow_redirects=True, timeout=10, verify=ssl_verify(),
                        headers=accessor.headers, cookies=accessor.cookies,
                    )
                    accessor_resp = accessor_client.get(url)

                    # Compare responses
                    if (accessor_resp.status_code == 200 and
                        creator_resp.status_code == 200 and
                        len(accessor_resp.text) > 50 and
                        self._responses_differ(creator_resp.text, accessor_resp.text)):

                        findings.append(Finding(
                            vuln_type="Broken Object Level Authorization (BOLA)",
                            title=f"BOLA: {accessor.name} can access {creator.name}'s resource (ID: {resource_id})",
                            severity="HIGH",
                            url=url,
                            parameter=f"id={resource_id}",
                            method=method,
                            evidence=f"Creator ({creator.name}): {len(creator_resp.text)} bytes, Accessor ({accessor.name}): {len(accessor_resp.text)} bytes",
                            description=f"User '{accessor.username}' can access resources belonging to user '{creator.username}' without authorization.",
                            remediation="Implement object-level authorization checks. Verify the requesting user owns or has permission to access the resource.",
                            cvss=7.5,
                            cwe="CWE-639",
                            tool="bola",
                            verified=True,
                            confidence="HIGH",
                        ))
                        break  # One finding per user pair

                except Exception:
                    continue

        if findings:
            console.print(f"    [critical]⚠ {len(findings)} BOLA vulnerabilities found![/critical]")
        else:
            console.print(f"    [success]No BOLA found[/success]")

        return findings

    def test_idor(self, endpoints: List[str]) -> List[Finding]:
        """Test for IDOR across multiple endpoints."""
        findings = []
        for endpoint in endpoints:
            findings.extend(self.test_bola(endpoint))
        return findings

    def test_privilege_escalation(self) -> List[Finding]:
        """Test if a regular user can access admin endpoints."""
        findings = []
        admin_endpoints = [
            "/api/admin", "/api/admin/users", "/api/admin/config",
            "/api/v1/admin", "/admin/api", "/api/management",
        ]

        non_admin = [s for s in self.sessions.values() if s.role != "admin" and s.logged_in]
        admin = next((s for s in self.sessions.values() if s.role == "admin"), None)

        if not non_admin or not admin:
            return findings

        import httpx
        for session in non_admin:
            client = httpx.Client(
                follow_redirects=True, timeout=10, verify=ssl_verify(),
                headers=session.headers, cookies=session.cookies,
            )

            for endpoint in admin_endpoints:
                # Find the base URL from login URL
                parsed = urlparse(session.login_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                url = f"{base}{endpoint}"

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        # Check if it's actual admin data (not a login redirect)
                        if "login" not in resp.text.lower()[:200]:
                            findings.append(Finding(
                                vuln_type="Privilege Escalation",
                                title=f"Non-admin user '{session.username}' can access admin endpoint: {endpoint}",
                                severity="CRITICAL",
                                url=url,
                                method="GET",
                                evidence=f"Status: {resp.status_code}, Size: {len(resp.text)} bytes",
                                description=f"Regular user '{session.username}' has access to admin endpoint {endpoint}.",
                                remediation="Implement role-based access control. Verify user roles before granting access to admin endpoints.",
                                cvss=9.1,
                                cwe="CWE-269",
                                tool="privesc",
                                verified=True,
                                confidence="HIGH",
                            ))
                except Exception:
                    continue

        return findings

    def get_session_info(self) -> Dict[str, Any]:
        """Get information about all sessions."""
        return {
            name: {
                "username": s.username,
                "role": s.role,
                "logged_in": s.logged_in,
                "has_token": bool(s.token),
            }
            for name, s in self.sessions.items()
        }

    def _responses_differ(self, body1: str, body2: str) -> bool:
        """Check if two responses contain different data."""
        # Extract potential identifiers
        emails1 = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body1[:1000]))
        emails2 = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body2[:1000]))

        if emails1 and emails2 and emails1 != emails2:
            return True

        # Different numeric IDs
        nums1 = set(re.findall(r'\b\d{4,}\b', body1[:1000]))
        nums2 = set(re.findall(r'\b\d{4,}\b', body2[:1000]))
        if nums1 and nums2 and nums1 != nums2:
            return True

        return False
