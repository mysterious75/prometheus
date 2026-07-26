"""Session Manager Scanner — tests session management security.

Covers:
- Cookie security flags (HttpOnly, Secure, SameSite)
- Session fixation
- Session hijacking vectors
- Token entropy analysis
- Session timeout
- Concurrent sessions
- Session rotation
- CSRF protection
- JWT security (none algorithm, weak secret, expiry, algorithm confusion)
"""

import re
import ssl
import hmac
import time
import json
import math
import base64
import hashlib
import secrets
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from collections import Counter

import httpx

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter
from .findings import Finding


class SessionManagerScanner:
    """Tests session management security."""

    NAME = "session_management"

    def __init__(self, rps: float = 10.0):
        self.limiter = get_limiter(rps)

    def _make_client(self, **kwargs) -> httpx.Client:
        defaults = {
            "timeout": 15,
            "verify": False,
            "follow_redirects": True,
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        }
        defaults.update(kwargs)
        return httpx.Client(**defaults)

    def _get_host(self, url: str) -> str:
        return urlparse(url).hostname or url

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scanner interface — runs all session management tests."""
        findings = []
        console.print(f"  [tool]▸ Session Management[/tool] → [target]{url}[/target]")
        findings.extend(self.test_cookie_security_flags(url))
        findings.extend(self.test_session_fixation(url))
        findings.extend(self.test_session_hijacking(url))
        findings.extend(self.test_token_entropy(url))
        findings.extend(self.test_session_timeout(url))
        findings.extend(self.test_concurrent_sessions(url))
        findings.extend(self.test_session_rotation(url))
        findings.extend(self.test_csrf_protection(url))
        findings.extend(self.test_jwt_security(url))
        console.print(f"  [tool]◂ Session Management[/tool] — {len(findings)} findings")
        return findings

    # ──────────────────────────────────────────────────────────────
    #  1. Cookie Security Flags
    # ──────────────────────────────────────────────────────────────

    def test_cookie_security_flags(self, url: str) -> List[Finding]:
        """Check cookie attributes: HttpOnly, Secure, SameSite, Domain, Path, Expires."""
        findings = []
        try:
            client = self._make_client(follow_redirects=True)
            resp = client.get(url)

            # Parse Set-Cookie headers manually for full attribute inspection
            set_cookie_headers = []
            for key, value in resp.headers.multi_items():
                if key.lower() == "set-cookie":
                    set_cookie_headers.append(value)

            for cookie_header in set_cookie_headers:
                parts = [p.strip() for p in cookie_header.split(";")]
                if not parts:
                    continue

                # First part is name=value
                cookie_name = parts[0].split("=", 1)[0].strip()
                attributes = {p.split("=", 1)[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else "" for p in parts[1:]}
                attr_lower = {p.strip().lower(): "" for p in parts[1:]}

                issues = []
                severity = "LOW"

                # HttpOnly check
                if "httponly" not in attr_lower and "httponly" not in attributes:
                    issues.append("Missing HttpOnly")
                    severity = "MEDIUM"

                # Secure check (only for HTTPS)
                if url.startswith("https://"):
                    if "secure" not in attr_lower and "secure" not in attributes:
                        issues.append("Missing Secure")
                        severity = "MEDIUM"

                # SameSite check
                if "samesite" not in attributes and "samesite" not in attr_lower:
                    issues.append("Missing SameSite")
                else:
                    samesite = attributes.get("samesite", "").lower()
                    if samesite == "none":
                        issues.append("SameSite=None (allows cross-site)")

                # Domain check
                domain = attributes.get("domain", "")
                if domain and domain.startswith("."):
                    issues.append(f"Domain set to wildcard: {domain}")

                # Path check
                path = attributes.get("path", "")
                if path == "/" or not path:
                    # Wide path scope — not necessarily bad but noted
                    pass

                # Expiry check
                expires = attributes.get("expires", "")
                max_age = attributes.get("max-age", "")
                if max_age:
                    try:
                        max_age_int = int(max_age)
                        if max_age_int > 31536000:  # > 1 year
                            issues.append(f"Excessive max-age: {max_age_int}s")
                    except ValueError:
                        pass

                if issues:
                    findings.append(Finding(
                        vuln_type="Insecure Cookie Configuration",
                        title=f"Cookie '{cookie_name}': {', '.join(issues)}",
                        severity=severity,
                        url=url,
                        evidence=f"Set-Cookie: {cookie_header[:200]}",
                        description=f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}.",
                        remediation="Set HttpOnly, Secure, SameSite=Lax/Strict on all session cookies.",
                        cvss=4.0 if severity == "MEDIUM" else 2.0,
                        cwe="CWE-614",
                        tool="session_management",
                        verified=True,
                        confidence="CONFIRMED",
                    ))

            # Check if any session-like cookies exist at all
            session_cookie_names = ["session", "sid", "sess", "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid"]
            has_session_cookie = any(
                any(sn in c.name.lower() for sn in session_cookie_names)
                for c in client.cookies.jar
            )

            if not has_session_cookie and client.cookies.jar:
                # Check for any cookie that looks like a session token
                for cookie in client.cookies.jar:
                    if len(cookie.value) > 16 and cookie.value.isalnum():
                        findings.append(Finding(
                            vuln_type="Session Cookie Naming",
                            title=f"Non-standard session cookie name: {cookie.name}",
                            severity="INFO",
                            url=url,
                            evidence=f"Cookie '{cookie.name}' appears to be a session token but uses non-standard name",
                            description="Non-standard cookie names can cause confusion but aren't necessarily insecure.",
                            remediation="Use standard session cookie names for clarity.",
                            cvss=0.0, cwe="CWE-200", tool="session_management",
                            verified=False, confidence="LOW",
                        ))
                        break

            client.close()
        except Exception as e:
            logger.debug(f"Cookie security test error: {e}")
        return findings

    # ──────────────────────────────────────────────────────────────
    #  2. Session Fixation
    # ──────────────────────────────────────────────────────────────

    def test_session_fixation(self, url: str) -> List[Finding]:
        """Test if session ID changes after authentication."""
        findings = []
        try:
            client = self._make_client()
            # Get pre-login session cookies
            resp = client.get(url)
            pre_cookies = {c.name: c.value for c in client.cookies.jar}

            if not pre_cookies:
                return findings

            # Try to log in and check if session changes
            login_paths = ["/login", "/signin", "/auth/login", "/api/login"]
            for path in login_paths:
                login_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    login_resp = client.post(login_url, data={
                        "username": "testuser",
                        "password": "testpassword123",
                    })

                    post_cookies = {c.name: c.value for c in client.cookies.jar}

                    # Compare session cookies before and after login attempt
                    for cookie_name in pre_cookies:
                        if cookie_name in post_cookies:
                            if pre_cookies[cookie_name] == post_cookies[cookie_name]:
                                # Check if this looks like a session cookie
                                if len(pre_cookies[cookie_name]) > 8:
                                    # Session ID didn't change after login attempt
                                    # This could be fixation (but we need actual login success for confirmation)
                                    pass  # Note: without successful login, this is informational
                            else:
                                # Session ID changed — good
                                findings.append(Finding(
                                    vuln_type="Session Rotation on Login",
                                    title=f"Session ID changes on login attempt: {cookie_name}",
                                    severity="INFO",
                                    url=login_url,
                                    evidence=f"Cookie '{cookie_name}' value changed after login POST",
                                    description="Session ID rotates on login. Good practice.",
                                    remediation="No action needed — informational.",
                                    cvss=0.0, cwe="CWE-384", tool="session_management",
                                    verified=True,
                                    confidence="MEDIUM",
                                ))
                except Exception:
                    pass

            # Check if session ID is in URL (fixation vector)
            if any(kw in url.lower() for kw in ["sessionid=", "sid=", "jsessionid=", "phpsessid="]):
                findings.append(Finding(
                    vuln_type="Session ID in URL",
                    title="Session identifier exposed in URL",
                    severity="HIGH",
                    url=url,
                    evidence=f"URL contains session parameter: {url}",
                    description="Session ID in URL can be stolen via Referer header, bookmarks, and logs.",
                    remediation="Use cookies for session management. Never embed session IDs in URLs.",
                    cvss=7.5, cwe="CWE-598", tool="session_management",
                    verified=True,
                    confidence="CONFIRMED",
                ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  3. Session Hijacking
    # ──────────────────────────────────────────────────────────────

    def test_session_hijacking(self, url: str) -> List[Finding]:
        """Test for session hijacking vectors."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)

            # Check for session tokens in response body (not just cookies)
            body = resp.text
            token_patterns = [
                (r'session[_-]?id["\s:=]+["\']?([a-zA-Z0-9_-]{16,})', "Session ID in body"),
                (r'access[_-]?token["\s:=]+["\']?([a-zA-Z0-9._-]{20,})', "Access token in body"),
                (r'auth[_-]?token["\s:=]+["\']?([a-zA-Z0-9._-]{20,})', "Auth token in body"),
                (r'Bearer\s+[a-zA-Z0-9._-]{20,}', "Bearer token in body"),
            ]

            for pattern, desc in token_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    findings.append(Finding(
                        vuln_type="Token in Response Body",
                        title=f"{desc} found in HTML/JS",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"{desc}: {matches[0][:30]}...",
                        description="Session/auth tokens in response body can be stolen via XSS.",
                        remediation="Keep tokens in HttpOnly cookies. Don't embed in HTML/JS.",
                        cvss=5.3, cwe="CWE-598", tool="session_management",
                        verified=True,
                        confidence="MEDIUM",
                    ))

            # Check for token in localStorage/sessionStorage
            if "localstorage" in body.lower() or "sessionstorage" in body.lower():
                storage_set = re.findall(r'(?:localStorage|sessionStorage)\.setItem\(["\']([^"\']*)["\']', body, re.IGNORECASE)
                sensitive_keys = [k for k in storage_set if any(s in k.lower() for s in ["token", "session", "auth", "jwt", "secret"])]
                if sensitive_keys:
                    findings.append(Finding(
                        vuln_type="Token in Web Storage",
                        title=f"Sensitive token stored in browser storage: {', '.join(sensitive_keys)}",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"Storage keys: {', '.join(sensitive_keys)}",
                        description="Tokens in localStorage/sessionStorage are accessible via XSS.",
                        remediation="Use HttpOnly cookies for session tokens.",
                        cvss=5.3, cwe="CWE-922", tool="session_management",
                        verified=True,
                        confidence="HIGH",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  4. Token Entropy
    # ──────────────────────────────────────────────────────────────

    def test_token_entropy(self, url: str) -> List[Finding]:
        """Analyze session token randomness."""
        findings = []
        try:
            client = self._make_client()
            tokens = []

            # Collect session tokens from multiple requests
            for _ in range(5):
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(url)
                    for cookie in client.cookies.jar:
                        if len(cookie.value) > 8:
                            tokens.append(cookie.value)
                    # Clear cookies for next request
                    client.cookies.clear()
                except Exception:
                    pass

            if len(tokens) >= 3:
                # Analyze entropy of the tokens
                for token in tokens[:1]:  # Analyze first token
                    entropy = self._calculate_entropy(token)
                    unique_chars = len(set(token))
                    length = len(token)

                    # Low entropy check
                    if entropy < 3.0 and length > 10:
                        findings.append(Finding(
                            vuln_type="Low Token Entropy",
                            title=f"Session token has low entropy: {entropy:.2f} bits/char",
                            severity="HIGH",
                            url=url,
                            evidence=f"Token: {token[:20]}... Length: {length}, Entropy: {entropy:.2f}, Unique chars: {unique_chars}",
                            description="Low entropy session tokens can be predicted or brute-forced.",
                            remediation="Use cryptographically secure random generators for session tokens (min 128 bits).",
                            cvss=7.5, cwe="CWE-331", tool="session_management",
                            verified=True,
                            confidence="MEDIUM",
                        ))

                    # Short token check
                    if length < 16:
                        findings.append(Finding(
                            vuln_type="Short Session Token",
                            title=f"Session token is too short: {length} characters",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"Token length: {length} characters",
                            description="Short session tokens are easier to guess or brute-force.",
                            remediation="Use at least 32-character session tokens.",
                            cvss=5.3, cwe="CWE-330", tool="session_management",
                            verified=True,
                            confidence="HIGH",
                        ))

                    # Check if tokens are sequential or predictable
                    if len(tokens) >= 3:
                        diffs = []
                        for i in range(1, len(tokens)):
                            try:
                                diff = int(tokens[i]) - int(tokens[i - 1])
                                diffs.append(diff)
                            except ValueError:
                                pass

                        if diffs and len(set(diffs)) == 1:
                            findings.append(Finding(
                                vuln_type="Sequential Session Tokens",
                                title="Session tokens appear to be sequential",
                                severity="CRITICAL",
                                url=url,
                                evidence=f"Tokens differ by constant: {diffs[0]}",
                                description="Sequential session tokens allow prediction of other users' sessions.",
                                remediation="Use cryptographically secure random token generation.",
                                cvss=9.8, cwe="CWE-330", tool="session_management",
                                verified=True,
                                confidence="HIGH",
                            ))

            client.close()
        except Exception:
            pass
        return findings

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string in bits per character."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ──────────────────────────────────────────────────────────────
    #  5. Session Timeout
    # ──────────────────────────────────────────────────────────────

    def test_session_timeout(self, url: str) -> List[Finding]:
        """Test if sessions expire properly."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)

            # Check cookie expiry/max-age
            for cookie in client.cookies.jar:
                if cookie.expires:
                    ttl = cookie.expires - time.time()
                    if ttl > 86400 * 30:  # > 30 days
                        findings.append(Finding(
                            vuln_type="Excessive Session Lifetime",
                            title=f"Cookie '{cookie.name}' has TTL > 30 days: {int(ttl/86400)} days",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"Cookie '{cookie.name}' expires in {int(ttl/86400)} days",
                            description="Long session lifetimes increase risk of session hijacking.",
                            remediation="Set session timeout to 15-30 minutes of inactivity.",
                            cvss=4.0, cwe="CWE-613", tool="session_management",
                            verified=True,
                            confidence="HIGH",
                        ))
                elif not cookie.discard:
                    # No expiry and not a session cookie (discard=True means session-only)
                    findings.append(Finding(
                        vuln_type="Persistent Cookie Without Expiry",
                        title=f"Cookie '{cookie.name}' is persistent with no explicit expiry",
                        severity="LOW",
                        url=url,
                        evidence=f"Cookie '{cookie.name}' has no Expires/Max-Age set",
                        description="Cookie may persist indefinitely.",
                        remediation="Set explicit expiry for all cookies.",
                        cvss=2.0, cwe="CWE-613", tool="session_management",
                        verified=True,
                        confidence="MEDIUM",
                    ))

            # Check for timeout-related headers or meta tags
            body = resp.text.lower()
            if "timeout" in body or "session-timeout" in body:
                # Try to find timeout value
                timeout_match = re.search(r'timeout["\s:=]+(\d+)', body)
                if timeout_match:
                    timeout_val = int(timeout_match.group(1))
                    if timeout_val > 3600:  # > 1 hour
                        findings.append(Finding(
                            vuln_type="Long Session Timeout",
                            title=f"Session timeout configured to {timeout_val} seconds",
                            severity="LOW",
                            url=url,
                            evidence=f"Session timeout: {timeout_val} seconds",
                            description="Long session timeouts increase risk window.",
                            remediation="Set session timeout to 15-30 minutes.",
                            cvss=2.0, cwe="CWE-613", tool="session_management",
                            verified=True,
                            confidence="LOW",
                        ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  6. Concurrent Sessions
    # ──────────────────────────────────────────────────────────────

    def test_concurrent_sessions(self, url: str) -> List[Finding]:
        """Test if multiple concurrent sessions are allowed."""
        findings = []
        try:
            # This test is informational — check if the app mentions session limits
            client = self._make_client()
            resp = client.get(url)
            body = resp.text.lower()

            # Check for session management features
            if "concurrent" in body or "active sessions" in body or "other devices" in body:
                findings.append(Finding(
                    vuln_type="Concurrent Session Awareness",
                    title="Application mentions concurrent session management",
                    severity="INFO",
                    url=url,
                    evidence="Application references concurrent sessions or active devices",
                    description="Application appears to be aware of concurrent sessions.",
                    remediation="Verify that session limits are properly enforced.",
                    cvss=0.0, cwe="CWE-384", tool="session_management",
                    verified=False,
                    confidence="LOW",
                ))

            # Try to establish two sessions and see if both work
            client2 = self._make_client()
            resp1 = client.get(url)
            resp2 = client2.get(url)

            cookies1 = {c.name: c.value for c in client.cookies.jar}
            cookies2 = {c.name: c.value for c in client2.cookies.jar}

            # Check if both sessions are valid
            if cookies1 and cookies2:
                # Both have session cookies — this is normal without authentication
                # But we note it for the report
                pass

            client.close()
            client2.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  7. Session Rotation
    # ──────────────────────────────────────────────────────────────

    def test_session_rotation(self, url: str) -> List[Finding]:
        """Test if session is rotated on privilege change."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            pre_cookies = {c.name: c.value for c in client.cookies.jar}

            # Look for privilege-change endpoints
            priv_paths = ["/login", "/signin", "/auth/login", "/admin/login", "/elevate", "/sudo"]
            for path in priv_paths:
                login_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    login_resp = client.post(login_url, data={
                        "username": "admin",
                        "password": "test123",
                    })

                    post_cookies = {c.name: c.value for c in client.cookies.jar}

                    # Check if session cookie changed
                    for name in pre_cookies:
                        if name in post_cookies and pre_cookies[name] == post_cookies[name]:
                            # Same session ID after login attempt — could be fixation
                            if len(pre_cookies[name]) > 16:
                                findings.append(Finding(
                                    vuln_type="Session Not Rotated",
                                    title=f"Session ID not rotated after login attempt: {name}",
                                    severity="MEDIUM",
                                    url=login_url,
                                    evidence=f"Cookie '{name}' unchanged after POST to {path}",
                                    description="Session ID should change on privilege change to prevent fixation.",
                                    remediation="Regenerate session ID after successful authentication.",
                                    cvss=5.3, cwe="CWE-384", tool="session_management",
                                    verified=False,
                                    confidence="LOW",
                                ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  8. CSRF Protection
    # ──────────────────────────────────────────────────────────────

    def test_csrf_protection(self, url: str) -> List[Finding]:
        """Test for CSRF token presence and validation."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Find all forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
            form_tags = re.findall(r'<form[^>]*>', body, re.IGNORECASE)

            for i, (form_content, form_tag) in enumerate(zip(forms, form_tags)):
                # Determine form method
                method_match = re.search(r'method=["\'](\w+)["\']', form_tag, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                if method == "POST":
                    # Check for CSRF token
                    csrf_patterns = [
                        r'csrf', r'_token', r'authenticity_token', r'csrfmiddlewaretoken',
                        r'__requestverificationtoken', r'nonce', r'_csrf', r'csrf_token',
                    ]
                    has_csrf = any(
                        re.search(p, form_content, re.IGNORECASE)
                        for p in csrf_patterns
                    )

                    # Also check for hidden token fields
                    hidden_fields = re.findall(
                        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\']',
                        form_content, re.IGNORECASE
                    )
                    has_token_field = any(
                        any(kw in name.lower() for kw in ["token", "csrf", "nonce", "_token"])
                        for name in hidden_fields
                    )

                    if not has_csrf and not has_token_field:
                        # Extract form action for context
                        action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
                        action = action_match.group(1) if action_match else url

                        findings.append(Finding(
                            vuln_type="Missing CSRF Protection",
                            title=f"POST form #{i+1} lacks CSRF token",
                            severity="MEDIUM",
                            url=urljoin(url, action),
                            evidence=f"POST form without CSRF token. Hidden fields: {hidden_fields}",
                            description="Form does not include a CSRF token, making it vulnerable to cross-site request forgery.",
                            remediation="Add CSRF tokens to all state-changing forms. Use SameSite cookies.",
                            cvss=5.3, cwe="CWE-352", tool="session_management",
                            verified=True,
                            confidence="HIGH",
                        ))
                    else:
                        # Check token randomness
                        for name in hidden_fields:
                            if any(kw in name.lower() for kw in ["token", "csrf"]):
                                value_match = re.search(
                                    rf'name=["\']' + re.escape(name) + r'["\'][^>]*value=["\']([^"\']*)["\']',
                                    form_content, re.IGNORECASE
                                )
                                if value_match:
                                    token_val = value_match.group(1)
                                    if token_val and len(token_val) < 16:
                                        findings.append(Finding(
                                            vuln_type="Weak CSRF Token",
                                            title=f"CSRF token '{name}' is short: {len(token_val)} chars",
                                            severity="MEDIUM",
                                            url=url,
                                            parameter=name,
                                            evidence=f"CSRF token value: {token_val} (length: {len(token_val)})",
                                            description="Short CSRF tokens may be predictable.",
                                            remediation="Use at least 32-character random CSRF tokens.",
                                            cvss=4.0, cwe="CWE-352", tool="session_management",
                                            verified=True,
                                            confidence="MEDIUM",
                                        ))

            # Check for SameSite cookie attribute (CSRF mitigation)
            set_cookie = resp.headers.get("set-cookie", "")
            if set_cookie and "samesite" not in set_cookie.lower():
                findings.append(Finding(
                    vuln_type="Missing SameSite Cookie",
                    title="Session cookies lack SameSite attribute",
                    severity="LOW",
                    url=url,
                    evidence=f"Set-Cookie header lacks SameSite: {set_cookie[:100]}",
                    description="Without SameSite, cookies are sent on cross-site requests.",
                    remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                    cvss=3.1, cwe="CWE-352", tool="session_management",
                    verified=True,
                    confidence="HIGH",
                ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  9. JWT Security
    # ──────────────────────────────────────────────────────────────

    def test_jwt_security(self, url: str) -> List[Finding]:
        """Test JWT implementation for common vulnerabilities."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text
            headers = resp.headers

            # Find JWT tokens in response
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            jwt_tokens = []

            # Check response body
            jwt_tokens.extend(re.findall(jwt_pattern, body))

            # Check headers
            auth_header = headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                if re.match(jwt_pattern, token):
                    jwt_tokens.append(token)

            # Check cookies
            for cookie in client.cookies.jar:
                if re.match(jwt_pattern, cookie.value):
                    jwt_tokens.append(cookie.value)

            for token in jwt_tokens:
                try:
                    parts = token.split(".")
                    if len(parts) != 3:
                        continue

                    # Decode header
                    header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_padded))

                    # Decode payload
                    payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_padded))

                    alg = header.get("alg", "")

                    # Test 1: None algorithm
                    if alg == "none" or alg == "None" or alg == "NONE":
                        findings.append(Finding(
                            vuln_type="JWT None Algorithm",
                            title="JWT accepts 'none' algorithm",
                            severity="CRITICAL",
                            url=url,
                            payload=token[:50] + "...",
                            evidence=f"JWT header alg: {alg}",
                            description="JWT uses 'none' algorithm — no signature verification. Any attacker can forge tokens.",
                            remediation="Reject tokens with 'none' algorithm. Always verify signatures.",
                            cvss=9.8, cwe="CWE-347", tool="session_management",
                            verified=True, confidence="CONFIRMED",
                        ))

                    # Test 2: Algorithm confusion (RS256 → HS256)
                    if alg == "RS256":
                        findings.append(Finding(
                            vuln_type="JWT Algorithm Confusion Risk",
                            title=f"JWT uses RS256 — test for algorithm confusion",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"JWT algorithm: {alg}",
                            description="If server accepts HS256 with RSA public key, tokens can be forged.",
                            remediation="Explicitly validate algorithm. Reject algorithm changes.",
                            cvss=7.5, cwe="CWE-347", tool="session_management",
                            verified=False, confidence="MEDIUM",
                        ))

                    # Test 3: Weak secret (try common secrets for HS256)
                    if alg == "HS256":
                        weak_secrets = ["secret", "password", "123456", "jwt_secret", "key", "changeme", "default"]
                        header_b64 = parts[0]
                        payload_b64 = parts[1]
                        message = f"{header_b64}.{payload_b64}".encode()

                        for weak_secret in weak_secrets:
                            try:
                                expected_sig = base64.urlsafe_b64encode(
                                    hmac.new(weak_secret.encode(), message, hashlib.sha256).digest()
                                ).rstrip(b"=").decode()

                                if expected_sig == parts[2]:
                                    findings.append(Finding(
                                        vuln_type="JWT Weak Secret",
                                        title=f"JWT signed with weak secret: '{weak_secret}'",
                                        severity="CRITICAL",
                                        url=url,
                                        evidence=f"JWT verified with secret '{weak_secret}'",
                                        description=f"JWT uses a weak HS256 secret: '{weak_secret}'. Tokens can be forged.",
                                        remediation="Use a strong random secret (256+ bits).",
                                        cvss=9.8, cwe="CWE-326", tool="session_management",
                                        verified=True, confidence="CONFIRMED",
                                    ))
                                    break
                            except Exception:
                                pass

                    # Test 4: Missing expiry
                    exp = payload.get("exp")
                    if not exp:
                        findings.append(Finding(
                            vuln_type="JWT No Expiry",
                            title="JWT has no expiration claim",
                            severity="MEDIUM",
                            url=url,
                            evidence="No 'exp' claim in JWT payload",
                            description="JWT without expiry can be used indefinitely if stolen.",
                            remediation="Set reasonable expiration time for all tokens.",
                            cvss=5.3, cwe="CWE-613", tool="session_management",
                            verified=True, confidence="HIGH",
                        ))
                    elif exp < time.time():
                        findings.append(Finding(
                            vuln_type="JWT Expired",
                            title="JWT is expired",
                            severity="LOW",
                            url=url,
                            evidence=f"Token expired at: {time.ctime(exp)}",
                            description="Expired JWT should be rejected.",
                            remediation="Validate token expiry on every request.",
                            cvss=3.1, cwe="CWE-613", tool="session_management",
                            verified=False, confidence="LOW",
                        ))

                    # Test 5: Excessive expiry
                    if exp and (exp - time.time()) > 86400 * 30:  # > 30 days
                        findings.append(Finding(
                            vuln_type="JWT Excessive Expiry",
                            title=f"JWT expires in > 30 days: {int((exp - time.time()) / 86400)} days",
                            severity="LOW",
                            url=url,
                            evidence=f"Token expiry: {time.ctime(exp)}",
                            description="Long-lived tokens increase risk if compromised.",
                            remediation="Use short-lived access tokens (15-60 min) with refresh tokens.",
                            cvss=3.1, cwe="CWE-613", tool="session_management",
                            verified=True, confidence="HIGH",
                        ))

                    # Test 6: Sensitive data in payload
                    sensitive_keys = ["password", "secret", "key", "ssn", "credit_card", "private"]
                    for key in payload:
                        if any(s in key.lower() for s in sensitive_keys):
                            findings.append(Finding(
                                vuln_type="JWT Sensitive Data",
                                title=f"Sensitive data in JWT: {key}",
                                severity="HIGH",
                                url=url,
                                evidence=f"JWT payload contains '{key}'",
                                description="JWT payloads are base64-encoded, not encrypted. Anyone can read them.",
                                remediation="Never store sensitive data in JWTs.",
                                cvss=7.5, cwe="CWE-200", tool="session_management",
                                verified=True, confidence="HIGH",
                            ))

                    # Test 7: Try forging a 'none' algorithm token
                    if url and alg not in ("none", "None", "NONE"):
                        forged = self._forge_none_token(payload)
                        if forged:
                            bypass = self._test_forged_jwt(url, forged)
                            if bypass:
                                findings.append(Finding(
                                    vuln_type="JWT None Algorithm Bypass",
                                    title="Server accepts forged JWT with 'none' algorithm",
                                    severity="CRITICAL",
                                    url=url,
                                    payload=forged[:80] + "...",
                                    evidence="Forged 'none' algorithm token accepted",
                                    description="Server accepts unsigned JWTs. Complete authentication bypass.",
                                    remediation="Reject 'none' algorithm. Validate algorithm against whitelist.",
                                    cvss=9.8, cwe="CWE-347", tool="session_management",
                                    verified=True, confidence="CONFIRMED",
                                ))

                except Exception as e:
                    logger.debug(f"JWT decode error: {e}")

            client.close()
        except Exception:
            pass
        return findings

    def _forge_none_token(self, payload: Dict) -> Optional[str]:
        """Forge a JWT with 'none' algorithm."""
        try:
            header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            return f"{header}.{payload_b64}."
        except Exception:
            return None

    def _test_forged_jwt(self, url: str, token: str) -> bool:
        """Test if a forged JWT is accepted by the server."""
        try:
            client = httpx.Client(timeout=10, verify=False)
            resp = client.get(url, headers={"Authorization": f"Bearer {token}"})
            client.close()
            return resp.status_code == 200 and len(resp.text) > 50
        except Exception:
            return False
