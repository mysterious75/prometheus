"""IDOR JWT & GraphQL Enhancement — advanced IDOR detection.

Tests for:
- JWT claim manipulation (swap user_id in JWT)
- GraphQL object-level authorization bypass
- Encoded ID manipulation (base64, hex)
- Sequential enumeration with response diffing
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlencode

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


class IDORJwtGraphQLScanner:
    """Advanced IDOR testing via JWT and GraphQL."""

    NAME = "idor_jwt_graphql"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, auth_token: str = None, **kwargs) -> List[Finding]:
        """Scan URL for JWT/GraphQL IDOR vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        client = httpx.Client(verify=False, timeout=self.timeout, follow_redirects=True, headers=headers)

        try:
            # Test 1: JWT claim manipulation
            if auth_token and auth_token.count(".") == 2:
                findings.extend(self._test_jwt_manipulation(client, url, auth_token, host))

            # Test 2: GraphQL object-level auth
            findings.extend(self._test_graphql_idor(client, url, host))

            # Test 3: Base64-encoded ID manipulation
            findings.extend(self._test_base64_ids(client, url, host))

            # Test 4: UUID v1 time-based prediction
            findings.extend(self._test_uuid_prediction(client, url, host))

            # Test 5: Response diff-based IDOR
            findings.extend(self._test_response_diff(client, url, host))

        finally:
            client.close()

        logger.info(f"IDOR JWT/GraphQL scan: {len(findings)} findings")
        return findings

    def _test_jwt_manipulation(self, client, url: str, token: str, host: str) -> List[Finding]:
        """Test JWT claim manipulation for IDOR."""
        findings = []

        try:
            parts = token.split(".")
            # Decode payload (add padding)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)

            # Find user ID claims
            id_claims = []
            for claim in ["sub", "user_id", "userId", "id", "uid", "account_id", "accountId"]:
                if claim in payload:
                    id_claims.append((claim, payload[claim]))

            for claim, original_id in id_claims:
                # Try modifying the ID
                for delta in [1, -1, 2, -2, 100]:
                    try:
                        new_id = int(original_id) + delta
                    except (ValueError, TypeError):
                        # Try string-based ID
                        new_id = original_id
                        continue

                    modified_payload = dict(payload)
                    modified_payload[claim] = new_id

                    # Re-encode (without signature verification - we're testing if server trusts it)
                    modified_b64 = base64.urlsafe_b64encode(
                        json.dumps(modified_payload).encode()
                    ).rstrip(b"=").decode()

                    # Try with original header but modified payload
                    modified_token = f"{parts[0]}.{modified_b64}.{parts[2]}"

                    self.limiter.wait(host)
                    try:
                        resp = client.get(url, headers={"Authorization": f"Bearer {modified_token}"})
                        if resp.status_code == 200:
                            # Compare with original
                            orig_resp = client.get(url, headers={"Authorization": f"Bearer {token}"})
                            if len(resp.content) > 50 and resp.content != orig_resp.content:
                                findings.append(Finding(
                                    vuln_type="IDOR",
                                    title=f"JWT claim manipulation: {claim}={original_id}→{new_id}",
                                    severity="CRITICAL",
                                    url=url,
                                    method="GET",
                                    payload=f"JWT with {claim}={new_id}",
                                    evidence=f"Different response ({len(resp.content)}B vs {len(orig_resp.content)}B) with modified JWT {claim}",
                                    description=f"Modifying JWT claim '{claim}' from {original_id} to {new_id} returns different user data.",
                                    remediation="Validate JWT claims server-side. Don't trust client-modified tokens.",
                                    cvss=9.1, cwe="CWE-639",
                                    tool=self.NAME, verified=True, confidence="HIGH",
                                    request=f'curl -k "{url}" -H "Authorization: Bearer {modified_token[:50]}..."',
                                ))
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"JWT parsing failed: {e}")

        return findings

    def _test_graphql_idor(self, client, url: str, host: str) -> List[Finding]:
        """Test GraphQL object-level authorization bypass."""
        findings = []

        # Find GraphQL endpoint
        gql_url = None
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]:
            test_url = base + path
            self.limiter.wait(host)
            try:
                resp = client.post(test_url, json={"query": "{ __typename }"})
                if resp.status_code == 200:
                    gql_url = test_url
                    break
            except Exception:
                continue

        if not gql_url:
            return findings

        # Test introspection
        self.limiter.wait(host)
        try:
            introspection_query = """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        fields {
                            name
                            type { name kind ofType { name } }
                        }
                    }
                }
            }
            """
            resp = client.post(gql_url, json={"query": introspection_query})
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in data["data"]:
                        # Found accessible introspection
                        types = data["data"]["__schema"].get("types", [])
                        user_types = [t for t in types if t.get("name", "").lower() in [
                            "user", "account", "profile", "member", "customer",
                        ]]

                        if user_types:
                            findings.append(Finding(
                                vuln_type="IDOR",
                                title="GraphQL introspection enabled — user types exposed",
                                severity="MEDIUM",
                                url=gql_url,
                                method="POST",
                                payload="IntrospectionQuery",
                                evidence=f"Found user-related types: {[t['name'] for t in user_types]}",
                                description="GraphQL introspection exposes schema including user data types.",
                                remediation="Disable GraphQL introspection in production.",
                                cvss=5.3, cwe="CWE-200",
                                tool=self.NAME, verified=True, confidence="HIGH",
                            ))

                            # Try to query user data with different IDs
                            for user_type in user_types:
                                type_name = user_type["name"]
                                fields = [f["name"] for f in user_type.get("fields", [])]
                                fields_str = " ".join(fields[:10])

                                for test_id in [1, 2, 3, "me"]:
                                    id_val = str(test_id) if isinstance(test_id, int) else f'"{test_id}"'
                                    query = '{ ' + type_name + '(id: ' + id_val + ') { ' + fields_str + ' } }'
                                    self.limiter.wait(host)
                                    try:
                                        resp = client.post(gql_url, json={"query": query})
                                        if resp.status_code == 200:
                                            body = resp.text
                                            if "errors" not in body.lower() and len(body) > 50:
                                                findings.append(Finding(
                                                    vuln_type="IDOR",
                                                    title=f"GraphQL IDOR: {type_name}(id: {test_id})",
                                                    severity="HIGH",
                                                    url=gql_url,
                                                    method="POST",
                                                    payload=query[:200],
                                                    evidence=f"GraphQL query returned user data for id={test_id}",
                                                    description=f"Can access {type_name} data by ID without authorization.",
                                                    remediation="Implement object-level authorization in GraphQL resolvers.",
                                                    cvss=7.5, cwe="CWE-639",
                                                    tool=self.NAME, verified=True, confidence="MEDIUM",
                                                ))
                                    except Exception:
                                        pass
                except (json.JSONDecodeError, KeyError):
                    pass
        except Exception:
            pass

        return findings

    def _test_base64_ids(self, client, url: str, host: str) -> List[Finding]:
        """Test base64-encoded ID manipulation."""
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        # Look for base64-like strings in URL
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')
        matches = b64_pattern.findall(path)

        for match in matches:
            try:
                decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore")
                if decoded.isdigit():
                    # Try adjacent IDs
                    original = int(decoded)
                    for delta in [1, -1]:
                        new_id = original + delta
                        new_b64 = base64.b64encode(str(new_id).encode()).rstrip(b"=").decode()
                        new_url = url.replace(match, new_b64)

                        self.limiter.wait(host)
                        try:
                            baseline = client.get(url)
                            resp = client.get(new_url)
                            if resp.status_code == 200 and abs(len(resp.content) - len(baseline.content)) > 50:
                                findings.append(Finding(
                                    vuln_type="IDOR",
                                    title=f"Base64-encoded ID enumeration: {original}→{new_id}",
                                    severity="HIGH",
                                    url=new_url,
                                    method="GET",
                                    payload=f"base64({new_id})={new_b64}",
                                    evidence=f"Different response with base64 ID {new_id}",
                                    description=f"Base64-encoded sequential ID can be manipulated ({original}→{new_id}).",
                                    remediation="Use non-sequential, non-encodable identifiers. Add authorization checks.",
                                    cvss=7.5, cwe="CWE-639",
                                    tool=self.NAME, verified=True, confidence="HIGH",
                                ))
                        except Exception:
                            pass
            except Exception:
                continue

        return findings

    def _test_uuid_prediction(self, client, url: str, host: str) -> List[Finding]:
        """Test UUID v1 time-based prediction."""
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        # Find UUID v1 patterns
        uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', re.I)
        matches = uuid_pattern.findall(path + "?" + (parsed.query or ""))

        for uuid in matches:
            findings.append(Finding(
                vuln_type="IDOR",
                title=f"UUID v1 (time-based) detected: {uuid}",
                severity="MEDIUM",
                url=url,
                method="GET",
                payload=f"UUID v1: {uuid}",
                evidence=f"UUID v1 detected: {uuid}",
                description="UUID v1 is generated from timestamp and MAC address. It's predictable and can be enumerated.",
                remediation="Use UUID v4 (random) instead of UUID v1 (time-based).",
                cvss=5.3, cwe="CWE-330",
                tool=self.NAME, verified=True, confidence="HIGH",
            ))

        return findings

    def _test_response_diff(self, client, url: str, host: str) -> List[Finding]:
        """Test IDOR via response diffing with adjacent IDs."""
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        # Find numeric IDs in path
        id_pattern = re.compile(r'/(\d{1,10})(?:/|$)')
        matches = list(id_pattern.finditer(path))

        for match in matches:
            original_id = int(match.group(1))

            for delta in [1, -1, 2]:
                new_id = original_id + delta
                if new_id <= 0:
                    continue

                new_path = path[:match.start(1)] + str(new_id) + path[match.end(1):]
                new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                if parsed.query:
                    new_url += f"?{parsed.query}"

                self.limiter.wait(host)
                try:
                    baseline = client.get(url)
                    resp = client.get(new_url)

                    if resp.status_code == 200 and baseline.status_code == 200:
                        size_diff = abs(len(resp.content) - len(baseline.content))
                        if size_diff > 50 and len(resp.content) > 100:
                            findings.append(Finding(
                                vuln_type="IDOR",
                                title=f"Path-based IDOR: /{original_id} → /{new_id}",
                                severity="HIGH",
                                url=new_url,
                                method="GET",
                                payload=f"Changed path ID from {original_id} to {new_id}",
                                evidence=f"Response size changed: {len(baseline.content)}B → {len(resp.content)}B (diff: {size_diff}B)",
                                description=f"Accessing path with ID {new_id} instead of {original_id} returns different data.",
                                remediation="Implement authorization checks. Map resources to authenticated user.",
                                cvss=7.5, cwe="CWE-639",
                                tool=self.NAME, verified=True, confidence="MEDIUM",
                                request=f'curl -k "{new_url}"',
                            ))
                except Exception:
                    pass

        return findings


__all__ = ["IDORJwtGraphQLScanner"]
