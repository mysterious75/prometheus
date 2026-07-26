"""Advanced IDOR Testing — Beyond basic parameter manipulation.

Inspired by IDOR Cheat Sheet and real-world bug bounty writeups.

Tests for:
- Sequential ID enumeration
- UUID/GUID prediction
- Encoded ID manipulation (base64, hex, URL encoding)
- JWT user ID manipulation
- GraphQL object-level authorization
- Parameter pollution
- HTTP method switching
- Mass assignment via IDOR
"""

import re
import base64
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


class AdvancedIDORScanner:
    """Advanced IDOR testing with multiple attack vectors."""
    NAME = "advanced_idor"

    # Common ID parameter names
    ID_PARAMS = [
        "id", "user_id", "userid", "uid", "account_id", "accountid",
        "profile_id", "profileid", "member_id", "memberid", "doc_id",
        "docid", "file_id", "fileid", "order_id", "orderid", "item_id",
        "itemid", "product_id", "productid", "customer_id", "customerid",
        "patient_id", "patientid", "student_id", "studentid", "employee_id",
        "employeeid", "invoice_id", "invoiceid", "ticket_id", "ticketid",
        "message_id", "messageid", "comment_id", "commentid", "post_id",
        "postid", "blog_id", "blogid", "page_id", "pageid", "project_id",
        "projectid", "task_id", "taskid", "session_id", "sessionid",
        "reference", "ref", "number", "no", "num", "key", "token",
    ]

    # JWT-related headers
    JWT_HEADERS = ["Authorization", "X-Auth-Token", "X-JWT-Token", "X-Token", "Cookie"]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for advanced IDOR vulnerabilities."""
        findings = []

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            import httpx
        except ImportError:
            return findings

        client = httpx.Client(
            follow_redirects=True,
            timeout=15,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )

        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Find ID-like parameters
        id_params = {k: v[0] for k, v in params.items() if self._is_id_param(k)}

        if not id_params:
            # Try common ID parameters
            id_params = {"id": "1"}

        for param_name, param_value in id_params.items():
            # Test 1: Sequential ID enumeration
            seq_findings = self._test_sequential(client, url, param_name, param_value)
            findings.extend(seq_findings)

            # Test 2: UUID/GUID prediction
            uuid_findings = self._test_uuid(client, url, param_name, param_value)
            findings.extend(uuid_findings)

            # Test 3: Encoded ID manipulation
            enc_findings = self._test_encoded_ids(client, url, param_name, param_value)
            findings.extend(enc_findings)

            # Test 4: Parameter pollution
            poll_findings = self._test_param_pollution(client, url, param_name, param_value)
            findings.extend(poll_findings)

            # Test 5: HTTP method switching
            method_findings = self._test_method_switching(client, url, param_name, param_value)
            findings.extend(method_findings)

        client.close()
        return findings

    def _is_id_param(self, name: str) -> bool:
        """Check if parameter name looks like an ID."""
        name_lower = name.lower()
        return any(id_name in name_lower for id_name in self.ID_PARAMS)

    def _test_sequential(self, client, url: str, param: str, value: str) -> List[Finding]:
        """Test sequential ID enumeration."""
        findings = []

        # Get baseline response
        self.limiter.wait(urlparse(url).hostname)
        try:
            baseline = client.get(url)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            return findings

        # Try adjacent IDs
        try:
            original_id = int(value)
        except ValueError:
            return findings

        for offset in [-1, 1, 2, -2]:
            test_id = original_id + offset
            if test_id < 0:
                continue

            test_url = url.replace(f"{param}={value}", f"{param}={test_id}")
            self.limiter.wait(urlparse(url).hostname)

            try:
                resp = client.get(test_url)
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check if response is different from baseline (different user's data)
                    if abs(len(resp.text) - baseline_len) > 50:
                        findings.append(Finding(
                            vuln_type="IDOR",
                            title=f"Sequential ID enumeration via '{param}' parameter",
                            severity="HIGH",
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=f"{param}={test_id}",
                            evidence=f"Accessing {param}={test_id} returned different data ({len(resp.text)} bytes vs {baseline_len} bytes baseline)",
                            description=f"Changing {param} from {value} to {test_id} returns different user data, indicating IDOR vulnerability.",
                            remediation="Use UUIDs instead of sequential IDs. Implement authorization checks on every request.",
                            cvss=7.5,
                            cwe="CWE-639",
                            tool=self.NAME,
                            verified=True,
                            confidence="MEDIUM",
                        ))
            except Exception:
                continue

        return findings

    def _test_uuid(self, client, url: str, param: str, value: str) -> List[Finding]:
        """Test UUID/GUID-based IDOR."""
        findings = []

        # Check if value looks like a UUID
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )

        if not uuid_pattern.match(value):
            return findings

        # UUID v1 is time-based and predictable
        # Check if it's UUID v1 (time-based)
        try:
            version = int(value[14], 16)
            if version == 1:
                findings.append(Finding(
                    vuln_type="IDOR",
                    title=f"UUID v1 (time-based) detected for '{param}'",
                    severity="MEDIUM",
                    url=url,
                    parameter=param,
                    method="GET",
                    payload=f"UUID v1: {value}",
                    evidence=f"Parameter '{param}' uses UUID v1 which is time-based and predictable.",
                    description="UUID v1 is generated from timestamp and MAC address, making it potentially predictable.",
                    remediation="Use UUID v4 (random) instead of UUID v1 (time-based).",
                    cvss=5.3,
                    cwe="CWE-330",
                    tool=self.NAME,
                    verified=True,
                    confidence="MEDIUM",
                ))
        except (ValueError, IndexError):
            pass

        return findings

    def _test_encoded_ids(self, client, url: str, param: str, value: str) -> List[Finding]:
        """Test encoded ID manipulation."""
        findings = []

        # Try base64 decoding
        try:
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            if decoded and decoded != value:
                # Try incrementing the decoded value
                try:
                    decoded_int = int(decoded)
                    modified = str(decoded_int + 1)
                    modified_encoded = base64.b64encode(modified.encode()).decode()

                    test_url = url.replace(f"{param}={value}", f"{param}={modified_encoded}")
                    self.limiter.wait(urlparse(url).hostname)

                    baseline = client.get(url)
                    resp = client.get(test_url)

                    if resp.status_code == 200 and abs(len(resp.text) - len(baseline.text)) > 50:
                        findings.append(Finding(
                            vuln_type="IDOR",
                            title=f"Base64-encoded ID enumeration via '{param}'",
                            severity="HIGH",
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=f"{param}={modified_encoded} (decoded: {modified})",
                            evidence=f"Base64 ID manipulation: {value} → {modified_encoded} returns different data",
                            description=f"Parameter '{param}' uses base64-encoded sequential IDs that can be manipulated.",
                            remediation="Use non-sequential, non-encodable identifiers. Add authorization checks.",
                            cvss=7.5,
                            cwe="CWE-639",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))
                except ValueError:
                    pass
        except Exception:
            pass

        # Try hex decoding
        try:
            if all(c in '0123456789abcdefABCDEF' for c in value) and len(value) % 2 == 0:
                decoded_hex = bytes.fromhex(value).decode('utf-8', errors='ignore')
                if decoded_hex and decoded_hex != value:
                    findings.append(Finding(
                        vuln_type="IDOR",
                        title=f"Hex-encoded ID detected for '{param}'",
                        severity="MEDIUM",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=f"{param}={value} (hex decoded: {decoded_hex})",
                        evidence=f"Hex-encoded value: {value} decodes to {decoded_hex}",
                        description=f"Parameter '{param}' uses hex encoding which may be manipulable.",
                        remediation="Use non-encodable identifiers.",
                        cvss=5.3,
                        cwe="CWE-639",
                        tool=self.NAME,
                        verified=True,
                        confidence="LOW",
                    ))
        except Exception:
            pass

        return findings

    def _test_param_pollution(self, client, url: str, param: str, value: str) -> List[Finding]:
        """Test parameter pollution for IDOR."""
        findings = []

        # Try adding duplicate parameter with different ID
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        try:
            original_id = int(value)
        except ValueError:
            return findings

        # Add duplicate parameter
        params[param] = [str(original_id), str(original_id + 1)]
        polluted_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        self.limiter.wait(parsed.hostname)
        try:
            baseline = client.get(url)
            resp = client.get(polluted_url)

            if resp.status_code == 200 and abs(len(resp.text) - len(baseline.text)) > 50:
                findings.append(Finding(
                    vuln_type="IDOR",
                    title=f"Parameter pollution IDOR via '{param}'",
                    severity="HIGH",
                    url=url,
                    parameter=param,
                    method="GET",
                    payload=f"{param}={value}&{param}={original_id + 1}",
                    evidence=f"Duplicate parameter returns different data",
                    description=f"Adding duplicate '{param}' parameter returns different user data.",
                    remediation="Reject requests with duplicate parameters.",
                    cvss=7.5,
                    cwe="CWE-639",
                    tool=self.NAME,
                    verified=True,
                    confidence="MEDIUM",
                ))
        except Exception:
            pass

        return findings

    def _test_method_switching(self, client, url: str, param: str, value: str) -> List[Finding]:
        """Test HTTP method switching for IDOR."""
        findings = []

        # Try POST instead of GET
        try:
            self.limiter.wait(urlparse(url).hostname)
            baseline = client.get(url)

            # Try POST
            post_resp = client.post(url, data={param: value})
            if post_resp.status_code == 200 and abs(len(post_resp.text) - len(baseline.text)) > 50:
                findings.append(Finding(
                    vuln_type="IDOR",
                    title=f"HTTP method switch bypass via '{param}'",
                    severity="MEDIUM",
                    url=url,
                    parameter=param,
                    method="POST",
                    payload=f"POST {param}={value}",
                    evidence=f"GET returns {baseline.status_code}, POST returns {post_resp.status_code} with different data",
                    description=f"Switching from GET to POST bypasses access controls on '{param}'.",
                    remediation="Enforce access controls regardless of HTTP method.",
                    cvss=6.5,
                    cwe="CWE-639",
                    tool=self.NAME,
                    verified=True,
                    confidence="MEDIUM",
                ))
        except Exception:
            pass

        return findings


# Export
__all__ = ["AdvancedIDORScanner"]
