"""403/401 Bypass Scanner — tests for access control bypasses.

Inspired by NoMore403 (devploit). Tests multiple bypass categories:
- Path mutations (20+ techniques)
- HTTP method override headers
- IP spoofing headers
- Protocol bypasses
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from ..core.logger import logger, log_tool_start, log_tool_result, log_finding
from ..core.ratelimit import get_limiter
from .findings import Finding


# ---------------------------------------------------------------------------
# Bypass technique definitions
# ---------------------------------------------------------------------------

@dataclass
class BypassTechnique:
    """A single bypass technique to test."""
    name: str
    category: str  # path_mutation, header_override, ip_spoof, protocol
    description: str
    transform_url: Optional[str] = None  # mutated URL (if path mutation)
    headers: Optional[Dict[str, str]] = None  # extra headers
    method: Optional[str] = None  # override HTTP method
    body: Optional[str] = None  # request body (for protocol bypasses)


def _build_path_mutations(path: str) -> List[BypassTechnique]:
    """Generate 20+ path mutation techniques."""
    techniques = []

    mutations = [
        ("double_slash", f"//{path.lstrip('/')}", "Double slash prefix"),
        ("trailing_slash", f"{path}/", "Trailing slash"),
        ("dot_suffix", f"{path}/.", "Dot suffix"),
        ("dot_prefix", f"/./{path.lstrip('/')}", "Dot prefix path"),
        ("double_slash_both", f"//{path.lstrip('/')}//", "Double slash both ends"),
        ("space_suffix", f"{path}%20", "URL-encoded space suffix"),
        ("tab_suffix", f"{path}%09", "URL-encoded tab suffix"),
        ("null_byte", f"{path}%00", "Null byte suffix"),
        ("encoded_slash", f"/%2f/{path.lstrip('/')}", "Encoded slash prefix"),
        ("encoded_dot", f"/%2e/{path.lstrip('/')}", "Encoded dot prefix"),
        ("semicolon", f"{path}..;/", "Semicolon path traversal"),
        ("json_extension", f"{path}.json", "JSON extension suffix"),
        ("encoded_dot_suffix", f"{path}%2e", "Encoded dot suffix"),
        ("uppercase", path.upper(), "Uppercase path"),
        ("mixed_case", _mixed_case(path), "Mixed case path"),
        ("semicolon_suffix", f"{path};", "Semicolon suffix"),
        ("question_mark", f"{path}?", "Question mark suffix"),
        ("hash_suffix", f"{path}#", "Hash fragment suffix"),
        ("encoded_slash_suffix", f"{path}%2f", "Encoded slash suffix"),
        ("unicode_slash", f"/\u2215{path.lstrip('/')}", "Unicode slash prefix"),
    ]

    for name, mutated, desc in mutations:
        techniques.append(BypassTechnique(
            name=name,
            category="path_mutation",
            description=desc,
            transform_url=mutated,
        ))

    return techniques


def _mixed_case(path: str) -> str:
    """Alternate upper/lower case per character."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(path))


def _build_header_overrides() -> List[BypassTechnique]:
    """HTTP method override header techniques."""
    techniques = []
    headers_list = [
        ("x-http-method-override", "GET", "X-HTTP-Method-Override header"),
        ("x-method-override", "GET", "X-Method-Override header"),
        ("x-http-method", "GET", "X-HTTP-Method header"),
        ("x-original-method", "GET", "X-Original-Method header"),
        ("x-rewrite-method", "GET", "X-Rewrite-Method header"),
    ]
    for name, value, desc in headers_list:
        techniques.append(BypassTechnique(
            name=name,
            category="header_override",
            description=desc,
            headers={name: value},
        ))
    return techniques


def _build_ip_spoof_headers() -> List[BypassTechnique]:
    """IP spoofing header techniques."""
    techniques = []
    headers_list = [
        ("x-forwarded-for-local", {"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For: 127.0.0.1"),
        ("x-forwarded-for-localhost", {"X-Forwarded-For": "localhost"}, "X-Forwarded-For: localhost"),
        ("x-real-ip", {"X-Real-IP": "127.0.0.1"}, "X-Real-IP: 127.0.0.1"),
        ("x-originating-ip", {"X-Originating-IP": "127.0.0.1"}, "X-Originating-IP: 127.0.0.1"),
        ("x-remote-ip", {"X-Remote-IP": "127.0.0.1"}, "X-Remote-IP: 127.0.0.1"),
        ("x-client-ip", {"X-Client-IP": "127.0.0.1"}, "X-Client-IP: 127.0.0.1"),
        ("x-remote-addr", {"X-Remote-Addr": "127.0.0.1"}, "X-Remote-Addr: 127.0.0.1"),
        ("x-forwarded-host", {"X-Forwarded-Host": "localhost"}, "X-Forwarded-Host: localhost"),
        ("x-host", {"X-Host": "localhost"}, "X-Host: localhost"),
        ("x-proxy-url", {"X-Proxy-URL": "http://localhost"}, "X-Proxy-URL: http://localhost"),
    ]
    for name, headers, desc in headers_list:
        techniques.append(BypassTechnique(
            name=name,
            category="ip_spoof",
            description=desc,
            headers=headers,
        ))
    return techniques


def _build_protocol_bypasses() -> List[BypassTechnique]:
    """Protocol-level bypass techniques."""
    return [
        BypassTechnique(
            name="empty_post_body",
            category="protocol",
            description="POST with Content-Length: 0",
            method="POST",
            headers={"Content-Length": "0"},
            body="",
        ),
        BypassTechnique(
            name="chunked_encoding",
            category="protocol",
            description="Transfer-Encoding: chunked",
            method="POST",
            headers={"Transfer-Encoding": "chunked"},
            body="0\r\n\r\n",
        ),
        BypassTechnique(
            name="content_type_json",
            category="protocol",
            description="Content-Type: application/json",
            headers={"Content-Type": "application/json"},
        ),
        BypassTechnique(
            name="content_type_xml",
            category="protocol",
            description="Content-Type: application/xml",
            headers={"Content-Type": "application/xml"},
        ),
    ]


# ---------------------------------------------------------------------------
# Baseline response
# ---------------------------------------------------------------------------

@dataclass
class BaselineResponse:
    """Captured baseline (blocked) response for comparison."""
    status_code: int = 0
    content_length: int = 0
    body_hash: str = ""
    body_snippet: str = ""  # first 500 chars


class BypassScanner:
    """Tests for 403/401 access control bypasses."""

    NAME = "bypass_403"

    def __init__(self, rps: float = 10.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, methods: List[str] = None) -> List[Finding]:
        """Scan a URL for 403/401 bypass vulnerabilities.

        Args:
            url: Target URL that returns 403 or 401.
            methods: HTTP methods to test (default: GET).

        Returns:
            List of Finding objects for successful bypasses.
        """
        import httpx

        if methods is None:
            methods = ["GET"]

        log_tool_start(self.NAME, url)
        findings: List[Finding] = []

        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"

        # Build all techniques
        techniques: List[BypassTechnique] = []
        techniques.extend(_build_path_mutations(path))
        techniques.extend(_build_header_overrides())
        techniques.extend(_build_ip_spoof_headers())
        techniques.extend(_build_protocol_bypasses())

        client = httpx.Client(
            verify=False,
            timeout=self.timeout,
            follow_redirects=False,  # Important: don't follow redirects for bypass detection
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        )

        try:
            # Step 1: Capture baseline
            baseline = self._capture_baseline(client, url, host)
            if baseline.status_code not in (401, 403):
                logger.info(f"Baseline returned {baseline.status_code} (not 401/403) — still testing")

            # Step 2: Test each technique
            for technique in techniques:
                for method in methods:
                    self.limiter.wait(host)
                    finding = self._test_technique(
                        client, url, technique, method, baseline
                    )
                    if finding:
                        findings.append(finding)
                        log_finding(finding.severity, self.NAME, finding.url, technique.description)

        finally:
            client.close()

        log_tool_result(self.NAME, f"{len(findings)} bypasses found out of {len(techniques)} techniques")
        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _capture_baseline(
        self, client: "httpx.Client", url: str, host: str
    ) -> BaselineResponse:
        """Send a normal GET request to capture the blocked response."""
        self.limiter.wait(host)
        try:
            resp = client.get(url)
            body = resp.text[:500]
            import hashlib
            body_hash = hashlib.md5(resp.content).hexdigest()
            return BaselineResponse(
                status_code=resp.status_code,
                content_length=len(resp.content),
                body_hash=body_hash,
                body_snippet=body,
            )
        except Exception as e:
            logger.debug(f"Baseline request failed: {e}")
            return BaselineResponse()

    def _test_technique(
        self,
        client: "httpx.Client",
        original_url: str,
        technique: BypassTechnique,
        method: str,
        baseline: BaselineResponse,
    ) -> Optional[Finding]:
        """Test a single bypass technique and compare with baseline."""
        import hashlib

        parsed = urlparse(original_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Determine the target URL
        if technique.transform_url:
            target_url = base + technique.transform_url
        else:
            target_url = original_url

        # Build headers
        headers: Dict[str, str] = {}
        if technique.headers:
            headers.update(technique.headers)

        # Determine method
        http_method = technique.method or method

        try:
            if http_method == "POST":
                resp = client.post(
                    target_url,
                    headers=headers,
                    content=technique.body if technique.body is not None else None,
                )
            else:
                resp = client.request(
                    http_method,
                    target_url,
                    headers=headers,
                )
        except Exception as e:
            logger.debug(f"Request failed for {technique.name}: {e}")
            return None

        # Compare with baseline
        body = resp.content
        body_hash = hashlib.md5(body).hexdigest()
        status = resp.status_code
        content_length = len(body)

        bypass_detected = False
        evidence_parts: List[str] = []

        # Check 1: Status code changed from blocked to allowed
        if baseline.status_code in (401, 403) and status not in (401, 403):
            bypass_detected = True
            evidence_parts.append(
                f"Status changed: {baseline.status_code} → {status}"
            )

        # Check 2: Same status but significantly different content
        if baseline.status_code == status and baseline.body_hash != body_hash:
            # Verify it's not just a different error page
            if content_length > baseline.content_length * 1.5 or content_length < baseline.content_length * 0.5:
                if content_length > 100:  # Not empty
                    bypass_detected = True
                    evidence_parts.append(
                        f"Content changed: {baseline.content_length}B → {content_length}B"
                    )

        # Check 3: Redirect to a non-error page
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if location and "login" not in location.lower() and "error" not in location.lower():
                bypass_detected = True
                evidence_parts.append(f"Redirect to: {location}")

        if not bypass_detected:
            return None

        # Build evidence
        evidence = " | ".join(evidence_parts)
        evidence += f" | Technique: {technique.name} ({technique.description})"
        evidence += f" | URL: {target_url}"

        # Generate curl PoC
        curl_cmd = self._build_curl_poc(target_url, http_method, headers, technique.body)

        # Determine severity
        if status == 200:
            severity = "HIGH"
            confidence = "HIGH"
        elif status in (301, 302, 303, 307, 308):
            severity = "MEDIUM"
            confidence = "MEDIUM"
        else:
            severity = "MEDIUM"
            confidence = "MEDIUM"

        return Finding(
            vuln_type="bypass_403",
            title=f"403/401 Bypass via {technique.description}",
            severity=severity,
            url=target_url,
            method=http_method,
            payload=technique.transform_url or str(technique.headers),
            evidence=evidence[:500],
            description=(
                f"Access control bypass using {technique.category} technique "
                f"'{technique.name}'. Baseline response was {baseline.status_code}, "
                f"but the bypass returned {status}."
            ),
            remediation=(
                "Implement access control at the application layer, not just "
                "at the web server/reverse proxy level. Validate the canonical "
                "path and don't rely on URL pattern matching alone."
            ),
            cwe="CWE-284",
            tool=self.NAME,
            verified=True,
            confidence=confidence,
            request=curl_cmd,
            response_snippet=resp.text[:500] if resp.text else "",
        )

    def _build_curl_poc(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
    ) -> str:
        """Generate a curl PoC command."""
        parts = ["curl -k -i"]

        if method != "GET":
            parts.append(f'-X {method}')

        for k, v in headers.items():
            parts.append(f'-H "{k}: {v}"')

        if body is not None:
            parts.append(f'-d "{body}"')

        parts.append(f'"{url}"')
        return " ".join(parts)
