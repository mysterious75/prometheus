"""Race Condition Scanner — tests for TOCTOU and race vulnerabilities."""

import concurrent.futures
import time
from typing import List
from urllib.parse import urlparse

from .base import BaseScanner
from .findings import Finding
from ..core.transport import ssl_verify


class RaceConditionScanner(BaseScanner):
    """Tests for race condition vulnerabilities."""

    NAME = "race"

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Test for race conditions by sending concurrent requests."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=10, verify=ssl_verify(),
                              headers={"User-Agent": "Mozilla/5.0"})

        # Send 20 concurrent requests
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(client.get, url) for _ in range(20)]
            for f in concurrent.futures.as_completed(futures):
                try:
                    resp = f.result()
                    results.append(resp)
                except Exception:
                    continue

        if len(results) < 10:
            return findings

        # Check for inconsistent responses
        status_codes = [r.status_code for r in results]
        unique_statuses = set(status_codes)

        if len(unique_statuses) > 1:
            # Different status codes = potential race condition
            findings.append(Finding(
                vuln_type="Race Condition",
                title="Inconsistent responses under concurrent load",
                severity="MEDIUM",
                url=url,
                method="GET",
                evidence=f"Status codes: {dict((s, status_codes.count(s)) for s in unique_statuses)}",
                description="Server returns different responses to identical concurrent requests. May indicate race condition.",
                remediation="Implement proper locking/queuing for critical operations.",
                cvss=5.3,
                cwe="CWE-362",
                tool=self.NAME,
                verified=False,
                confidence="LOW",
            ))

        # Check for timing anomalies
        times = []
        for r in results:
            if hasattr(r, 'elapsed'):
                times.append(r.elapsed.total_seconds())

        if times:
            avg = sum(times) / len(times)
            outliers = [t for t in times if t > avg * 3]
            if outliers:
                findings.append(Finding(
                    vuln_type="Race Condition",
                    title="Timing anomaly under concurrent load",
                    severity="LOW",
                    url=url,
                    evidence=f"Avg: {avg:.2f}s, Outliers: {[f'{t:.2f}s' for t in outliers[:3]]}",
                    description="Significant timing variations under concurrent load suggest resource contention.",
                    remediation="Review for TOCTOU vulnerabilities in critical paths.",
                    cvss=3.1,
                    cwe="CWE-362",
                    tool=self.NAME,
                    verified=False,
                    confidence="LOW",
                ))

        return findings
