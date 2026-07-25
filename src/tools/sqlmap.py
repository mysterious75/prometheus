"""SQLMap Wrapper — automated SQL injection detection and exploitation.

Falls back to basic SQLi detection if sqlmap binary is not installed.
"""

import time
import re
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class SQLInjectionScanner(BaseTool):
    """Wrapper around sqlmap for SQL injection testing."""

    name = "sqlmap"
    binary = "sqlmap"
    description = "Automated SQL injection detection and exploitation"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Test a URL for SQL injection vulnerabilities."""
        if not self.installed:
            return self._fallback_scan(target, **kwargs)

        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",          # non-interactive
            "--level=1",        # test level
            "--risk=1",         # risk level
            "--random-agent",   # random user agent
            "--output-dir=/tmp/sqlmap_output",
        ]

        if kwargs.get("forms"):
            cmd.append("--forms")
        if kwargs.get("level"):
            cmd.extend([f"--level={kwargs['level']}"])
        if kwargs.get("dbms"):
            cmd.extend([f"--dbms={kwargs['dbms']}"])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        duration = time.time() - start

        findings = []
        if "is vulnerable" in result.stdout.lower() or "injectable" in result.stdout.lower():
            # Parse sqlmap output for injection details
            injections = re.findall(
                r"Parameter: (.+?)\n\s+Type: (.+?)\n",
                result.stdout,
            )
            for param, inj_type in injections:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "url": target,
                    "parameter": param.strip(),
                    "injection_type": inj_type.strip(),
                    "cvss": 9.8,
                })

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, target: str, **kwargs) -> ToolResult:
        """Basic SQLi detection using Python httpx."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings = []
        start = time.time()

        sql_payloads = [
            "'", "\"", "1' OR '1'='1", "1 OR 1=1", "' OR ''='",
            "1' AND SLEEP(3)--", "1' WAITFOR DELAY '0:0:3'--",
        ]

        sql_errors = [
            "sql syntax", "mysql_fetch", "sqlite3", "postgresql",
            "ORA-", "unclosed quotation", "incorrect syntax",
            "quoted string not properly terminated",
            "you have an error in your sql", "microsoft ole db",
            "microsoft access", "jdbc", "sqlstate",
        ]

        client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

        # Get baseline response
        try:
            baseline = client.get(target)
            baseline_len = len(baseline.text)
        except Exception as e:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error=str(e),
                duration=time.time() - start,
            )

        # Test each parameter in the URL
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # If no params, try common ones
            params = {"id": ["1"], "page": ["1"], "q": ["test"]}

        for param_name in params:
            for payload in sql_payloads:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                test_url = urlunparse(parsed._replace(
                    query=urlencode(test_params)
                ))

                try:
                    start_req = time.time()
                    resp = client.get(test_url)
                    elapsed = time.time() - start_req
                    body = resp.text.lower()

                    for error in sql_errors:
                        if error.lower() in body:
                            findings.append({
                                "type": "SQL Injection",
                                "severity": "CRITICAL",
                                "url": target,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": error,
                                "cvss": 9.8,
                            })
                            break

                    # Time-based detection
                    if "SLEEP" in payload.upper() and elapsed > 2.5:
                        findings.append({
                            "type": "SQL Injection (Time-based)",
                            "severity": "CRITICAL",
                            "url": target,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Response time: {elapsed:.1f}s",
                            "cvss": 9.8,
                        })

                except Exception:
                    continue

        duration = time.time() - start
        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )
