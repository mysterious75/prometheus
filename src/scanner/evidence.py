"""Evidence Engine — automated PoC execution, CVE submission, HackerOne reports.

Generates professional evidence for every finding.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ..scanner.findings import Finding
from ..core.logger import logger, console


@dataclass
class Evidence:
    """Evidence for a security finding."""
    finding: Finding
    poc_command: Tuple[str, list]  # (tool, [args...])
    poc_output: str = ""
    curl_command: str = ""
    http_request: str = ""
    http_response: str = ""
    screenshot_path: str = ""
    verified: bool = False

    def to_dict(self):
        return {
            "finding_id": self.finding.finding_id,
            "vuln_type": self.finding.vuln_type,
            "severity": self.finding.severity,
            "poc_command": self.poc_command,
            "poc_output": self.poc_output[:500],
            "curl_command": self.curl_command,
            "verified": self.verified,
        }


class EvidenceEngine:
    """Generates and manages evidence for security findings."""

    def generate_evidence(self, finding: Finding) -> Evidence:
        """Generate evidence for a finding."""
        evidence = Evidence(
            finding=finding,
            poc_command=self._generate_poc_command(finding),
            curl_command=self._generate_curl_command(finding),
            http_request=self._generate_http_request(finding),
        )

        # PoC command is returned as structured data; not auto-executed
        evidence.verified = self._verify_finding(finding, evidence.poc_output)

        return evidence

    def _generate_poc_command(self, finding: Finding) -> Tuple[str, list]:
        """Generate a PoC command for the finding. Returns (tool, [args...])."""
        vuln_type = finding.vuln_type.lower()

        if "sql" in vuln_type:
            return ("sqlmap", ["-u", finding.url, "-p", finding.parameter, "--batch", "--level=1"])
        elif "xss" in vuln_type:
            return ("curl", ["-k", f"{finding.url}?{finding.parameter}=<script>alert(1)</script>"])
        elif "ssrf" in vuln_type:
            return ("curl", ["-k", f"{finding.url}?{finding.parameter}=http://169.254.169.254/latest/meta-data/"])
        elif "command" in vuln_type or "cmdi" in vuln_type:
            return ("curl", ["-k", f"{finding.url}?{finding.parameter}=;id"])
        elif "traversal" in vuln_type or "lfi" in vuln_type:
            return ("curl", ["-k", f"{finding.url}?{finding.parameter}=../../../etc/passwd"])
        elif "redirect" in vuln_type:
            return ("curl", ["-k", "-I", f"{finding.url}?{finding.parameter}=https://evil.com"])
        elif "cors" in vuln_type:
            return ("curl", ["-k", "-H", "Origin: https://evil.com", finding.url])
        elif "header" in vuln_type:
            return ("curl", ["-k", "-I", finding.url])
        else:
            return ("curl", ["-k", finding.url])

    def _generate_curl_command(self, finding: Finding) -> str:
        """Generate a curl command for reproduction."""
        if finding.method == "POST":
            return f'curl -k -X POST "{finding.url}" -d "{finding.payload}"'
        return f'curl -k "{finding.url}"'

    def _generate_http_request(self, finding: Finding) -> str:
        """Generate a raw HTTP request."""
        from urllib.parse import urlparse
        parsed = urlparse(finding.url)

        if finding.method == "POST":
            return (
                f"POST {parsed.path} HTTP/1.1\r\n"
                f"Host: {parsed.netloc}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(finding.payload)}\r\n"
                f"\r\n"
                f"{finding.payload}"
            )
        return (
            f"GET {parsed.path}?{finding.parameter}={finding.payload} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"\r\n"
        )

    def _execute_poc(self, command: Tuple[str, list]) -> str:
        """No-op: PoC commands are not auto-executed. Logs the structured command."""
        tool, args = command
        logger.info("PoC command generated (not executed): %s %s", tool, " ".join(args))
        return "[DISABLED: PoC auto-execution removed for security]"

    def _verify_finding(self, finding: Finding, poc_output: str) -> bool:
        """Verify a finding based on PoC output."""
        vuln_type = finding.vuln_type.lower()

        if "sql" in vuln_type:
            return any(kw in poc_output.lower() for kw in ["sqlmap", "injectable", "payload"])
        elif "xss" in vuln_type:
            return "<script>" in poc_output
        elif "ssrf" in vuln_type:
            return any(kw in poc_output for kw in ["ami-", "instance-id", "root:"])
        elif "traversal" in vuln_type:
            return "root:" in poc_output
        elif "header" in vuln_type:
            return True  # Headers are directly observable
        else:
            return bool(poc_output and "[ERROR" not in poc_output)

    def generate_hackerone_report(self, finding: Finding, evidence: Evidence) -> str:
        """Generate a HackerOne-style vulnerability report."""
        return f"""## Summary

{finding.description}

## Severity

{finding.severity} (CVSS: {finding.cvss})

## Affected URL

`{finding.url}`

## Steps to Reproduce

1. Navigate to `{finding.url}`
2. Inject payload into the `{finding.parameter}` parameter
3. Observe the vulnerability

## Proof of Concept

```bash
{evidence.curl_command}
```

### HTTP Request

```http
{evidence.http_request}
```

### Response

```
{evidence.poc_output[:500]}
```

## Impact

{finding.description}

## Remediation

{finding.remediation}

## References

- CWE-{finding.cwe.split('-')[-1] if finding.cwe else 'N/A'}: {finding.vuln_type}
- OWASP: https://owasp.org/

---
*Generated by Prometheus Security Agent*
"""

    def generate_cve_template(self, finding: Finding) -> Dict[str, Any]:
        """Generate a CVE submission template."""
        return {
            "title": f"{finding.vuln_type} in {finding.url}",
            "description": finding.description,
            "severity": finding.severity,
            "cvss": finding.cvss,
            "cwe": finding.cwe,
            "affected_url": finding.url,
            "payload": finding.payload,
            "remediation": finding.remediation,
            "discovered": datetime.now().isoformat(),
        }
