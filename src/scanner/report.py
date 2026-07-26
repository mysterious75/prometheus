"""Report Generator — creates professional security reports.

Output formats: Markdown, HTML, JSON.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from .findings import ScanResult, Finding
from ..core.config import config


class ReportGenerator:
    """Generates professional security assessment reports."""

    def generate_markdown(self, result: ScanResult) -> str:
        """Generate a Markdown report."""
        lines = []
        lines.append(f"# 🔒 Security Assessment Report")
        lines.append(f"")
        lines.append(f"**Target:** {result.target}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"**Duration:** {result.duration:.1f}s")
        lines.append(f"")

        # Executive Summary
        summary = result.summary()
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| 🔴 CRITICAL | {summary['critical']} |")
        lines.append(f"| 🟠 HIGH | {summary['high']} |")
        lines.append(f"| 🟡 MEDIUM | {summary['medium']} |")
        lines.append(f"| 🔵 LOW | {summary['low']} |")
        lines.append(f"| **Total** | **{summary['total']}** |")
        lines.append(f"")

        if not result.findings:
            lines.append(f"✅ **No vulnerabilities found.** The target appears to be secure against the tests performed.")
            lines.append(f"")
            lines.append(f"**Note:** This does not guarantee the target is completely secure. "
                        f"Manual testing and additional tools may uncover issues not detectable by automated scanning.")
            return "\n".join(lines)

        # Critical Findings
        if result.critical:
            lines.append(f"## 🔴 Critical Findings")
            lines.append(f"")
            for f in sorted(result.critical, key=lambda x: x.cvss if x.cvss > 0 else -1, reverse=True):
                lines.extend(self._finding_section(f))

        # High Findings
        if result.high:
            lines.append(f"## 🟠 High Findings")
            lines.append(f"")
            for f in sorted(result.high, key=lambda x: x.cvss if x.cvss > 0 else -1, reverse=True):
                lines.extend(self._finding_section(f))

        # Medium Findings
        if result.medium:
            lines.append(f"## 🟡 Medium Findings")
            lines.append(f"")
            for f in sorted(result.medium, key=lambda x: x.cvss if x.cvss > 0 else -1, reverse=True):
                lines.extend(self._finding_section(f))

        # Low Findings
        if result.low:
            lines.append(f"## 🔵 Low Findings")
            lines.append(f"")
            for f in sorted(result.low, key=lambda x: x.cvss if x.cvss > 0 else -1, reverse=True):
                lines.extend(self._finding_section(f))

        # Crawl Summary
        if result.crawl:
            crawl = result.crawl
            lines.append(f"## Appendix: Attack Surface")
            lines.append(f"")
            lines.append(f"- URLs discovered: {len(crawl.urls)}")
            lines.append(f"- Forms found: {len(crawl.forms)}")
            lines.append(f"- JS files: {len(crawl.js_files)}")
            lines.append(f"- API endpoints: {len(crawl.api_endpoints)}")
            lines.append(f"- Emails: {len(crawl.emails)}")
            if crawl.technologies:
                lines.append(f"- Technologies: {', '.join(crawl.technologies)}")
            lines.append(f"")

        # Methodology
        lines.append(f"## Methodology")
        lines.append(f"")
        lines.append(f"This assessment was conducted using Prometheus v3.0, an AI-powered security scanner.")
        lines.append(f"Tests performed include:")
        lines.append(f"- SQL Injection (error-based, time-based, boolean-based)")
        lines.append(f"- Cross-Site Scripting (reflected, context-aware)")
        lines.append(f"- Server-Side Request Forgery")
        lines.append(f"- OS Command Injection")
        lines.append(f"- Path Traversal / Local File Inclusion")
        lines.append(f"- Server-Side Template Injection")
        lines.append(f"- XML External Entity Injection")
        lines.append(f"- HTTP Request Smuggling")
        lines.append(f"- Open Redirect")
        lines.append(f"- CORS Misconfiguration")
        lines.append(f"- IDOR / Broken Access Control")
        lines.append(f"- Sensitive File Exposure")
        lines.append(f"- Security Header Analysis")
        lines.append(f"- Race Condition Testing")
        lines.append(f"- Default Credential Testing")
        lines.append(f"")
        if all(f.verified for f in result.findings):
            lines.append(f"**All findings are verified** — no false positives.")
        else:
            lines.append(f"**Findings reported as detected** — manual verification recommended.")
        lines.append(f"")

        return "\n".join(lines)

    def _finding_section(self, f: Finding) -> list:
        """Generate markdown for a single finding."""
        lines = []
        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")

        lines.append(f"### {severity_icon} {f.title}")
        lines.append(f"")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Type** | {f.vuln_type} |")
        lines.append(f"| **Severity** | {f.severity} |")
        lines.append(f"| **URL** | `{f.url}` |")
        if f.parameter:
            lines.append(f"| **Parameter** | `{f.parameter}` |")
        lines.append(f"| **CVSS** | {f.cvss} |")
        if f.cwe:
            lines.append(f"| **CWE** | {f.cwe} |")
        lines.append(f"| **Confidence** | {f.confidence} |")
        lines.append(f"| **Verified** | {'✅ Yes' if f.verified else '⚠️ No'} |")
        lines.append(f"")

        lines.append(f"**Description:** {f.description}")
        lines.append(f"")

        if f.payload:
            lines.append(f"**Payload:**")
            lines.append(f"```")
            lines.append(f"{f.payload}")
            lines.append(f"```")
            lines.append(f"")

        if f.evidence:
            lines.append(f"**Evidence:**")
            lines.append(f"```")
            lines.append(f"{f.evidence[:500]}")
            lines.append(f"```")
            lines.append(f"")

        if f.request:
            lines.append(f"**Reproduction:**")
            lines.append(f"```")
            lines.append(f"{f.request}")
            lines.append(f"```")
            lines.append(f"")

        if f.poc_command():
            lines.append(f"**PoC Command:**")
            lines.append(f"```bash")
            lines.append(f"{f.poc_command()}")
            lines.append(f"```")
            lines.append(f"")

        lines.append(f"**Remediation:** {f.remediation}")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

        return lines

    def generate_json(self, result: ScanResult) -> str:
        """Generate JSON report."""
        report = {
            "target": result.target,
            "timestamp": result.timestamp,
            "duration": result.duration,
            "summary": result.summary(),
            "findings": [f.to_dict() for f in result.findings],
        }
        if result.crawl:
            report["crawl"] = result.crawl.to_dict()
        return json.dumps(report, indent=2, default=str)

    def save(self, result: ScanResult, output_dir: Path = None) -> Path:
        """Save report to disk in all formats."""
        out_dir = output_dir or (config.output_dir / result.target.replace("://", "_").replace(".", "_").replace("/", "_"))
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Markdown
        md_file = out_dir / f"report_{timestamp}.md"
        md_file.write_text(self.generate_markdown(result))

        # JSON
        json_file = out_dir / f"report_{timestamp}.json"
        json_file.write_text(self.generate_json(result))

        return md_file
