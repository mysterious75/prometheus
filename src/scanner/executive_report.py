"""Executive Report Generator — Professional security reports.

Based on: The Hacker Playbook (Peter Kim), OWASP Reporting Guide.

Generates:
- Executive Summary (risk level, key findings, business impact)
- Risk Matrix (Likelihood × Impact)
- Compliance Mapping (OWASP Top 10, PCI-DSS, SOC2, GDPR)
- Remediation Plan (prioritized fixes with effort estimates)
- Technical Appendix (detailed findings with PoC)

Output: Markdown + JSON
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .findings import Finding, ScanResult
from ..core.logger import logger


class ExecutiveReportGenerator:
    """Generates executive-level security reports."""
    NAME = "executive_report"

    # OWASP Top 10 2021 mapping
    OWASP_TOP10 = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery (SSRF)",
    }

    # CWE to OWASP mapping
    CWE_TO_OWASP = {
        "CWE-79": "A03:2021",   # XSS
        "CWE-89": "A03:2021",   # SQLi
        "CWE-78": "A03:2021",   # Command Injection
        "CWE-918": "A10:2021",  # SSRF
        "CWE-22": "A01:2021",   # Path Traversal
        "CWE-287": "A07:2021",  # Auth Bypass
        "CWE-200": "A01:2021",  # Info Disclosure
        "CWE-352": "A01:2021",  # CSRF
        "CWE-434": "A08:2021",  # File Upload
        "CWE-502": "A08:2021",  # Deserialization
        "CWE-611": "A05:2021",  # XXE
        "CWE-94": "A03:2021",   # Code Injection
        "CWE-295": "A02:2021",  # Certificate Validation
        "CWE-327": "A02:2021",  # Weak Crypto
        "CWE-319": "A02:2021",  # Cleartext
        "CWE-16": "A05:2021",   # Misconfiguration
        "CWE-269": "A01:2021",  # Access Control
        "CWE-598": "A01:2021",  # GET with sensitive data
    }

    # PCI-DSS requirement mapping
    PCI_MAPPING = {
        "injection": "PCI-DSS 6.5.1",
        "xss": "PCI-DSS 6.5.7",
        "authentication": "PCI-DSS 8",
        "access_control": "PCI-DSS 7",
        "encryption": "PCI-DSS 4",
        "session": "PCI-DSS 6.5.10",
        "configuration": "PCI-DSS 2, 6",
    }

    def generate_report(self, scan_result: ScanResult, output_dir: Optional[str] = None) -> str:
        """Generate executive report from scan results.
        
        Returns path to generated markdown report.
        """
        findings = scan_result.findings
        target = scan_result.target

        # Calculate risk scores
        risk_summary = self._calculate_risk(findings)

        # Generate compliance mapping
        compliance = self._map_compliance(findings)

        # Generate remediation plan
        remediation = self._generate_remediation(findings)

        # Build report
        report = self._build_report(target, findings, risk_summary, compliance, remediation, scan_result)

        # Save report
        if output_dir is None:
            output_dir = str(Path.cwd() / "reports")
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        
        # Save Markdown
        md_path = Path(output_dir) / f"report_{safe_target}_{timestamp}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report)

        # Save JSON
        json_path = Path(output_dir) / f"report_{safe_target}_{timestamp}.json"
        json_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "risk_summary": risk_summary,
            "compliance": compliance,
            "findings": [f.to_dict() for f in findings],
            "remediation": remediation,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        logger.info(f"Report saved: {md_path}")
        return str(md_path)

    def _calculate_risk(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate overall risk score."""
        severity_scores = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        
        total_score = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for f in findings:
            sev = f.severity.upper()
            if sev in severity_scores:
                total_score += severity_scores[sev]
                severity_counts[sev] += 1

        # Risk level
        if severity_counts["CRITICAL"] > 0 or total_score > 50:
            risk_level = "CRITICAL"
            risk_color = "🔴"
        elif severity_counts["HIGH"] > 2 or total_score > 30:
            risk_level = "HIGH"
            risk_color = "🟠"
        elif severity_counts["MEDIUM"] > 3 or total_score > 15:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        elif total_score > 0:
            risk_level = "LOW"
            risk_color = "🟢"
        else:
            risk_level = "SECURE"
            risk_color = "✅"

        return {
            "risk_level": risk_level,
            "risk_color": risk_color,
            "total_score": total_score,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        }

    def _map_compliance(self, findings: List[Finding]) -> Dict[str, Any]:
        """Map findings to compliance frameworks."""
        owasp_findings = {}
        pci_findings = {}

        for f in findings:
            cwe = f.cwe or ""
            owasp_id = self.CWE_TO_OWASP.get(cwe, "")
            
            if owasp_id:
                if owasp_id not in owasp_findings:
                    owasp_findings[owasp_id] = {
                        "name": self.OWASP_TOP10.get(owasp_id, ""),
                        "findings": [],
                    }
                owasp_findings[owasp_id]["findings"].append(f.title)

            # PCI-DSS mapping
            vuln_lower = f.vuln_type.lower()
            for keyword, pci_req in self.PCI_MAPPING.items():
                if keyword in vuln_lower:
                    if pci_req not in pci_findings:
                        pci_findings[pci_req] = []
                    pci_findings[pci_req].append(f.title)

        return {
            "owasp_top10": owasp_findings,
            "pci_dss": pci_findings,
            "owasp_compliant": len(owasp_findings) == 0,
            "pci_compliant": len(pci_findings) == 0,
        }

    def _generate_remediation(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation plan."""
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.upper(), 5))

        remediation = []
        for f in sorted_findings:
            effort = self._estimate_effort(f)
            remediation.append({
                "finding": f.title,
                "severity": f.severity,
                "cwe": f.cwe,
                "remediation": f.remediation,
                "effort": effort,
                "priority": severity_order.get(f.severity.upper(), 5),
            })

        return remediation

    def _estimate_effort(self, finding: Finding) -> str:
        """Estimate remediation effort."""
        cwe = finding.cwe or ""
        
        # Quick fixes (configuration changes)
        quick_fixes = ["CWE-16", "CWE-693", "CWE-523", "CWE-319"]
        if cwe in quick_fixes:
            return "Low (1-2 hours)"

        # Medium fixes (code changes)
        medium_fixes = ["CWE-79", "CWE-295", "CWE-327", "CWE-352"]
        if cwe in medium_fixes:
            return "Medium (4-8 hours)"

        # Complex fixes (architecture changes)
        complex_fixes = ["CWE-89", "CWE-78", "CWE-918", "CWE-22", "CWE-287"]
        if cwe in complex_fixes:
            return "High (1-3 days)"

        return "Medium (4-8 hours)"

    def _build_report(self, target: str, findings: List[Finding],
                      risk_summary: Dict, compliance: Dict,
                      remediation: List[Dict], scan_result: ScanResult) -> str:
        """Build the full markdown report."""
        lines = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Header
        lines.append("# 🛡️ Prometheus Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {target}")
        lines.append(f"**Date:** {now}")
        lines.append(f"**Duration:** {scan_result.duration:.1f}s")
        lines.append("")

        # Executive Summary
        lines.append("---")
        lines.append("")
        lines.append("## 📋 Executive Summary")
        lines.append("")
        lines.append(f"**Overall Risk Level:** {risk_summary['risk_color']} **{risk_summary['risk_level']}**")
        lines.append(f"**Total Findings:** {risk_summary['total_findings']}")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = risk_summary["severity_counts"].get(sev, 0)
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(sev, "")
            lines.append(f"| {icon} {sev} | {count} |")
        lines.append("")

        # Business Impact
        lines.append("### Business Impact")
        lines.append("")
        if risk_summary["risk_level"] == "CRITICAL":
            lines.append("⚠️ **CRITICAL RISK** — Immediate action required. The application has vulnerabilities")
            lines.append("that could lead to data breach, unauthorized access, or complete system compromise.")
        elif risk_summary["risk_level"] == "HIGH":
            lines.append("⚠️ **HIGH RISK** — Urgent remediation needed. Significant vulnerabilities exist")
            lines.append("that could be exploited by attackers to access sensitive data or systems.")
        elif risk_summary["risk_level"] == "MEDIUM":
            lines.append("⚡ **MEDIUM RISK** — Timely remediation recommended. Several security issues")
            lines.append("exist that could be combined or escalated by skilled attackers.")
        elif risk_summary["risk_level"] == "LOW":
            lines.append("✅ **LOW RISK** — Minor issues found. The application has good security posture")
            lines.append("with some areas for improvement.")
        else:
            lines.append("✅ **SECURE** — No significant vulnerabilities detected.")
        lines.append("")

        # Key Findings
        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if critical_high:
            lines.append("### Key Findings")
            lines.append("")
            for i, f in enumerate(critical_high[:5], 1):
                lines.append(f"{i}. **{f.title}** ({f.severity})")
                lines.append(f"   - {f.description[:150]}")
            lines.append("")

        # Risk Matrix
        lines.append("---")
        lines.append("")
        lines.append("## 📊 Risk Matrix")
        lines.append("")
        lines.append("| Finding | Severity | CVSS | CWE | Likelihood | Impact |")
        lines.append("|---------|----------|------|-----|------------|--------|")
        for f in findings:
            likelihood = "High" if f.severity in ("CRITICAL", "HIGH") else "Medium" if f.severity == "MEDIUM" else "Low"
            impact = "High" if f.severity in ("CRITICAL", "HIGH") else "Medium" if f.severity == "MEDIUM" else "Low"
            lines.append(f"| {f.title[:50]} | {f.severity} | {f.cvss:.1f} | {f.cwe or 'N/A'} | {likelihood} | {impact} |")
        lines.append("")

        # Compliance Mapping
        lines.append("---")
        lines.append("")
        lines.append("## 📜 Compliance Mapping")
        lines.append("")

        # OWASP Top 10
        lines.append("### OWASP Top 10 (2021)")
        lines.append("")
        if compliance["owasp_top10"]:
            lines.append("| OWASP ID | Category | Findings |")
            lines.append("|----------|----------|----------|")
            for owasp_id, data in compliance["owasp_top10"].items():
                count = len(data["findings"])
                lines.append(f"| {owasp_id} | {data['name']} | {count} finding(s) |")
        else:
            lines.append("✅ No OWASP Top 10 violations detected.")
        lines.append("")

        # PCI-DSS
        lines.append("### PCI-DSS")
        lines.append("")
        if compliance["pci_dss"]:
            lines.append("| Requirement | Findings |")
            lines.append("|-------------|----------|")
            for req, findings_list in compliance["pci_dss"].items():
                lines.append(f"| {req} | {len(findings_list)} finding(s) |")
        else:
            lines.append("✅ No PCI-DSS violations detected.")
        lines.append("")

        # Remediation Plan
        lines.append("---")
        lines.append("")
        lines.append("## 🔧 Remediation Plan")
        lines.append("")
        lines.append("Prioritized by severity (fix critical issues first):")
        lines.append("")
        for i, r in enumerate(remediation[:20], 1):
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["severity"], "ℹ️")
            lines.append(f"### {i}. {r['finding']} {sev_icon}")
            lines.append(f"- **Severity:** {r['severity']}")
            lines.append(f"- **CWE:** {r['cwe'] or 'N/A'}")
            lines.append(f"- **Effort:** {r['effort']}")
            lines.append(f"- **Fix:** {r['remediation']}")
            lines.append("")

        # Technical Appendix
        lines.append("---")
        lines.append("")
        lines.append("## 📎 Technical Appendix")
        lines.append("")
        for i, f in enumerate(findings, 1):
            lines.append(f"### Finding {i}: {f.title}")
            lines.append("")
            lines.append(f"- **Type:** {f.vuln_type}")
            lines.append(f"- **Severity:** {f.severity}")
            lines.append(f"- **URL:** {f.url}")
            lines.append(f"- **Parameter:** {f.parameter or 'N/A'}")
            lines.append(f"- **Method:** {f.method}")
            lines.append(f"- **CWE:** {f.cwe or 'N/A'}")
            lines.append(f"- **CVSS:** {f.cvss:.1f}")
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append(f"- **Tool:** {f.tool}")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            if f.evidence:
                lines.append(f"**Evidence:**")
                lines.append(f"```")
                lines.append(f"{f.evidence[:500]}")
                lines.append(f"```")
                lines.append("")
            if f.payload:
                lines.append(f"**Payload:** `{f.payload[:200]}`")
                lines.append("")
            if f.request:
                lines.append(f"**Request:**")
                lines.append(f"```http")
                lines.append(f"{f.request[:500]}")
                lines.append(f"```")
                lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Footer
        lines.append("")
        lines.append("---")
        lines.append(f"*Report generated by Prometheus v3.0 on {now}*")
        lines.append(f"*Source: https://github.com/mysterious75/prometheus*")

        return "\n".join(lines)


# Export
__all__ = ["ExecutiveReportGenerator"]
