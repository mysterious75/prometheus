"""Market Features — Professional reports, pricing, bug bounty integration.

Features:
- Professional security report generation
- USD/INR pricing model
- Bug bounty platform integration
- CERT-In compliance reporting
- Executive summary generation
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import json

from ..scanner.findings import Finding, ScanResult
from ..core.logger import logger


class ProfessionalReportGenerator:
    """Generates professional security reports with executive summaries."""
    
    SEVERITY_LABELS = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Informational",
    }
    
    RISK_STATEMENTS = {
        "CRITICAL": "CRITICAL RISK — Immediate action required",
        "HIGH": "HIGH RISK — Urgent remediation needed",
        "MEDIUM": "MEDIUM RISK — Timely remediation recommended",
        "LOW": "LOW RISK — Minor improvements suggested",
        "SECURE": "SECURE — No significant issues found",
    }
    
    VULN_DESCRIPTIONS = {
        "SQL Injection": "SQL Injection — Allows database manipulation through malicious queries",
        "Cross-Site Scripting": "Cross-Site Scripting (XSS) — Allows injection of malicious scripts into web pages",
        "SSRF": "Server-Side Request Forgery — Allows access to internal network from the server",
        "Command Injection": "Command Injection — Allows execution of system commands on the server",
        "Path Traversal": "Path Traversal — Allows access to sensitive files outside the web root",
        "IDOR": "Insecure Direct Object Reference — Allows unauthorized access to other users' data",
        "Missing Security Headers": "Missing Security Headers — Weakens the website's security posture",
        "Exposed Secrets": "Exposed Secrets — API keys, passwords, or other sensitive data are visible",
        "CORS Misconfiguration": "CORS Misconfiguration — Allows unauthorized cross-origin access",
        "Open Redirect": "Open Redirect — Can be used for phishing attacks",
    }
    
    def generate_report(self, scan_result: ScanResult, output_dir: Optional[str] = None) -> str:
        """Generate a professional security report in English."""
        findings = scan_result.findings
        target = scan_result.target
        
        lines = []
        now = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
        
        # Header
        lines.append("# Prometheus Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {target}")
        lines.append(f"**Date:** {now}")
        lines.append(f"**Duration:** {scan_result.duration:.1f} seconds")
        lines.append("")
        
        # Executive Summary
        lines.append("---")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Risk level
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 2:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 3:
            risk_level = "MEDIUM"
        elif sum(severity_counts.values()) > 0:
            risk_level = "LOW"
        else:
            risk_level = "SECURE"
        
        lines.append(f"**Overall Risk Level:** {self.RISK_STATEMENTS.get(risk_level, risk_level)}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            label = self.SEVERITY_LABELS.get(sev, sev)
            lines.append(f"| {label} | {count} |")
        lines.append("")
        
        # Key Findings
        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if critical_high:
            lines.append("### Key Findings")
            lines.append("")
            for i, f in enumerate(critical_high[:5], 1):
                vuln_desc = self.VULN_DESCRIPTIONS.get(f.vuln_type, f.vuln_type)
                lines.append(f"{i}. **{f.title}** ({self.SEVERITY_LABELS.get(f.severity, f.severity)})")
                lines.append(f"   - {vuln_desc}")
                lines.append(f"   - Impact: {f.description[:150]}")
            lines.append("")
        
        # Business Impact
        lines.append("### Business Impact")
        lines.append("")
        if risk_level == "CRITICAL":
            lines.append("WARNING: CRITICAL RISK — Immediate action required. These vulnerabilities could lead to:")
            lines.append("- Data breach (customer data, passwords, financial information)")
            lines.append("- Complete system compromise by attackers")
            lines.append("- Legal consequences (IT Act 2000, CERT-In guidelines, GDPR)")
            lines.append("- Loss of customer trust and reputation damage")
        elif risk_level == "HIGH":
            lines.append("WARNING: HIGH RISK — Urgent remediation needed. These issues could lead to:")
            lines.append("- Sensitive data exposure")
            lines.append("- Website reputation damage")
            lines.append("- CERT-In reporting requirement")
        elif risk_level == "MEDIUM":
            lines.append("NOTICE: MEDIUM RISK — Timely remediation recommended.")
            lines.append("- Several security weaknesses should be addressed")
        else:
            lines.append("GOOD: Strong security posture with minor areas for improvement.")
        lines.append("")
        
        # Detailed Findings
        lines.append("---")
        lines.append("")
        lines.append("## Detailed Findings")
        lines.append("")
        
        for i, f in enumerate(findings, 1):
            sev_label = self.SEVERITY_LABELS.get(f.severity, f.severity)
            vuln_desc = self.VULN_DESCRIPTIONS.get(f.vuln_type, f.vuln_type)
            
            lines.append(f"### {i}. {f.title}")
            lines.append("")
            lines.append(f"- **Type:** {vuln_desc}")
            lines.append(f"- **Severity:** {sev_label}")
            lines.append(f"- **URL:** {f.url}")
            lines.append(f"- **CVSS Score:** {f.cvss:.1f}/10")
            lines.append(f"- **CWE:** {f.cwe or 'N/A'}")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            if f.evidence:
                lines.append(f"**Evidence:**")
                lines.append(f"```")
                lines.append(f"{f.evidence[:300]}")
                lines.append(f"```")
                lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")
        
        # Compliance
        lines.append("## Compliance Reference")
        lines.append("")
        lines.append("This report aligns with the following standards:")
        lines.append("")
        lines.append("- **OWASP Top 10 (2021)** — Web Application Security Risks")
        lines.append("- **CERT-In** — Indian Computer Emergency Response Team guidelines")
        lines.append("- **IT Act 2000** — Section 43A (Data Protection)")
        lines.append("- **PCI-DSS** — Payment Card Industry Data Security Standard")
        lines.append("- **ISO 27001** — Information Security Management")
        lines.append("")
        lines.append("### Recommended Actions")
        lines.append("")
        lines.append("1. Fix Critical vulnerabilities within 48 hours")
        lines.append("2. Fix High vulnerabilities within 1 week")
        lines.append("3. Fix Medium vulnerabilities within 1 month")
        lines.append("4. Report data breaches to CERT-In within 6 hours")
        lines.append("5. Maintain security audit trail as per IT Act 2000")
        lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Report generated by Prometheus v3.0 — {now}*")
        lines.append(f"*Source: https://github.com/mysterious75/prometheus*")
        
        report = "\n".join(lines)
        
        # Save
        if output_dir is None:
            output_dir = str(Path.cwd() / "reports")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        md_path = Path(output_dir) / f"report_{safe_target}_{timestamp}.md"
        
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report)
        
        logger.info(f"Report saved: {md_path}")
        return str(md_path)


class PricingModel:
    """Pricing model with USD and INR support."""
    
    PLANS = {
        "free": {
            "name": "Free",
            "price_inr": 0,
            "price_usd": 0,
            "features": [
                "5 URLs per month",
                "5 scanners (SQLi, XSS, Headers, CORS, Secrets)",
                "CLI access",
                "Professional reports",
                "Community support",
            ],
            "limits": {"urls_per_month": 5, "scanners": 5},
        },
        "pro": {
            "name": "Pro",
            "price_inr": 1499,
            "price_usd": 19,
            "features": [
                "Unlimited URLs",
                "All 21 scanners",
                "OWASP methodology",
                "API access",
                "Executive reports",
                "Priority support",
            ],
            "limits": {"urls_per_month": -1, "scanners": 21},
        },
        "team": {
            "name": "Team",
            "price_inr": 7499,
            "price_usd": 99,
            "features": [
                "Everything in Pro",
                "5 team members",
                "Continuous scanning",
                "Auto-fix PRs",
                "CI/CD integration",
                "Compliance reports (CERT-In, ISO 27001)",
                "Dedicated support",
            ],
            "limits": {"urls_per_month": -1, "scanners": 21, "team_members": 5},
        },
        "enterprise": {
            "name": "Enterprise",
            "price_inr": 22499,
            "price_usd": 299,
            "features": [
                "Everything in Team",
                "Unlimited team members",
                "SSO/SAML integration",
                "On-premise deployment",
                "Custom playbooks",
                "Dedicated account manager",
                "SLA (99.9% uptime)",
            ],
            "limits": {},
        },
    }
    
    @classmethod
    def get_plan(cls, plan_name: str) -> Dict[str, Any]:
        return cls.PLANS.get(plan_name, cls.PLANS["free"])
    
    @classmethod
    def get_all_plans(cls) -> Dict[str, Dict]:
        return cls.PLANS
    
    @classmethod
    def format_pricing_table(cls) -> str:
        lines = ["| Plan | Price (INR/month) | Price (USD/month) |",
                 "|------|-------------------|-------------------|"]
        for key, plan in cls.PLANS.items():
            lines.append(f"| {plan['name']} | Rs.{plan['price_inr']} | ${plan['price_usd']} |")
        return "\n".join(lines)


class BugBountyIntegration:
    """Bug bounty platform integration."""
    
    PLATFORMS = {
        "bugcrowd": {
            "name": "Bugcrowd",
            "url": "https://bugcrowd.com",
            "api": "https://api.bugcrowd.com",
        },
        "hackerone": {
            "name": "HackerOne",
            "url": "https://hackerone.com",
            "api": "https://api.hackerone.com",
        },
        "yeswehack": {
            "name": "YesWeHack",
            "url": "https://yeswehack.com",
        },
        "india_programs": {
            "name": "Indian Bug Bounty Programs",
            "programs": [
                {"name": "Flipkart", "url": "https://www.flipkart.com/pages/responsible-disclosure"},
                {"name": "Paytm", "url": "https://paytm.com/about/responsible-disclosure/"},
                {"name": "PhonePe", "url": "https://www.phonepe.com/responsible-disclosure/"},
                {"name": "Zomato", "url": "https://www.zomato.com/responsible-disclosure"},
                {"name": "Swiggy", "url": "https://www.swiggy.com/responsible-disclosure"},
                {"name": "Ola", "url": "https://www.olacabs.com/responsible-disclosure"},
                {"name": "MakeMyTrip", "url": "https://www.makemytrip.com/responsible-disclosure"},
            ],
        },
    }
    
    @classmethod
    def generate_hackerone_report(cls, finding: Finding) -> str:
        """Generate HackerOne format report."""
        report = f"""## Summary

{finding.title}

## Severity

{finding.severity} (CVSS: {finding.cvss:.1f})

## Description

{finding.description}

## Steps To Reproduce

1. Navigate to {finding.url}
2. Send the following request:

```http
{finding.request or f'GET {finding.url} HTTP/1.1'}
```

3. Observe the response:

```
{finding.evidence[:500]}
```

## Impact

This vulnerability allows an attacker to {finding.description[:200]}

## Remediation

{finding.remediation}

## References

- CWE-{finding.cwe or 'N/A'}: https://cwe.mitre.org/data/definitions/{finding.cwe or '0'}.html
- OWASP: https://owasp.org/

---
*Report generated by Prometheus v3.0*
"""
        return report
    
    @classmethod
    def generate_certin_report(cls, scan_result: ScanResult) -> str:
        """Generate CERT-In compliant report."""
        lines = []
        lines.append("# CERT-In Security Assessment Report")
        lines.append("")
        lines.append(f"**Organization:** [Organization Name]")
        lines.append(f"**Assessment Date:** {datetime.now().strftime('%B %d, %Y')}")
        lines.append(f"**Target:** {scan_result.target}")
        lines.append(f"**Assessor:** Prometheus Automated Security Scanner")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in scan_result.findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        lines.append(f"Total vulnerabilities found: {len(scan_result.findings)}")
        lines.append(f"- Critical: {severity_counts['CRITICAL']}")
        lines.append(f"- High: {severity_counts['HIGH']}")
        lines.append(f"- Medium: {severity_counts['MEDIUM']}")
        lines.append(f"- Low: {severity_counts['LOW']}")
        lines.append("")
        lines.append("## Compliance Status")
        lines.append("")
        lines.append("### IT Act 2000 - Section 43A")
        if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
            lines.append("NON-COMPLIANT — Critical/High vulnerabilities found.")
            lines.append("Immediate action required as per IT Act 2000.")
        else:
            lines.append("COMPLIANT — No critical/high vulnerabilities found.")
        lines.append("")
        lines.append("### CERT-In Reporting Requirement")
        lines.append("As per CERT-In guidelines, critical vulnerabilities must be reported within 6 hours.")
        lines.append("")
        
        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")
        for i, f in enumerate(scan_result.findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"- Severity: {f.severity}")
            lines.append(f"- CVSS: {f.cvss:.1f}")
            lines.append(f"- CWE: {f.cwe or 'N/A'}")
            lines.append(f"- URL: {f.url}")
            lines.append(f"- Description: {f.description}")
            lines.append(f"- Remediation: {f.remediation}")
            lines.append("")
        
        return "\n".join(lines)


# Export
__all__ = ["ProfessionalReportGenerator", "PricingModel", "BugBountyIntegration"]
