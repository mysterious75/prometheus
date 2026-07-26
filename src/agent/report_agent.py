"""Report Agent — report generation specialist.

Takes all findings from other agents and generates:
- Markdown report (human-readable)
- JSON report (machine-readable)
- HackerOne-format report (bug bounty submission)

Includes severity breakdown, remediation, CVSS scores, CWE IDs.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import os

from ..core.logger import logger, console


@dataclass
class AgentResult:
    """Standardized result from any agent execution."""
    agent: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "success": self.success,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "assets": self.assets,
            "stats": self.stats,
            "duration": self.duration,
            "error": self.error,
        }


# Severity ordering and CVSS ranges
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CVSS_RANGES = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}


class ReportAgent:
    """Report generation specialist agent.

    Responsibilities:
    - Aggregate findings from all agents
    - Generate Markdown report
    - Generate JSON report
    - Generate HackerOne-format report
    - Include severity breakdown, remediation, CVSS, CWE
    """

    NAME = "report"

    def __init__(self):
        pass

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Generate reports from all collected findings.

        Args:
            target: Primary target
            context: Must contain 'all_findings', 'agent_results', 'recon_assets'

        Returns:
            AgentResult with report file paths
        """
        start = datetime.now()
        context = context or {}

        console.print(f"\n[bold blue]═══ Report Agent: {target} ═══[/bold blue]")

        all_findings = context.get("all_findings", [])
        agent_results = context.get("agent_results", {})
        recon_assets = context.get("recon_assets", {})
        exploit_chains = context.get("exploit_chains", [])
        total_duration = context.get("total_duration", 0.0)

        # Deduplicate and sort findings
        findings = self._prepare_findings(all_findings)

        # Generate reports
        reports = {}

        # Markdown report
        md_path = self._generate_markdown(target, findings, agent_results,
                                           recon_assets, exploit_chains, total_duration)
        reports["markdown"] = md_path

        # JSON report
        json_path = self._generate_json(target, findings, agent_results,
                                         recon_assets, exploit_chains, total_duration)
        reports["json"] = json_path

        # HackerOne report
        h1_path = self._generate_hackerone(target, findings, recon_assets, exploit_chains)
        reports["hackerone"] = h1_path

        duration = (datetime.now() - start).total_seconds()

        stats = {
            "total_findings": len(findings),
            "reports_generated": len(reports),
            "report_paths": reports,
        }

        console.print(f"  [success]Reports generated: {len(reports)} files[/success]")
        for name, path in reports.items():
            console.print(f"    → {name}: {path}")

        return AgentResult(
            agent=self.NAME,
            success=True,
            findings=[],
            assets={"reports": reports},
            stats=stats,
            duration=duration,
        )

    def _prepare_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate and sort findings by severity."""
        # Deduplicate by (type, url, parameter)
        seen: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('type', '')}:{f.get('url', '')}:{f.get('parameter', '')}"
            existing = seen.get(key)
            if not existing:
                seen[key] = f
            else:
                # Keep the validated one, or the one with higher confidence
                conf_order = {"CONFIRMED": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                existing_conf = conf_order.get(existing.get("confidence", "LOW"), 0)
                new_conf = conf_order.get(f.get("confidence", "LOW"), 0)
                if f.get("validated") and not existing.get("validated"):
                    seen[key] = f
                elif new_conf > existing_conf:
                    seen[key] = f

        deduped = list(seen.values())

        # Sort by severity
        deduped.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))
        return deduped

    def _generate_markdown(self, target: str, findings: List[Dict[str, Any]],
                           agent_results: Dict[str, Any],
                           recon_assets: Dict[str, Any],
                           exploit_chains: List[Dict[str, Any]],
                           total_duration: float) -> str:
        """Generate a comprehensive Markdown report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Severity counts
        severity_count = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        lines = [
            f"# 🛡️ Prometheus Security Assessment Report",
            f"",
            f"**Target:** `{target}`",
            f"**Date:** {now}",
            f"**Duration:** {total_duration:.1f}s",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_count.get(sev, 0)
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
            lines.append(f"| {icon} {sev} | {count} |")

        lines.extend([
            f"",
            f"**Total Findings:** {len(findings)}",
            f"",
        ])

        # Recon summary
        subdomains = recon_assets.get("subdomains", [])
        ports = recon_assets.get("ports", [])
        http_services = recon_assets.get("http_services", [])
        tech_stack = recon_assets.get("tech_stack", [])

        if subdomains or ports or http_services:
            lines.extend([
                f"---",
                f"",
                f"## Reconnaissance",
                f"",
            ])
            if subdomains:
                lines.append(f"**Subdomains:** {len(subdomains)}")
                for s in subdomains[:20]:
                    lines.append(f"- `{s}`")
                if len(subdomains) > 20:
                    lines.append(f"- ... and {len(subdomains) - 20} more")
                lines.append("")

            if ports:
                lines.append(f"**Open Ports:** {len(ports)}")
                for p in ports[:15]:
                    lines.append(f"- `{p.get('port')}/{p.get('protocol')}` → {p.get('service', 'unknown')}")
                lines.append("")

            if http_services:
                lines.append(f"**HTTP Services:** {len(http_services)}")
                for s in http_services[:10]:
                    lines.append(f"- `{s.get('url', '')}` [{s.get('status_code', '')}] {s.get('title', '')}")
                lines.append("")

            if tech_stack:
                lines.append(f"**Technology Stack:** {', '.join(tech_stack[:15])}")
                lines.append("")

        # Exploit chains
        if exploit_chains:
            lines.extend([
                f"---",
                f"",
                f"## 🔗 Exploit Chains",
                f"",
            ])
            for chain in exploit_chains:
                lines.extend([
                    f"### {chain.get('chain_id', 'chain')}: {chain.get('description', '')}",
                    f"",
                    f"**Combined Severity:** {chain.get('combined_severity', 'HIGH')}",
                    f"",
                    f"**Steps:**",
                ])
                for step in chain.get("steps", []):
                    lines.append(f"1. `{step.get('type', '')}` at `{step.get('url', '')}`")
                lines.extend([
                    f"",
                    f"**PoC:**",
                ])
                for poc in chain.get("poc_steps", []):
                    lines.append(f"- {poc}")
                lines.append("")

        # Findings detail
        if findings:
            lines.extend([
                f"---",
                f"",
                f"## Findings",
                f"",
            ])

            for i, f in enumerate(findings, 1):
                sev = f.get("severity", "INFO")
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
                vuln_type = f.get("type", f.get("vuln_type", "Unknown"))
                title = f.get("title", vuln_type)

                lines.extend([
                    f"### {i}. {icon} [{sev}] {title}",
                    f"",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Type** | {vuln_type} |",
                    f"| **Severity** | {sev} |",
                    f"| **URL** | `{f.get('url', 'N/A')}` |",
                ])

                if f.get("parameter"):
                    lines.append(f"| **Parameter** | `{f.get('parameter')}` |")
                if f.get("cvss"):
                    lines.append(f"| **CVSS** | {f.get('cvss')} |")
                if f.get("cwe"):
                    lines.append(f"| **CWE** | {f.get('cwe')} |")
                if f.get("tool"):
                    lines.append(f"| **Tool** | {f.get('tool')} |")
                if f.get("validated") is not None:
                    val = "✅ Yes" if f.get("validated") else "❌ No"
                    lines.append(f"| **Validated** | {val} |")

                lines.append("")

                if f.get("description"):
                    lines.append(f"**Description:** {f.get('description')}")
                    lines.append("")

                if f.get("evidence"):
                    lines.extend([
                        f"**Evidence:**",
                        f"```",
                        f"{f.get('evidence')[:500]}",
                        f"```",
                        "",
                    ])

                if f.get("payload"):
                    lines.extend([
                        f"**Payload:**",
                        f"```",
                        f"{f.get('payload')[:300]}",
                        f"```",
                        "",
                    ])

                if f.get("remediation"):
                    lines.extend([
                        f"**Remediation:** {f.get('remediation')}",
                        "",
                    ])

                lines.append("---")
                lines.append("")

        # Footer
        lines.extend([
            f"",
            f"---",
            f"",
            f"*Generated by Prometheus Security Testing Platform*",
            f"*{now}*",
        ])

        content = "\n".join(lines)
        path = f"reports/report_{target.replace('/', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

        return path

    def _generate_json(self, target: str, findings: List[Dict[str, Any]],
                       agent_results: Dict[str, Any],
                       recon_assets: Dict[str, Any],
                       exploit_chains: List[Dict[str, Any]],
                       total_duration: float) -> str:
        """Generate a machine-readable JSON report."""
        now = datetime.now().isoformat()

        severity_count = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        report = {
            "metadata": {
                "tool": "Prometheus Security Testing Platform",
                "version": "1.0.0",
                "target": target,
                "timestamp": now,
                "duration_seconds": total_duration,
            },
            "summary": {
                "total_findings": len(findings),
                "findings_by_severity": severity_count,
                "agents_run": list(agent_results.keys()),
            },
            "recon": {
                "subdomains": recon_assets.get("subdomains", []),
                "ports": recon_assets.get("ports", []),
                "http_services": recon_assets.get("http_services", []),
                "tech_stack": recon_assets.get("tech_stack", []),
                "dns_records": recon_assets.get("dns_records", {}),
            },
            "findings": findings,
            "exploit_chains": exploit_chains,
            "agent_results": {
                name: result.to_dict() if hasattr(result, "to_dict") else result
                for name, result in agent_results.items()
            },
        }

        path = f"reports/report_{target.replace('/', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)

        return path

    def _generate_hackerone(self, target: str, findings: List[Dict[str, Any]],
                            recon_assets: Dict[str, Any],
                            exploit_chains: List[Dict[str, Any]]) -> str:
        """Generate HackerOne-format reports for bug bounty submissions.

        One report per significant finding (HIGH+ severity).
        """
        now = datetime.now().strftime("%Y-%m-%d")

        h1_findings = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
        ]

        if not h1_findings:
            # Generate a summary report even if no significant findings
            h1_findings = findings[:5] if findings else []

        sections = []

        for i, f in enumerate(h1_findings, 1):
            vuln_type = f.get("type", f.get("vuln_type", "Unknown"))
            sev = f.get("severity", "INFO")
            url = f.get("url", "N/A")
            description = f.get("description", "No description provided.")
            evidence = f.get("evidence", "")
            poc = f.get("payload", "")
            remediation = f.get("remediation", "Implement input validation and output encoding.")
            cvss = f.get("cvss", 0.0)
            cwe = f.get("cwe", "")

            section = f"""## Report #{i}: {vuln_type}

### Summary
**Severity:** {sev}
**URL:** {url}
**CWE:** {cwe or 'CWE-Other'}
**CVSS:** {cvss or 'Not calculated'}

### Description
{description}

### Steps To Reproduce
1. Navigate to `{url}`
2. {"Inject the following payload:" if poc else "Observe the vulnerable behavior."}
{('```' + chr(10) + poc + chr(10) + '```') if poc else ""}

### Impact
{self._get_impact_text(sev, vuln_type)}

### Evidence
{evidence[:1000] if evidence else "See Steps To Reproduce."}

### Remediation
{remediation}

---
"""
            sections.append(section)

        sections_joined = "---".join(sections)
        content = f"""# HackerOne Report: {target}
**Date:** {now}
**Program Target:** {target}

{sections_joined}

*Generated by Prometheus Security Testing Platform*
"""

        path = f"reports/hackerone_{target.replace('/', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

        return path

    def _get_impact_text(self, severity: str, vuln_type: str) -> str:
        """Generate impact text based on severity and type."""
        impacts = {
            "CRITICAL": "This vulnerability allows an attacker to fully compromise the application, "
                        "potentially leading to complete data breach, remote code execution, or "
                        "account takeover of any user including administrators.",
            "HIGH": "This vulnerability allows an attacker to access sensitive data or perform "
                    "unauthorized actions, potentially affecting multiple users.",
            "MEDIUM": "This vulnerability could be exploited to obtain limited sensitive information "
                      "or perform actions on behalf of the victim.",
            "LOW": "This vulnerability has limited impact but could be used as part of a larger attack chain.",
        }
        return impacts.get(severity, "Impact assessment pending.")
