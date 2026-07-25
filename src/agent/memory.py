"""Agent Working Memory — tracks scan context, findings, and attack state.

This is the agent's short-term memory during an active assessment.
Persistent memory (knowledge base) is in src/knowledge/.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from ..tools.base import ToolResult


@dataclass
class Finding:
    """A consolidated security finding."""
    id: int
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    description: str
    evidence: str = ""
    tool: str = ""
    payload: str = ""
    remediation: str = ""
    cvss: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence[:300],
            "tool": self.tool,
            "cvss": self.cvss,
            "verified": self.verified,
        }


class WorkingMemory:
    """Agent's working memory during an active security assessment.

    Tracks:
    - Target information
    - Discovered assets (subdomains, ports, services)
    - Findings (vulnerabilities)
    - Attack history (what tools were run, what worked)
    - Context for the LLM planner
    """

    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()

        # Discovered assets
        self.subdomains: List[str] = []
        self.open_ports: List[Dict[str, Any]] = []
        self.http_services: List[Dict[str, Any]] = []
        self.urls: List[str] = []
        self.emails: List[str] = []
        self.usernames: List[Dict[str, Any]] = []

        # Findings
        self.findings: List[Finding] = []
        self._finding_counter = 0

        # Attack history
        self.tool_history: List[Dict[str, Any]] = []
        self.attack_plan: List[str] = []
        self.completed_steps: List[str] = []

        # Context
        self.tech_stack: List[str] = []
        self.notes: List[str] = []

    # --- Asset Management ---

    def add_subdomains(self, subdomains: List[str]):
        """Add discovered subdomains (deduped)."""
        new = [s for s in subdomains if s not in self.subdomains]
        self.subdomains.extend(new)

    def add_ports(self, ports: List[Dict[str, Any]]):
        """Add discovered open ports."""
        for port in ports:
            if port not in self.open_ports:
                self.open_ports.append(port)

    def add_http_services(self, services: List[Dict[str, Any]]):
        """Add discovered HTTP services."""
        for svc in services:
            if svc not in self.http_services:
                self.http_services.append(svc)
            # Extract tech stack
            for tech in svc.get("tech", []):
                if tech not in self.tech_stack:
                    self.tech_stack.append(tech)

    def add_urls(self, urls: List[str]):
        """Add discovered URLs."""
        new = [u for u in urls if u not in self.urls]
        self.urls.extend(new)

    # --- Finding Management ---

    def add_finding(
        self,
        vuln_type: str,
        severity: str,
        url: str,
        description: str,
        **kwargs,
    ) -> Finding:
        """Add a security finding."""
        self._finding_counter += 1
        finding = Finding(
            id=self._finding_counter,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            description=description,
            **kwargs,
        )
        self.findings.append(finding)
        return finding

    def add_tool_result(self, result: ToolResult):
        """Process a tool result and extract findings/assets."""
        self.tool_history.append(result.to_dict())

        for item in result.findings:
            ftype = item.get("type", "")

            if ftype == "subdomain":
                self.add_subdomains([item["value"]])

            elif ftype == "open_port":
                self.add_ports([item])

            elif ftype == "http_service":
                self.add_http_services([item])

            elif ftype == "username_found":
                self.usernames.append(item)

            elif "Injection" in ftype or "XSS" in ftype or "SSRF" in ftype:
                self.add_finding(
                    vuln_type=ftype,
                    severity=item.get("severity", "HIGH"),
                    url=item.get("url", ""),
                    description=item.get("description", item.get("evidence", "")),
                    evidence=item.get("evidence", ""),
                    tool=result.tool,
                    payload=item.get("payload", ""),
                    cvss=item.get("cvss", 0.0),
                )

            elif ftype == "Information Disclosure" or ftype == "Missing Security Headers":
                self.add_finding(
                    vuln_type=ftype,
                    severity=item.get("severity", "MEDIUM"),
                    url=item.get("url", ""),
                    description=item.get("description", ""),
                    evidence=item.get("evidence", ""),
                    tool=result.tool,
                )

    # --- Attack Planning ---

    def set_plan(self, steps: List[str]):
        """Set the attack plan."""
        self.attack_plan = steps

    def mark_step_done(self, step: str):
        """Mark an attack step as completed."""
        self.completed_steps.append(step)

    def add_note(self, note: str):
        """Add a note to working memory."""
        self.notes.append(f"[{datetime.now().strftime('%H:%M')}] {note}")

    # --- Context for LLM ---

    def get_context(self) -> str:
        """Generate a text summary of current state for the LLM planner."""
        lines = [
            f"=== Security Assessment: {self.target} ===",
            f"Duration: {(datetime.now() - self.start_time).seconds // 60} min",
            "",
        ]

        # Assets
        if self.subdomains:
            lines.append(f"Subdomains ({len(self.subdomains)}):")
            for s in self.subdomains[:20]:
                lines.append(f"  - {s}")
            if len(self.subdomains) > 20:
                lines.append(f"  ... and {len(self.subdomains) - 20} more")

        if self.open_ports:
            lines.append(f"\nOpen Ports ({len(self.open_ports)}):")
            for p in self.open_ports[:15]:
                lines.append(f"  - {p.get('port')}/{p.get('protocol')} → {p.get('service', 'unknown')}")

        if self.http_services:
            lines.append(f"\nHTTP Services ({len(self.http_services)}):")
            for s in self.http_services[:10]:
                title = s.get('title', '')
                tech = ', '.join(s.get('tech', []))
                lines.append(f"  - {s.get('url', '')} [{s.get('status_code', '')}] {title} ({tech})")

        if self.tech_stack:
            lines.append(f"\nTech Stack: {', '.join(self.tech_stack[:10])}")

        if self.emails:
            lines.append(f"\nEmails ({len(self.emails)}): {', '.join(self.emails[:5])}")

        if self.usernames:
            lines.append(f"\nUsernames ({len(self.usernames)}):")
            for u in self.usernames[:5]:
                lines.append(f"  - {u.get('username')} on {u.get('platform')}")

        # Findings
        if self.findings:
            lines.append(f"\n{'='*40}")
            lines.append(f"FINDINGS ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"  [{f.severity}] {f.vuln_type} at {f.url}")
                if f.description:
                    lines.append(f"    → {f.description[:100]}")

        # Attack progress
        if self.completed_steps:
            lines.append(f"\nCompleted Steps:")
            for s in self.completed_steps:
                lines.append(f"  ✓ {s}")

        if self.notes:
            lines.append(f"\nNotes:")
            for n in self.notes[-5:]:
                lines.append(f"  {n}")

        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics."""
        severity_count = {}
        for f in self.findings:
            severity_count[f.severity] = severity_count.get(f.severity, 0) + 1

        return {
            "target": self.target,
            "duration_minutes": (datetime.now() - self.start_time).seconds // 60,
            "subdomains": len(self.subdomains),
            "open_ports": len(self.open_ports),
            "http_services": len(self.http_services),
            "total_findings": len(self.findings),
            "findings_by_severity": severity_count,
            "tools_run": len(self.tool_history),
            "steps_completed": len(self.completed_steps),
        }
