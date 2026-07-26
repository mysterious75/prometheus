"""Scan Agent — vulnerability scanning specialist.

Takes recon data as input and runs all vulnerability scanners:
- Nuclei template-based scanning
- All 15 custom scanners from src/scanner/
- Focused scanning based on discovered tech stack

Outputs verified findings with evidence.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import time

from ..core.logger import logger, console
from ..tools.registry import registry
from ..scanner.runner import ScanRunner
from ..scanner.findings import ScanResult


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


class ScanAgent:
    """Vulnerability scanning specialist agent.

    Responsibilities:
    - Run nuclei template-based scans
    - Run all 15 custom vulnerability scanners
    - Take recon data (subdomains, ports, URLs) as input
    - Focus scans based on discovered tech stack
    - Output verified findings with evidence
    """

    NAME = "scan"

    def __init__(self, rps: float = 10.0):
        self.rps = rps
        self.scan_runner = ScanRunner(rps=rps)
        self._scanned_urls: set = set()

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Execute vulnerability scanning against a target.

        Args:
            target: Primary target (domain/URL)
            context: Recon results with subdomains, ports, http_services, urls

        Returns:
            AgentResult with all vulnerability findings
        """
        start = time.time()
        context = context or {}
        all_findings: List[Dict[str, Any]] = []

        console.print(f"\n[bold blue]═══ Scan Agent: {target} ═══[/bold blue]")

        # Extract scan targets from recon context
        scan_targets = self._build_target_list(target, context)
        console.print(f"  [info]Scanning {len(scan_targets)} targets[/info]")

        # Phase 1: Nuclei template scan
        self._run_nuclei(scan_targets, context, all_findings)

        # Phase 2: Full scanner suite on primary target
        self._run_full_scan(target, all_findings)

        # Phase 3: Focused scanning on high-value HTTP services
        http_services = context.get("http_services", [])
        if http_services:
            self._run_focused_scans(http_services, context, all_findings)

        duration = time.time() - start

        # Deduplicate findings by (vuln_type, url)
        deduped = self._deduplicate_findings(all_findings)

        severity_count = {}
        for f in deduped:
            sev = f.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        stats = {
            "total_findings": len(deduped),
            "targets_scanned": len(self._scanned_urls),
            "findings_by_severity": severity_count,
        }

        console.print(f"  [success]Scan complete: {len(deduped)} findings "
                       f"across {len(self._scanned_urls)} targets[/success]")

        return AgentResult(
            agent=self.NAME,
            success=True,
            findings=deduped,
            stats=stats,
            duration=duration,
        )

    def _build_target_list(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Build list of targets to scan from recon data."""
        targets = []

        # Primary target
        if target.startswith(("http://", "https://")):
            targets.append(target)
        else:
            targets.append(f"https://{target}")

        # From recon context
        for svc in context.get("http_services", []):
            url = svc.get("url", "")
            if url and url not in targets:
                targets.append(url)

        for url in context.get("urls", []):
            if url not in targets:
                targets.append(url)

        # Subdomains as potential targets
        for sub in context.get("subdomains", []):
            url = f"https://{sub}"
            if url not in targets:
                targets.append(url)

        return targets

    def _run_nuclei(self, targets: List[str], context: Dict[str, Any],
                    findings: List[Dict[str, Any]]):
        """Run nuclei template-based vulnerability scanning."""
        console.print("  [info]Phase 1: Nuclei template scanning[/info]")

        tech_stack = context.get("tech_stack", [])
        severity = "critical,high,medium"

        # Scan up to 30 targets with nuclei
        for url in targets[:30]:
            if url in self._scanned_urls:
                continue

            result = registry.run("nuclei", url, severity=severity)
            self._scanned_urls.add(url)

            if result.success:
                for f in result.findings:
                    f["agent"] = self.NAME
                    f["phase"] = "nuclei"
                    findings.append(f)

    def _run_full_scan(self, target: str, findings: List[Dict[str, Any]]):
        """Run the full scanner suite (all 15 scanners) on the primary target."""
        console.print("  [info]Phase 2: Full scanner suite[/info]")

        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        if url in self._scanned_urls:
            return

        try:
            scan_result: ScanResult = self.scan_runner.scan(url, full=True)
            self._scanned_urls.add(url)

            for f in scan_result.findings:
                findings.append({
                    "type": f.vuln_type,
                    "title": f.title,
                    "severity": f.severity,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cvss": f.cvss,
                    "cwe": f.cwe,
                    "tool": f.tool,
                    "verified": f.verified,
                    "confidence": f.confidence,
                    "agent": self.NAME,
                    "phase": "full_scan",
                })

        except Exception as e:
            logger.error(f"Full scan failed for {url}: {e}")
            console.print(f"    [error]Full scan error: {e}[/error]")

    def _run_focused_scans(self, http_services: List[Dict[str, Any]],
                           context: Dict[str, Any],
                           findings: List[Dict[str, Any]]):
        """Run focused scans on high-value HTTP services."""
        console.print("  [info]Phase 3: Focused scanning on services[/info]")

        tech_stack = context.get("tech_stack", [])

        # Prioritize services with interesting tech
        priority_services = []
        for svc in http_services:
            url = svc.get("url", "")
            tech = svc.get("tech", [])
            # Prioritize services running known-vulnerable tech
            if any(t.lower() in ("wordpress", "joomla", "drupal", "php", "apache", "nginx",
                                  "tomcat", "iis", "express", "flask", "django", "spring")
                   for t in tech):
                priority_services.insert(0, svc)
            else:
                priority_services.append(svc)

        # Scan top priority services with nuclei
        for svc in priority_services[:10]:
            url = svc.get("url", "")
            if not url or url in self._scanned_urls:
                continue

            result = registry.run("nuclei", url, severity="critical,high,medium")
            self._scanned_urls.add(url)

            if result.success:
                for f in result.findings:
                    f["agent"] = self.NAME
                    f["phase"] = "focused_scan"
                    findings.append(f)

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate findings by (type, url) keeping the one with best evidence."""
        seen: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            key = f"{f.get('type', '')}:{f.get('url', '')}:{f.get('parameter', '')}"
            existing = seen.get(key)

            if not existing:
                seen[key] = f
            else:
                # Keep the one with better evidence or higher confidence
                conf_order = {"CONFIRMED": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                existing_conf = conf_order.get(existing.get("confidence", "LOW"), 0)
                new_conf = conf_order.get(f.get("confidence", "LOW"), 0)
                if new_conf > existing_conf:
                    seen[key] = f

        return list(seen.values())
