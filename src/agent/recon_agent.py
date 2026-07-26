"""Recon Agent — reconnaissance specialist.

Discovers the full attack surface: subdomains, open ports, HTTP services,
technology stack, DNS records, WHOIS data. Smart deduplication avoids
re-scanning already discovered assets.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import time
import json
import re

from ..core.logger import logger, console
from ..tools.registry import registry


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


class ReconAgent:
    """Reconnaissance specialist agent.

    Responsibilities:
    - Subdomain enumeration (subfinder)
    - HTTP service probing (httpx)
    - Port scanning (nmap/portscan)
    - WHOIS lookups
    - DNS enumeration
    - Technology fingerprinting

    Smart dedup: tracks discovered assets and skips re-scanning.
    """

    NAME = "recon"

    def __init__(self):
        self.discovered_subdomains: set = set()
        self.discovered_ports: List[Dict[str, Any]] = []
        self.discovered_http_services: List[Dict[str, Any]] = []
        self.discovered_urls: List[str] = []
        self.tech_stack: List[str] = []
        self.dns_records: Dict[str, List[str]] = {}
        self.whois_data: Dict[str, Any] = {}

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Execute full reconnaissance against a target.

        Args:
            target: Domain, IP, or URL to recon
            context: Optional prior context (e.g., from previous runs)

        Returns:
            AgentResult with all discovered assets
        """
        start = time.time()
        context = context or {}
        all_findings: List[Dict[str, Any]] = []

        console.print(f"\n[bold blue]═══ Recon Agent: {target} ═══[/bold blue]")

        # Restore prior context for dedup
        if "subdomains" in context:
            self.discovered_subdomains = set(context["subdomains"])
        if "ports" in context:
            self.discovered_ports = context["ports"]
        if "http_services" in context:
            self.discovered_http_services = context["http_services"]

        # Phase 1: WHOIS (fast, always useful)
        self._run_whois(target, all_findings)

        # Phase 2: DNS enumeration
        self._run_dns(target, all_findings)

        # Phase 3: Subdomain discovery
        new_subdomains = self._run_subfinder(target, all_findings)

        # Phase 4: Port scanning
        self._run_portscan(target, all_findings)

        # Phase 5: HTTP probing on discovered subdomains
        if new_subdomains:
            self._run_httpx(new_subdomains, all_findings)
        else:
            # Probe the target itself
            self._run_httpx([target], all_findings)

        duration = time.time() - start

        # Build assets summary
        assets = {
            "subdomains": sorted(self.discovered_subdomains),
            "ports": self.discovered_ports,
            "http_services": self.discovered_http_services,
            "urls": self.discovered_urls,
            "tech_stack": self.tech_stack,
            "dns_records": self.dns_records,
            "whois": self.whois_data,
        }

        stats = {
            "subdomains_found": len(self.discovered_subdomains),
            "ports_found": len(self.discovered_ports),
            "http_services_found": len(self.discovered_http_services),
            "urls_found": len(self.discovered_urls),
            "new_subdomains": len(new_subdomains),
        }

        console.print(f"  [success]Recon complete: {stats['subdomains_found']} subdomains, "
                       f"{stats['ports_found']} ports, {stats['http_services_found']} HTTP services[/success]")

        return AgentResult(
            agent=self.NAME,
            success=True,
            findings=all_findings,
            assets=assets,
            stats=stats,
            duration=duration,
        )

    def _run_whois(self, target: str, findings: List[Dict[str, Any]]):
        """Run WHOIS lookup."""
        console.print("  [info]Phase 1: WHOIS lookup[/info]")
        # Extract domain from URL if needed
        domain = target
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[1].split("/")[0]

        result = registry.run("whois", domain) if registry.get("whois") else None
        if result and result.success:
            self.whois_data = {
                "raw": result.raw_output[:2000] if result.raw_output else "",
                "findings": result.findings,
            }
            for f in result.findings:
                f["agent"] = self.NAME
                f["phase"] = "whois"
                findings.append(f)

    def _run_dns(self, target: str, findings: List[Dict[str, Any]]):
        """Run DNS enumeration."""
        console.print("  [info]Phase 2: DNS enumeration[/info]")
        domain = target
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[1].split("/")[0]

        result = registry.run("dns", domain) if registry.get("dns") else None
        if result and result.success:
            for f in result.findings:
                ftype = f.get("type", "")
                if ftype == "dns_record":
                    record_type = f.get("record_type", "A")
                    value = f.get("value", "")
                    self.dns_records.setdefault(record_type, []).append(value)
                f["agent"] = self.NAME
                f["phase"] = "dns"
                findings.append(f)

    def _run_subfinder(self, target: str, findings: List[Dict[str, Any]]) -> List[str]:
        """Run subfinder for subdomain discovery. Returns only NEW subdomains."""
        console.print("  [info]Phase 3: Subdomain discovery[/info]")
        domain = target
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[1].split("/")[0]

        result = registry.run("subfinder", domain)
        new_subdomains = []

        if result.success:
            for f in result.findings:
                ftype = f.get("type", "")
                if ftype == "subdomain":
                    sub = f.get("value", "")
                    if sub and sub not in self.discovered_subdomains:
                        self.discovered_subdomains.add(sub)
                        new_subdomains.append(sub)
                        f["agent"] = self.NAME
                        f["phase"] = "subfinder"
                        findings.append(f)

        console.print(f"    Found {len(new_subdomains)} new subdomains "
                       f"(total: {len(self.discovered_subdomains)})")
        return new_subdomains

    def _run_portscan(self, target: str, findings: List[Dict[str, Any]]):
        """Run port scanning."""
        console.print("  [info]Phase 4: Port scanning[/info]")
        # Extract host from URL
        host = target
        if host.startswith(("http://", "https://")):
            host = host.split("//")[1].split("/")[0]

        known_ports = {p.get("port") for p in self.discovered_ports}

        result = registry.run("portscan", host)
        if result.success:
            for f in result.findings:
                if f.get("type") == "open_port":
                    port = f.get("port")
                    if port and port not in known_ports:
                        self.discovered_ports.append(f)
                        known_ports.add(port)
                f["agent"] = self.NAME
                f["phase"] = "portscan"
                findings.append(f)

    def _run_httpx(self, targets: List[str], findings: List[Dict[str, Any]]):
        """Probe HTTP services on a list of hosts."""
        console.print(f"  [info]Phase 5: HTTP probing ({len(targets)} targets)[/info]")

        known_urls = {svc.get("url") for svc in self.discovered_http_services}

        # Limit to avoid excessive probing
        for host in targets[:50]:
            url = host if host.startswith(("http://", "https://")) else f"https://{host}"
            if url in known_urls:
                continue

            result = registry.run("httpx", url)
            if result.success:
                for f in result.findings:
                    if f.get("type") == "http_service":
                        svc_url = f.get("url", url)
                        if svc_url not in known_urls:
                            self.discovered_http_services.append(f)
                            known_urls.add(svc_url)
                            # Extract tech
                            for tech in f.get("tech", []):
                                if tech not in self.tech_stack:
                                    self.tech_stack.append(tech)
                    f["agent"] = self.NAME
                    f["phase"] = "httpx"
                    findings.append(f)
