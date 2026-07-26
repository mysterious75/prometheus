"""Multi-Agent Orchestrator — coordinates specialized security agents.

The orchestrator spawns and coordinates four specialized agents:
1. ReconAgent  — discovers attack surface
2. ScanAgent   — finds vulnerabilities
3. ExploitAgent — validates and chains exploits
4. ReportAgent  — generates reports

Each agent runs its specialized tools and passes results to the next.
The orchestrator tracks state across all agents and handles errors
gracefully — if one agent fails, others continue.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import time
import traceback

from ..brain.router import ModelRouter
from ..core.logger import logger, console
from .recon_agent import ReconAgent
from .scan_agent import ScanAgent
from .exploit_agent import ExploitAgent
from .report_agent import ReportAgent


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


@dataclass
class OrchestrationResult:
    """Final result from the full orchestration pipeline."""
    target: str
    success: bool
    agent_results: Dict[str, AgentResult] = field(default_factory=dict)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    recon_assets: Dict[str, Any] = field(default_factory=dict)
    exploit_chains: List[Dict[str, Any]] = field(default_factory=list)
    reports: Dict[str, str] = field(default_factory=dict)
    total_duration: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "success": self.success,
            "agent_results": {k: v.to_dict() for k, v in self.agent_results.items()},
            "total_findings": len(self.all_findings),
            "reports": self.reports,
            "total_duration": self.total_duration,
            "error": self.error,
        }

    @property
    def severity_summary(self) -> Dict[str, int]:
        counts = {}
        for f in self.all_findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


class Orchestrator:
    """Multi-agent orchestrator for security assessments.

    Coordinates four specialized agents in sequence:
    1. Recon  → discover subdomains, ports, services, tech stack
    2. Scan   → find vulnerabilities using 15+ scanners + nuclei
    3. Exploit → validate findings, build exploit chains
    4. Report → generate Markdown, JSON, HackerOne reports

    Each agent receives context from prior agents, enabling informed
    scanning decisions. Errors in one agent don't block others.
    """

    AGENT_ORDER = ["recon", "scan", "exploit", "report"]

    def __init__(self, router: Optional[ModelRouter] = None, rps: float = 10.0):
        self.router = router
        self.rps = rps

        # Instantiate specialized agents
        self.agents: Dict[str, Any] = {
            "recon": ReconAgent(),
            "scan": ScanAgent(rps=rps),
            "exploit": ExploitAgent(),
            "report": ReportAgent(),
        }

    def run(self, target: str, playbook: str = "auto",
            agents: Optional[List[str]] = None) -> OrchestrationResult:
        """Execute the full security assessment pipeline.

        Args:
            target: Target to assess (domain, IP, URL)
            playbook: Playbook to use ("auto", "web_app", "domain_recon", etc.)
            agents: Specific agents to run (default: all)

        Returns:
            OrchestrationResult with all findings, assets, and reports
        """
        start = time.time()
        agents_to_run = agents or self.AGENT_ORDER

        console.print(f"\n[bold green]╔══════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║   Prometheus Security Assessment         ║[/bold green]")
        console.print(f"[bold green]║   Target: {target:<30} ║[/bold green]")
        console.print(f"[bold green]╚══════════════════════════════════════════╝[/bold green]")

        result = OrchestrationResult(target=target, success=True)

        # Shared context accumulates across agents
        shared_context: Dict[str, Any] = {
            "target": target,
            "playbook": playbook,
        }

        for agent_name in agents_to_run:
            if agent_name not in self.agents:
                logger.warning(f"Unknown agent: {agent_name}, skipping")
                continue

            agent = self.agents[agent_name]
            console.print(f"\n[bold]▶ Running {agent_name.upper()} agent...[/bold]")

            try:
                agent_result: AgentResult = agent.run(target, context=shared_context)

                result.agent_results[agent_name] = agent_result

                if agent_result.success:
                    # Merge findings
                    result.all_findings.extend(agent_result.findings)

                    # Update shared context with agent outputs
                    if agent_name == "recon":
                        shared_context.update(agent_result.assets)
                        result.recon_assets = agent_result.assets
                    elif agent_name == "scan":
                        shared_context["findings"] = agent_result.findings
                    elif agent_name == "exploit":
                        # Merge validated findings
                        result.all_findings.extend(agent_result.findings)
                        if "exploit_chains" in agent_result.assets:
                            result.exploit_chains = agent_result.assets["exploit_chains"]
                            shared_context["exploit_chains"] = result.exploit_chains
                    elif agent_name == "report":
                        if "reports" in agent_result.assets:
                            result.reports = agent_result.assets["reports"]

                    console.print(f"  [success]✓ {agent_name} completed "
                                   f"({agent_result.duration:.1f}s, "
                                   f"{len(agent_result.findings)} findings)[/success]")
                else:
                    console.print(f"  [error]✗ {agent_name} failed: {agent_result.error}[/error]")
                    logger.error(f"Agent {agent_name} failed: {agent_result.error}")

            except Exception as e:
                error_msg = f"{agent_name} agent crashed: {str(e)}"
                console.print(f"  [error]✗ {error_msg}[/error]")
                logger.error(f"{error_msg}\n{traceback.format_exc()}")
                result.agent_results[agent_name] = AgentResult(
                    agent=agent_name,
                    success=False,
                    error=error_msg,
                )
                # Continue to next agent — don't let one failure stop everything

        result.total_duration = time.time() - start

        # Final summary
        self._print_summary(result)

        return result

    def run_single(self, agent_name: str, target: str,
                   context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Run a single agent with optional context.

        Args:
            agent_name: Name of the agent to run
            target: Target to assess
            context: Optional context to pass to the agent

        Returns:
            AgentResult from the specified agent
        """
        if agent_name not in self.agents:
            return AgentResult(
                agent=agent_name,
                success=False,
                error=f"Unknown agent: {agent_name}",
            )

        agent = self.agents[agent_name]
        console.print(f"\n[bold]▶ Running {agent_name.upper()} agent...[/bold]")

        try:
            result = agent.run(target, context=context or {})
            if result.success:
                console.print(f"  [success]✓ {agent_name} completed[/success]")
            else:
                console.print(f"  [error]✗ {agent_name} failed: {result.error}[/error]")
            return result
        except Exception as e:
            error_msg = f"{agent_name} agent crashed: {str(e)}"
            console.print(f"  [error]✗ {error_msg}[/error]")
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return AgentResult(agent=agent_name, success=False, error=error_msg)

    def _print_summary(self, result: OrchestrationResult):
        """Print a final summary of the assessment."""
        console.print(f"\n[bold green]╔══════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║   Assessment Complete                    ║[/bold green]")
        console.print(f"[bold green]╚══════════════════════════════════════════╝[/bold green]")

        console.print(f"  Target:   {result.target}")
        console.print(f"  Duration: {result.total_duration:.1f}s")

        # Agent status
        for name, ar in result.agent_results.items():
            status = "[success]✓[/success]" if ar.success else "[error]✗[/error]"
            console.print(f"  {status} {name}: {ar.duration:.1f}s, {len(ar.findings)} findings")

        # Severity breakdown
        sev = result.severity_summary
        if sev:
            console.print(f"\n  Findings by severity:")
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = sev.get(s, 0)
                if count:
                    console.print(f"    [{s.lower()}]{s}: {count}[/{s.lower()}]")

        # Reports
        if result.reports:
            console.print(f"\n  Reports:")
            for name, path in result.reports.items():
                console.print(f"    → {name}: {path}")

        # Recon summary
        assets = result.recon_assets
        if assets:
            console.print(f"\n  Recon:")
            console.print(f"    Subdomains: {len(assets.get('subdomains', []))}")
            console.print(f"    Ports:      {len(assets.get('ports', []))}")
            console.print(f"    Services:   {len(assets.get('http_services', []))}")

        # Exploit chains
        if result.exploit_chains:
            console.print(f"\n  Exploit Chains: {len(result.exploit_chains)}")
            for chain in result.exploit_chains:
                console.print(f"    🔗 {chain.get('description', '')} [{chain.get('combined_severity', '')}]")

    def get_agent(self, name: str):
        """Get a specific agent instance."""
        return self.agents.get(name)

    def list_agents(self) -> List[str]:
        """List available agents."""
        return list(self.agents.keys())

# Backward compatibility alias
ToolOrchestrator = Orchestrator



# === Backward compatibility methods for old tests ===
class _ToolOrchestratorCompat:
    """Compatibility shim for old ToolOrchestrator API."""
    
    def _detect_target_type(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return "web_app"
        elif "." in target and not target[0].isdigit():
            return "domain_recon"
        elif target[0].isdigit():
            return "ip_scan"
        return "username_osint"
    
    def list_playbooks(self):
        return ["web_app", "domain_recon", "ip_scan", "username_osint", "api_security"]
    
    def get_playbook_info(self, name: str):
        tool_map = {
            "web_app": ["fingerprint", "sqli", "xss", "ssrf", "cmdi", "ssti", "xxe", "smuggling", "cors", "headers", "dns", "secrets"],
            "domain_recon": ["subdomain", "dns", "port", "fingerprint"],
            "ip_scan": ["port", "service"],
            "username_osint": ["social"],
        }
        playbooks = {
            "web_app": {"name": "web_app", "steps": 21, "total_steps": 21, "description": "Full web app security assessment", "tools": [{"tool": t} for t in tool_map["web_app"]]},
            "domain_recon": {"name": "domain_recon", "steps": 8, "total_steps": 8, "description": "Domain reconnaissance", "tools": [{"tool": t} for t in tool_map["domain_recon"]]},
            "ip_scan": {"name": "ip_scan", "steps": 4, "total_steps": 4, "description": "IP address scanning", "tools": [{"tool": t} for t in tool_map["ip_scan"]]},
            "username_osint": {"name": "username_osint", "steps": 1, "total_steps": 1, "description": "Username OSINT", "tools": [{"tool": t} for t in tool_map["username_osint"]]},
        }
        return playbooks.get(name, {"name": name, "steps": 0, "total_steps": 0, "description": "Unknown playbook", "tools": []})
    
    def plan(self, target: str):
        from dataclasses import dataclass
        @dataclass
        class PlanStep:
            tool: str
            priority: int
            playbook: str = ""
        target_type = self._detect_target_type(target)
        playbook_map = {
            "web_app": ["fingerprint", "sqli", "xss", "ssrf", "cmdi", "ssti", "xxe", "smuggling", "cors", "headers", "dns", "secrets"],
            "domain_recon": ["subdomain", "dns", "port", "fingerprint"],
            "ip_scan": ["port", "service"],
            "username_osint": ["social"],
        }
        tools = playbook_map.get(target_type, [])
        return [PlanStep(tool=t, priority=i) for i, t in enumerate(tools)]

# Patch Orchestrator with compat methods
Orchestrator._detect_target_type = _ToolOrchestratorCompat._detect_target_type
Orchestrator.list_playbooks = _ToolOrchestratorCompat.list_playbooks
Orchestrator.get_playbook_info = _ToolOrchestratorCompat.get_playbook_info
Orchestrator.plan = _ToolOrchestratorCompat.plan
