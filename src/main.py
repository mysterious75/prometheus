"""Prometheus Orchestrator — the main assessment engine.

Coordinates the agent brain, tools, knowledge base, and reporting
to conduct autonomous security assessments.
"""

from typing import Dict, Any, Optional
from datetime import datetime

from .agent.planner import AttackPlanner, AttackStep
from .agent.executor import ToolExecutor
from .agent.memory import WorkingMemory
from .agent.chain import ChainBuilder
from .brain.router import ModelRouter
from .core.config import config
from .core.auth import auth
from .core.logger import logger, console
from .knowledge.index import knowledge


class Prometheus:
    """Main Prometheus security assessment engine.

    Usage:
        prometheus = Prometheus()
        prometheus.assess("example.com")  # full autonomous assessment
        prometheus.status()                # system status
    """

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router or ModelRouter()
        self.planner = AttackPlanner(self.router)
        self.chain_builder = ChainBuilder(self.router)
        self.memory: Optional[WorkingMemory] = None

    def assess(self, target: str, max_steps: int = 15) -> Dict[str, Any]:
        """Run a full autonomous security assessment on a target.

        1. Check authorization
        2. Generate attack plan
        3. Execute tools step by step
        4. Analyze results
        5. Build exploit chains
        6. Generate report
        """
        # Authorization check
        if not auth.require_auth(target):
            return {"error": "Target not authorized", "target": target}

        console.print(f"\n[bold blue]═══ Prometheus Security Assessment ═══[/bold blue]")
        console.print(f"[target]Target: {target}[/target]")
        console.print(f"[info]Max steps: {max_steps}[/info]\n")

        # Initialize working memory
        self.memory = WorkingMemory(target)
        executor = ToolExecutor(self.memory)

        # Load knowledge base context
        kb_context = knowledge.search(target, limit=5)
        if kb_context:
            self.memory.add_note(f"Found {len(kb_context)} relevant knowledge base entries")
            for entry in kb_context[:3]:
                self.memory.add_note(f"KB: {entry.title}")

        # Generate initial plan
        initial_steps = self.planner.plan_initial(target)
        self.memory.set_plan([str(s) for s in initial_steps])

        console.print(f"[info]Plan: {len(initial_steps)} initial steps[/info]\n")

        # Execute initial plan
        for i, step in enumerate(initial_steps):
            if i >= max_steps:
                break
            console.print(f"\n[bold]Step {i+1}/{min(len(initial_steps), max_steps)}: {step.reasoning}[/bold]")
            executor.execute(step.tool, step.target, **step.args)

        # AI-guided continuation
        steps_done = len(initial_steps)
        while steps_done < max_steps:
            context = self.memory.get_context()
            available = executor.get_available_tools()

            next_step = self.planner.plan_next(target, context, available)
            if next_step is None:
                console.print("\n[success]✓ Assessment complete — no more actions needed.[/success]")
                break

            steps_done += 1
            console.print(
                f"\n[bold]AI Step {steps_done}: {next_step.reasoning}[/bold]"
            )
            executor.execute_plan(next_step.tool, next_step.target, next_step.args)

        # Analyze exploit chains
        if len(self.memory.findings) >= 2:
            console.print("\n[bold cyan]Analyzing exploit chains...[/bold cyan]")
            chains = self.chain_builder.find_chains(self.memory)
            if chains:
                console.print(f"  [warning]Found {len(chains)} exploit chains![/warning]")
                for chain in chains:
                    console.print(f"  [critical]⚡ {chain.name}[/critical]")
                    console.print(f"    Impact: {chain.impact[:100]}")

        # Generate final analysis
        stats = self.memory.get_stats()
        report = self._generate_report(stats)

        console.print(f"\n[bold blue]═══ Assessment Complete ═══[/bold blue]")
        console.print(f"  Findings: {stats['total_findings']}")
        for sev, count in stats.get('findings_by_severity', {}).items():
            console.print(f"    [{sev.lower()}]{sev}: {count}[/{sev.lower()}]")
        console.print(f"  Tools run: {stats['tools_run']}")
        console.print(f"  Duration: {stats['duration_minutes']} min")

        return report

    def _generate_report(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final assessment report."""
        report = {
            "target": self.memory.target,
            "timestamp": datetime.now().isoformat(),
            "stats": stats,
            "findings": [f.to_dict() for f in self.memory.findings],
            "subdomains": self.memory.subdomains[:50],
            "open_ports": self.memory.open_ports,
            "http_services": self.memory.http_services[:20],
            "tech_stack": self.memory.tech_stack,
            "usernames": self.memory.usernames,
        }

        # Generate LLM analysis if findings exist
        if self.memory.findings:
            context = self.memory.get_context()
            try:
                analysis = self.planner.analyze_findings(context)
                report["analysis"] = analysis
            except Exception:
                report["analysis"] = "Analysis generation failed."

        # Save report
        output_dir = config.output_dir / self.memory.target.replace(".", "_")
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            import json
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            console.print(f"\n  [info]Report saved: {report_file}[/info]")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

        return report

    def status(self) -> str:
        """Get system status."""
        lines = [
            "\n[bold]Prometheus v3.0 — AI Security Researcher[/bold]",
            "",
            f"  Model: {self.router.get_status()[:200]}",
            "",
        ]

        # Tool status
        from .tools.registry import registry
        lines.append(registry.status())

        # Knowledge base
        kb_stats = knowledge.get_stats()
        lines.append(f"\n  Knowledge Base: {kb_stats['total_entries']} entries")

        # Auth
        lines.append(f"\n  {auth.list_targets()}")

        return "\n".join(lines)

    def osint(self, target: str) -> Dict[str, Any]:
        """Run OSINT on a target (no auth needed for passive recon)."""
        from .tools.registry import registry

        console.print(f"\n[bold cyan]OSINT: {target}[/bold cyan]")

        results = {"target": target, "findings": []}

        # Username search
        if not target.startswith(("http://", "https://", ".")):
            result = registry.run("sherlock", target)
            results["findings"].extend(result.findings)

        # Subdomain + HTTP probe for domains
        if "." in target:
            sub_result = registry.run("subfinder", target)
            results["findings"].extend(sub_result.findings)

            subdomains = [f["value"] for f in sub_result.findings]
            if subdomains:
                http_result = registry.run("httpx", target, targets=subdomains[:20])
                results["findings"].extend(http_result.findings)

        console.print(f"\n  [success]OSINT complete: {len(results['findings'])} findings[/success]")
        return results
