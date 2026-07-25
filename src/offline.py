"""Offline Mode — runs security scans without LLM API keys.

Uses predefined attack sequences instead of AI planning.
The tool works fully offline — no network calls to LLM providers.
"""

from typing import Dict, Any

from .scanner.runner import ScanRunner
from .scanner.report import ReportGenerator
from .tools.registry import registry
from .core.auth import auth
from .core.logger import console


class OfflinePrometheus:
    """Prometheus in offline mode — no LLM required.

    Runs a predefined sequence of security checks:
    1. Crawl target
    2. Run all vulnerability scanners
    3. Generate report

    All without any API keys.
    """

    def __init__(self, rps: float = 10.0):
        self.runner = ScanRunner(rps=rps)
        self.reporter = ReportGenerator()

    def scan(self, target: str, full: bool = True) -> Dict[str, Any]:
        """Run a full security scan offline."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Auth check
        if not auth.require_auth(target):
            return {"error": "Target not authorized"}

        # Run scan
        result = self.runner.scan(target, full=full)

        # Generate report
        report_path = self.reporter.save(result)
        console.print(f"\n  [success]Report saved: {report_path}[/success]")

        return {
            "target": target,
            "summary": result.summary(),
            "report_path": str(report_path),
            "findings": [f.to_dict() for f in result.findings],
        }

    def osint(self, target: str) -> Dict[str, Any]:
        """Run OSINT offline."""
        console.print(f"\n[bold cyan]OSINT (offline): {target}[/bold cyan]")

        results = {"target": target, "findings": []}

        # Username search
        if not target.startswith(("http://", "https://", ".")):
            result = registry.run("sherlock", target)
            results["findings"].extend(result.findings)

        # Subdomain + HTTP probe
        if "." in target and not target.startswith("http"):
            sub_result = registry.run("subfinder", target)
            results["findings"].extend(sub_result.findings)

            subdomains = [f["value"] for f in sub_result.findings]
            if subdomains:
                http_result = registry.run("httpx", target, targets=subdomains[:20])
                results["findings"].extend(http_result.findings)

        console.print(f"  [success]OSINT complete: {len(results['findings'])} results[/success]")
        return results

    def status(self) -> str:
        """Get system status (offline)."""
        return registry.status()
