"""Prometheus CLI — professional command-line interface.

Rich output, scan profiles, history, export, and API management.
"""

import sys
import json
import time
import subprocess
import signal
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from ..main import Prometheus
from ..core.auth import auth
from ..core.logger import console
from ..core.config import config, get_profile, list_profiles, SCAN_PROFILES, OutputConfig
from ..brain.router import ModelRouter
from ..knowledge.index import knowledge


# ──────────────────────────────────────────────
# Scan History
# ──────────────────────────────────────────────


class ScanHistory:
    """Persistent scan history store."""

    def __init__(self, history_file: Optional[Path] = None):
        self._file = history_file or config.output_dir / "scan_history.json"
        self._entries: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        if self._file.exists():
            try:
                self._entries = json.loads(self._file.read_text())
            except (json.JSONDecodeError, KeyError):
                self._entries = []

    def _save(self):
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps(self._entries, indent=2, default=str))

    def add(self, target: str, scan_type: str, findings_count: int, duration: float, report_path: str = ""):
        entry = {
            "target": target,
            "scan_type": scan_type,
            "findings_count": findings_count,
            "duration": f"{duration:.1f}s",
            "report_path": report_path,
            "timestamp": datetime.now().isoformat(),
        }
        self._entries.insert(0, entry)
        # Keep last 50 entries
        self._entries = self._entries[:50]
        self._save()

    def get_all(self) -> List[Dict[str, Any]]:
        return self._entries

    def get_last(self) -> Optional[Dict[str, Any]]:
        return self._entries[0] if self._entries else None

    def clear(self):
        self._entries = []
        self._save()


# ──────────────────────────────────────────────
# Target Lists
# ──────────────────────────────────────────────


class TargetListManager:
    """Save and load target lists for batch scanning."""

    def __init__(self, lists_dir: Optional[Path] = None):
        self._dir = lists_dir or config.output_dir / "target_lists"
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, targets: List[str]) -> Path:
        path = self._dir / f"{name}.json"
        path.write_text(json.dumps(targets, indent=2))
        return path

    def load(self, name: str) -> List[str]:
        path = self._dir / f"{name}.json"
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, KeyError):
            return []

    def list_all(self) -> List[str]:
        return [p.stem for p in self._dir.glob("*.json")]

    def delete(self, name: str) -> bool:
        path = self._dir / f"{name}.json"
        if path.exists():
            path.unlink()
            return True
        return False


# ──────────────────────────────────────────────
# Output Formatters
# ──────────────────────────────────────────────


def format_findings_table(findings: List[Dict[str, Any]]) -> None:
    """Display findings as a rich table."""
    from rich.table import Table

    if not findings:
        console.print("[info]No findings to display.[/info]")
        return

    table = Table(title="Security Findings", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=20)
    table.add_column("Title", width=40)
    table.add_column("URL", width=40)
    table.add_column("CVSS", width=6, justify="center")

    severity_styles = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "blue",
    }

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        style = severity_styles.get(sev, "")
        table.add_row(
            str(i),
            f"[{style}]{sev}[/{style}]",
            f.get("vuln_type", ""),
            f.get("title", ""),
            f.get("url", ""),
            str(f.get("cvss", "")),
        )

    console.print(table)


def format_findings_json(findings: List[Dict[str, Any]]) -> None:
    """Display findings as JSON."""
    console.print(json.dumps(findings, indent=2, default=str))


def format_findings_markdown(findings: List[Dict[str, Any]]) -> None:
    """Display findings as markdown."""
    lines = ["# Findings\n"]
    for f in findings:
        sev = f.get("severity", "INFO")
        lines.append(f"## [{sev}] {f.get('title', 'Unknown')}")
        lines.append(f"- **Type:** {f.get('vuln_type', '')}")
        lines.append(f"- **URL:** {f.get('url', '')}")
        lines.append(f"- **CVSS:** {f.get('cvss', 0)}")
        if f.get("evidence"):
            lines.append(f"- **Evidence:** {f['evidence'][:200]}")
        lines.append("")
    console.print("\n".join(lines))


def export_findings(findings: List[Dict[str, Any]], format: str, filepath: str) -> Path:
    """Export findings to a file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        path.write_text(json.dumps(findings, indent=2, default=str))
    elif format == "markdown":
        lines = ["# Security Findings\n"]
        for f in findings:
            sev = f.get("severity", "INFO")
            lines.append(f"## [{sev}] {f.get('title', 'Unknown')}")
            lines.append(f"- **Type:** {f.get('vuln_type', '')}")
            lines.append(f"- **URL:** {f.get('url', '')}")
            lines.append(f"- **CVSS:** {f.get('cvss', 0)}")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {f['cwe']}")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** {f['evidence'][:500]}")
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append("")
        path.write_text("\n".join(lines))
    elif format == "csv":
        import csv
        import io
        output = io.StringIO()
        if findings:
            writer = csv.DictWriter(output, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
        path.write_text(output.getvalue())
    else:
        raise ValueError(f"Unsupported export format: {format}")

    return path


# ──────────────────────────────────────────────
# CLI Class
# ──────────────────────────────────────────────


class CLI:
    """Interactive CLI for Prometheus with professional-grade features."""

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router or ModelRouter()
        self.prometheus = Prometheus(self.router)
        self.running = True
        self.output_format = config.output.format  # table, json, markdown
        self.current_profile = config.default_profile
        self.last_findings: List[Dict[str, Any]] = []
        self.last_target: str = ""
        self.history = ScanHistory()
        self.target_lists = TargetListManager()
        self._api_process: Optional[subprocess.Popen] = None

    def run(self):
        """Main CLI loop."""
        self._print_banner()

        while self.running:
            try:
                user_input = console.input("\n[bold cyan]you▸[/bold cyan] ").strip()
                if not user_input:
                    continue
                self._handle(user_input)
            except KeyboardInterrupt:
                console.print("\n[info]Use 'quit' to exit.[/info]")
            except EOFError:
                break

        console.print("[info]Stay safe. Hack ethically. 🛡️[/info]")

    def _handle(self, text: str):
        """Route user input to the appropriate handler."""
        parts = text.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""

        handlers = {
            # Assessment
            "scan": self._cmd_scan,
            "assess": self._cmd_scan,
            "recon": self._cmd_recon,
            "osint": self._cmd_osint,
            "quick": self._cmd_quick,
            "stealth": self._cmd_stealth,

            # Book-based scanners
            "owasp": self._cmd_owasp,
            "business": self._cmd_business,
            "session": self._cmd_session,
            "crypto": self._cmd_crypto,
            "ssl": self._cmd_crypto,
            "api": self._cmd_api,
            "report": self._cmd_report,

            # Authorization
            "authorize": self._cmd_authorize,
            "auth": self._cmd_authorize,
            "revoke": self._cmd_revoke,
            "targets": self._cmd_targets,

            # History & Export
            "history": self._cmd_history,
            "export": self._cmd_export,

            # Profiles
            "profile": self._cmd_profile,
            "profiles": self._cmd_profiles,

            # Target lists
            "save-targets": self._cmd_save_targets,
            "load-targets": self._cmd_load_targets,
            "list-targets": self._cmd_list_target_lists,

            # Output
            "output": self._cmd_output,

            # Knowledge
            "kb": self._cmd_knowledge,
            "knowledge": self._cmd_knowledge,
            "playbook": self._cmd_playbook,

            # API server
            "api": self._cmd_api_server,

            # System
            "status": self._cmd_status,
            "tools": self._cmd_tools,
            "help": self._cmd_help,
            "quit": self._cmd_quit,
            "exit": self._cmd_quit,
            "q": self._cmd_quit,
        }

        handler = handlers.get(command)
        if handler:
            handler(args)
        else:
            # Treat as chat with the AI
            self._cmd_chat(text)

    # ──────────────────────────────────────────
    # Assessment Commands
    # ──────────────────────────────────────────

    def _cmd_scan(self, target: str):
        """Run a full security assessment."""
        if not target:
            console.print("[error]Usage: scan <target>[/error]")
            return
        self._run_scan_with_profile(target, self.current_profile)

    def _cmd_quick(self, target: str):
        """Run a quick scan (top 10 vulns only)."""
        if not target:
            console.print("[error]Usage: quick <target>[/error]")
            return
        self._run_scan_with_profile(target, "quick")

    def _cmd_stealth(self, target: str):
        """Run a slow, stealthy scan."""
        if not target:
            console.print("[error]Usage: stealth <target>[/error]")
            return
        self._run_scan_with_profile(target, "stealth")

    def _run_scan_with_profile(self, target: str, profile_name: str):
        """Run a scan using a specific profile with progress display."""
        if not auth.require_auth(target):
            return

        profile = get_profile(profile_name)
        self.last_target = target

        from rich.panel import Panel
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Profile:[/bold] {profile.name} — {profile.description}\n"
            f"[bold]RPS:[/bold] {profile.rps} | [bold]Max URLs:[/bold] {profile.max_urls} | "
            f"[bold]Crawl Depth:[/bold] {profile.crawl_depth}",
            title="🔍 Security Scan",
            border_style="cyan",
        ))

        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=100)

            try:
                if profile.scanners and len(profile.scanners) == 1:
                    # Specialized scanner
                    scanner_type = profile.scanners[0]
                    progress.update(task, advance=10, description=f"Running {scanner_type} scanner...")
                    findings = self._run_specialized_scan(scanner_type, target)
                    progress.update(task, advance=80, description="Processing results...")
                else:
                    # General scan
                    from ..scanner.runner import ScanRunner
                    runner = ScanRunner(rps=profile.rps)
                    progress.update(task, advance=10, description="Crawling target...")

                    result = runner.scan(target, full=profile.full_crawl)
                    findings = result.findings
                    progress.update(task, advance=80, description="Processing results...")

                self.last_findings = [f.to_dict() for f in findings]
                progress.update(task, completed=100, description="Complete!")

            except Exception as e:
                progress.update(task, description=f"[error]Failed: {e}[/error]")
                console.print(f"[error]Scan error: {e}[/error]")
                return

        duration = time.time() - start_time

        # Display results
        self._display_results(target, findings, duration, profile_name)

        # Save to history
        self.history.add(
            target=target,
            scan_type=profile_name,
            findings_count=len(findings),
            duration=duration,
        )

    def _run_specialized_scan(self, scanner_type: str, target: str) -> list:
        """Run a specialized scanner."""
        if scanner_type == "owasp":
            from ..scanner.owasp_methodology import OWASPMethodologyScanner
            result = OWASPMethodologyScanner().scan(target)
            return result.findings if hasattr(result, 'findings') else []
        elif scanner_type == "business_logic":
            from ..scanner.business_logic import BusinessLogicScanner
            return BusinessLogicScanner().scan_url(target)
        elif scanner_type == "session_manager":
            from ..scanner.session_manager import SessionManagerScanner
            return SessionManagerScanner().scan_url(target)
        elif scanner_type == "crypto":
            from ..scanner.crypto_scanner import CryptoScanner
            return CryptoScanner().scan_url(target)
        elif scanner_type == "api_security":
            from ..scanner.api_security import APISecurityScanner
            return APISecurityScanner().scan_url(target)
        return []

    def _display_results(self, target: str, findings: list, duration: float, profile_name: str):
        """Display scan results in the configured output format."""
        from rich.panel import Panel

        # Severity counts
        severity_counts = {}
        for f in findings:
            sev = f.severity if hasattr(f, 'severity') else f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_lines = [
            f"[bold]Target:[/bold] {target}",
            f"[bold]Profile:[/bold] {profile_name}",
            f"[bold]Duration:[/bold] {duration:.1f}s",
            f"[bold]Findings:[/bold] {len(findings)}",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = sev.lower()
                summary_lines.append(f"  [{style}]{sev}: {count}[/{style}]")

        console.print(Panel("\n".join(summary_lines), title="📊 Results", border_style="green"))

        # Display findings based on output format
        findings_dicts = self.last_findings if self.last_findings else [
            f.to_dict() if hasattr(f, 'to_dict') else f for f in findings
        ]

        if self.output_format == "json":
            format_findings_json(findings_dicts)
        elif self.output_format == "markdown":
            format_findings_markdown(findings_dicts)
        else:
            format_findings_table(findings_dicts)

    def _cmd_recon(self, target: str):
        """Run recon only (subdomain + ports + HTTP)."""
        if not target:
            console.print("[error]Usage: recon <target>[/error]")
            return
        if not auth.require_auth(target):
            return
        from ..tools.registry import registry
        console.print(f"\n[bold cyan]Recon: {target}[/bold cyan]")
        registry.run("subfinder", target)
        registry.run("httpx", target)
        registry.run("nmap", target)

    def _cmd_osint(self, target: str):
        """Run OSINT (no auth needed for passive recon)."""
        if not target:
            console.print("[error]Usage: osint <username_or_domain>[/error]")
            return
        self.prometheus.osint(target)

    def _cmd_owasp(self, target: str):
        """Run OWASP Testing Guide v4 methodology scan."""
        if not target:
            console.print("[error]Usage: owasp <target>[/error]")
            return
        self._run_scan_with_profile(target, "owasp")

    def _cmd_business(self, target: str):
        """Run business logic vulnerability tests."""
        if not target:
            console.print("[error]Usage: business <target>[/error]")
            return
        self._run_scan_with_profile(target, "business")

    def _cmd_session(self, target: str):
        """Run session management security tests."""
        if not target:
            console.print("[error]Usage: session <target>[/error]")
            return
        self._run_scan_with_profile(target, "session")

    def _cmd_crypto(self, target: str):
        """Run cryptographic security tests."""
        if not target:
            console.print("[error]Usage: crypto <target>[/error]")
            return
        self._run_scan_with_profile(target, "crypto")

    def _cmd_api(self, target: str):
        """Run API security tests."""
        if not target:
            console.print("[error]Usage: api <target>[/error]")
            return
        self._run_scan_with_profile(target, "api")

    def _cmd_report(self, target: str):
        """Generate executive security report."""
        if not target:
            console.print("[error]Usage: report <target>[/error]")
            return
        try:
            from ..scanner.executive_report import ExecutiveReportGenerator
            from ..scanner.runner import ScanRunner
            generator = ExecutiveReportGenerator()
            runner = ScanRunner()
            console.print(f"\n[bold cyan]Generating Executive Report: {target}[/bold cyan]")
            result = runner.scan(target)
            report_path = generator.generate_report(result)
            console.print(f"\n  [success]Report saved: {report_path}[/success]")
        except ImportError:
            console.print("[error]Report generator not available.[/error]")
        except Exception as e:
            console.print(f"[error]Error: {e}[/error]")

    # ──────────────────────────────────────────
    # Authorization
    # ──────────────────────────────────────────

    def _cmd_authorize(self, target: str):
        """Authorize a target for scanning."""
        if not target:
            console.print("[error]Usage: authorize <target>[/error]")
            return
        result = auth.authorize(target)
        console.print(f"[success]{result}[/success]")

    def _cmd_revoke(self, target: str):
        """Revoke target authorization."""
        if not target:
            console.print("[error]Usage: revoke <target>[/error]")
            return
        result = auth.revoke(target)
        console.print(f"[info]{result}[/info]")

    def _cmd_targets(self, _args: str):
        """List authorized targets."""
        console.print(f"[info]{auth.list_targets()}[/info]")

    # ──────────────────────────────────────────
    # History & Export
    # ──────────────────────────────────────────

    def _cmd_history(self, _args: str):
        """Show previous scan results."""
        from rich.table import Table

        entries = self.history.get_all()
        if not entries:
            console.print("[info]No scan history yet.[/info]")
            return

        table = Table(title="Scan History", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Timestamp", width=20)
        table.add_column("Target", width=30)
        table.add_column("Profile", width=12)
        table.add_column("Findings", width=10, justify="center")
        table.add_column("Duration", width=10, justify="center")

        for i, entry in enumerate(entries[:20], 1):
            ts = entry.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    ts = dt.strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    pass
            table.add_row(
                str(i),
                ts,
                entry.get("target", ""),
                entry.get("scan_type", ""),
                str(entry.get("findings_count", 0)),
                entry.get("duration", ""),
            )

        console.print(table)

    def _cmd_export(self, args: str):
        """Export last results to file. Usage: export <format> [filepath]"""
        if not self.last_findings:
            console.print("[error]No findings to export. Run a scan first.[/error]")
            return

        parts = args.split(maxsplit=1)
        fmt = parts[0] if parts else "json"
        filepath = parts[1] if len(parts) > 1 else None

        if fmt not in ("json", "markdown", "csv"):
            console.print("[error]Supported formats: json, markdown, csv[/error]")
            return

        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = {"json": "json", "markdown": "md", "csv": "csv"}[fmt]
            filepath = str(config.output_dir / f"findings_{timestamp}.{ext}")

        try:
            path = export_findings(self.last_findings, fmt, filepath)
            console.print(f"[success]Exported {len(self.last_findings)} findings to {path}[/success]")
        except Exception as e:
            console.print(f"[error]Export failed: {e}[/error]")

    # ──────────────────────────────────────────
    # Profiles
    # ──────────────────────────────────────────

    def _cmd_profile(self, args: str):
        """Set or show current scan profile. Usage: profile [name]"""
        if not args:
            profile = get_profile(self.current_profile)
            from rich.panel import Panel
            console.print(Panel(
                f"[bold]Current Profile:[/bold] {profile.name}\n"
                f"[bold]Description:[/bold] {profile.description}\n"
                f"[bold]RPS:[/bold] {profile.rps}\n"
                f"[bold]Max URLs:[/bold] {profile.max_urls}\n"
                f"[bold]Crawl Depth:[/bold] {profile.crawl_depth}\n"
                f"[bold]Stealth:[/bold] {profile.stealth}\n"
                f"[bold]Aggressive:[/bold] {profile.aggressive}",
                title="📋 Scan Profile",
                border_style="cyan",
            ))
            return

        name = args.strip().lower()
        if name not in SCAN_PROFILES:
            console.print(f"[error]Unknown profile '{name}'. Available: {', '.join(SCAN_PROFILES.keys())}[/error]")
            return

        self.current_profile = name
        profile = get_profile(name)
        console.print(f"[success]Profile set to '{name}': {profile.description}[/success]")

    def _cmd_profiles(self, _args: str):
        """List all available scan profiles."""
        from rich.table import Table

        table = Table(title="Scan Profiles", show_lines=True)
        table.add_column("Name", width=12, style="bold cyan")
        table.add_column("Description", width=50)
        table.add_column("RPS", width=6, justify="center")
        table.add_column("Max URLs", width=10, justify="center")
        table.add_column("Active", width=8, justify="center")

        for name, profile in SCAN_PROFILES.items():
            is_active = "✓" if name == self.current_profile else ""
            table.add_row(
                name,
                profile.description,
                str(profile.rps),
                str(profile.max_urls),
                is_active,
            )

        console.print(table)

    # ──────────────────────────────────────────
    # Target Lists
    # ──────────────────────────────────────────

    def _cmd_save_targets(self, args: str):
        """Save current authorized targets to a named list."""
        if not args:
            console.print("[error]Usage: save-targets <name>[/error]")
            return
        targets = sorted(auth.authorized)
        if not targets:
            console.print("[error]No authorized targets to save.[/error]")
            return
        path = self.target_lists.save(args, targets)
        console.print(f"[success]Saved {len(targets)} targets to {path}[/success]")

    def _cmd_load_targets(self, args: str):
        """Load targets from a named list and authorize them."""
        if not args:
            console.print("[error]Usage: load-targets <name>[/error]")
            return
        targets = self.target_lists.load(args)
        if not targets:
            console.print(f"[error]No targets found in list '{args}'.[/error]")
            return
        for t in targets:
            auth.authorize(t)
        console.print(f"[success]Loaded and authorized {len(targets)} targets from '{args}'.[/success]")

    def _cmd_list_target_lists(self, _args: str):
        """List saved target lists."""
        names = self.target_lists.list_all()
        if not names:
            console.print("[info]No saved target lists.[/info]")
            return
        console.print("[bold]Saved Target Lists:[/bold]")
        for name in names:
            targets = self.target_lists.load(name)
            console.print(f"  • {name} ({len(targets)} targets)")

    # ──────────────────────────────────────────
    # Output Format
    # ──────────────────────────────────────────

    def _cmd_output(self, args: str):
        """Set output format. Usage: output [table|json|markdown]"""
        if not args:
            console.print(f"[info]Current output format: {self.output_format}[/info]")
            console.print("[info]Available: table, json, markdown[/info]")
            return

        fmt = args.strip().lower()
        if fmt not in ("table", "json", "markdown"):
            console.print("[error]Supported formats: table, json, markdown[/error]")
            return

        self.output_format = fmt
        console.print(f"[success]Output format set to '{fmt}'[/success]")

    # ──────────────────────────────────────────
    # Knowledge Base
    # ──────────────────────────────────────────

    def _cmd_knowledge(self, query: str):
        """Search the knowledge base."""
        if not query:
            stats = knowledge.get_stats()
            console.print(f"\n[bold]Knowledge Base[/bold]")
            console.print(f"  Entries: {stats['total_entries']}")
            console.print(f"  Vuln types: {stats['vuln_types']}")
            for vtype, count in stats.get('top_vuln_types', [])[:5]:
                console.print(f"    {vtype}: {count}")
            return

        results = knowledge.search(query)
        if not results:
            console.print(f"[info]No results for '{query}'[/info]")
            return

        console.print(f"\n[bold]Knowledge: '{query}' → {len(results)} results[/bold]")
        for entry in results[:5]:
            console.print(f"  [{entry.severity}] {entry.title}")
            if entry.attack_vector:
                console.print(f"    Attack: {entry.attack_vector[:80]}")

    def _cmd_playbook(self, vuln_type: str):
        """Get attack playbook for a vulnerability type."""
        if not vuln_type:
            console.print("[error]Usage: playbook <vuln_type>[/error]")
            return
        playbook = knowledge.get_playbook(vuln_type)
        if not playbook["found"]:
            console.print(f"[info]{playbook['message']}[/info]")
            return
        console.print(f"\n[bold]Playbook: {vuln_type}[/bold]")
        for entry in playbook["entries"][:3]:
            console.print(f"  • {entry['title']}")
        if playbook["attack_vectors"]:
            console.print(f"\n  Attack vectors:")
            for av in playbook["attack_vectors"][:3]:
                if av:
                    console.print(f"    → {av[:100]}")

    # ──────────────────────────────────────────
    # API Server Management
    # ──────────────────────────────────────────

    def _cmd_api_server(self, args: str):
        """Manage the API server. Usage: api start|stop|status"""
        if not args:
            console.print("[error]Usage: api start|stop|status[/error]")
            return

        subcmd = args.strip().lower()

        if subcmd == "start":
            self._start_api_server()
        elif subcmd == "stop":
            self._stop_api_server()
        elif subcmd == "status":
            self._api_server_status()
        else:
            console.print(f"[error]Unknown api command '{subcmd}'. Use: start, stop, status[/error]")

    def _start_api_server(self):
        """Start the API server as a background process."""
        if self._api_process and self._api_process.poll() is None:
            console.print("[warning]API server is already running.[/warning]")
            return

        host = config.api.host
        port = config.api.port

        try:
            cmd = [
                sys.executable, "-m", "src.api.app",
                "--host", host,
                "--port", str(port),
            ]
            if not config.api.require_auth:
                cmd.append("--no-auth")

            self._api_process = subprocess.Popen(
                cmd,
                cwd=str(Path(__file__).parent.parent.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait a moment for startup
            time.sleep(2)

            if self._api_process.poll() is not None:
                stderr = self._api_process.stderr.read().decode() if self._api_process.stderr else ""
                console.print(f"[error]API server failed to start: {stderr[:200]}[/error]")
                self._api_process = None
                return

            console.print(f"[success]API server started on {host}:{port}[/success]")
            console.print(f"[info]Docs: http://{host}:{port}/docs[/info]")
            console.print(f"[info]PID: {self._api_process.pid}[/info]")

        except Exception as e:
            console.print(f"[error]Failed to start API server: {e}[/error]")

    def _stop_api_server(self):
        """Stop the API server."""
        if not self._api_process or self._api_process.poll() is not None:
            console.print("[info]API server is not running.[/info]")
            self._api_process = None
            return

        try:
            self._api_process.terminate()
            self._api_process.wait(timeout=5)
            console.print("[success]API server stopped.[/success]")
        except subprocess.TimeoutExpired:
            self._api_process.kill()
            console.print("[success]API server killed (forced).[/success]")
        except Exception as e:
            console.print(f"[error]Failed to stop API server: {e}[/error]")
        finally:
            self._api_process = None

    def _api_server_status(self):
        """Show API server status."""
        if self._api_process and self._api_process.poll() is None:
            host = config.api.host
            port = config.api.port
            console.print(f"[success]API server is running[/success]")
            console.print(f"  PID: {self._api_process.pid}")
            console.print(f"  URL: http://{host}:{port}")
            console.print(f"  Docs: http://{host}:{port}/docs")
        else:
            console.print("[info]API server is not running.[/info]")
            self._api_process = None

    # ──────────────────────────────────────────
    # System
    # ──────────────────────────────────────────

    def _cmd_status(self, _args: str):
        """Show system status."""
        from rich.panel import Panel

        status_lines = [
            f"[bold]Prometheus v{config.version}[/bold]",
            f"[bold]Profile:[/bold] {self.current_profile}",
            f"[bold]Output:[/bold] {self.output_format}",
            "",
            self.prometheus.status(),
        ]

        # API server status
        if self._api_process and self._api_process.poll() is None:
            status_lines.append(f"\n[bold]API Server:[/bold] Running (PID {self._api_process.pid})")
        else:
            status_lines.append(f"\n[bold]API Server:[/bold] Not running")

        console.print(Panel("\n".join(status_lines), title="📊 System Status", border_style="cyan"))

    def _cmd_tools(self, _args: str):
        """Show tool status."""
        from ..tools.registry import registry
        from rich.table import Table

        config.check_tools()
        table = Table(title="Security Tools", show_lines=True)
        table.add_column("Tool", width=15, style="bold")
        table.add_column("Binary", width=15)
        table.add_column("Status", width=10)
        table.add_column("Fallback", width=10)

        for name, cfg in config.tools.items():
            status = "[success]✓ Installed[/success]" if cfg.installed else "[error]✗ Missing[/error]"
            fallback = "Yes" if cfg.fallback else "No"
            table.add_row(cfg.name, cfg.binary, status, fallback)

        console.print(table)

    def _cmd_chat(self, text: str):
        """General chat with the AI."""
        try:
            response = self.router.generate(text, role="primary")
            console.print(f"\n[prometheus]{response}[/prometheus]")
        except Exception as e:
            console.print(f"[error]Error: {e}[/error]")

    def _cmd_help(self, _args: str):
        """Show help."""
        console.print("""
[bold]Prometheus v3.0 — AI Security Researcher[/bold]

[bold cyan]Assessment Commands:[/bold cyan]
  scan <target>          Full autonomous security assessment
  quick <target>         Fast scan (top 10 vulns only)
  stealth <target>       Slow, stealthy scan
  recon <target>         Reconnaissance only (subdomains, ports, HTTP)
  osint <target>         OSINT (username search or domain intel)

[bold cyan]Specialized Scanners:[/bold cyan]
  owasp <target>         OWASP Testing Guide v4 scan
  business <target>      Business logic vulnerability testing
  session <target>       Session management security testing
  crypto <target>        SSL/TLS and cryptographic weakness testing
  api <target>           API security testing (REST/GraphQL/JWT)
  report <target>        Generate executive security report

[bold cyan]Authorization:[/bold cyan]
  authorize <target>     Authorize a target for scanning
  revoke <target>        Revoke target authorization
  targets                List authorized targets

[bold cyan]Profiles & Output:[/bold cyan]
  profile [name]         Show/set scan profile
  profiles               List all scan profiles
  output [format]        Set output format (table|json|markdown)

[bold cyan]History & Export:[/bold cyan]
  history                Show previous scan results
  export <format> [file] Export last findings (json|markdown|csv)

[bold cyan]Target Lists:[/bold cyan]
  save-targets <name>    Save authorized targets to list
  load-targets <name>    Load and authorize targets from list
  list-targets           Show saved target lists

[bold cyan]API Server:[/bold cyan]
  api start              Start the REST API server
  api stop               Stop the API server
  api status             Show API server status

[bold cyan]Knowledge Base:[/bold cyan]
  kb [query]             Search knowledge base (1242+ reports)
  playbook <vuln_type>   Get attack playbook

[bold cyan]System:[/bold cyan]
  status                 System status
  tools                  Tool availability
  help                   This message
  quit                   Exit

[bold cyan]General:[/bold cyan]
  <anything else>        Chat with the AI
""")

    def _cmd_quit(self, _args: str):
        """Exit."""
        # Stop API server if running
        if self._api_process and self._api_process.poll() is None:
            self._stop_api_server()
        self.running = False

    def _print_banner(self):
        """Print startup banner."""
        from rich.panel import Panel
        from rich.text import Text

        banner_text = """
    ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝
    ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗
    ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║
    ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"""

        info_lines = [
            f"[bold cyan]v{config.version} — AI Security Researcher[/bold cyan]",
            f"[dim]Profile: {self.current_profile} | Output: {self.output_format}[/dim]",
            "[dim]Type 'help' for commands | 'scan <target>' to start | 'quit' to exit[/dim]",
        ]

        console.print(banner_text, style="bold red")
        console.print("\n".join(info_lines))
