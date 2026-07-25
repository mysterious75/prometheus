"""Prometheus CLI — command-line interface.

Simple, clean, focused on security research commands.
"""

import sys
from typing import Optional

from ..main import Prometheus
from ..core.auth import auth
from ..core.logger import console
from ..brain.router import ModelRouter
from ..knowledge.index import knowledge


class CLI:
    """Interactive CLI for Prometheus."""

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router or ModelRouter()
        self.prometheus = Prometheus(self.router)
        self.running = True

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

            # Authorization
            "authorize": self._cmd_authorize,
            "auth": self._cmd_authorize,
            "revoke": self._cmd_revoke,
            "targets": self._cmd_targets,

            # Knowledge
            "kb": self._cmd_knowledge,
            "knowledge": self._cmd_knowledge,
            "playbook": self._cmd_playbook,

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

    # --- Commands ---

    def _cmd_scan(self, target: str):
        """Run a full security assessment."""
        if not target:
            console.print("[error]Usage: scan <target>[/error]")
            return
        self.prometheus.assess(target)

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

    def _cmd_status(self, _args: str):
        """Show system status."""
        console.print(self.prometheus.status())

    def _cmd_tools(self, _args: str):
        """Show tool status."""
        from ..tools.registry import registry
        console.print(registry.status())

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
  recon <target>         Reconnaissance only (subdomains, ports, HTTP)
  osint <target>         OSINT (username search or domain intel)

[bold cyan]Authorization:[/bold cyan]
  authorize <target>     Authorize a target for scanning
  revoke <target>        Revoke target authorization
  targets                List authorized targets

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
        self.running = False

    def _print_banner(self):
        """Print startup banner."""
        console.print("""
[bold red]
    ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝
    ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗
    ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║
    ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
[/bold red]
[bold cyan]    v3.0 — AI Security Researcher[/bold cyan]
[dim]    Autonomous penetration testing with AI-guided attack planning[/dim]
[dim]    Type 'help' for commands | 'scan <target>' to start | 'quit' to exit[/dim]
""")
