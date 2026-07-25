"""AI Tool Orchestrator — the brain that knows when to use each tool.

Given a target and context, the orchestrator decides:
1. Which tools to run
2. In what order
3. With what parameters
4. How to chain results

This is what makes Prometheus smart — not just running tools,
but KNOWING which tool to use when.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..brain.router import ModelRouter
from ..core.logger import logger, console


@dataclass
class ToolPlan:
    """A planned tool execution."""
    tool: str
    args: Dict[str, Any]
    reasoning: str
    priority: int  # 1 = do first
    depends_on: List[str] = None  # tools that must run first

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []


class ToolOrchestrator:
    """AI-powered tool selection and orchestration.

    This is the 'brain' that decides which security tools to use
    based on the target type, discovered information, and context.
    """

    # Pre-defined attack playbooks (fast, no LLM needed)
    PLAYBOOKS = {
        "web_app": [
            ToolPlan(tool="fingerprint", args={}, reasoning="Identify technologies", priority=1),
            ToolPlan(tool="dns", args={"mode": "full"}, reasoning="Map DNS infrastructure", priority=1),
            ToolPlan(tool="whois", args={}, reasoning="Domain registration info", priority=1),
            ToolPlan(tool="crawler", args={}, reasoning="Discover attack surface", priority=2, depends_on=["fingerprint"]),
            ToolPlan(tool="headers", args={}, reasoning="Check security headers", priority=2),
            ToolPlan(tool="cors", args={}, reasoning="Test CORS config", priority=2),
            ToolPlan(tool="secrets", args={}, reasoning="Find exposed secrets", priority=2),
            ToolPlan(tool="sqli", args={}, reasoning="Test for SQL injection", priority=3, depends_on=["crawler"]),
            ToolPlan(tool="xss", args={}, reasoning="Test for XSS", priority=3, depends_on=["crawler"]),
            ToolPlan(tool="ssrf", args={}, reasoning="Test for SSRF", priority=3, depends_on=["crawler"]),
            ToolPlan(tool="cmdi", args={}, reasoning="Test for command injection", priority=3, depends_on=["crawler"]),
            ToolPlan(tool="idor", args={}, reasoning="Test for IDOR", priority=3, depends_on=["crawler"]),
            ToolPlan(tool="ssti", args={}, reasoning="Test for SSTI", priority=3),
            ToolPlan(tool="traversal", args={}, reasoning="Test for path traversal", priority=3),
            ToolPlan(tool="redirect", args={}, reasoning="Test for open redirect", priority=3),
            ToolPlan(tool="smuggling", args={}, reasoning="Test for HTTP smuggling", priority=4),
            ToolPlan(tool="xxe", args={}, reasoning="Test for XXE", priority=4),
            ToolPlan(tool="race", args={}, reasoning="Test for race conditions", priority=4),
            ToolPlan(tool="auth", args={}, reasoning="Test for auth bypass", priority=4),
            ToolPlan(tool="takeover", args={}, reasoning="Check subdomain takeover", priority=4, depends_on=["dns"]),
            ToolPlan(tool="cloud", args={}, reasoning="Check cloud storage", priority=4),
        ],
        "domain_recon": [
            ToolPlan(tool="whois", args={}, reasoning="Domain registration", priority=1),
            ToolPlan(tool="dns", args={"mode": "full"}, reasoning="DNS enumeration", priority=1),
            ToolPlan(tool="subfinder", args={}, reasoning="Subdomain discovery", priority=1),
            ToolPlan(tool="takeover", args={}, reasoning="Subdomain takeover check", priority=2, depends_on=["dns"]),
            ToolPlan(tool="cloud", args={}, reasoning="Cloud bucket check", priority=2),
            ToolPlan(tool="shodan", args={}, reasoning="Internet intelligence", priority=2),
            ToolPlan(tool="fingerprint", args={}, reasoning="Technology detection", priority=3, depends_on=["subfinder"]),
            ToolPlan(tool="ssl", args={}, reasoning="SSL/TLS analysis", priority=3),
        ],
        "ip_scan": [
            ToolPlan(tool="nmap", args={"top_ports": 1000}, reasoning="Port scan", priority=1),
            ToolPlan(tool="shodan", args={"mode": "host"}, reasoning="Internet intelligence", priority=1),
            ToolPlan(tool="reverse_dns", args={}, reasoning="Reverse DNS", priority=1),
            ToolPlan(tool="nmap_vuln", args={}, reasoning="Vulnerability scripts", priority=2, depends_on=["nmap"]),
        ],
        "username_osint": [
            ToolPlan(tool="sherlock", args={}, reasoning="Username search 400+ platforms", priority=1),
        ],
        "exploit_search": [
            ToolPlan(tool="searchsploit", args={}, reasoning="Search ExploitDB", priority=1),
            ToolPlan(tool="cve_search", args={}, reasoning="Check NVD database", priority=1),
        ],
    }

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router

    def plan(self, target: str, context: str = "", playbook: str = "auto") -> List[ToolPlan]:
        """Decide which tools to run for a target.

        Args:
            target: The target (URL, domain, IP, username)
            context: Current scan context
            playbook: Which playbook to use ("auto", "web_app", "domain_recon", etc.)
        """
        if playbook == "auto":
            playbook = self._detect_target_type(target)

        console.print(f"  [info]Playbook: {playbook}[/info]")

        # Get base plan from playbook
        plans = self.PLAYBOOKS.get(playbook, self.PLAYBOOKS["web_app"])

        # If we have an LLM, enhance the plan
        if self.router and context:
            plans = self._enhance_with_llm(target, context, plans)

        return sorted(plans, key=lambda p: p.priority)

    def _detect_target_type(self, target: str) -> str:
        """Auto-detect target type."""
        import re

        # IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return "ip_scan"

        # URL (has path or protocol)
        if target.startswith("http://") or target.startswith("https://"):
            return "web_app"

        # Domain
        if "." in target and not target.startswith("http"):
            return "domain_recon"

        # Username (no dots, no protocol)
        return "username_osint"

    def _enhance_with_llm(self, target: str, context: str, base_plans: List[ToolPlan]) -> List[ToolPlan]:
        """Use LLM to enhance the attack plan based on context."""
        if not self.router:
            return base_plans

        try:
            prompt = f"""You are an expert security researcher. Based on the target and context,
suggest any additional tools or modifications to the attack plan.

Target: {target}
Context: {context[:500]}

Current plan tools: {[p.tool for p in base_plans]}

Respond with ONLY a comma-separated list of additional tools to add (if any).
Available tools: dns, fingerprint, crawler, sqli, xss, ssrf, cmdi, idor, ssti, xxe,
traversal, redirect, smuggling, race, auth, secrets, headers, cors, takeover, cloud,
shodan, whois, nmap, searchsploit, cve, sherlock, theharvester, photon, ffuf, nikto, ssl

If no additions needed, respond "NONE".
"""

            response = self.router.generate(prompt, role="primary").strip()
            if response.upper() != "NONE" and response:
                additional_tools = [t.strip().lower() for t in response.split(",") if t.strip()]
                existing_tools = {p.tool for p in base_plans}

                for tool in additional_tools:
                    if tool not in existing_tools and tool in self._all_tools():
                        base_plans.append(ToolPlan(
                            tool=tool, args={},
                            reasoning="AI-recommended based on context",
                            priority=3,
                        ))

        except Exception as e:
            logger.debug(f"LLM plan enhancement failed: {e}")

        return base_plans

    def _all_tools(self) -> set:
        """Return set of all available tool names."""
        return {
            "dns", "fingerprint", "crawler", "sqli", "xss", "ssrf", "cmdi",
            "idor", "ssti", "xxe", "traversal", "redirect", "smuggling", "race",
            "auth", "secrets", "headers", "cors", "takeover", "cloud", "shodan",
            "whois", "nmap", "searchsploit", "cve", "sherlock", "theharvester",
            "photon", "ffuf", "nikto", "ssl", "nuclei", "subfinder", "httpx",
            "sqlmap", "portscan", "recon", "exploit",
        }

    def get_playbook_info(self, playbook: str) -> Dict[str, Any]:
        """Get information about a playbook."""
        plans = self.PLAYBOOKS.get(playbook, [])
        return {
            "name": playbook,
            "tools": [{"tool": p.tool, "priority": p.priority, "reasoning": p.reasoning} for p in plans],
            "total_steps": len(plans),
        }

    def list_playbooks(self) -> List[str]:
        """List available playbooks."""
        return list(self.PLAYBOOKS.keys())
