"""Intelligent Attack Planner — LLM-powered security assessment planning.

The planner analyzes the target type, chooses appropriate playbooks,
and adapts strategy based on discovered findings. Uses LLM for
intelligent next-step decision making.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import re

from ..brain.router import ModelRouter
from ..core.logger import logger, console


@dataclass
class AttackStep:
    """A planned attack step."""
    tool: str
    target: str
    args: Dict[str, Any]
    reasoning: str
    priority: int = 1  # 1=do first, 5=do last
    playbook: str = ""
    depends_on: List[str] = None

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []

    def __str__(self):
        return f"{self.tool} → {self.target} ({self.reasoning[:60]})"


@dataclass
class Playbook:
    """A named sequence of attack phases for a target type."""
    name: str
    description: str
    phases: List[Dict[str, Any]]
    applicable_when: List[str]  # conditions that make this playbook relevant

    def matches_target(self, target: str, target_type: str) -> bool:
        """Check if this playbook is appropriate for the target."""
        # First check by target type (most specific)
        if target_type in self.applicable_when:
            return True
        # Then check string conditions, but only for non-type conditions
        # Skip generic conditions like "." if we already matched by type
        for condition in self.applicable_when:
            # Skip regex-like patterns and generic dot checks for IP targets
            if target_type == "ip" and condition == ".":
                continue
            if condition in target.lower():
                return True
        return False


class AttackPlanner:
    """LLM-powered attack planning engine.

    Supports multiple playbooks:
    - web_app: Full web application security assessment
    - domain_recon: Domain and subdomain reconnaissance
    - ip_scan: IP address and network scanning
    - api_security: API endpoint security testing

    Analyzes target type to choose appropriate playbook,
    then uses LLM for intelligent adaptation based on findings.
    """

    PLAYBOOKS: Dict[str, Playbook] = {
        "web_app": Playbook(
            name="web_app",
            description="Full web application security assessment",
            applicable_when=["http", "web", "app"],
            phases=[
                {
                    "name": "recon",
                    "tools": ["subfinder", "httpx", "whois", "dns"],
                    "goal": "Map the attack surface",
                },
                {
                    "name": "crawl",
                    "tools": ["crawler"],
                    "goal": "Discover endpoints, forms, and parameters",
                    "depends_on": ["recon"],
                },
                {
                    "name": "vuln_scan",
                    "tools": ["nuclei", "headers", "cors", "secrets"],
                    "goal": "Find known vulnerabilities and misconfigurations",
                    "depends_on": ["recon"],
                },
                {
                    "name": "injection_test",
                    "tools": ["sqli", "xss", "ssrf", "cmdi", "ssti", "idor", "traversal", "redirect"],
                    "goal": "Test for injection and logic vulnerabilities",
                    "depends_on": ["crawl"],
                },
                {
                    "name": "advanced",
                    "tools": ["smuggling", "xxe", "race", "auth"],
                    "goal": "Test for advanced vulnerabilities",
                    "depends_on": ["crawl"],
                },
                {
                    "name": "validate",
                    "tools": ["sqlmap"],
                    "goal": "Validate findings with real PoCs",
                    "depends_on": ["injection_test"],
                },
            ],
        ),
        "domain_recon": Playbook(
            name="domain_recon",
            description="Domain and subdomain reconnaissance",
            applicable_when=["domain"],
            phases=[
                {
                    "name": "whois",
                    "tools": ["whois"],
                    "goal": "Domain registration intelligence",
                },
                {
                    "name": "dns",
                    "tools": ["dns"],
                    "goal": "DNS infrastructure mapping",
                },
                {
                    "name": "subdomains",
                    "tools": ["subfinder"],
                    "goal": "Subdomain enumeration",
                },
                {
                    "name": "probe",
                    "tools": ["httpx"],
                    "goal": "Identify live HTTP services",
                    "depends_on": ["subdomains"],
                },
                {
                    "name": "port_scan",
                    "tools": ["portscan"],
                    "goal": "Discover open ports",
                },
                {
                    "name": "vuln_check",
                    "tools": ["nuclei"],
                    "goal": "Quick vulnerability check on discovered services",
                    "depends_on": ["probe"],
                },
            ],
        ),
        "ip_scan": Playbook(
            name="ip_scan",
            description="IP address and network scanning",
            applicable_when=["ip", r"\d+\.\d+\.\d+\.\d+"],
            phases=[
                {
                    "name": "port_scan",
                    "tools": ["portscan"],
                    "goal": "Full port scan",
                },
                {
                    "name": "service_enum",
                    "tools": ["httpx"],
                    "goal": "Identify running services",
                    "depends_on": ["port_scan"],
                },
                {
                    "name": "vuln_scan",
                    "tools": ["nuclei"],
                    "goal": "Vulnerability scanning on discovered services",
                    "depends_on": ["service_enum"],
                },
            ],
        ),
        "api_security": Playbook(
            name="api_security",
            description="API endpoint security testing",
            applicable_when=["api"],
            phases=[
                {
                    "name": "discovery",
                    "tools": ["subfinder", "httpx"],
                    "goal": "Discover API endpoints",
                },
                {
                    "name": "crawl",
                    "tools": ["crawler"],
                    "goal": "Enumerate API routes and parameters",
                    "depends_on": ["discovery"],
                },
                {
                    "name": "auth_test",
                    "tools": ["auth"],
                    "goal": "Test authentication and authorization",
                    "depends_on": ["crawl"],
                },
                {
                    "name": "injection",
                    "tools": ["sqli", "xss", "ssrf"],
                    "goal": "Test for injection vulnerabilities",
                    "depends_on": ["crawl"],
                },
                {
                    "name": "idor",
                    "tools": ["idor"],
                    "goal": "Test for IDOR vulnerabilities",
                    "depends_on": ["crawl"],
                },
                {
                    "name": "rate_limit",
                    "tools": ["race"],
                    "goal": "Test rate limiting and race conditions",
                    "depends_on": ["crawl"],
                },
            ],
        ),
    }

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router

    def detect_target_type(self, target: str) -> str:
        """Auto-detect the target type."""
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return "ip"
        if target.startswith(("http://", "https://")):
            if "/api/" in target or "api." in target:
                return "api"
            return "web"
        if "." in target:
            return "domain"
        return "unknown"

    def choose_playbook(self, target: str, playbook: str = "auto") -> str:
        """Choose the appropriate playbook for a target.

        Args:
            target: The target to assess
            playbook: Requested playbook ("auto" or specific name)

        Returns:
            Playbook name to use
        """
        if playbook != "auto":
            if playbook in self.PLAYBOOKS:
                return playbook
            logger.warning(f"Unknown playbook '{playbook}', falling back to auto")
            return "auto"

        target_type = self.detect_target_type(target)

        # First pass: match by target type (most specific)
        for name, pb in self.PLAYBOOKS.items():
            if target_type in pb.applicable_when:
                console.print(f"  [info]Auto-selected playbook: {name} (target type: {target_type})[/info]")
                return name

        # Second pass: match by string conditions (fallback)
        for name, pb in self.PLAYBOOKS.items():
            if pb.matches_target(target, target_type):
                console.print(f"  [info]Auto-selected playbook: {name} (target type: {target_type})[/info]")
                return name

        # Default
        console.print(f"  [info]Default playbook: web_app (target type: {target_type})[/info]")
        return "web_app"

    def plan_initial(self, target: str, playbook: str = "auto") -> List[AttackStep]:
        """Generate initial attack plan for a new target.

        Args:
            target: The target to assess
            playbook: Playbook to use

        Returns:
            Ordered list of AttackSteps
        """
        chosen = self.choose_playbook(target, playbook)
        pb = self.PLAYBOOKS.get(chosen, self.PLAYBOOKS["web_app"])

        console.print(f"  [info]Planning with playbook: {pb.name} — {pb.description}[/info]")

        steps = []
        for phase in pb.phases:
            for tool in phase["tools"]:
                step = AttackStep(
                    tool=tool,
                    target=target,
                    args={},
                    reasoning=phase.get("goal", "Execute tool"),
                    priority=self._phase_priority(phase["name"]),
                    playbook=pb.name,
                    depends_on=phase.get("depends_on", []),
                )
                steps.append(step)

        # Sort by priority
        steps.sort(key=lambda s: s.priority)

        # If LLM available, enhance the plan
        if self.router:
            steps = self._enhance_plan(target, steps, pb)

        return steps

    def plan_next(
        self,
        target: str,
        context: str,
        available_tools: List[str],
        playbook: str = "web_app",
    ) -> Optional[AttackStep]:
        """Decide the next action based on current context.

        Uses LLM to analyze what we know and decide the best next step.

        Args:
            target: Primary target
            context: Current scan context (from WorkingMemory.get_context())
            available_tools: List of available tool names
            playbook: Current playbook name

        Returns:
            Next AttackStep or None if assessment is complete
        """
        if not self.router:
            return None

        prompt = f"""You are an expert security researcher conducting an authorized penetration test.
You are using the "{playbook}" playbook.

TARGET: {target}

CURRENT STATE:
{context}

AVAILABLE TOOLS: {', '.join(available_tools)}

Based on the current state, decide the SINGLE BEST next action.

Rules:
1. If subdomains found but not probed → run httpx on them
2. If HTTP services found but not scanned → run nuclei on them
3. If web app found with parameters → test for SQLi/XSS
4. If interesting service on unusual port → investigate further
5. If enough data gathered → summarize findings
6. NEVER repeat a tool that already ran successfully
7. Focus on highest-impact actions first
8. Consider the {playbook} playbook goals

Respond in EXACTLY this format (one line per field):
TOOL: <tool_name>
TARGET: <target_or_url>
ARGS: <key=value pairs or "none">
REASONING: <why this action>
PRIORITY: <1-5>

Or respond "DONE" if the assessment is complete.
"""

        try:
            response = self.router.generate(prompt, role="primary").strip()

            if response.upper().startswith("DONE"):
                return None

            return self._parse_step(response, target)

        except Exception as e:
            logger.error(f"Planner error: {e}")
            return None

    def analyze_findings(self, context: str) -> str:
        """Generate a human-readable analysis of all findings."""
        if not self.router:
            return "LLM analysis not available."

        prompt = f"""You are an expert security researcher. Analyze these findings and provide:

1. RISK SUMMARY: Overall risk level and key concerns
2. CRITICAL FINDINGS: What needs immediate attention
3. ATTACK PATHS: How vulnerabilities could be chained
4. REMEDIATION: Priority fixes

Findings:
{context}

Provide a concise, professional security assessment.
"""

        try:
            return self.router.generate(prompt, role="primary")
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return "Error generating analysis."

    def get_playbook_info(self, playbook: str) -> Dict[str, Any]:
        """Get detailed information about a playbook."""
        pb = self.PLAYBOOKS.get(playbook)
        if not pb:
            return {"error": f"Unknown playbook: {playbook}"}
        return {
            "name": pb.name,
            "description": pb.description,
            "phases": [
                {
                    "name": p["name"],
                    "tools": p["tools"],
                    "goal": p["goal"],
                    "depends_on": p.get("depends_on", []),
                }
                for p in pb.phases
            ],
            "total_tools": sum(len(p["tools"]) for p in pb.phases),
        }

    def list_playbooks(self) -> List[Dict[str, str]]:
        """List all available playbooks."""
        return [
            {"name": pb.name, "description": pb.description}
            for pb in self.PLAYBOOKS.values()
        ]

    def _phase_priority(self, phase_name: str) -> int:
        """Map phase names to priority numbers."""
        priorities = {
            "recon": 1, "whois": 1, "dns": 1, "subdomains": 1,
            "discovery": 1, "port_scan": 1,
            "probe": 2, "crawl": 2, "service_enum": 2,
            "vuln_scan": 3, "vuln_check": 3,
            "injection_test": 4, "injection": 4,
            "auth_test": 4, "idor": 4, "rate_limit": 4,
            "advanced": 5, "validate": 5,
        }
        return priorities.get(phase_name, 3)

    def _enhance_plan(self, target: str, steps: List[AttackStep],
                      playbook: Playbook) -> List[AttackStep]:
        """Use LLM to enhance the attack plan."""
        if not self.router:
            return steps

        try:
            prompt = f"""You are an expert security researcher. Review this attack plan for:
Target: {target}
Playbook: {playbook.name} — {playbook.description}

Current plan:
{chr(10).join(f"  {i+1}. {s.tool} — {s.reasoning}" for i, s in enumerate(steps[:15]))}

Suggest any additional tools or modifications. Consider:
- Technology-specific checks (e.g., WordPress scanners for WP sites)
- Alternative approaches if primary tools fail
- Time-saving optimizations

Respond with ONLY a comma-separated list of additional tools (if any).
Available tools: dns, fingerprint, crawler, sqli, xss, ssrf, cmdi, idor, ssti, xxe,
traversal, redirect, smuggling, race, auth, secrets, headers, cors, takeover, cloud,
shodan, whois, nmap, searchsploit, cve, sherlock, theharvester, photon, ffuf, nikto, ssl,
nuclei, subfinder, httpx, sqlmap, portscan, recon, exploit

If no additions needed, respond "NONE".
"""

            response = self.router.generate(prompt, role="primary").strip()
            if response.upper() != "NONE" and response:
                additional = [t.strip().lower() for t in response.split(",") if t.strip()]
                existing = {s.tool for s in steps}
                all_tools = self._all_tools()

                for tool in additional:
                    if tool not in existing and tool in all_tools:
                        steps.append(AttackStep(
                            tool=tool,
                            target=target,
                            args={},
                            reasoning="AI-recommended based on target analysis",
                            priority=3,
                            playbook=playbook.name,
                        ))

        except Exception as e:
            logger.debug(f"LLM plan enhancement failed: {e}")

        return steps

    def _parse_step(self, response: str, default_target: str) -> Optional[AttackStep]:
        """Parse LLM response into an AttackStep."""
        try:
            lines = response.strip().split("\n")
            data = {}
            for line in lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    data[key.strip().upper()] = value.strip()

            tool = data.get("TOOL", "").lower()
            target = data.get("TARGET", default_target)
            reasoning = data.get("REASONING", "AI-guided action")
            priority = int(data.get("PRIORITY", "3"))

            args = {}
            args_str = data.get("ARGS", "none")
            if args_str.lower() != "none":
                for pair in args_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        args[k.strip()] = v.strip()

            if not tool:
                return None

            return AttackStep(
                tool=tool,
                target=target,
                args=args,
                reasoning=reasoning,
                priority=priority,
            )

        except Exception as e:
            logger.debug(f"Failed to parse planner response: {e}")
            return None

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
