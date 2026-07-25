"""Attack Planner — LLM-powered security assessment planning.

The planner analyzes the target and current context, then decides
what to do next. This is the "brain" of the autonomous agent.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

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

    def __str__(self):
        return f"{self.tool} → {self.target} ({self.reasoning[:60]})"


class AttackPlanner:
    """LLM-powered attack planning engine.

    Given a target and current context, decides:
    1. What tools to run next
    2. In what order
    3. With what parameters
    4. Why (reasoning)
    """

    def __init__(self, router: ModelRouter):
        self.router = router

    def plan_initial(self, target: str) -> List[AttackStep]:
        """Generate initial attack plan for a new target.

        This is called once at the start of an assessment.
        Uses fast heuristics + LLM for planning.
        """
        steps = []

        # Step 1: Always start with subdomain enumeration
        steps.append(AttackStep(
            tool="subfinder",
            target=target,
            args={},
            reasoning="Enumerate subdomains to discover the full attack surface",
            priority=1,
        ))

        # Step 2: Probe HTTP services
        steps.append(AttackStep(
            tool="httpx",
            target=target,
            args={},
            reasoning="Identify live HTTP services, tech stack, and response codes",
            priority=2,
        ))

        # Step 3: Port scan
        steps.append(AttackStep(
            tool="nmap",
            target=target,
            args={"top_ports": 100},
            reasoning="Discover open ports and running services",
            priority=2,
        ))

        # Step 4: Vulnerability scan with nuclei
        steps.append(AttackStep(
            tool="nuclei",
            target=target,
            args={"severity": "critical,high,medium"},
            reasoning="Run template-based vulnerability checks for known CVEs and misconfigurations",
            priority=3,
        ))

        # Step 5: SQLi test if web services found
        steps.append(AttackStep(
            tool="sqlmap",
            target=target,
            args={},
            reasoning="Test for SQL injection in discovered web applications",
            priority=4,
        ))

        return steps

    def plan_next(
        self,
        target: str,
        context: str,
        available_tools: List[str],
    ) -> Optional[AttackStep]:
        """Decide the next action based on current context.

        This is the core intelligence — the LLM analyzes what we know
        and decides what to do next.
        """
        prompt = f"""You are an expert security researcher conducting an authorized penetration test.

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

            # Parse args
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

    def analyze_findings(self, context: str) -> str:
        """Generate a human-readable analysis of all findings."""
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
