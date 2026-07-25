"""Exploit Chain Builder — connects findings into attack chains.

Analyzes multiple findings to identify combined attack paths
that have higher impact than individual vulnerabilities.
"""

from typing import List, Dict, Any

from .memory import WorkingMemory, Finding
from ..brain.router import ModelRouter
from ..core.logger import logger, console


class ExploitChain:
    """A chain of vulnerabilities that can be combined for higher impact."""

    def __init__(self, name: str, findings: List[Finding], impact: str, steps: List[str]):
        self.name = name
        self.findings = findings
        self.impact = impact
        self.steps = steps

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "impact": self.impact,
            "steps": self.steps,
            "findings": [f.to_dict() for f in self.findings],
            "severity": max(
                (f.severity for f in self.findings),
                key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)
            ),
        }


# Type alias
Router = ModelRouter


class ChainBuilder:
    """Analyzes findings and identifies exploit chains."""

    # Pre-defined chain patterns (fast, no LLM needed)
    CHAIN_PATTERNS = [
        {
            "name": "Account Takeover via XSS + CSRF",
            "requires": ["Cross-Site Scripting", "CSRF"],
            "impact": "Attacker can steal user sessions and perform actions as the victim",
            "steps": [
                "Inject stored XSS payload in vulnerable field",
                "Wait for victim to view the page",
                "XSS executes and steals session token",
                "Use stolen token to access victim's account",
            ],
        },
        {
            "name": "Cloud Key Extraction via SSRF",
            "requires": ["SSRF", "Cloud"],
            "impact": "Attacker can extract cloud credentials and gain infrastructure access",
            "steps": [
                "Exploit SSRF to access cloud metadata endpoint (169.254.169.254)",
                "Extract IAM credentials from metadata",
                "Use credentials to access cloud resources",
                "Pivot to other cloud services",
            ],
        },
        {
            "name": "Full Database Compromise via SQLi",
            "requires": ["SQL Injection"],
            "impact": "Attacker can read/modify/delete entire database",
            "steps": [
                "Confirm SQL injection vulnerability",
                "Enumerate database structure",
                "Extract sensitive data (users, passwords, tokens)",
                "Attempt privilege escalation via DB functions",
            ],
        },
        {
            "name": "Server Takeover via Command Injection",
            "requires": ["Command Injection", "OS Command"],
            "impact": "Attacker can execute arbitrary commands on the server",
            "steps": [
                "Confirm command injection vulnerability",
                "Establish reverse shell",
                "Escalate privileges",
                "Access sensitive files and pivot to other systems",
            ],
        },
        {
            "name": "Infrastructure Exposure via Info Disclosure",
            "requires": ["Information Disclosure", "Missing Security Headers"],
            "impact": "Attacker gains knowledge of internal infrastructure for targeted attacks",
            "steps": [
                "Enumerate exposed files and endpoints",
                "Extract technology versions and configurations",
                "Search for known CVEs in identified technologies",
                "Craft targeted exploit based on version info",
            ],
        },
    ]

    def __init__(self, router: Router):
        self.router = router

    def find_chains(self, memory: WorkingMemory) -> List[ExploitChain]:
        """Analyze findings and identify exploit chains."""
        chains = []

        # Fast: pattern-based chain detection
        chains.extend(self._pattern_chains(memory.findings))

        # Smart: LLM-based chain analysis (if enough findings)
        if len(memory.findings) >= 2:
            llm_chains = self._llm_chains(memory)
            chains.extend(llm_chains)

        return chains

    def _pattern_chains(self, findings: List[Finding]) -> List[ExploitChain]:
        """Find chains using pre-defined patterns."""
        chains = []
        vuln_types = [f.vuln_type.lower() for f in findings]

        for pattern in self.CHAIN_PATTERNS:
            matches = []
            for req in pattern["requires"]:
                for f in findings:
                    if req.lower() in f.vuln_type.lower():
                        matches.append(f)
                        break

            if len(matches) >= len(pattern["requires"]):
                chains.append(ExploitChain(
                    name=pattern["name"],
                    findings=matches,
                    impact=pattern["impact"],
                    steps=pattern["steps"],
                ))

        return chains

    def _llm_chains(self, memory: WorkingMemory) -> List[ExploitChain]:
        """Use LLM to find non-obvious chains."""
        findings_text = "\n".join([
            f"- [{f.severity}] {f.vuln_type} at {f.url}: {f.description[:100]}"
            for f in memory.findings
        ])

        prompt = f"""You are an expert penetration tester analyzing findings for exploit chains.

Findings:
{findings_text}

Target: {memory.target}
Tech Stack: {', '.join(memory.tech_stack[:5])}

Identify 1-3 exploit chains (combinations of vulnerabilities that create higher impact).
For each chain, provide:
- NAME: descriptive name
- COMBINED IMPACT: what an attacker can achieve
- STEPS: step-by-step exploitation
- FINDINGS USED: which finding IDs are involved

If no meaningful chains exist, respond "NO_CHAINS".
"""

        try:
            response = self.router.generate(prompt, role="primary")
            if "NO_CHAINS" in response:
                return []
            return self._parse_chains(response, memory.findings)
        except Exception as e:
            logger.debug(f"LLM chain analysis failed: {e}")
            return []

    def _parse_chains(self, response: str, findings: List[Finding]) -> List[ExploitChain]:
        """Parse LLM response into ExploitChain objects."""
        chains = []
        # Simple parsing — look for structured blocks
        blocks = response.split("\n\n")
        for block in blocks:
            lines = block.strip().split("\n")
            data = {}
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    data[key.strip().upper()] = val.strip()

            name = data.get("NAME", "")
            impact = data.get("COMBINED IMPACT", data.get("IMPACT", ""))
            steps_str = data.get("STEPS", "")

            if name and impact:
                steps = [
                    s.strip().lstrip("0123456789.-) ")
                    for s in steps_str.split("\n") if s.strip()
                ] if steps_str else []

                chains.append(ExploitChain(
                    name=name,
                    findings=findings[:2],  # approximate
                    impact=impact,
                    steps=steps,
                ))

        return chains[:3]  # max 3 chains
