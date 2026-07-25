"""Stateful Attack Tracker — tracks attack state across multi-step attacks.

Maintains context between attack steps so the AI agent can:
- Remember what worked and what didn't
- Chain discoveries across tools
- Track authentication state
- Build attack graphs
"""

import json
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..core.config import config
from ..core.logger import logger, console


@dataclass
class AttackStep:
    """A single attack step."""
    id: int
    tool: str
    action: str
    target: str
    result: str  # success, failure, partial
    findings: List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float = 0.0
    parent_id: Optional[int] = None  # for chaining


@dataclass
class AttackPath:
    """A complete attack path (chain of steps)."""
    name: str
    steps: List[AttackStep]
    impact: str
    severity: str
    verified: bool = False


class AttackTracker:
    """Tracks attack state and builds attack graphs.

    Features:
    - Tracks all attack steps with results
    - Builds attack chains (step A → step B → exploit)
    - Remembers what worked for future reference
    - Exports attack graphs for visualization
    """

    def __init__(self, target: str):
        self.target = target
        self.steps: List[AttackStep] = []
        self.paths: List[AttackPath] = []
        self._step_counter = 0
        self._successful_tools: Set[str] = set()
        self._failed_tools: Set[str] = set()
        self._discovered_endpoints: List[str] = []
        self._auth_tokens: Dict[str, str] = {}
        self._waf_bypasses: Dict[str, str] = {}  # tool -> bypass technique

    def add_step(self, tool: str, action: str, target: str, result: str,
                 findings: List[Dict] = None, parent_id: int = None) -> AttackStep:
        """Record an attack step."""
        self._step_counter += 1
        step = AttackStep(
            id=self._step_counter,
            tool=tool, action=action, target=target,
            result=result, findings=findings or [],
            parent_id=parent_id,
        )
        self.steps.append(step)

        if result == "success":
            self._successful_tools.add(tool)
        elif result == "failure":
            self._failed_tools.add(tool)

        return step

    def add_endpoint(self, endpoint: str):
        """Record a discovered endpoint."""
        if endpoint not in self._discovered_endpoints:
            self._discovered_endpoints.append(endpoint)

    def add_auth_token(self, session: str, token: str):
        """Store an auth token for a session."""
        self._auth_tokens[session] = token

    def add_waf_bypass(self, tool: str, bypass: str):
        """Record a WAF bypass technique that worked."""
        self._waf_bypasses[tool] = bypass

    def get_waf_bypass(self, tool: str) -> Optional[str]:
        """Get a known WAF bypass for a tool."""
        return self._waf_bypasses.get(tool)

    def build_attack_paths(self) -> List[AttackPath]:
        """Analyze steps and build attack paths."""
        paths = []

        # Find chains of successful steps
        successful = [s for s in self.steps if s.result == "success"]
        if not successful:
            return paths

        # Group by parent-child relationships
        for step in successful:
            if step.parent_id:
                parent = next((s for s in self.steps if s.id == step.parent_id), None)
                if parent and parent.result == "success":
                    paths.append(AttackPath(
                        name=f"{parent.tool} → {step.tool}",
                        steps=[parent, step],
                        impact=f"Chained {parent.action} with {step.action}",
                        severity="HIGH",
                    ))

        # Single-step critical findings
        for step in successful:
            if step.findings:
                for f in step.findings:
                    if f.get("severity") in ("CRITICAL", "HIGH"):
                        paths.append(AttackPath(
                            name=f"{step.tool}: {f.get('vuln_type', 'Unknown')}",
                            steps=[step],
                            impact=f.get("description", ""),
                            severity=f.get("severity", "MEDIUM"),
                        ))

        self.paths = paths
        return paths

    def get_next_actions(self) -> List[str]:
        """Suggest next actions based on current state."""
        suggestions = []

        # If we found subdomains, probe them
        subdomain_steps = [s for s in self.steps if "subdomain" in s.action.lower() and s.result == "success"]
        if subdomain_steps:
            suggestions.append("Probe discovered subdomains with httpx")

        # If we found web services, scan them
        web_steps = [s for s in self.steps if "http" in s.action.lower() and s.result == "success"]
        if web_steps:
            suggestions.append("Run vulnerability scanners on discovered services")

        # If we found a login page, test auth
        auth_steps = [s for s in self.steps if "login" in s.action.lower() or "auth" in s.action.lower()]
        if auth_steps and "bola" not in self._successful_tools:
            suggestions.append("Test for BOLA/IDOR with multi-session")

        # If WAF detected, try bypasses
        waf_steps = [s for s in self.steps if "waf" in s.action.lower()]
        if waf_steps:
            suggestions.append("Try WAF bypass techniques")

        return suggestions

    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics."""
        return {
            "target": self.target,
            "total_steps": len(self.steps),
            "successful": len([s for s in self.steps if s.result == "success"]),
            "failed": len([s for s in self.steps if s.result == "failure"]),
            "attack_paths": len(self.paths),
            "endpoints_discovered": len(self._discovered_endpoints),
            "successful_tools": list(self._successful_tools),
            "waf_bypasses": len(self._waf_bypasses),
        }

    def export_graph(self) -> Dict[str, Any]:
        """Export attack graph for visualization."""
        nodes = []
        edges = []

        for step in self.steps:
            nodes.append({
                "id": step.id,
                "label": f"{step.tool}: {step.action[:30]}",
                "result": step.result,
                "tool": step.tool,
            })
            if step.parent_id:
                edges.append({
                    "from": step.parent_id,
                    "to": step.id,
                    "label": "led to",
                })

        return {"nodes": nodes, "edges": edges, "target": self.target}

    def save(self, path: Path = None):
        """Save attack state to disk."""
        save_path = path or (config.output_dir / self.target.replace(".", "_") / "attack_state.json")
        save_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "target": self.target,
            "steps": [
                {
                    "id": s.id, "tool": s.tool, "action": s.action,
                    "target": s.target, "result": s.result,
                    "findings": s.findings, "timestamp": s.timestamp,
                    "parent_id": s.parent_id,
                }
                for s in self.steps
            ],
            "stats": self.get_stats(),
            "graph": self.export_graph(),
        }

        save_path.write_text(json.dumps(data, indent=2, default=str))
