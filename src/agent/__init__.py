"""Agent package — Multi-agent security testing architecture.

Agents:
    - Orchestrator: Coordinates all specialized agents
    - ReconAgent:   Reconnaissance specialist (subdomains, ports, services)
    - ScanAgent:    Vulnerability scanning specialist (nuclei + 15 scanners)
    - ExploitAgent: Exploit validation and chain building
    - ReportAgent:  Report generation (Markdown, JSON, HackerOne)
    - AttackPlanner: LLM-powered intelligent planning with playbooks
"""

from .orchestrator import Orchestrator, OrchestrationResult, AgentResult
from .recon_agent import ReconAgent
from .scan_agent import ScanAgent
from .exploit_agent import ExploitAgent
from .report_agent import ReportAgent
from .planner import AttackPlanner, AttackStep, Playbook
from .memory import WorkingMemory, Finding

__all__ = [
    "Orchestrator",
    "OrchestrationResult",
    "AgentResult",
    "ReconAgent",
    "ScanAgent",
    "ExploitAgent",
    "ReportAgent",
    "AttackPlanner",
    "AttackStep",
    "Playbook",
    "WorkingMemory",
    "Finding",
]
