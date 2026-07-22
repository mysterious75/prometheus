"""Safety & Permission System - Warns about risks, asks before destructive ops."""

import os
import shutil
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import logger, console


class RiskLevel(Enum):
    SAFE = "safe"           # No risk
    LOW = "low"             # Minor risk
    MEDIUM = "medium"       # Moderate risk
    HIGH = "high"           # Significant risk
    CRITICAL = "critical"   # Dangerous, could break things


@dataclass
class RiskWarning:
    """Warning about an operation."""
    operation: str
    level: RiskLevel
    description: str
    consequences: List[str]
    mitigation: str


# Known risky operations
RISK_DATABASE = {
    "delete_file": RiskWarning(
        operation="Delete File",
        level=RiskLevel.MEDIUM,
        description="Permanently deletes a file from the system",
        consequences=["File will be removed", "May need reinstall to recover"],
        mitigation="Backup created before deletion"
    ),
    "delete_directory": RiskWarning(
        operation="Delete Directory",
        level=RiskLevel.HIGH,
        description="Removes an entire directory and all contents",
        consequences=["All files in directory lost", "May break dependencies"],
        mitigation="Backup created, can be restored"
    ),
    "modify_source": RiskWarning(
        operation="Modify Source Code",
        level=RiskLevel.LOW,
        description="Changes Prometheus source files",
        consequences=["Behavior may change", "Could introduce bugs"],
        mitigation="Auto-backup before modification"
    ),
    "network_scan": RiskWarning(
        operation="Network Scan",
        level=RiskLevel.MEDIUM,
        description="Scans target network for open ports and services",
        consequences=["May trigger IDS/firewall", "Ensure you have authorization"],
        mitigation="Use only on authorized targets"
    ),
    "vuln_scan": RiskWarning(
        operation="Vulnerability Scan",
        level=RiskLevel.HIGH,
        description="Active vulnerability scanning with Nuclei",
        consequences=["May exploit vulnerabilities", "Could cause service disruption", "Legal risk if unauthorized"],
        mitigation="Only scan authorized targets, keep logs"
    ),
    "port_scan": RiskWarning(
        operation="Port Scan",
        level=RiskLevel.MEDIUM,
        description="Scans target for open ports",
        consequences=["Visible in target logs", "May trigger security alerts"],
        mitigation="Scan slowly, use authorized targets only"
    ),
    "subdomain_enum": RiskWarning(
        operation="Subdomain Enumeration",
        level=RiskLevel.LOW,
        description="Discovers subdomains of a target",
        consequences=["Visible in DNS logs", "Passive technique, low risk"],
        mitigation="Already passive, minimal risk"
    ),
    "code_execute": RiskWarning(
        operation="Execute Code",
        level=RiskLevel.HIGH,
        description="Executes arbitrary code on the system",
        consequences=["Could modify system", "Potential security risk"],
        mitigation="Review code before execution"
    ),
    "system_command": RiskWarning(
        operation="System Command",
        level=RiskLevel.HIGH,
        description="Runs a system-level command",
        consequences=["Could modify system state", "May need admin privileges"],
        mitigation="Verify command before execution"
    ),
}


class PermissionSystem:
    """Asks permission before risky operations, warns about consequences."""

    def __init__(self):
        self.auto_approve = False  # Set True to skip prompts (dangerous)
        self.approved_operations: List[str] = []
        self.denied_operations: List[str] = []
        self.log: List[Dict] = []

    def get_risk(self, operation: str) -> Optional[RiskWarning]:
        """Get risk info for an operation."""
        return RISK_DATABASE.get(operation)

    def ask_permission(self, operation: str, target: str = "", auto: bool = False) -> bool:
        """Ask user permission before risky operation."""
        risk = self.get_risk(operation)
        if not risk:
            return True  # Unknown operation, allow

        if risk.level == RiskLevel.SAFE:
            return True

        if auto or self.auto_approve:
            self.approved_operations.append(operation)
            return True

        # Print warning
        level_colors = {
            RiskLevel.LOW: "yellow",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red"
        }
        color = level_colors.get(risk.level, "yellow")

        console.print(f"\n[{color}]RISK WARNING[/{color}]")
        console.print(f"  Operation: {risk.operation}")
        console.print(f"  Risk Level: {risk.level.value.upper()}")
        console.print(f"  What: {risk.description}")
        if target:
            console.print(f"  Target: {target}")
        console.print(f"\n  Possible consequences:")
        for c in risk.consequences:
            console.print(f"    - {c}")
        console.print(f"\n  Mitigation: {risk.mitigation}")

        # Ask permission
        response = console.input(f"\n  Allow this operation? [y/N]: ").strip().lower()

        if response in ("y", "yes"):
            self.approved_operations.append(operation)
            self.log.append({"operation": operation, "target": target, "approved": True})
            return True
        else:
            self.denied_operations.append(operation)
            self.log.append({"operation": operation, "target": target, "approved": False})
            console.print("[yellow]Operation cancelled by user.[/yellow]")
            return False

    def warn_only(self, operation: str, target: str = "") -> bool:
        """Just warn without asking (for informational purposes)."""
        risk = self.get_risk(operation)
        if not risk or risk.level == RiskLevel.SAFE:
            return True

        level_colors = {
            RiskLevel.LOW: "yellow",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red"
        }
        color = level_colors.get(risk.level, "yellow")

        console.print(f"[{color}][WARN] {risk.operation}: {risk.description}[/{color}]")
        for c in risk.consequences:
            console.print(f"  -> {c}")
        return True

    def safe_delete(self, path: str) -> bool:
        """Delete with backup and permission."""
        if not os.path.exists(path):
            return True

        if not self.ask_permission("delete_file" if os.path.isfile(path) else "delete_directory", path):
            return False

        # Create backup
        backup_dir = os.path.join(os.path.dirname(path), ".backups")
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, os.path.basename(path) + ".bak")

        try:
            if os.path.isfile(path):
                shutil.copy2(path, backup_path)
                os.remove(path)
            else:
                shutil.make_archive(backup_path, 'zip', path)
                shutil.rmtree(path)
            console.print(f"[green]Deleted: {path} (backup: {backup_path})[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Delete failed: {e}[/red]")
            return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "approved": len(self.approved_operations),
            "denied": len(self.denied_operations),
            "log": self.log[-10:]
        }


# Global instance
safety = PermissionSystem()
