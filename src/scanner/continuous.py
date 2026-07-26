"""Continuous Scanning Engine — scheduled scans, diff-based, fix verification.

Inspired by MindFort/RunSybil continuous testing:
- Scheduled scans (cron-style)
- Diff-based scanning (only new endpoints)
- Fix verification (re-test after patch)
- Alert on new findings
"""

import json
import time
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from ..core.config import config
from ..core.logger import logger, console
from ..scanner.findings import Finding, ScanResult
from .base import BaseScanner


@dataclass
class ScanSchedule:
    """A scheduled scan configuration."""
    target: str
    interval_hours: int = 24
    playbooks: List[str] = field(default_factory=lambda: ["web_app"])
    enabled: bool = True
    last_scan: Optional[str] = None
    next_scan: Optional[str] = None


@dataclass
class ScanDiff:
    """Difference between two scans."""
    new_findings: List[Finding] = field(default_factory=list)
    fixed_findings: List[Finding] = field(default_factory=list)
    unchanged_findings: List[Finding] = field(default_factory=list)
    new_endpoints: List[str] = field(default_factory=list)


class ContinuousScanner(BaseScanner):
    """Continuous security scanning engine.

    Features:
    - Schedule scans for targets
    - Detect new findings between scans
    - Verify that fixes actually work
    - Alert on new vulnerabilities
    """

    def __init__(self):
        super().__init__()
        self.schedules: Dict[str, ScanSchedule] = {}
        self.scan_history: Dict[str, List[Dict]] = {}  # target -> list of scan results
        self._load_state()

    def _load_state(self):
        """Load persistent state from disk."""
        state_file = config.output_dir / "continuous_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                for target, sched_data in data.get("schedules", {}).items():
                    self.schedules[target] = ScanSchedule(**sched_data)
                self.scan_history = data.get("history", {})
            except Exception:
                pass

    def _save_state(self):
        """Save persistent state to disk."""
        state_file = config.output_dir / "continuous_state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "schedules": {
                target: {
                    "target": s.target, "interval_hours": s.interval_hours,
                    "playbooks": s.playbooks, "enabled": s.enabled,
                    "last_scan": s.last_scan, "next_scan": s.next_scan,
                }
                for target, s in self.schedules.items()
            },
            "history": {
                target: [r for r in scans[-10:]]  # Keep last 10 scans
                for target, scans in self.scan_history.items()
            },
        }
        state_file.write_text(json.dumps(data, indent=2, default=str))

    def add_schedule(self, target: str, interval_hours: int = 24, playbooks: List[str] = None):
        """Add a scheduled scan."""
        self.schedules[target] = ScanSchedule(
            target=target,
            interval_hours=interval_hours,
            playbooks=playbooks or ["web_app"],
        )
        self._save_state()
        console.print(f"  [success]Scheduled scan: {target} every {interval_hours}h[/success]")

    def remove_schedule(self, target: str):
        """Remove a scheduled scan."""
        self.schedules.pop(target, None)
        self._save_state()

    def get_due_scans(self) -> List[str]:
        """Get targets that are due for a scan."""
        now = datetime.now()
        due = []
        for target, schedule in self.schedules.items():
            if not schedule.enabled:
                continue
            if schedule.last_scan:
                last = datetime.fromisoformat(schedule.last_scan)
                next_time = last + timedelta(hours=schedule.interval_hours)
                if now >= next_time:
                    due.append(target)
            else:
                due.append(target)
        return due

    def record_scan(self, target: str, result: ScanResult):
        """Record a scan result for diff comparison."""
        if target not in self.scan_history:
            self.scan_history[target] = []

        self.scan_history[target].append({
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(result.findings),
            "findings": [f.to_dict() for f in result.findings],
        })

        # Update schedule
        if target in self.schedules:
            self.schedules[target].last_scan = datetime.now().isoformat()

        self._save_state()

    def get_diff(self, target: str) -> Optional[ScanDiff]:
        """Get the difference between the last two scans."""
        history = self.scan_history.get(target, [])
        if len(history) < 2:
            return None

        prev_findings = {self._finding_key(f): f for f in history[-2]["findings"]}
        curr_findings = {self._finding_key(f): f for f in history[-1]["findings"]}

        diff = ScanDiff()
        for key, finding in curr_findings.items():
            if key not in prev_findings:
                diff.new_findings.append(Finding(**finding))
            else:
                diff.unchanged_findings.append(Finding(**finding))

        for key, finding in prev_findings.items():
            if key not in curr_findings:
                diff.fixed_findings.append(Finding(**finding))

        return diff

    def _finding_key(self, finding: Dict) -> str:
        """Generate a unique key for a finding."""
        return f"{finding.get('vuln_type', '')}:{finding.get('url', '')}:{finding.get('parameter', '')}"

    def verify_fix(self, target: str, finding: Finding, scanner) -> bool:
        """Verify that a fix actually works by re-testing."""
        console.print(f"  [info]Verifying fix for: {finding.title}[/info]")

        # Re-run the specific test
        try:
            results = scanner.scan_url(finding.url)
            for result in results:
                if result.vuln_type == finding.vuln_type and result.url == finding.url:
                    console.print(f"  [error]Fix NOT verified — vulnerability still exists[/error]")
                    return False

            console.print(f"  [success]Fix verified — vulnerability no longer present[/success]")
            return True
        except Exception as e:
            console.print(f"  [warning]Could not verify fix: {e}[/warning]")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get continuous scanning statistics."""
        return {
            "scheduled_targets": len(self.schedules),
            "total_scans": sum(len(v) for v in self.scan_history.values()),
            "targets_with_history": len(self.scan_history),
        }

    def list_schedules(self) -> List[Dict]:
        """List all scheduled scans."""
        return [
            {
                "target": s.target,
                "interval": f"{s.interval_hours}h",
                "enabled": s.enabled,
                "last_scan": s.last_scan,
            }
            for s in self.schedules.values()
        ]
