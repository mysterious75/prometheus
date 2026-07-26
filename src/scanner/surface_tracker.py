"""Attack Surface Change Detection — Track changes between scans.

Inspired by n8n Red/Blue AppSec Workflows.

Features:
- Compare current scan with previous scan
- Detect new subdomains, ports, endpoints
- Detect removed assets
- Alert on significant changes
- Historical tracking
"""

import json
import time
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field

from ..core.logger import logger, console


@dataclass
class AssetSnapshot:
    """Snapshot of discovered assets at a point in time."""
    timestamp: str
    target: str
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    http_services: List[Dict] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    findings_count: int = 0


@dataclass
class AssetChange:
    """Change detected between two snapshots."""
    change_type: str  # new, removed, modified
    asset_type: str  # subdomain, port, endpoint, technology, finding
    value: str
    details: str = ""


@dataclass
class ChangeReport:
    """Report of all changes between scans."""
    target: str
    previous_scan: str
    current_scan: str
    new_assets: List[AssetChange] = field(default_factory=list)
    removed_assets: List[AssetChange] = field(default_factory=list)
    new_findings: int = 0
    summary: str = ""

    @property
    def has_changes(self) -> bool:
        return len(self.new_assets) > 0 or len(self.removed_assets) > 0 or self.new_findings > 0


class AttackSurfaceTracker:
    """Tracks attack surface changes over time.
    
    Stores snapshots on disk and compares between scans.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir or "data/snapshots")
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def save_snapshot(self, target: str, snapshot: AssetSnapshot) -> str:
        """Save a scan snapshot to disk."""
        safe_name = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = self.data_dir / f"{safe_name}_{timestamp}.json"
        
        data = {
            "timestamp": snapshot.timestamp,
            "target": snapshot.target,
            "subdomains": snapshot.subdomains,
            "open_ports": snapshot.open_ports,
            "http_services": snapshot.http_services,
            "endpoints": snapshot.endpoints,
            "technologies": snapshot.technologies,
            "findings_count": snapshot.findings_count,
        }
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Snapshot saved: {filepath}")
        return str(filepath)
    
    def load_latest_snapshot(self, target: str) -> Optional[AssetSnapshot]:
        """Load the most recent snapshot for a target."""
        safe_name = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        
        snapshots = sorted(
            self.data_dir.glob(f"{safe_name}_*.json"),
            reverse=True
        )
        
        if not snapshots:
            return None
        
        try:
            with open(snapshots[0]) as f:
                data = json.load(f)
            return AssetSnapshot(**data)
        except Exception as e:
            logger.warning(f"Failed to load snapshot: {e}")
            return None
    
    def load_all_snapshots(self, target: str) -> List[AssetSnapshot]:
        """Load all snapshots for a target."""
        safe_name = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        
        snapshots = []
        for filepath in sorted(self.data_dir.glob(f"{safe_name}_*.json")):
            try:
                with open(filepath) as f:
                    data = json.load(f)
                snapshots.append(AssetSnapshot(**data))
            except Exception:
                continue
        
        return snapshots
    
    def compare(self, target: str, current: AssetSnapshot) -> Optional[ChangeReport]:
        """Compare current scan with previous scan."""
        previous = self.load_latest_snapshot(target)
        
        if previous is None:
            logger.info(f"No previous snapshot for {target}")
            return None
        
        report = ChangeReport(
            target=target,
            previous_scan=previous.timestamp,
            current_scan=current.timestamp,
        )
        
        # Compare subdomains
        prev_subs = set(previous.subdomains)
        curr_subs = set(current.subdomains)
        
        new_subs = curr_subs - prev_subs
        removed_subs = prev_subs - curr_subs
        
        for sub in new_subs:
            report.new_assets.append(AssetChange(
                change_type="new",
                asset_type="subdomain",
                value=sub,
                details=f"New subdomain discovered: {sub}",
            ))
        
        for sub in removed_subs:
            report.removed_assets.append(AssetChange(
                change_type="removed",
                asset_type="subdomain",
                value=sub,
                details=f"Subdomain no longer resolving: {sub}",
            ))
        
        # Compare ports
        prev_ports = {(p.get("host", ""), p.get("port", 0)) for p in previous.open_ports}
        curr_ports = {(p.get("host", ""), p.get("port", 0)) for p in current.open_ports}
        
        new_ports = curr_ports - prev_ports
        removed_ports = prev_ports - curr_ports
        
        for host, port in new_ports:
            report.new_assets.append(AssetChange(
                change_type="new",
                asset_type="port",
                value=f"{host}:{port}",
                details=f"New open port: {host}:{port}",
            ))
        
        for host, port in removed_ports:
            report.removed_assets.append(AssetChange(
                change_type="removed",
                asset_type="port",
                value=f"{host}:{port}",
                details=f"Port closed: {host}:{port}",
            ))
        
        # Compare endpoints
        prev_endpoints = set(previous.endpoints)
        curr_endpoints = set(current.endpoints)
        
        new_endpoints = curr_endpoints - prev_endpoints
        removed_endpoints = prev_endpoints - curr_endpoints
        
        for ep in new_endpoints:
            report.new_assets.append(AssetChange(
                change_type="new",
                asset_type="endpoint",
                value=ep,
                details=f"New endpoint discovered: {ep}",
            ))
        
        for ep in removed_endpoints:
            report.removed_assets.append(AssetChange(
                change_type="removed",
                asset_type="endpoint",
                value=ep,
                details=f"Endpoint removed: {ep}",
            ))
        
        # Compare technologies
        prev_tech = set(previous.technologies)
        curr_tech = set(current.technologies)
        
        new_tech = curr_tech - prev_tech
        for tech in new_tech:
            report.new_assets.append(AssetChange(
                change_type="new",
                asset_type="technology",
                value=tech,
                details=f"New technology detected: {tech}",
            ))
        
        # Compare findings
        report.new_findings = current.findings_count - previous.findings_count
        
        # Generate summary
        report.summary = self._generate_summary(report)
        
        return report
    
    def _generate_summary(self, report: ChangeReport) -> str:
        """Generate human-readable summary."""
        lines = []
        lines.append(f"Attack Surface Change Report: {report.target}")
        lines.append(f"Previous scan: {report.previous_scan}")
        lines.append(f"Current scan: {report.current_scan}")
        lines.append("")
        
        if report.new_assets:
            lines.append(f"NEW ASSETS ({len(report.new_assets)}):")
            for change in report.new_assets[:20]:
                lines.append(f"  + [{change.asset_type}] {change.value}")
            if len(report.new_assets) > 20:
                lines.append(f"  ... and {len(report.new_assets) - 20} more")
        
        if report.removed_assets:
            lines.append(f"\nREMOVED ASSETS ({len(report.removed_assets)}):")
            for change in report.removed_assets[:20]:
                lines.append(f"  - [{change.asset_type}] {change.value}")
        
        if report.new_findings != 0:
            direction = "more" if report.new_findings > 0 else "fewer"
            lines.append(f"\nFindings: {abs(report.new_findings)} {direction} than previous scan")
        
        if not report.has_changes:
            lines.append("No significant changes detected.")
        
        return "\n".join(lines)
    
    def cleanup(self, keep_days: int = 30):
        """Remove snapshots older than keep_days."""
        cutoff = time.time() - (keep_days * 86400)
        removed = 0
        
        for filepath in self.data_dir.glob("*.json"):
            if filepath.stat().st_mtime < cutoff:
                filepath.unlink()
                removed += 1
        
        if removed:
            logger.info(f"Cleaned up {removed} old snapshots")
    
    def get_history(self, target: str) -> List[Dict]:
        """Get scan history for a target."""
        snapshots = self.load_all_snapshots(target)
        return [
            {
                "timestamp": s.timestamp,
                "subdomains": len(s.subdomains),
                "ports": len(s.open_ports),
                "endpoints": len(s.endpoints),
                "findings": s.findings_count,
            }
            for s in snapshots
        ]


# Export
__all__ = ["AttackSurfaceTracker", "AssetSnapshot", "ChangeReport", "AssetChange"]
