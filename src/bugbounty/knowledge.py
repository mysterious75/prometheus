"""Bug Bounty Knowledge Base - AI Learning System.

Loads 1000+ reports and patterns for AI to learn from.
Integrates with Prometheus brain for autonomous learning.
"""

import json
import random
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..utils.logger import logger


class BugBountyKnowledge:
    """AI-accessible bug bounty knowledge base."""

    BASE_DIR = Path(__file__).parent.parent.parent / "learn-from-others"

    def __init__(self):
        self.knowledge_base = []
        self.index = {}
        self.patterns = {}
        self.payloads = {}
        self.playbooks = {}
        self.bounty_ranges = {}
        self.tech_patterns = {}
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy load knowledge base."""
        if not self._loaded:
            self.load()
            self._loaded = True

    def load(self):
        """Load all knowledge base files."""
        try:
            # Main knowledge base
            kb_file = self.BASE_DIR / "knowledge_base.json"
            if kb_file.exists():
                data = json.loads(kb_file.read_text(encoding="utf-8"), strict=False)
                if isinstance(data, dict):
                    self.knowledge_base = data.get("entries", data.get("data", []))
                elif isinstance(data, list):
                    self.knowledge_base = data
                else:
                    self.knowledge_base = []
                logger.info(f"[green]Loaded {len(self.knowledge_base)} knowledge entries[/green]")

            # Index
            index_file = self.BASE_DIR / "knowledge_index.json"
            if index_file.exists():
                try:
                    self.index = json.loads(index_file.read_text(encoding="utf-8"), strict=False)
                except Exception:
                    pass

            # Patterns
            for name in ["vuln_cheatsheet", "attack_playbooks", "payload_database",
                         "bounty_ranges", "tech_stack_patterns"]:
                p_file = self.BASE_DIR / "patterns" / f"{name}.json"
                if p_file.exists():
                    try:
                        data = json.loads(p_file.read_text(encoding="utf-8"), strict=False)
                        setattr(self, name.replace("-", "_"), data)
                    except Exception:
                        pass

            self._loaded = True
        except Exception as e:
            logger.error(f"Knowledge base load error: {e}")

    def get_random_entries(self, count: int = 10, vuln_type: str = None,
                           severity: str = None, difficulty: str = None) -> List[Dict]:
        """Get random entries for AI learning."""
        self._ensure_loaded()

        entries = self.knowledge_base

        if vuln_type:
            entries = [e for e in entries if vuln_type.lower() in
                       (e.get("vuln_type", "") or e.get("vulnerability_type", "")).lower()]
        if severity:
            entries = [e for e in entries if severity.lower() in e.get("severity", "").lower()]
        if difficulty:
            entries = [e for e in entries if difficulty.lower() in
                       (e.get("difficulty", "") or e.get("difficulty_level", "")).lower()]

        return random.sample(entries, min(count, len(entries)))

    def get_entries_by_type(self, vuln_type: str) -> List[Dict]:
        """Get all entries for a specific vulnerability type."""
        self._ensure_loaded()
        return [e for e in self.knowledge_base
                if vuln_type.lower() in
                (e.get("vuln_type", "") or e.get("vulnerability_type", "")).lower()]

    def get_cheatsheet(self, vuln_type: str) -> Dict:
        """Get quick cheatsheet for a vulnerability type."""
        self._ensure_loaded()
        return self.vuln_cheatsheet.get(vuln_type, {})

    def get_playbook(self, vuln_type: str) -> Dict:
        """Get attack playbook for a vulnerability type."""
        self._ensure_loaded()
        return self.playbooks.get(vuln_type, {})

    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for a vulnerability type."""
        self._ensure_loaded()
        return self.payloads.get(vuln_type, [])

    def get_bounty_info(self, vuln_type: str, severity: str = "") -> Dict:
        """Get bounty range info."""
        self._ensure_loaded()
        info = self.bounty_ranges.get(vuln_type, {})
        if severity and severity in info:
            return info[severity]
        return info

    def get_tech_vulns(self, tech: str) -> Dict:
        """Get common vulnerabilities for a technology stack."""
        self._ensure_loaded()
        return self.tech_patterns.get(tech, {})

    def search(self, query: str, limit: int = 20) -> List[Dict]:
        """Search knowledge base by keyword."""
        self._ensure_loaded()
        query_lower = query.lower()
        results = []

        for entry in self.knowledge_base:
            searchable = json.dumps(entry).lower()
            if query_lower in searchable:
                results.append(entry)
                if len(results) >= limit:
                    break

        return results

    def get_learning_prompt(self, vuln_type: str = None, count: int = 5) -> str:
        """Generate a learning prompt for the AI to study."""
        self._ensure_loaded()

        if vuln_type:
            entries = self.get_entries_by_type(vuln_type)[:count]
        else:
            entries = self.get_random_entries(count)

        if not entries:
            return "No entries found for learning."

        prompt = f"Study these {len(entries)} bug bounty reports and learn the patterns:\n\n"

        for i, entry in enumerate(entries, 1):
            prompt += f"""
--- Report {i} ---
Title: {entry.get('title', 'N/A')}
Vulnerability: {entry.get('vuln_type', 'N/A')}
Severity: {entry.get('severity', 'N/A')}
Bounty: {entry.get('bounty', 'N/A')}
Target: {entry.get('target', 'N/A')}
Methodology: {entry.get('methodology', 'N/A')[:500]}
Payloads: {json.dumps(entry.get('payloads', []))[:300]}
Impact: {entry.get('impact', 'N/A')[:200]}
Fix: {entry.get('remediation', 'N/A')[:200]}
"""

        prompt += """
Analyze these reports and identify:
1. Common patterns in discovery methodology
2. Payload variations that work
3. Impact assessment patterns
4. Remediation approaches
5. Bounty justification factors
"""
        return prompt

    def get_stats(self) -> Dict:
        """Get knowledge base statistics."""
        self._ensure_loaded()

        vuln_counts = {}
        severity_counts = {}
        for entry in self.knowledge_base:
            vtype = entry.get("vuln_type", "") or entry.get("vulnerability_type", "Unknown")
            severity = entry.get("severity", "Unknown")
            vuln_counts[vtype] = vuln_counts.get(vtype, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_entries": len(self.knowledge_base),
            "vuln_types": vuln_counts,
            "severities": severity_counts,
            "payloads_loaded": sum(len(v) for v in self.payloads.values()),
            "playbooks_loaded": len(self.playbooks),
            "tech_stacks": list(self.tech_patterns.keys()),
        }

    def format_stats(self) -> str:
        """Format stats as readable string."""
        stats = self.get_stats()
        lines = [
            "Bug Bounty Knowledge Base Stats:",
            f"  Total entries: {stats['total_entries']}",
            f"  Payloads: {stats['payloads_loaded']}",
            f"  Playbooks: {stats['playbooks_loaded']}",
            f"  Tech stacks: {', '.join(stats['tech_stacks'])}",
            "",
            "By Vulnerability Type:",
        ]
        for vtype, count in sorted(stats["vuln_types"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {vtype}: {count}")

        lines.append("\nBy Severity:")
        for sev, count in sorted(stats["severities"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {sev}: {count}")

        return "\n".join(lines)


# Singleton
knowledge = BugBountyKnowledge()
