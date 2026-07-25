"""Self-Learning Engine — learns from scan history to improve future scans.

Inspired by how experienced security researchers work:
- Remembers what WAFs block and what bypasses work
- Learns framework-specific attack patterns
- Builds knowledge from successful attacks
- Shares learnings across scans
"""

import json
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import config
from ..core.logger import logger, console


@dataclass
class LearnedPattern:
    """A pattern learned from scan history."""
    pattern_type: str  # waf_bypass, framework_attack, endpoint_pattern
    target_pattern: str  # what to match (e.g., "cloudflare", "react", "/api/v1")
    attack_pattern: str  # what works (e.g., "<img onerror>", "JWT none algo")
    success_rate: float = 0.0
    times_used: int = 0
    times_successful: int = 0
    last_used: str = ""
    source: str = ""  # which scan/target taught this


class SelfLearningEngine:
    """Learns from scan history to improve future scans.

    Features:
    - WAF bypass memory (remembers what bypasses work)
    - Framework attack patterns (React XSS, Django SQLi, etc.)
    - Endpoint discovery patterns (common API paths)
    - Success rate tracking (knows which attacks are reliable)
    """

    def __init__(self):
        self.patterns: List[LearnedPattern] = []
        self._state_file = config.output_dir / "learned_patterns.json"
        self._load()

    def _load(self):
        """Load learned patterns from disk."""
        if self._state_file.exists():
            try:
                data = json.loads(self._state_file.read_text())
                for p in data.get("patterns", []):
                    self.patterns.append(LearnedPattern(**p))
            except Exception:
                pass

    def _save(self):
        """Save learned patterns to disk."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "patterns": [
                {
                    "pattern_type": p.pattern_type,
                    "target_pattern": p.target_pattern,
                    "attack_pattern": p.attack_pattern,
                    "success_rate": p.success_rate,
                    "times_used": p.times_used,
                    "times_successful": p.times_successful,
                    "last_used": p.last_used,
                    "source": p.source,
                }
                for p in self.patterns
            ]
        }
        self._state_file.write_text(json.dumps(data, indent=2))

    def learn_waf_bypass(self, waf_name: str, bypass_technique: str, worked: bool, source: str = ""):
        """Learn a WAF bypass technique."""
        existing = self._find_pattern("waf_bypass", waf_name, bypass_technique)
        if existing:
            existing.times_used += 1
            if worked:
                existing.times_successful += 1
            existing.success_rate = existing.times_successful / existing.times_used
            existing.last_used = time.strftime("%Y-%m-%d %H:%M")
        else:
            self.patterns.append(LearnedPattern(
                pattern_type="waf_bypass",
                target_pattern=waf_name.lower(),
                attack_pattern=bypass_technique,
                success_rate=1.0 if worked else 0.0,
                times_used=1,
                times_successful=1 if worked else 0,
                last_used=time.strftime("%Y-%m-%d %H:%M"),
                source=source,
            ))
        self._save()

    def learn_framework_attack(self, framework: str, vuln_type: str, attack: str, worked: bool, source: str = ""):
        """Learn an attack pattern for a specific framework."""
        key = f"{framework.lower()}:{vuln_type.lower()}"
        existing = self._find_pattern("framework_attack", key, attack)
        if existing:
            existing.times_used += 1
            if worked:
                existing.times_successful += 1
            existing.success_rate = existing.times_successful / existing.times_used
        else:
            self.patterns.append(LearnedPattern(
                pattern_type="framework_attack",
                target_pattern=key,
                attack_pattern=attack,
                success_rate=1.0 if worked else 0.0,
                times_used=1,
                times_successful=1 if worked else 0,
                source=source,
            ))
        self._save()

    def learn_endpoint_pattern(self, tech: str, endpoint: str, source: str = ""):
        """Learn a common endpoint pattern for a technology."""
        existing = self._find_pattern("endpoint_pattern", tech.lower(), endpoint)
        if not existing:
            self.patterns.append(LearnedPattern(
                pattern_type="endpoint_pattern",
                target_pattern=tech.lower(),
                attack_pattern=endpoint,
                success_rate=1.0,
                times_used=1,
                times_successful=1,
                source=source,
            ))
            self._save()

    def get_waf_bypasses(self, waf_name: str) -> List[str]:
        """Get known bypasses for a WAF, sorted by success rate."""
        bypasses = [
            p for p in self.patterns
            if p.pattern_type == "waf_bypass" and p.target_pattern == waf_name.lower()
        ]
        bypasses.sort(key=lambda p: p.success_rate, reverse=True)
        return [p.attack_pattern for p in bypasses]

    def get_framework_attacks(self, framework: str, vuln_type: str) -> List[str]:
        """Get known attacks for a framework and vulnerability type."""
        key = f"{framework.lower()}:{vuln_type.lower()}"
        attacks = [
            p for p in self.patterns
            if p.pattern_type == "framework_attack" and p.target_pattern == key
        ]
        attacks.sort(key=lambda p: p.success_rate, reverse=True)
        return [p.attack_pattern for p in attacks]

    def get_endpoints_for_tech(self, tech: str) -> List[str]:
        """Get known endpoints for a technology."""
        endpoints = [
            p for p in self.patterns
            if p.pattern_type == "endpoint_pattern" and p.target_pattern == tech.lower()
        ]
        return [p.attack_pattern for p in endpoints]

    def get_recommendations(self, target_info: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get attack recommendations based on learned patterns and target info."""
        recommendations = {}

        # WAF bypasses
        waf = target_info.get("waf", "").lower()
        if waf:
            bypasses = self.get_waf_bypasses(waf)
            if bypasses:
                recommendations["waf_bypasses"] = bypasses[:5]

        # Framework attacks
        framework = target_info.get("framework", "").lower()
        if framework:
            for vuln_type in ["sqli", "xss", "ssrf", "idor"]:
                attacks = self.get_framework_attacks(framework, vuln_type)
                if attacks:
                    recommendations[f"{framework}_{vuln_type}"] = attacks[:3]

        # Endpoint patterns
        tech = target_info.get("server", "").lower() or target_info.get("cms", "").lower()
        if tech:
            endpoints = self.get_endpoints_for_tech(tech)
            if endpoints:
                recommendations["endpoints"] = endpoints[:10]

        return recommendations

    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        by_type = {}
        for p in self.patterns:
            by_type[p.pattern_type] = by_type.get(p.pattern_type, 0) + 1

        return {
            "total_patterns": len(self.patterns),
            "by_type": by_type,
            "avg_success_rate": (
                sum(p.success_rate for p in self.patterns) / len(self.patterns)
                if self.patterns else 0
            ),
        }

    def _find_pattern(self, pattern_type: str, target: str, attack: str) -> Optional[LearnedPattern]:
        """Find an existing pattern."""
        for p in self.patterns:
            if p.pattern_type == pattern_type and p.target_pattern == target and p.attack_pattern == attack:
                return p
        return None
