"""Scope Enforcement — blocks out-of-scope scanning.

Loads scope rules from bug-bounty programs (HackerOne, Bugcrowd)
and validates every target before scanning.
"""

import re
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from urllib.parse import urlparse

from ..core.logger import logger


@dataclass
class ScopeRule:
    """A single scope rule."""
    type: str  # domain, url, ip, cidr, wildcard
    value: str  # example.com, *.example.com, 192.168.0.0/24
    asset_type: str = "web"  # web, api, mobile, android, ios
    max_severity: str = "CRITICAL"  # what severity can be reported

    def matches(self, target: str) -> bool:
        """Check if a target matches this rule."""
        target = target.strip().lower()
        val = self.value.strip().lower()

        if self.type == "domain":
            return target == val or target.endswith(f".{val}")
        elif self.type == "wildcard":
            # *.example.com matches sub.example.com but not example.com
            pattern = val.replace(".", r"\.").replace("*", r"[a-zA-Z0-9_-]+")
            return bool(re.fullmatch(pattern, target))
        elif self.type == "url":
            return target.startswith(val)
        elif self.type == "ip":
            return target == val
        elif self.type == "cidr":
            try:
                network = ipaddress.ip_network(val, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in network
            except ValueError:
                return False
        return False


class ScopeManager:
    """Enforces target scope — blocks out-of-scope scanning."""

    def __init__(self):
        self.in_scope: List[ScopeRule] = []
        self.out_of_scope: List[ScopeRule] = []
        self._program_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Loading scope
    # ------------------------------------------------------------------

    def load_hackerone_scope(self, program: str) -> None:
        """Load scope from a HackerOne program handle.

        In production this would hit the H1 API. Here we accept a program
        name and load a local JSON if available, otherwise log a warning.
        """
        self._program_name = program
        scope_file = Path(f"data/scopes/{program}_hackerone.json")
        if scope_file.exists():
            self._load_from_file(scope_file)
            logger.info(f"Loaded HackerOne scope for {program}")
        else:
            logger.warning(
                f"Scope file {scope_file} not found — "
                f"add scope rules manually or create the file."
            )

    def load_bugcrowd_scope(self, program: str) -> None:
        """Load scope from a Bugcrowd program handle."""
        self._program_name = program
        scope_file = Path(f"data/scopes/{program}_bugcrowd.json")
        if scope_file.exists():
            self._load_from_file(scope_file)
            logger.info(f"Loaded Bugcrowd scope for {program}")
        else:
            logger.warning(
                f"Scope file {scope_file} not found — "
                f"add scope rules manually or create the file."
            )

    def add_in_scope(self, rule: ScopeRule) -> None:
        """Manually add an in-scope rule."""
        self.in_scope.append(rule)

    def add_out_of_scope(self, rule: ScopeRule) -> None:
        """Manually add an out-of-scope rule."""
        self.out_of_scope.append(rule)

    def load_from_dict(self, data: Dict) -> None:
        """Load scope from a dictionary (e.g., parsed YAML/JSON).

        Expected format:
        {
            "in_scope": [
                {"type": "domain", "value": "example.com", "asset_type": "web"},
                {"type": "wildcard", "value": "*.api.example.com", "asset_type": "api"},
            ],
            "out_of_scope": [
                {"type": "domain", "value": "admin.example.com"},
            ]
        }
        """
        for entry in data.get("in_scope", []):
            self.in_scope.append(ScopeRule(
                type=entry.get("type", "domain"),
                value=entry.get("value", ""),
                asset_type=entry.get("asset_type", "web"),
                max_severity=entry.get("max_severity", "CRITICAL"),
            ))
        for entry in data.get("out_of_scope", []):
            self.out_of_scope.append(ScopeRule(
                type=entry.get("type", "domain"),
                value=entry.get("value", ""),
                asset_type=entry.get("asset_type", "web"),
                max_severity=entry.get("max_severity", "CRITICAL"),
            ))
        logger.info(
            f"Loaded scope: {len(self.in_scope)} in-scope, "
            f"{len(self.out_of_scope)} out-of-scope rules."
        )

    # ------------------------------------------------------------------
    # Scope checking
    # ------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope.

        Returns True only if the target matches an in-scope rule AND
        does not match any out-of-scope rule.
        """
        target = target.strip()
        if not target:
            return False

        # Extract hostname for domain matching
        hostname = self._extract_hostname(target)

        # Must match at least one in-scope rule
        matches_in = any(rule.matches(hostname) or rule.matches(target) for rule in self.in_scope)
        if not matches_in:
            return False

        # Must NOT match any out-of-scope rule
        matches_out = any(rule.matches(hostname) or rule.matches(target) for rule in self.out_of_scope)
        if matches_out:
            return False

        return True

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate if a URL can be scanned.

        Returns (allowed, reason).
        """
        url = url.strip()
        if not url:
            return False, "Empty URL"

        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL: {e}"

        if not parsed.scheme:
            return False, "URL missing scheme (http/https)"
        if not parsed.hostname:
            return False, "URL missing hostname"

        hostname = parsed.hostname

        # Check out-of-scope first
        for rule in self.out_of_scope:
            if rule.matches(hostname) or rule.matches(url):
                return False, f"Explicitly out-of-scope: {rule.value}"

        # Check in-scope
        for rule in self.in_scope:
            if rule.matches(hostname) or rule.matches(url):
                return True, f"Matches scope rule: {rule.value}"

        return False, f"Host '{hostname}' does not match any in-scope rule"

    def filter_targets(self, targets: List[str]) -> List[str]:
        """Filter a list of targets to only in-scope ones."""
        allowed = []
        blocked = []
        for t in targets:
            if self.is_in_scope(t):
                allowed.append(t)
            else:
                blocked.append(t)

        if blocked:
            logger.warning(f"Blocked {len(blocked)} out-of-scope targets: {blocked[:5]}...")
        logger.info(f"Scope filter: {len(allowed)}/{len(targets)} targets in scope")
        return allowed

    def get_scope_summary(self) -> Dict:
        """Return a summary of loaded scope rules."""
        return {
            "program": self._program_name,
            "in_scope_count": len(self.in_scope),
            "out_of_scope_count": len(self.out_of_scope),
            "in_scope": [
                {"type": r.type, "value": r.value, "asset_type": r.asset_type}
                for r in self.in_scope
            ],
            "out_of_scope": [
                {"type": r.type, "value": r.value}
                for r in self.out_of_scope
            ],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from a URL or bare hostname."""
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").lower()
        # Could be IP, domain, or CIDR
        return target.strip().lower()

    def _load_from_file(self, path: Path) -> None:
        """Load scope rules from a JSON file."""
        import json
        try:
            data = json.loads(path.read_text())
            self.load_from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load scope file {path}: {e}")
