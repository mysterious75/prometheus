"""Authorization Manager — authorize targets before scanning.

Security-first: no scanning without explicit authorization.
"""

import json
from pathlib import Path
from typing import Set
from urllib.parse import urlparse

from ..core.config import config
from ..core.logger import console


class TargetAuthorization:
    """Manages authorized targets for security scanning."""

    def __init__(self):
        self.authorized: Set[str] = set()
        self._file = config.authorized_targets_file
        self._load()

    def _load(self):
        """Load authorized targets from config file."""
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text())
                self.authorized = set(data.get("targets", []))
            except (json.JSONDecodeError, KeyError):
                self.authorized = set()

    def _save(self):
        """Save authorized targets to config file."""
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps(
            {"targets": sorted(self.authorized)}, indent=2
        ))

    def _normalize(self, target: str) -> str:
        """Normalize target to hostname."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        hostname = urlparse(target).hostname or target
        return hostname.lower().strip()

    def authorize(self, target: str) -> str:
        """Authorize a target for scanning."""
        hostname = self._normalize(target)
        self.authorized.add(hostname)
        self._save()
        return f"✓ Target '{hostname}' authorized for scanning."

    def revoke(self, target: str) -> str:
        """Revoke authorization for a target."""
        hostname = self._normalize(target)
        self.authorized.discard(hostname)
        self._save()
        return f"✓ Authorization revoked for '{hostname}'."

    def is_authorized(self, target: str) -> bool:
        """Check if a target is authorized."""
        hostname = self._normalize(target)
        return hostname in self.authorized

    def list_targets(self) -> str:
        """List all authorized targets."""
        if not self.authorized:
            return "No authorized targets. Use 'authorize <target>' first."
        lines = ["Authorized targets:"]
        for t in sorted(self.authorized):
            lines.append(f"  • {t}")
        return "\n".join(lines)

    def require_auth(self, target: str) -> bool:
        """Check authorization and print error if not authorized."""
        if not self.is_authorized(target):
            console.print(
                f"  [error]✗ Target '{target}' is NOT authorized.[/error]\n"
                f"  Run: [bold]authorize {target}[/bold]"
            )
            return False
        return True


# Singleton
auth = TargetAuthorization()
