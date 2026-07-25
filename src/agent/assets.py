"""Smart Asset Manager — deduplicates findings across all tools.

When multiple tools discover subdomains, IPs, URLs, etc.,
this module ensures no duplicate work is done and each tool
focuses on NEW assets only.

Key principle: If tool A found subdomain X, tool B should NOT
re-scan X — it should focus on finding NEW subdomains.
"""

import re
import socket
import time
from typing import List, Dict, Any, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..core.logger import logger, console


@dataclass
class Asset:
    """A discovered asset (subdomain, IP, URL, etc.)."""
    value: str
    asset_type: str  # subdomain, ip, url, email, port, service
    source: str  # which tool found it
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    alive: Optional[bool] = None  # None=not checked, True/False


class SmartAssetManager:
    """Manages and deduplicates all discovered assets.

    Features:
    - Global deduplication across all tools
    - Each tool only scans NEW (undiscovered) assets
    - Tracks which tool found what
    - Provides filtered lists for each tool
    - Resolves and deduplicates by IP (not just hostname)
    """

    def __init__(self, domain: str):
        self.domain = domain
        self._assets: Dict[str, Asset] = {}  # key: normalized value
        self._ip_map: Dict[str, Set[str]] = {}  # ip -> set of hostnames
        self._scanned_by: Dict[str, Set[str]] = {}  # tool -> set of scanned values

    # --- Asset Management ---

    def add_subdomain(self, subdomain: str, source: str) -> bool:
        """Add a subdomain. Returns True if it's NEW (not seen before)."""
        subdomain = subdomain.lower().strip().rstrip('.')
        if not subdomain or not subdomain.endswith(self.domain):
            return False

        key = f"subdomain:{subdomain}"
        if key in self._assets:
            return False  # Already seen

        self._assets[key] = Asset(
            value=subdomain, asset_type="subdomain", source=source
        )

        # Mark as scanned by the source that found it
        self._scanned_by.setdefault(source, set())
        self._scanned_by[source].add(subdomain)

        # Try to resolve and deduplicate by IP
        try:
            ip = socket.gethostbyname(subdomain)
            if ip not in self._ip_map:
                self._ip_map[ip] = set()
            self._ip_map[ip].add(subdomain)
            self._assets[key].metadata["ip"] = ip
        except Exception:
            pass

        return True

    def add_subdomains(self, subdomains: List[str], source: str) -> List[str]:
        """Add multiple subdomains, return only NEW ones."""
        new = []
        for sub in subdomains:
            if self.add_subdomain(sub, source):
                new.append(sub)
        return new

    def add_url(self, url: str, source: str) -> bool:
        """Add a URL. Returns True if NEW."""
        url = url.strip()
        if not url:
            return False

        # Normalize
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')

        key = f"url:{normalized}"
        if key in self._assets:
            return False

        self._assets[key] = Asset(value=url, asset_type="url", source=source)
        return True

    def add_urls(self, urls: List[str], source: str) -> List[str]:
        """Add multiple URLs, return only NEW ones."""
        return [u for u in urls if self.add_url(u, source)]

    def add_email(self, email: str, source: str) -> bool:
        """Add an email. Returns True if NEW."""
        email = email.lower().strip()
        key = f"email:{email}"
        if key in self._assets:
            return False
        self._assets[key] = Asset(value=email, asset_type="email", source=source)
        return True

    def add_ip(self, ip: str, source: str) -> bool:
        """Add an IP. Returns True if NEW."""
        ip = ip.strip()
        key = f"ip:{ip}"
        if key in self._assets:
            return False
        self._assets[key] = Asset(value=ip, asset_type="ip", source=source)
        return True

    def add_port(self, ip: str, port: int, service: str, source: str) -> bool:
        """Add an open port. Returns True if NEW."""
        key = f"port:{ip}:{port}"
        if key in self._assets:
            return False
        self._assets[key] = Asset(
            value=f"{ip}:{port}", asset_type="port", source=source,
            metadata={"port": port, "service": service}
        )
        return True

    # --- Smart Filtering (what each tool should scan) ---

    def get_new_subdomains(self, source: str, limit: int = 100) -> List[str]:
        """Get subdomains NOT yet scanned by this source.
        Only returns subdomains that haven't been scanned by ANY tool yet.
        """
        self._scanned_by.setdefault(source, set())
        all_scanned = set()
        for scanned_set in self._scanned_by.values():
            all_scanned.update(scanned_set)
        new = []
        for key, asset in self._assets.items():
            if asset.asset_type == "subdomain" and asset.value not in all_scanned:
                new.append(asset.value)
                if len(new) >= limit:
                    break
        return new

    def get_new_urls(self, source: str, limit: int = 50) -> List[str]:
        """Get URLs NOT yet scanned by this source."""
        self._scanned_by.setdefault(source, set())
        new = []
        for key, asset in self._assets.items():
            if asset.asset_type == "url" and asset.value not in self._scanned_by[source]:
                new.append(asset.value)
                if len(new) >= limit:
                    break
        return new

    def mark_scanned(self, values: List[str], source: str):
        """Mark assets as scanned by a source."""
        self._scanned_by.setdefault(source, set())
        self._scanned_by[source].update(values)

    # --- Queries ---

    def get_all_subdomains(self) -> List[str]:
        """Get all discovered subdomains."""
        return sorted([
            a.value for a in self._assets.values()
            if a.asset_type == "subdomain"
        ])

    def get_all_urls(self) -> List[str]:
        """Get all discovered URLs."""
        return [a.value for a in self._assets.values() if a.asset_type == "url"]

    def get_all_emails(self) -> List[str]:
        """Get all discovered emails."""
        return sorted([a.value for a in self._assets.values() if a.asset_type == "email"])

    def get_all_ips(self) -> List[str]:
        """Get all discovered IPs."""
        return sorted(set([
            a.metadata.get("ip", "") for a in self._assets.values()
            if a.asset_type == "subdomain" and a.metadata.get("ip")
        ]))

    def get_subdomains_by_ip(self, ip: str) -> List[str]:
        """Get all subdomains pointing to a specific IP."""
        return sorted(list(self._ip_map.get(ip, set())))

    def get_unique_ips(self) -> Dict[str, List[str]]:
        """Get IP → subdomains mapping."""
        return {ip: sorted(subs) for ip, subs in self._ip_map.items() if len(subs) > 1}

    def get_source_stats(self) -> Dict[str, int]:
        """Get count of assets by source."""
        stats = {}
        for asset in self._assets.values():
            stats[asset.source] = stats.get(asset.source, 0) + 1
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Get overall asset statistics."""
        types = {}
        for asset in self._assets.values():
            types[asset.asset_type] = types.get(asset.asset_type, 0) + 1

        return {
            "total_assets": len(self._assets),
            "by_type": types,
            "unique_ips": len(self._ip_map),
            "sources": self.get_source_stats(),
        }

    # --- Dedup Helpers ---

    def is_duplicate(self, value: str, asset_type: str) -> bool:
        """Check if an asset already exists."""
        key = f"{asset_type}:{value.lower().strip()}"
        return key in self._assets

    def get_deduplicated_subdomains_for_tool(self, tool_name: str, candidates: List[str]) -> List[str]:
        """Given a list of candidate subdomains from a tool,
        return only those that are NEW (not found by any tool yet)."""
        new = []
        for sub in candidates:
            sub = sub.lower().strip().rstrip('.')
            if sub and sub.endswith(self.domain):
                key = f"subdomain:{sub}"
                if key not in self._assets:
                    new.append(sub)
        return new
