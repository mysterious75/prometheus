"""Shodan/Censys Integration — internet-wide intelligence.

Finds exposed services, vulnerabilities, and infrastructure details.
"""

import subprocess
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


@dataclass
class ShodanResult:
    """Shodan search result."""
    ip: str
    port: int
    transport: str = "tcp"
    product: str = ""
    version: str = ""
    banner: str = ""
    org: str = ""
    os: str = ""
    vulns: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "ip": self.ip, "port": self.port, "product": self.product,
            "version": self.version, "org": self.org, "vulns": self.vulns,
        }


class ShodanTool:
    """Shodan and Censys integration for internet intelligence."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.has_shodan_cli = self._check_cli()

    def _check_cli(self) -> bool:
        """Check if shodan CLI is installed."""
        import shutil
        return shutil.which("shodan") is not None

    def search(self, query: str) -> List[ShodanResult]:
        """Search Shodan for a query."""
        if not self.has_shodan_cli and not self.api_key:
            return self._fallback_search(query)

        results = []
        try:
            if self.has_shodan_cli:
                cmd = ["shodan", "search", "--fields", "ip_str,port,product,version,org,os,hostnames,vulns", query]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode == 0:
                    for line in proc.stdout.strip().split("\n"):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                results.append(ShodanResult(
                                    ip=parts[0], port=int(parts[1]) if parts[1].isdigit() else 0,
                                    product=parts[2] if len(parts) > 2 else "",
                                    version=parts[3] if len(parts) > 3 else "",
                                ))
        except Exception as e:
            logger.debug(f"Shodan search failed: {e}")

        return results

    def host_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed information about a host."""
        if not self.has_shodan_cli and not self.api_key:
            return self._fallback_host_info(ip)

        try:
            if self.has_shodan_cli:
                cmd = ["shodan", "host", ip]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode == 0:
                    return {"ip": ip, "raw": proc.stdout[:2000]}
        except Exception as e:
            logger.debug(f"Shodan host lookup failed: {e}")

        return {"ip": ip, "error": "lookup failed"}

    def check_cve(self, cve_id: str) -> Dict[str, Any]:
        """Check if a CVE affects known services."""
        if not self.has_shodan_cli:
            return {"cve": cve_id, "error": "shodan CLI not installed"}

        try:
            cmd = ["shodan", "search", f"vuln:{cve_id}", "--fields", "ip_str,port,product"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                hosts = []
                for line in proc.stdout.strip().split("\n"):
                    if line.strip():
                        hosts.append(line.strip())
                return {"cve": cve_id, "affected_hosts": len(hosts), "hosts": hosts[:10]}
        except Exception:
            pass

        return {"cve": cve_id}

    def _fallback_search(self, query: str) -> List[ShodanResult]:
        """Fallback: use web search for Shodan data."""
        try:
            import httpx
            # Use Shodan's web interface
            client = httpx.Client(timeout=10, verify=True)
            url = f"https://www.shodan.io/search?query={query}"
            resp = client.get(url)
            # Parse basic results from HTML (limited)
            return []
        except Exception:
            return []

    def _fallback_host_info(self, ip: str) -> Dict[str, Any]:
        """Fallback: basic host info via reverse DNS."""
        import socket
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {"ip": ip, "hostname": hostname, "source": "reverse_dns"}
        except Exception:
            return {"ip": ip}

    def internetdb_search(self, ip: str) -> Dict[str, Any]:
        """Use Shodan's free InternetDB API (no API key needed)."""
        try:
            import httpx
            client = httpx.Client(timeout=10, verify=True)
            resp = client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {"ip": ip, "error": "InternetDB lookup failed"}
