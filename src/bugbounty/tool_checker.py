"""Tool Checker - Verifies bug bounty tools are installed and up-to-date."""

import subprocess
import shutil
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..utils.logger import logger


@dataclass
class ToolStatus:
    """Status of a single tool."""
    name: str
    installed: bool
    version: str = ""
    latest: str = ""
    path: str = ""
    status: str = ""  # ok, outdated, missing, unknown


# Latest known versions (update periodically)
KNOWN_LATEST = {
    "nuclei": "3.2.0",
    "subfinder": "2.6.3",
    "httpx": "1.6.0",
    "naabu": "2.3.0",
    "katana": "1.1.0",
    "gau": "2.2.0",
    "ffuf": "2.1.0",
    "assetfinder": "0.1.1",
    "waybackurls": "0.0.1",
}


class ToolChecker:
    """Checks if bug bounty tools are installed and latest."""

    def __init__(self):
        self.tools: Dict[str, ToolStatus] = {}
        self._check_all()

    def _run(self, cmd: List[str], timeout: int = 10) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip() + result.stderr.strip()
        except Exception:
            return ""

    def _extract_version(self, output: str) -> str:
        """Extract version string from tool output."""
        match = re.search(r'v?(\d+\.\d+\.\d+)', output)
        return match.group(1) if match else ""

    def _check_tool(self, name: str, version_cmd: List[str]) -> ToolStatus:
        """Check a single tool."""
        path = shutil.which(name)
        if not path:
            return ToolStatus(
                name=name, installed=False, status="missing"
            )

        output = self._run(version_cmd)
        version = self._extract_version(output)
        latest = KNOWN_LATEST.get(name, "")

        if not version:
            return ToolStatus(
                name=name, installed=True, path=path, version="unknown", status="unknown"
            )

        # Compare versions
        if latest and self._version_compare(version, latest) < 0:
            status = "outdated"
        else:
            status = "ok"

        return ToolStatus(
            name=name, installed=True, version=version,
            latest=latest, path=path, status=status
        )

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare versions. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            for a, b in zip(parts1, parts2):
                if a < b:
                    return -1
                elif a > b:
                    return 1
            return 0
        except Exception:
            return 0

    def _check_all(self):
        """Check all known tools."""
        checks = [
            ("nuclei", ["nuclei", "-version"]),
            ("subfinder", ["subfinder", "-version"]),
            ("httpx", ["httpx", "-version"]),
            ("naabu", ["naabu", "-version"]),
            ("katana", ["katana", "-version"]),
            ("gau", ["gau", "--version"]),
            ("ffuf", ["ffuf", "-V"]),
            ("assetfinder", ["assetfinder", "--version"]),
            ("waybackurls", ["waybackurls", "-h"]),
        ]

        for name, cmd in checks:
            self.tools[name] = self._check_tool(name, cmd)

    def get_status(self) -> Dict[str, Any]:
        """Get status of all tools."""
        result = {
            "total": len(self.tools),
            "installed": 0,
            "outdated": 0,
            "missing": 0,
            "tools": {}
        }

        for name, tool in self.tools.items():
            result["tools"][name] = {
                "installed": tool.installed,
                "version": tool.version,
                "latest": tool.latest,
                "path": tool.path,
                "status": tool.status
            }
            if tool.status == "ok":
                result["installed"] += 1
            elif tool.status == "outdated":
                result["outdated"] += 1
            else:
                result["missing"] += 1

        return result

    def print_status(self):
        """Print formatted status of all tools."""
        print("\n  Bug Bounty Tools Status:")
        print("  " + "=" * 45)

        for name, tool in self.tools.items():
            if tool.status == "ok":
                icon = "[OK]"
                color = "green"
                detail = f"v{tool.version}"
            elif tool.status == "outdated":
                icon = "[UPDATE]"
                color = "yellow"
                detail = f"v{tool.version} -> v{tool.latest}"
            elif tool.status == "missing":
                icon = "[MISSING]"
                color = "red"
                detail = "Not installed"
            else:
                icon = "[?]"
                color = "yellow"
                detail = "Version unknown"

            print(f"  {icon} {name:15s} {detail}")

        print("  " + "=" * 45)
        print(f"  Installed: {sum(1 for t in self.tools.values() if t.status == 'ok')}/{len(self.tools)}")

    def get_missing(self) -> List[str]:
        """Get list of missing tools."""
        return [name for name, t in self.tools.items() if not t.installed]

    def get_outdated(self) -> List[str]:
        """Get list of outdated tools."""
        return [name for name, t in self.tools.items() if t.status == "outdated"]

    def all_ready(self) -> bool:
        """Check if all critical tools are installed."""
        critical = ["nuclei", "subfinder", "httpx", "naabu"]
        return all(self.tools.get(t, ToolStatus(name=t, installed=False)).installed for t in critical)

    def get_install_commands(self) -> str:
        """Get install commands for missing tools."""
        missing = self.get_missing()
        outdated = self.get_outdated()

        lines = []
        for tool in missing:
            lines.append(f"go install {self._get_repo(tool)}@latest")
        for tool in outdated:
            lines.append(f"go install {self._get_repo(tool)}@latest  # update")

        return "\n".join(lines) if lines else "All tools are up to date!"

    def _get_repo(self, tool: str) -> str:
        repos = {
            "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx",
            "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
            "katana": "github.com/projectdiscovery/katana/cmd/katana",
            "gau": "github.com/lc/gau/v2/cmd/gau",
            "ffuf": "github.com/ffuf/ffuf/v2",
            "assetfinder": "github.com/tomnomnom/assetfinder",
            "waybackurls": "github.com/tomnomnom/waybackurls",
        }
        return repos.get(tool, "")
