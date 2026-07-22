"""Cross-Platform Tool Checker - Works on Windows, Linux, macOS."""

import os
import subprocess
import shutil
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..platform import detector, OS
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
    platform_available: bool = True


# Latest known versions
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

# Tool repos for go install
TOOL_REPOS = {
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

# Some tools don't work well on Windows
WINDOWS_LIMITATIONS = {
    "naabu": "Port scanning requires raw sockets - may need Npcap on Windows",
    "katana": "May have limited functionality on Windows",
}


class CrossPlatformToolChecker:
    """Checks bug bounty tools across all platforms."""

    def __init__(self):
        self.platform = detector.info
        self.tools: Dict[str, ToolStatus] = {}
        self._check_all()

    def _run(self, cmd: List[str], timeout: int = 10) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip() + result.stderr.strip()
        except Exception:
            return ""

    def _extract_version(self, output: str) -> str:
        match = re.search(r'v?(\d+\.\d+\.\d+)', output)
        return match.group(1) if match else ""

    def _check_tool(self, name: str, version_cmd: List[str]) -> ToolStatus:
        """Check a single tool with platform awareness."""
        # Check platform availability
        if self.platform.os == OS.WINDOWS and name in WINDOWS_LIMITATIONS:
            # Still check, but note limitations
            pass

        # Find tool
        path = detector.find_tool(name)
        if not path:
            return ToolStatus(
                name=name, installed=False, status="missing"
            )

        # Get version
        output = self._run(version_cmd)
        version = self._extract_version(output)
        latest = KNOWN_LATEST.get(name, "")

        if not version:
            return ToolStatus(
                name=name, installed=True, path=path,
                version="unknown", status="unknown"
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
        """Check all tools for current platform."""
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
        result = {
            "platform": self.platform.os.value,
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
                "status": tool.status,
                "limitation": WINDOWS_LIMITATIONS.get(name, "")
            }
            if tool.status == "ok":
                result["installed"] += 1
            elif tool.status == "outdated":
                result["outdated"] += 1
            else:
                result["missing"] += 1

        return result

    def print_status(self):
        """Print formatted status."""
        os_name = self.platform.os.value.upper()
        print(f"\n  Bug Bounty Tools - {os_name}")
        print(f"  {'=' * 50}")

        for name, tool in self.tools.items():
            if tool.status == "ok":
                icon = "[OK]"
                detail = f"v{tool.version}"
            elif tool.status == "outdated":
                icon = "[UPDATE]"
                detail = f"v{tool.version} -> v{tool.latest}"
            elif tool.status == "missing":
                icon = "[MISSING]"
                detail = "Not installed"
            else:
                icon = "[?]"
                detail = "Unknown version"

            limitation = WINDOWS_LIMITATIONS.get(name, "")
            limit_note = f" (!{limitation[:30]})" if limitation and self.platform.os == OS.WINDOWS else ""
            print(f"  {icon:10s} {name:15s} {detail}{limit_note}")

        print(f"  {'=' * 50}")
        installed = sum(1 for t in self.tools.values() if t.status == "ok")
        print(f"  Installed: {installed}/{len(self.tools)}")

    def get_missing(self) -> List[str]:
        return [name for name, t in self.tools.items() if not t.installed]

    def get_outdated(self) -> List[str]:
        return [name for name, t in self.tools.items() if t.status == "outdated"]

    def all_ready(self) -> bool:
        critical = ["nuclei", "subfinder", "httpx"]
        return all(self.tools.get(t, ToolStatus(name=t, installed=False)).installed for t in critical)

    def get_install_command(self, tool: str) -> str:
        """Get install command for current platform."""
        repo = TOOL_REPOS.get(tool, "")
        if not repo:
            return f"# Unknown tool: {tool}"

        if self.platform.os == OS.WINDOWS:
            return f"go install {repo}@latest"
        else:
            return f"go install {repo}@latest"

    def get_all_install_commands(self) -> str:
        """Get install commands for all missing/outdated tools."""
        lines = []
        for tool in self.get_missing():
            lines.append(self.get_install_command(tool))
        for tool in self.get_outdated():
            lines.append(f"# Update: {self.get_install_command(tool)}")
        return "\n".join(lines) if lines else "# All tools up to date!"
