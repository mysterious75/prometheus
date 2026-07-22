"""Platform Detection - Auto-detects OS and provides correct commands."""

import os
import sys
import platform
import subprocess
import shutil
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum


class OS(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class Arch(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Detected platform information."""
    os: OS
    arch: Arch
    os_version: str
    shell: str
    home_dir: str
    is_root: bool
    go_path: str
    bin_dir: str
    python_cmd: str
    pip_cmd: str


class PlatformDetector:
    """Detects the current platform and provides OS-specific configurations."""

    def __init__(self):
        self.info = self._detect()

    def _detect(self) -> PlatformInfo:
        """Detect current platform."""
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Detect OS
        if system == "windows":
            os_type = OS.WINDOWS
        elif system == "linux":
            os_type = OS.LINUX
        elif system == "darwin":
            os_type = OS.MACOS
        else:
            os_type = OS.UNKNOWN

        # Detect architecture
        if machine in ("x86", "i386", "i686"):
            arch = Arch.X86
        elif machine in ("x86_64", "amd64"):
            arch = Arch.X64
        elif machine.startswith("arm"):
            arch = Arch.ARM64 if "64" in machine else Arch.ARM
        else:
            arch = Arch.UNKNOWN

        # OS-specific settings
        if os_type == OS.WINDOWS:
            shell = "powershell"
            home_dir = os.path.expanduser("~")
            is_root = self._check_windows_admin()
            go_path = os.path.join(home_dir, "go", "bin")
            bin_dir = os.path.join(home_dir, "go", "bin")
            python_cmd = "python"
            pip_cmd = "pip"
        elif os_type == OS.LINUX:
            shell = "bash"
            home_dir = os.path.expanduser("~")
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            go_path = os.path.join(home_dir, "go", "bin")
            bin_dir = os.path.join(home_dir, "go", "bin")
            python_cmd = "python3"
            pip_cmd = "pip3"
        elif os_type == OS.MACOS:
            shell = "zsh"
            home_dir = os.path.expanduser("~")
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            go_path = os.path.join(home_dir, "go", "bin")
            bin_dir = os.path.join(home_dir, "go", "bin")
            python_cmd = "python3"
            pip_cmd = "pip3"
        else:
            shell = "sh"
            home_dir = os.path.expanduser("~")
            is_root = False
            go_path = os.path.join(home_dir, "go", "bin")
            bin_dir = os.path.join(home_dir, "go", "bin")
            python_cmd = "python3"
            pip_cmd = "pip3"

        return PlatformInfo(
            os=os_type,
            arch=arch,
            os_version=platform.version(),
            shell=shell,
            home_dir=home_dir,
            is_root=is_root,
            go_path=go_path,
            bin_dir=bin_dir,
            python_cmd=python_cmd,
            pip_cmd=pip_cmd
        )

    def _check_windows_admin(self) -> bool:
        """Check if running as admin on Windows."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def find_tool(self, tool_name: str) -> Optional[str]:
        """Find a tool on the system."""
        # Check common locations
        search_paths = [
            self.info.go_path,
            self.info.bin_dir,
            "/usr/local/bin",
            "/usr/bin",
            os.path.join(self.info.home_dir, ".local", "bin"),
        ]

        # On Windows, add .exe
        if self.info.os == OS.WINDOWS:
            tool_name = tool_name if tool_name.endswith(".exe") else tool_name + ".exe"

        # Check PATH first
        path = shutil.which(tool_name)
        if path:
            return path

        # Check common directories
        for search_dir in search_paths:
            full_path = os.path.join(search_dir, tool_name)
            if os.path.exists(full_path):
                return full_path

        return None

    def get_install_command(self, tool: str, repo: str) -> List[str]:
        """Get the correct install command for this platform."""
        if self.info.os == OS.WINDOWS:
            return ["go", "install", f"{repo}@latest"]
        else:
            return ["go", "install", f"{repo}@latest"]

    def get_tool_version(self, tool_name: str) -> str:
        """Get version of an installed tool."""
        path = self.find_tool(tool_name)
        if not path:
            return ""

        try:
            result = subprocess.run(
                [path, "-version"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
            import re
            match = re.search(r'v?(\d+\.\d+\.\d+)', output)
            return match.group(1) if match else ""
        except Exception:
            return ""

    def get_system_info(self) -> Dict[str, Any]:
        """Get complete system information."""
        return {
            "os": self.info.os.value,
            "os_version": self.info.os_version,
            "architecture": self.info.arch.value,
            "shell": self.info.shell,
            "python": self.info.python_cmd,
            "is_admin_root": self.info.is_root,
            "go_path": self.info.go_path,
            "home": self.info.home_dir,
            "platform": platform.platform(),
            "processor": platform.processor(),
        }

    def print_info(self):
        """Print system information."""
        info = self.get_system_info()
        print(f"\n  Platform Info:")
        print(f"  {'=' * 40}")
        print(f"  OS:           {info['os'].upper()} {info['os_version'][:30]}")
        print(f"  Architecture: {info['architecture']}")
        print(f"  Shell:        {info['shell']}")
        print(f"  Admin/Root:   {'YES' if info['is_admin_root'] else 'NO'}")
        print(f"  Python:       {info['python']}")
        print(f"  Go Path:      {info['go_path']}")
        print(f"  {'=' * 40}")


# Global instance
detector = PlatformDetector()
