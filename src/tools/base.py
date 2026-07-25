"""Base Security Tool Wrapper — abstract interface for all tools."""

import subprocess
import json
import time
import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..core.logger import logger, log_tool_start, log_tool_result


@dataclass
class ToolResult:
    """Standardized result from any tool execution."""
    tool: str
    target: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "success": self.success,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp,
        }

    def summary(self) -> str:
        if not self.success:
            return f"FAILED: {self.error}"
        return f"{len(self.findings)} findings in {self.duration:.1f}s"


class BaseTool(ABC):
    """Abstract base class for security tool wrappers."""

    name: str = "base"
    binary: str = ""
    description: str = ""

    def __init__(self):
        self.installed = self._check_installed()

    def _check_installed(self) -> bool:
        """Check if the tool binary is available."""
        import shutil
        return shutil.which(self.binary) is not None

    def _run_cmd(
        self,
        cmd: List[str],
        timeout: int = 300,
        capture: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute a shell command safely."""
        log_tool_start(self.name, " ".join(cmd[:5]))
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
            )
            return result
        except subprocess.TimeoutExpired:
            logger.warning(f"[{self.name}] Command timed out after {timeout}s")
            return subprocess.CompletedProcess(cmd, 1, "", "Timeout")
        except FileNotFoundError:
            logger.warning(f"[{self.name}] Binary not found: {cmd[0]}")
            return subprocess.CompletedProcess(cmd, 1, "", f"Binary not found: {cmd[0]}")
        except Exception as e:
            logger.error(f"[{self.name}] Command failed: {e}")
            return subprocess.CompletedProcess(cmd, 1, "", str(e))

    @abstractmethod
    def scan(self, target: str, **kwargs) -> ToolResult:
        """Run the tool against a target. Must be implemented by subclasses."""
        ...

    def is_available(self) -> bool:
        """Check if tool is available for use."""
        return self.installed

    def get_help(self) -> str:
        """Return usage help for this tool."""
        return f"{self.name}: {self.description}"
