"""Prometheus Logger — structured logging with Rich console output."""

import logging
from rich.console import Console
from rich.theme import Theme

# Custom theme for security output
_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info-sev": "blue",
    "target": "bold magenta",
    "tool": "bold cyan",
    "finding": "bold yellow",
})

console = Console(theme=_theme)

# Standard logger
logger = logging.getLogger("prometheus")
logger.setLevel(logging.DEBUG)

# Console handler
_handler = logging.StreamHandler()
_handler.setLevel(logging.INFO)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
))
logger.addHandler(_handler)


def log_finding(severity: str, vuln_type: str, url: str, detail: str = ""):
    """Log a vulnerability finding with severity-colored output."""
    _sev = severity.lower()
    console.print(
        f"  [{_sev}][{_sev.upper()}][/{_sev}] {vuln_type} → {url}"
        + (f"  ({detail})" if detail else "")
    )


def log_tool_start(tool: str, target: str):
    """Log a tool execution start."""
    console.print(f"  [tool]▸ {tool}[/tool] → [target]{target}[/target]")


def log_tool_result(tool: str, summary: str):
    """Log a tool result summary."""
    console.print(f"  [tool]◂ {tool}[/tool] — {summary}")
