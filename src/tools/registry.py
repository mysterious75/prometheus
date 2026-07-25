"""Tool Registry — central hub for all security tools.

Usage:
    from src.tools import registry
    result = registry.run("nuclei", "https://example.com")
    results = registry.run_all("https://example.com")
"""

from typing import Dict, List, Optional, Any

from .base import BaseTool, ToolResult
from .nuclei import NucleiScanner
from .subfinder import SubdomainEnumerator
from .httpx import HttpProber
from .sqlmap import SQLInjectionScanner
from .sherlock import UsernameOSINT
from .portscan import PortScanner
from ..core.logger import logger, console


class ToolRegistry:
    """Central registry for all security tools."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._register_defaults()

    def _register_defaults(self):
        """Register all built-in tool wrappers."""
        self.register(NucleiScanner())
        self.register(SubdomainEnumerator())
        self.register(HttpProber())
        self.register(SQLInjectionScanner())
        self.register(UsernameOSINT())
        self.register(PortScanner())

    def register(self, tool: BaseTool):
        """Register a tool."""
        self._tools[tool.name] = tool
        status = "✓ installed" if tool.installed else "⚠ fallback mode"
        logger.debug(f"Tool registered: {tool.name} ({status})")

    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def run(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Run a specific tool against a target."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ToolResult(
                tool=tool_name,
                target=target,
                success=False,
                error=f"Tool not found: {tool_name}",
            )

        console.print(f"  [tool]▸ {tool_name}[/tool] → [target]{target}[/target]")
        result = tool.scan(target, **kwargs)
        console.print(f"  [tool]◂ {tool_name}[/tool] — {result.summary()}")
        return result

    def run_all(self, target: str, **kwargs) -> Dict[str, ToolResult]:
        """Run all available tools against a target."""
        results = {}
        for name, tool in self._tools.items():
            if tool.is_available() or tool.name in ["nuclei", "httpx", "portscan"]:
                # Always run tools with fallback support
                results[name] = self.run(name, target, **kwargs)
        return results

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools with their status."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "installed": tool.installed,
                "has_fallback": True,
            }
            for tool in self._tools.values()
        ]

    def status(self) -> str:
        """Get formatted status of all tools."""
        lines = ["\n  Tool Status:"]
        for tool in self._tools.values():
            icon = "✓" if tool.installed else "⚠"
            mode = "binary" if tool.installed else "fallback"
            lines.append(f"    {icon} {tool.name:15} [{mode:8}] {tool.description}")
        return "\n".join(lines)

    @property
    def available(self) -> List[str]:
        """List names of tools with binaries installed."""
        return [t.name for t in self._tools.values() if t.installed]

    @property
    def with_fallback(self) -> List[str]:
        """List names of all tools (including fallbacks)."""
        return list(self._tools.keys())


# Singleton
registry = ToolRegistry()
