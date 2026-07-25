"""Tool Executor — runs security tools and processes results.

Handles the actual execution of tools, error recovery, and result processing.
"""

from typing import Dict, Any, Optional

from ..tools.registry import registry
from ..tools.base import ToolResult
from .memory import WorkingMemory
from ..core.logger import logger, console


class ToolExecutor:
    """Executes security tools and feeds results into working memory."""

    def __init__(self, memory: WorkingMemory):
        self.memory = memory
        self.registry = registry

    def execute(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Execute a tool and update working memory with results."""
        # Check if tool exists
        tool = self.registry.get(tool_name)
        if not tool:
            console.print(f"  [error]✗ Unknown tool: {tool_name}[/error]")
            return ToolResult(
                tool=tool_name,
                target=target,
                success=False,
                error=f"Unknown tool: {tool_name}",
            )

        # Run the tool
        result = self.registry.run(tool_name, target, **kwargs)

        # Update working memory
        self.memory.add_tool_result(result)

        # Log summary
        if result.success:
            self.memory.mark_step_done(f"{tool_name} → {target}")
            if result.findings:
                console.print(
                    f"  [success]✓ {tool_name}[/success]: "
                    f"{len(result.findings)} findings"
                )
            else:
                console.print(f"  [info]• {tool_name}[/info]: no findings")
        else:
            console.print(f"  [error]✗ {tool_name}[/error]: {result.error}")

        return result

    def execute_plan(self, tool_name: str, target: str, args: Dict[str, Any]) -> ToolResult:
        """Execute a planned step with arguments."""
        return self.execute(tool_name, target, **args)

    def get_available_tools(self) -> list:
        """Get list of available tool names."""
        return self.registry.with_fallback

    def get_tool_status(self) -> str:
        """Get formatted tool status."""
        return self.registry.status()
