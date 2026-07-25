"""Prometheus Configuration — centralized config management."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"


@dataclass
class ToolConfig:
    """Configuration for an external security tool."""
    name: str
    binary: str  # path or command name
    installed: bool = False
    version: str = ""
    fallback: bool = True  # use built-in fallback if not installed


@dataclass
class AgentConfig:
    """Configuration for the AI agent."""
    max_steps: int = 20
    max_tool_calls: int = 50
    timeout_per_step: int = 120
    auto_confirm: bool = False  # require human confirmation for dangerous ops
    sandbox_mode: bool = True  # run tools in sandboxed mode


@dataclass
class PrometheusConfig:
    """Main Prometheus configuration."""
    # Project info
    name: str = "Prometheus"
    version: str = "3.0.0"
    description: str = "AI Security Researcher"

    # LLM
    primary_model: str = "deepseek"
    consciousness_model: str = "gemini"
    fallback_model: str = "openrouter"

    # Agent
    agent: AgentConfig = field(default_factory=AgentConfig)

    # Authorized targets file
    authorized_targets_file: Path = field(
        default_factory=lambda: CONFIG_DIR / "authorized_targets.json"
    )

    # Knowledge base
    knowledge_base_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "learn-from-others"
    )

    # Tools
    tools: Dict[str, ToolConfig] = field(default_factory=dict)

    # Output
    output_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "output"
    )

    def __post_init__(self):
        """Initialize default tool configs."""
        _default_tools = {
            "nuclei": ToolConfig("Nuclei", "nuclei"),
            "subfinder": ToolConfig("Subfinder", "subfinder"),
            "httpx": ToolConfig("httpx", "httpx"),
            "katana": ToolConfig("Katana", "katana"),
            "naabu": ToolConfig("Naabu", "naabu"),
            "nmap": ToolConfig("Nmap", "nmap"),
            "sqlmap": ToolConfig("SQLMap", "sqlmap"),
            "sherlock": ToolConfig("Sherlock", "sherlock"),
            "theharvester": ToolConfig("theHarvester", "theHarvester"),
            "gau": ToolConfig("gau", "gau"),
            "ffuf": ToolConfig("ffuf", "ffuf"),
            "dalfox": ToolConfig("Dalfox", "dalfox"),
        }
        for name, cfg in _default_tools.items():
            if name not in self.tools:
                self.tools[name] = cfg

    def check_tools(self) -> Dict[str, bool]:
        """Check which tools are installed."""
        import shutil
        results = {}
        for name, cfg in self.tools.items():
            cfg.installed = shutil.which(cfg.binary) is not None
            results[name] = cfg.installed
        return results

    def get_installed_tools(self) -> list:
        """Return list of installed tool names."""
        self.check_tools()
        return [name for name, cfg in self.tools.items() if cfg.installed]

    def get_missing_tools(self) -> list:
        """Return list of missing tool names."""
        self.check_tools()
        return [name for name, cfg in self.tools.items() if not cfg.installed]


def load_config() -> PrometheusConfig:
    """Load configuration from files and environment."""
    config = PrometheusConfig()

    # Load from config file if exists
    config_file = CONFIG_DIR / "prometheus.json"
    if config_file.exists():
        try:
            with open(config_file) as f:
                data = json.load(f)
            if "primary_model" in data:
                config.primary_model = data["primary_model"]
            if "max_steps" in data:
                config.agent.max_steps = data["max_steps"]
        except (json.JSONDecodeError, KeyError):
            pass

    return config


# Singleton
config = load_config()
