"""Prometheus Configuration — centralized config management.

Includes scan profiles, rate limits, API settings, and report configuration.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"


# ──────────────────────────────────────────────
# Scan Profiles
# ──────────────────────────────────────────────


@dataclass
class ScanProfile:
    """Defines behavior for a scan profile."""
    name: str
    description: str
    rps: float = 10.0           # Requests per second
    max_urls: int = 50          # Max URLs to scan
    crawl_depth: int = 3        # Crawl depth
    timeout_per_url: int = 30   # Seconds per URL
    full_crawl: bool = True     # Whether to crawl first
    scanners: List[str] = field(default_factory=list)  # Empty = all scanners
    stealth: bool = False       # Slow, randomized timing
    aggressive: bool = False    # Fast, noisy


# Built-in scan profiles
SCAN_PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan — top 10 vuln checks only, no deep crawling",
        rps=20.0,
        max_urls=5,
        crawl_depth=1,
        timeout_per_url=10,
        full_crawl=False,
        scanners=["headers", "cors", "secrets"],
    ),
    "full": ScanProfile(
        name="full",
        description="Complete scan — all scanners, full crawl",
        rps=10.0,
        max_urls=50,
        crawl_depth=3,
        timeout_per_url=30,
        full_crawl=True,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Slow, low-noise scan — randomized delays, limited concurrency",
        rps=2.0,
        max_urls=20,
        crawl_depth=2,
        timeout_per_url=60,
        full_crawl=True,
        stealth=True,
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        description="Fast, thorough scan — high concurrency, all payloads",
        rps=25.0,
        max_urls=100,
        crawl_depth=4,
        timeout_per_url=15,
        full_crawl=True,
        aggressive=True,
    ),
    "owasp": ScanProfile(
        name="owasp",
        description="OWASP Testing Guide v4 methodology",
        rps=10.0,
        max_urls=30,
        crawl_depth=3,
        timeout_per_url=30,
        full_crawl=True,
        scanners=["owasp"],
    ),
    "business": ScanProfile(
        name="business",
        description="Business logic vulnerability testing",
        rps=5.0,
        max_urls=20,
        crawl_depth=2,
        timeout_per_url=45,
        full_crawl=True,
        scanners=["business_logic"],
    ),
    "session": ScanProfile(
        name="session",
        description="Session management security testing",
        rps=5.0,
        max_urls=15,
        crawl_depth=2,
        timeout_per_url=30,
        full_crawl=False,
        scanners=["session_manager"],
    ),
    "crypto": ScanProfile(
        name="crypto",
        description="SSL/TLS and cryptographic weakness testing",
        rps=3.0,
        max_urls=10,
        crawl_depth=1,
        timeout_per_url=60,
        full_crawl=False,
        scanners=["crypto"],
    ),
    "api": ScanProfile(
        name="api",
        description="API security testing (REST, GraphQL, JWT)",
        rps=10.0,
        max_urls=50,
        crawl_depth=3,
        timeout_per_url=30,
        full_crawl=True,
        scanners=["api_security"],
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Get a scan profile by name. Falls back to 'full' if not found."""
    return SCAN_PROFILES.get(name, SCAN_PROFILES["full"])


def list_profiles() -> Dict[str, str]:
    """List all available profiles with descriptions."""
    return {name: p.description for name, p in SCAN_PROFILES.items()}


# ──────────────────────────────────────────────
# Tool Configuration
# ──────────────────────────────────────────────


@dataclass
class ToolConfig:
    """Configuration for an external security tool."""
    name: str
    binary: str  # path or command name
    installed: bool = False
    version: str = ""
    fallback: bool = True  # use built-in fallback if not installed


# ──────────────────────────────────────────────
# Rate Limit Settings
# ──────────────────────────────────────────────


@dataclass
class RateLimitConfig:
    """Rate limit configuration per target."""
    default_rps: float = 10.0
    burst: int = 20
    per_host: bool = True
    # Per-target overrides: target_pattern -> rps
    overrides: Dict[str, float] = field(default_factory=dict)

    def get_rps(self, target: str) -> float:
        """Get RPS for a specific target, checking overrides."""
        for pattern, rps in self.overrides.items():
            if pattern in target:
                return rps
        return self.default_rps


# ──────────────────────────────────────────────
# API Server Settings
# ──────────────────────────────────────────────


@dataclass
class APIServerConfig:
    """API server configuration."""
    host: str = "127.0.0.1"
    port: int = 8000
    require_auth: bool = True
    requests_per_minute: int = 60
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    api_keys_file: Optional[str] = None
    persist_scans: bool = True


# ──────────────────────────────────────────────
# Report Settings
# ──────────────────────────────────────────────


@dataclass
class ReportConfig:
    """Report generation settings."""
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "output")
    default_format: str = "markdown"  # markdown, json, html
    include_evidence: bool = True
    include_remediation: bool = True
    include_methodology: bool = True
    max_evidence_length: int = 500
    template_dir: Optional[Path] = None


# ──────────────────────────────────────────────
# Output Settings
# ──────────────────────────────────────────────


@dataclass
class OutputConfig:
    """Output display settings."""
    format: str = "table"  # table, json, markdown
    color: bool = True
    verbose: bool = False
    quiet: bool = False


# ──────────────────────────────────────────────
# Agent Configuration
# ──────────────────────────────────────────────


@dataclass
class AgentConfig:
    """Configuration for the AI agent."""
    max_steps: int = 20
    max_tool_calls: int = 50
    timeout_per_step: int = 120
    auto_confirm: bool = False  # require human confirmation for dangerous ops
    sandbox_mode: bool = True  # run tools in sandboxed mode


# ──────────────────────────────────────────────
# Main Configuration
# ──────────────────────────────────────────────


@dataclass
class PrometheusConfig:
    """Main Prometheus configuration."""
    # Project info
    name: str = "Prometheus"
    version: str = "3.0.0"
    description: str = "AI Security Researcher"

    # LLM
    primary_model: str = "deepseek"
    fast_model: str = "gemini"
    fallback_model: str = "openrouter"

    # Agent
    agent: AgentConfig = field(default_factory=AgentConfig)

    # Scan profiles
    scan_profiles: Dict[str, ScanProfile] = field(
        default_factory=lambda: dict(SCAN_PROFILES)
    )
    default_profile: str = "full"

    # Rate limits
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)

    # API server
    api: APIServerConfig = field(default_factory=APIServerConfig)

    # Reports
    report: ReportConfig = field(default_factory=ReportConfig)

    # Output
    output: OutputConfig = field(default_factory=OutputConfig)

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

    # Legacy output dir (kept for backward compat)
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

    def get_profile(self, name: Optional[str] = None) -> ScanProfile:
        """Get a scan profile by name, or the default."""
        profile_name = name or self.default_profile
        return self.scan_profiles.get(profile_name, SCAN_PROFILES["full"])


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
            if "default_profile" in data:
                config.default_profile = data["default_profile"]
            if "api" in data:
                api_data = data["api"]
                if "host" in api_data:
                    config.api.host = api_data["host"]
                if "port" in api_data:
                    config.api.port = api_data["port"]
                if "require_auth" in api_data:
                    config.api.require_auth = api_data["require_auth"]
                if "requests_per_minute" in api_data:
                    config.api.requests_per_minute = api_data["requests_per_minute"]
            if "rate_limits" in data:
                rl_data = data["rate_limits"]
                if "default_rps" in rl_data:
                    config.rate_limits.default_rps = rl_data["default_rps"]
                if "overrides" in rl_data:
                    config.rate_limits.overrides = rl_data["overrides"]
            if "output" in data:
                out_data = data["output"]
                if "format" in out_data:
                    config.output.format = out_data["format"]
                if "verbose" in out_data:
                    config.output.verbose = out_data["verbose"]
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")

    # Environment variable overrides
    if os.environ.get("PROMETHEUS_API_HOST"):
        config.api.host = os.environ["PROMETHEUS_API_HOST"]
    if os.environ.get("PROMETHEUS_API_PORT"):
        config.api.port = int(os.environ["PROMETHEUS_API_PORT"])
    if os.environ.get("PROMETHEUS_DEFAULT_PROFILE"):
        config.default_profile = os.environ["PROMETHEUS_DEFAULT_PROFILE"]

    return config


# Singleton
config = load_config()
