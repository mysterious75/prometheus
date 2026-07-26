"""Prometheus v3.0 — Test Suite.

Tests for tools, agent, knowledge, and core modules.
All tests run WITHOUT external tools or API keys.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.base import ToolResult


# =========================================================================
# Core — Config
# =========================================================================

class TestConfig:
    def test_config_loads(self):
        from src.core.config import config
        assert config.name == "Prometheus"
        assert config.version == "3.0.0"

    def test_default_tools_registered(self):
        from src.core.config import config
        assert "nuclei" in config.tools
        assert "subfinder" in config.tools
        assert "sqlmap" in config.tools
        assert "sherlock" in config.tools

    def test_check_tools_returns_dict(self):
        from src.core.config import config
        results = config.check_tools()
        assert isinstance(results, dict)
        assert all(isinstance(v, bool) for v in results.values())


# =========================================================================
# Core — Auth
# =========================================================================

class TestAuth:
    @pytest.fixture
    def auth(self, tmp_path):
        from src.core.auth import TargetAuthorization
        from src.core.config import config
        config.authorized_targets_file = tmp_path / "targets.json"
        return TargetAuthorization()

    def test_authorize_adds_target(self, auth):
        result = auth.authorize("example.com")
        assert "authorized" in result.lower()
        assert auth.is_authorized("example.com")

    def test_authorize_normalizes(self, auth):
        auth.authorize("https://Example.COM/path")
        assert auth.is_authorized("example.com")

    def test_revoke_removes_target(self, auth):
        auth.authorize("test.com")
        auth.revoke("test.com")
        assert not auth.is_authorized("test.com")

    def test_list_targets(self, auth):
        auth.authorize("a.com")
        auth.authorize("b.com")
        result = auth.list_targets()
        assert "a.com" in result
        assert "b.com" in result

    def test_empty_list(self, auth):
        result = auth.list_targets()
        assert "No authorized" in result


# =========================================================================
# Tools — Base
# =========================================================================

class TestToolResult:
    def test_summary_success(self):
        from src.tools.base import ToolResult
        r = ToolResult(tool="test", target="x.com", success=True,
                       findings=[{"a": 1}, {"b": 2}], duration=1.5)
        assert "2 findings" in r.summary()

    def test_summary_failure(self):
        from src.tools.base import ToolResult
        r = ToolResult(tool="test", target="x.com", success=False, error="timeout")
        assert "FAILED" in r.summary()

    def test_to_dict(self):
        from src.tools.base import ToolResult
        r = ToolResult(tool="test", target="x.com", success=True)
        d = r.to_dict()
        assert d["tool"] == "test"
        assert d["success"] is True


# =========================================================================
# Tools — Registry
# =========================================================================

class TestToolRegistry:
    def test_all_tools_registered(self):
        from src.tools.registry import registry
        tools = registry.list_tools()
        names = [t["name"] for t in tools]
        assert "nuclei" in names
        assert "subfinder" in names
        assert "httpx" in names
        assert "sqlmap" in names
        assert "sherlock" in names
        assert "nmap" in names

    def test_get_existing_tool(self):
        from src.tools.registry import registry
        tool = registry.get("nuclei")
        assert tool is not None
        assert tool.name == "nuclei"

    def test_get_nonexistent_tool(self):
        from src.tools.registry import registry
        tool = registry.get("nonexistent_tool_xyz")
        assert tool is None

    def test_list_tools_has_all_fields(self):
        from src.tools.registry import registry
        for tool in registry.list_tools():
            assert "name" in tool
            assert "description" in tool
            assert "installed" in tool

    def test_status_string(self):
        from src.tools.registry import registry
        status = registry.status()
        assert "nuclei" in status
        assert "subfinder" in status


# =========================================================================
# Tools — Nuclei (fallback)
# =========================================================================

class TestNucleiFallback:
    def test_fallback_scan_returns_result(self):
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        # Use fallback mode (binary likely not installed)
        result = scanner._fallback_scan("http://httpbin.org")
        assert isinstance(result, ToolResult)
        # If httpx is installed, success=True with findings; otherwise success=False with error
        if result.success:
            assert isinstance(result.findings, list)
        else:
            assert "httpx" in result.error or "not installed" in result.error

    def test_fallback_handles_missing_httpx(self):
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        result = scanner._fallback_scan("http://example.com")
        # Should return a ToolResult, never raise
        assert isinstance(result, ToolResult)


# =========================================================================
# Tools — Sherlock (fallback)
# =========================================================================

class TestSherlockFallback:
    def test_fallback_returns_result(self):
        from src.tools.sherlock import UsernameOSINT
        from src.tools.base import ToolResult
        tool = UsernameOSINT()
        result = tool._fallback_scan("testuser123xyz999")
        assert isinstance(result, ToolResult)
        # If httpx installed, success=True; otherwise handles gracefully
        if not result.success:
            assert "httpx" in result.error or "not installed" in result.error


# =========================================================================
# Tools — Port Scanner (fallback)
# =========================================================================

class TestPortScannerFallback:
    def test_fallback_returns_result(self):
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        result = scanner._fallback_scan("localhost", ports=[80, 443])
        assert result.success is True
        assert isinstance(result.findings, list)

    def test_port_remediation(self):
        from src.tools.portscan import PortScanner
        assert "FTP" in PortScanner._port_remediation(21, "ftp")
        assert "SSH" in PortScanner._port_remediation(22, "ssh")
        assert "HTTPS" in PortScanner._port_remediation(443, "https") or "TLS" in PortScanner._port_remediation(443, "https")


# =========================================================================
# Agent — Working Memory
# =========================================================================

class TestWorkingMemory:
    @pytest.fixture
    def mem(self):
        from src.agent.memory import WorkingMemory
        return WorkingMemory("example.com")

    def test_initial_state(self, mem):
        assert mem.target == "example.com"
        assert len(mem.findings) == 0
        assert len(mem.subdomains) == 0

    def test_add_subdomains(self, mem):
        mem.add_subdomains(["a.example.com", "b.example.com"])
        assert len(mem.subdomains) == 2

    def test_add_subdomains_dedup(self, mem):
        mem.add_subdomains(["a.example.com"])
        mem.add_subdomains(["a.example.com", "b.example.com"])
        assert len(mem.subdomains) == 2

    def test_add_finding(self, mem):
        f = mem.add_finding(
            vuln_type="SQL Injection",
            severity="CRITICAL",
            url="http://example.com/api",
            description="SQLi in id parameter",
        )
        assert f.id == 1
        assert len(mem.findings) == 1
        assert f.severity == "CRITICAL"

    def test_add_note(self, mem):
        mem.add_note("Test note")
        assert len(mem.notes) == 1
        assert "Test note" in mem.notes[0]

    def test_get_context(self, mem):
        mem.add_subdomains(["sub.example.com"])
        mem.add_finding("XSS", "HIGH", "http://example.com", "Reflected XSS")
        context = mem.get_context()
        assert "example.com" in context
        assert "sub.example.com" in context
        assert "XSS" in context

    def test_get_stats(self, mem):
        mem.add_finding("XSS", "HIGH", "http://example.com", "test")
        stats = mem.get_stats()
        assert stats["total_findings"] == 1
        assert stats["target"] == "example.com"

    def test_severity_count(self, mem):
        mem.add_finding("A", "CRITICAL", "url", "desc")
        mem.add_finding("B", "HIGH", "url", "desc")
        mem.add_finding("C", "CRITICAL", "url", "desc")
        stats = mem.get_stats()
        assert stats["findings_by_severity"]["CRITICAL"] == 2
        assert stats["findings_by_severity"]["HIGH"] == 1


# =========================================================================
# Agent — Planner
# =========================================================================

class TestPlanner:
    def test_initial_plan_has_steps(self):
        from src.agent.planner import AttackPlanner
        mock_router = MagicMock()
        planner = AttackPlanner(mock_router)
        steps = planner.plan_initial("example.com")
        assert len(steps) >= 3
        tools = [s.tool for s in steps]
        assert "subfinder" in tools
        assert "nuclei" in tools

    def test_parse_step(self):
        from src.agent.planner import AttackPlanner
        mock_router = MagicMock()
        planner = AttackPlanner(mock_router)
        response = """TOOL: nuclei
TARGET: http://example.com
ARGS: severity=critical
REASONING: Check for critical vulns
PRIORITY: 1"""
        step = planner._parse_step(response, "example.com")
        assert step is not None
        assert step.tool == "nuclei"
        assert step.target == "http://example.com"
        assert step.args.get("severity") == "critical"

    def test_parse_done(self):
        from src.agent.planner import AttackPlanner
        mock_router = MagicMock()
        planner = AttackPlanner(mock_router)
        step = planner._parse_step("DONE", "example.com")
        assert step is None


# =========================================================================
# Knowledge
# =========================================================================

class TestKnowledge:
    def test_load_returns_count(self):
        from src.knowledge.index import KnowledgeIndex
        kb = KnowledgeIndex()
        count = kb.load()
        assert isinstance(count, int)

    def test_search_returns_list(self):
        from src.knowledge.index import KnowledgeIndex
        kb = KnowledgeIndex()
        results = kb.search("sql injection")
        assert isinstance(results, list)

    def test_get_playbook_structure(self):
        from src.knowledge.index import KnowledgeIndex
        kb = KnowledgeIndex()
        playbook = kb.get_playbook("XSS")
        assert "vuln_type" in playbook
        assert "found" in playbook

    def test_stats_structure(self):
        from src.knowledge.index import KnowledgeIndex
        kb = KnowledgeIndex()
        stats = kb.get_stats()
        assert "total_entries" in stats
        assert "vuln_types" in stats


# =========================================================================
# Chain Builder
# =========================================================================

class TestChainBuilder:
    def test_pattern_chains(self):
        from src.agent.chain import ChainBuilder
        from src.agent.memory import WorkingMemory, Finding
        mock_router = MagicMock()
        builder = ChainBuilder(mock_router)

        mem = WorkingMemory("example.com")
        mem.add_finding("Cross-Site Scripting", "HIGH", "http://example.com", "XSS")
        mem.add_finding("CSRF", "MEDIUM", "http://example.com", "No CSRF token")

        chains = builder._pattern_chains(mem.findings)
        assert len(chains) >= 1
        assert any("XSS" in c.name or "CSRF" in c.name for c in chains)

    def test_no_chains_single_finding(self):
        from src.agent.chain import ChainBuilder
        from src.agent.memory import WorkingMemory
        mock_router = MagicMock()
        builder = ChainBuilder(mock_router)

        mem = WorkingMemory("example.com")
        mem.add_finding("Info Disclosure", "LOW", "http://example.com", "test")

        chains = builder._pattern_chains(mem.findings)
        assert len(chains) == 0
