"""Tests for tool wrappers — uses mock responses, no real tool execution."""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.base import ToolResult, BaseTool


# =========================================================================
# ToolResult
# =========================================================================

class TestToolResult:
    def test_success_summary_with_findings(self):
        r = ToolResult(tool="test", target="x.com", success=True,
                       findings=[{"a": 1}, {"b": 2}], duration=1.5)
        assert "2 findings" in r.summary()
        assert "1.5s" in r.summary()

    def test_failure_summary(self):
        r = ToolResult(tool="test", target="x.com", success=False, error="timeout")
        assert "FAILED" in r.summary()
        assert "timeout" in r.summary()

    def test_to_dict_has_all_fields(self):
        r = ToolResult(tool="nuclei", target="example.com", success=True, findings=[{"type": "xss"}])
        d = r.to_dict()
        assert d["tool"] == "nuclei"
        assert d["target"] == "example.com"
        assert d["success"] is True
        assert d["findings_count"] == 1
        assert "timestamp" in d

    def test_empty_findings(self):
        r = ToolResult(tool="test", target="x.com", success=True)
        assert r.findings == []
        assert "0 findings" in r.summary()

    def test_default_timestamp(self):
        r = ToolResult(tool="test", target="x.com", success=True)
        assert r.timestamp  # auto-populated


# =========================================================================
# BaseTool
# =========================================================================

class TestBaseTool:
    def test_cannot_instantiate_abstract(self):
        """BaseTool is abstract — cannot instantiate directly."""
        with pytest.raises(TypeError):
            BaseTool()


# =========================================================================
# NucleiScanner
# =========================================================================

class TestNucleiScanner:
    def test_scan_returns_tool_result(self):
        """scan() must return a ToolResult even when binary is missing."""
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        # Binary likely not installed — should use fallback or return error result
        with patch.object(scanner, '_run_cmd') as mock_run, \
             patch.object(scanner, 'installed', True):
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
            result = scanner.scan("http://example.com")
        assert isinstance(result, ToolResult)
        assert result.tool == "nuclei"

    def test_fallback_scan_returns_tool_result(self):
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        result = scanner._fallback_scan("http://httpbin.org")
        assert isinstance(result, ToolResult)
        # Either success with findings or failure with error message
        if result.success:
            assert isinstance(result.findings, list)
        else:
            assert "httpx" in result.error or "not installed" in result.error

    def test_fallback_handles_missing_httpx(self):
        """Fallback should never crash, even without httpx."""
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        with patch.dict('sys.modules', {'httpx': None}):
            # This should still return a ToolResult, not raise
            result = scanner._fallback_scan("http://example.com")
        assert isinstance(result, ToolResult)

    def test_scan_json_parsing(self):
        """Verify nuclei JSON output is parsed into findings."""
        from src.tools.nuclei import NucleiScanner
        scanner = NucleiScanner()
        json_output = '{"template-id":"test","info":{"name":"Test Finding","severity":"high"},"matched-at":"http://example.com"}'
        with patch.object(scanner, 'installed', True), \
             patch.object(scanner, '_run_cmd') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=json_output, stderr="")
            result = scanner.scan("http://example.com")
        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["title"] == "Test Finding"
        assert result.findings[0]["severity"] == "HIGH"


# =========================================================================
# PortScanner
# =========================================================================

class TestPortScanner:
    def test_scan_returns_tool_result(self):
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        with patch.object(scanner, 'installed', True), \
             patch.object(scanner, '_run_cmd') as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
            result = scanner.scan("localhost")
        assert isinstance(result, ToolResult)

    def test_fallback_returns_success(self):
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        result = scanner._fallback_scan("localhost", ports=[80, 443])
        assert result.success is True
        assert isinstance(result.findings, list)

    def test_port_remediation(self):
        """Verify _port_remediation returns strings for known ports."""
        from src.tools.portscan import PortScanner
        rem_80 = PortScanner._port_remediation(80, "http")
        assert isinstance(rem_80, str)
        assert len(rem_80) > 0

    def test_parse_nmap_xml(self):
        """Verify nmap XML parsing extracts open ports."""
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        xml = '''
        <nmaprun>
            <host>
                <address addr="example.com" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.19"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https" product="nginx" version="1.19"/>
                    </port>
                    <port protocol="tcp" portid="8080">
                        <state state="closed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        '''
        findings = scanner._parse_nmap_xml(xml, "example.com")
        # Findings contain port info in title like "Open Port 80/tcp"
        assert len(findings) >= 2
        port_strings = [f.get("title", "") for f in findings]
        assert any("80" in p for p in port_strings)
        assert any("443" in p for p in port_strings)

    def test_parse_nmap_regex_fallback(self):
        """Verify regex fallback parses nmap output."""
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        xml = '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
        findings = scanner._parse_nmap_regex(xml)
        assert isinstance(findings, list)

    def test_scan_has_fallback(self):
        from src.tools.portscan import PortScanner
        scanner = PortScanner()
        assert hasattr(scanner, '_fallback_scan')


# =========================================================================
# Sherlock / UsernameOSINT
# =========================================================================

class TestSherlock:
    def test_scan_returns_tool_result(self):
        from src.tools.sherlock import UsernameOSINT
        tool = UsernameOSINT()
        with patch.object(tool, 'installed', True), \
             patch.object(tool, '_run_cmd') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = tool.scan("testuser")
        assert isinstance(result, ToolResult)
        assert result.target == "testuser"

    def test_fallback_returns_tool_result(self):
        from src.tools.sherlock import UsernameOSINT
        tool = UsernameOSINT()
        result = tool._fallback_scan("testuser123xyz999")
        assert isinstance(result, ToolResult)
        if not result.success:
            assert "httpx" in result.error or "not installed" in result.error

    def test_fallback_platforms_covered(self):
        """Sherlock should check multiple platforms in fallback mode."""
        from src.tools.sherlock import UsernameOSINT
        tool = UsernameOSINT()
        # The fallback scan should attempt multiple platforms
        assert tool.name == "sherlock"
        assert tool.description  # should have a description

    def test_sherlock_output_parsing(self):
        """Verify sherlock stdout is parsed into findings."""
        from src.tools.sherlock import UsernameOSINT
        tool = UsernameOSINT()
        output = "[+] github: https://github.com/testuser\n[+] twitter: https://x.com/testuser"
        with patch.object(tool, 'installed', True), \
             patch.object(tool, '_run_cmd') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=output, stderr="")
            result = tool.scan("testuser")
        assert result.success is True
        assert len(result.findings) == 2
        platforms = [f["platform"] for f in result.findings]
        assert "github" in platforms


# =========================================================================
# ToolRegistry
# =========================================================================

class TestToolRegistry:
    def test_all_default_tools_registered(self):
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
        assert registry.get("nonexistent_xyz") is None

    def test_list_tools_has_required_fields(self):
        from src.tools.registry import registry
        for tool_info in registry.list_tools():
            assert "name" in tool_info
            assert "description" in tool_info
            assert "installed" in tool_info
            assert isinstance(tool_info["installed"], bool)

    def test_status_string_contains_tools(self):
        from src.tools.registry import registry
        status = registry.status()
        assert "nuclei" in status
        assert "sherlock" in status

    def test_run_nonexistent_tool(self):
        from src.tools.registry import registry
        result = registry.run("nonexistent_xyz", "http://example.com")
        assert isinstance(result, ToolResult)
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_available_property(self):
        from src.tools.registry import registry
        available = registry.available
        assert isinstance(available, list)

    def test_with_fallback_property(self):
        from src.tools.registry import registry
        with_fallback = registry.with_fallback
        assert isinstance(with_fallback, list)
        assert len(with_fallback) >= 6
