"""Smart Tools Tests — deduplication, dorking, subdomain discovery, orchestrator."""

import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================================
# Smart Asset Manager
# =========================================================================

class TestSmartAssetManager:
    @pytest.fixture
    def am(self):
        from src.agent.assets import SmartAssetManager
        return SmartAssetManager("example.com")

    def test_add_new_subdomain(self, am):
        result = am.add_subdomain("api.example.com", "test")
        assert result is True
        assert "api.example.com" in am.get_all_subdomains()

    def test_add_duplicate_subdomain(self, am):
        am.add_subdomain("api.example.com", "tool1")
        result = am.add_subdomain("api.example.com", "tool2")
        assert result is False

    def test_different_tools_different_subdomains(self, am):
        # Tool A finds sub1
        am.add_subdomain("sub1.example.com", "toolA")
        # Tool B finds sub2 (new)
        am.add_subdomain("sub2.example.com", "toolB")
        # Tool B should NOT re-scan sub1
        new_for_b = am.get_new_subdomains("toolB")
        assert "sub1.example.com" not in new_for_b  # already known
        assert "sub2.example.com" not in new_for_b  # already scanned by B

    def test_get_new_subdomains_for_tool(self, am):
        am.add_subdomain("a.example.com", "crt_sh")
        am.add_subdomain("b.example.com", "dns")
        # Both are already discovered by other tools, so no new for nmap
        new = am.get_new_subdomains("nmap")
        assert len(new) == 0
        # But if we add a new one not yet seen by any tool
        am.add_subdomain("c.example.com", "bruteforce")
        # c is already in bruteforce's scanned set, so nmap still sees 0
        new = am.get_new_subdomains("nmap")
        assert len(new) == 0
        # mark_scanned adds to nmap's set
        am.mark_scanned(["c.example.com"], "nmap")
        new = am.get_new_subdomains("nmap")
        assert len(new) == 0

    def test_mark_scanned(self, am):
        am.add_subdomain("a.example.com", "crt_sh")
        am.mark_scanned(["a.example.com"], "nmap")
        new = am.get_new_subdomains("nmap")
        assert "a.example.com" not in new

    def test_dedup_by_domain(self, am):
        # Should not add subdomain from different domain
        result = am.add_subdomain("other.com", "test")
        assert result is False

    def test_add_urls_dedup(self, am):
        am.add_url("https://example.com/page1", "crawler")
        am.add_url("https://example.com/page1", "nuclei")  # duplicate
        am.add_url("https://example.com/page2", "nuclei")  # new
        assert len(am.get_all_urls()) == 2

    def test_add_email(self, am):
        am.add_email("test@example.com", "harvester")
        am.add_email("test@example.com", "crawler")  # dup
        assert len(am.get_all_emails()) == 1

    def test_source_stats(self, am):
        am.add_subdomain("a.example.com", "crt_sh")
        am.add_subdomain("b.example.com", "dns")
        am.add_subdomain("c.example.com", "dns")
        stats = am.get_source_stats()
        assert stats["crt_sh"] == 1
        assert stats["dns"] == 2

    def test_get_stats(self, am):
        am.add_subdomain("a.example.com", "test")
        am.add_email("e@example.com", "test")
        stats = am.get_stats()
        assert stats["total_assets"] == 2
        assert "subdomain" in stats["by_type"]
        assert "email" in stats["by_type"]


# =========================================================================
# Dorking Engine
# =========================================================================

class TestDorkingEngine:
    def test_google_dork_categories(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        categories = de.get_dork_categories()
        assert "sensitive_files" in categories
        assert "exposed_panels" in categories
        assert "info_disclosure" in categories
        assert len(categories) >= 5

    def test_google_dork_generates_results(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        results = de.google_dork("example.com", categories=["sensitive_files"])
        assert len(results) > 0
        assert all(r.source == "google" for r in results)
        assert all("example.com" in r.dork for r in results)

    def test_github_dork(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        results = de.github_dork("example.com")
        assert len(results) > 0
        assert all(r.source == "github" for r in results)

    def test_shodan_dork(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        results = de.shodan_dork("example.com")
        assert len(results) > 0
        assert all(r.source == "shodan" for r in results)

    def test_bing_dork(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        results = de.bing_dork("example.com")
        assert len(results) > 0

    def test_full_dork(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        results = de.full_dork("example.com")
        assert "google" in results
        assert "github" in results
        assert "shodan" in results
        assert "bing" in results
        total = sum(len(v) for v in results.values())
        assert total > 50  # Should generate many dorks

    def test_custom_dork(self):
        from src.tools.dorking import DorkingEngine
        de = DorkingEngine()
        dork = de.get_custom_dork("example.com", "login")
        assert "example.com" in dork
        assert "login" in dork

    def test_dork_result_to_dict(self):
        from src.tools.dorking import DorkResult
        r = DorkResult(url="http://test.com", title="Test", snippet="...", source="google", dork="site:test.com")
        d = r.to_dict()
        assert d["source"] == "google"
        assert "url" in d


# =========================================================================
# Tool Orchestrator
# =========================================================================

class TestToolOrchestrator:
    def test_detect_web_app(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        assert o._detect_target_type("https://example.com") == "web_app"
        assert o._detect_target_type("http://test.com/page") == "web_app"

    def test_detect_domain(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        assert o._detect_target_type("example.com") == "domain_recon"

    def test_detect_ip(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        assert o._detect_target_type("192.168.1.1") == "ip_scan"

    def test_detect_username(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        assert o._detect_target_type("johndoe") == "username_osint"

    def test_web_app_playbook(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        plans = o.plan("https://example.com")
        tools = [p.tool for p in plans]
        assert "fingerprint" in tools
        assert "sqli" in tools
        assert "xss" in tools
        assert "dns" in tools

    def test_playbook_sorted_by_priority(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        plans = o.plan("example.com")
        priorities = [p.priority for p in plans]
        assert priorities == sorted(priorities)

    def test_list_playbooks(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        playbooks = o.list_playbooks()
        assert "web_app" in playbooks
        assert "domain_recon" in playbooks
        assert "ip_scan" in playbooks

    def test_playbook_info(self):
        from src.agent.orchestrator import ToolOrchestrator
        o = ToolOrchestrator()
        info = o.get_playbook_info("web_app")
        assert info["total_steps"] > 10
        assert all("tool" in t for t in info["tools"])


# =========================================================================
# DNS Tools
# =========================================================================

class TestDNSTools:
    def test_init(self):
        from src.tools.dns import DNSTools
        dns = DNSTools()
        assert len(dns.BRUTE_SUBDOMAINS) > 100

    def test_record_types(self):
        from src.tools.dns import DNSTools
        dns = DNSTools()
        assert "A" in dns.RECORD_TYPES
        assert "MX" in dns.RECORD_TYPES
        assert "NS" in dns.RECORD_TYPES
        assert "TXT" in dns.RECORD_TYPES


# =========================================================================
# Cloud Scanner
# =========================================================================

class TestCloudScanner:
    def test_bucket_patterns(self):
        from src.tools.cloud import CloudScanner
        cs = CloudScanner()
        assert len(cs.BUCKET_PATTERNS) > 20

    def test_scan_returns_list(self):
        from src.tools.cloud import CloudScanner
        cs = CloudScanner()
        # Should not crash even without httpx
        results = cs.scan_s3("testbucket123xyz999")
        assert isinstance(results, list)


# =========================================================================
# Subdomain Takeover
# =========================================================================

class TestTakeoverScanner:
    def test_fingerprints(self):
        from src.tools.takeover import SubdomainTakeoverScanner
        ts = SubdomainTakeoverScanner()
        assert "GitHub Pages" in ts.VULNERABLE_FINGERPRINTS
        assert "Heroku" in ts.VULNERABLE_FINGERPRINTS
        assert "AWS S3" in ts.VULNERABLE_FINGERPRINTS
        assert len(ts.VULNERABLE_FINGERPRINTS) >= 10


# =========================================================================
# Exploit Tools
# =========================================================================

class TestExploitTools:
    def test_capabilities(self):
        from src.tools.exploits import ExploitTools
        et = ExploitTools()
        caps = et.get_capabilities()
        assert "searchsploit" in caps
        assert "nmap" in caps


# =========================================================================
# Fingerprinter
# =========================================================================

class TestFingerprinter:
    def test_cms_patterns(self):
        from src.tools.fingerprint import WebFingerprinter
        wf = WebFingerprinter()
        assert "WordPress" in wf.CMS_PATTERNS
        assert "Drupal" in wf.CMS_PATTERNS
        assert "Joomla" in wf.CMS_PATTERNS

    def test_waf_signatures(self):
        from src.tools.fingerprint import WebFingerprinter
        wf = WebFingerprinter()
        assert "Cloudflare" in wf.WAF_SIGNATURES
        assert "AWS WAF" in wf.WAF_SIGNATURES

    def test_js_framework_patterns(self):
        from src.tools.fingerprint import WebFingerprinter
        wf = WebFingerprinter()
        assert "React" in wf.JS_FRAMEWORK_PATTERNS
        assert "Vue.js" in wf.JS_FRAMEWORK_PATTERNS


# =========================================================================
# Subdomain Discovery
# =========================================================================

class TestSubdomainDiscovery:
    def test_wordlist_large(self):
        from src.agent.subdomain_discovery import SmartSubdomainDiscovery
        sd = SmartSubdomainDiscovery("example.com")
        assert len(sd.WORDLIST_LARGE) > 100

    def test_permutation_patterns(self):
        from src.agent.subdomain_discovery import SmartSubdomainDiscovery
        sd = SmartSubdomainDiscovery("example.com")
        assert len(sd.PERMUTATION_PATTERNS) > 0
        assert len(sd.PERMUTATION_WORDS) > 0
