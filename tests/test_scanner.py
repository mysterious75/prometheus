"""Scanner Tests — tests for all vulnerability scanners.

All tests use mock responses — no real HTTP calls.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================================
# Finding & ScanResult
# =========================================================================

class TestFinding:
    def test_finding_creation(self):
        from src.scanner.findings import Finding
        f = Finding(
            vuln_type="SQL Injection",
            title="SQLi in id param",
            severity="CRITICAL",
            url="http://example.com/api",
            evidence="SQL syntax error",
        )
        assert f.vuln_type == "SQL Injection"
        assert f.severity == "CRITICAL"
        assert f.evidence == "SQL syntax error"

    def test_finding_to_dict(self):
        from src.scanner.findings import Finding
        f = Finding(vuln_type="XSS", severity="HIGH", url="http://test.com")
        d = f.to_dict()
        assert d["vuln_type"] == "XSS"
        assert d["severity"] == "HIGH"

    def test_finding_poc_command(self):
        from src.scanner.findings import Finding
        f = Finding(url="http://example.com/api?id=1", method="GET")
        poc = f.poc_command()
        assert "curl" in poc
        assert "http://example.com/api?id=1" in poc

    def test_finding_poc_post(self):
        from src.scanner.findings import Finding
        f = Finding(url="http://example.com/login", method="POST", payload="user=admin")
        poc = f.poc_command()
        assert "-X POST" in poc


class TestScanResult:
    def test_add_finding(self):
        from src.scanner.findings import ScanResult, Finding
        result = ScanResult(target="http://example.com")
        f1 = Finding(vuln_type="XSS", severity="HIGH", url="http://example.com", parameter="q", payload="<script>")
        f2 = Finding(vuln_type="SQLi", severity="CRITICAL", url="http://example.com", parameter="id", payload="' OR 1=1")
        result.add(f1)
        result.add(f2)
        assert len(result.findings) == 2
        assert result.findings[0].finding_id == 1
        assert result.findings[1].finding_id == 2

    def test_severity_filters(self):
        from src.scanner.findings import ScanResult, Finding
        result = ScanResult(target="http://example.com")
        result.add(Finding(severity="CRITICAL", url="http://example.com/a", vuln_type="SQLi"))
        result.add(Finding(severity="HIGH", url="http://example.com/b", vuln_type="XSS"))
        result.add(Finding(severity="HIGH", url="http://example.com/c", vuln_type="XSS"))
        result.add(Finding(severity="MEDIUM", url="http://example.com/d", vuln_type="INFO"))
        result.add(Finding(severity="LOW", url="http://example.com/e", vuln_type="INFO"))
        assert len(result.critical) == 1
        assert len(result.high) == 2
        assert len(result.medium) == 1
        assert len(result.low) == 1

    def test_summary(self):
        from src.scanner.findings import ScanResult, Finding
        result = ScanResult(target="http://example.com", duration=10.5)
        result.add(Finding(severity="CRITICAL", url="http://example.com/a", vuln_type="SQLi"))
        result.add(Finding(severity="HIGH", url="http://example.com/b", vuln_type="XSS"))
        s = result.summary()
        assert s["total"] == 2
        assert s["critical"] == 1
        assert s["high"] == 1
        assert s["duration"] == "10.5s"


# =========================================================================
# Crawler
# =========================================================================

class TestCrawler:
    def test_crawler_init(self):
        from src.scanner.crawler import WebCrawler
        c = WebCrawler(max_depth=2, max_urls=50)
        assert c.max_depth == 2
        assert c.max_urls == 50

    def test_extract_links(self):
        from src.scanner.crawler import WebCrawler
        c = WebCrawler()
        html = '''
        <a href="/page1">Link 1</a>
        <a href="https://example.com/page2">Link 2</a>
        <a href="https://other.com/page3">External</a>
        <a href="#fragment">Fragment</a>
        <a href="mailto:test@test.com">Email</a>
        '''
        links = c._extract_links(html, "https://example.com", "example.com")
        assert "https://example.com/page1" in links
        assert "https://example.com/page2" in links
        assert not any("other.com" in l for l in links)
        assert not any("mailto" in l for l in links)

    def test_extract_forms(self):
        from src.scanner.crawler import WebCrawler
        c = WebCrawler()
        html = '''
        <form action="/login" method="POST">
            <input name="username" type="text" value="">
            <input name="password" type="password" value="">
            <input type="submit" value="Login">
        </form>
        '''
        forms = c._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert forms[0].method == "POST"
        assert len(forms[0].inputs) == 2  # username + password (submit has no name)
        assert forms[0].inputs[0].name == "username"

    def test_crawl_result_structure(self):
        from src.scanner.crawler import CrawlResult
        r = CrawlResult(target="http://example.com")
        r.urls.append("http://example.com/page1")
        r.emails.append("test@example.com")
        d = r.to_dict()
        assert d["urls_count"] == 1
        assert d["emails"] == ["test@example.com"]


# =========================================================================
# Rate Limiter
# =========================================================================

class TestRateLimiter:
    def test_limiter_allows_first_request(self):
        from src.core.ratelimit import RateLimiter
        limiter = RateLimiter(requests_per_second=100)
        wait = limiter.acquire("test.com")
        assert wait == 0.0

    def test_limiter_tracks_tokens(self):
        from src.core.ratelimit import RateLimiter
        limiter = RateLimiter(requests_per_second=100, burst=5)
        for _ in range(5):
            limiter.acquire("test.com")
        # 6th request should have to wait
        wait = limiter.acquire("test.com")
        assert wait > 0.0

    def test_per_host_isolation(self):
        from src.core.ratelimit import RateLimiter
        limiter = RateLimiter(requests_per_second=100, burst=1)
        limiter.acquire("host1.com")
        # Different host should not be affected
        wait = limiter.acquire("host2.com")
        assert wait == 0.0


# =========================================================================
# Report Generator
# =========================================================================

class TestReportGenerator:
    def test_markdown_report(self):
        from src.scanner.report import ReportGenerator
        from src.scanner.findings import ScanResult, Finding
        gen = ReportGenerator()
        result = ScanResult(target="http://example.com", duration=5.0)
        result.add(Finding(
            vuln_type="SQL Injection", title="SQLi in id", severity="CRITICAL",
            url="http://example.com/api", evidence="SQL error", payload="'",
            remediation="Use parameterized queries", cvss=9.8, cwe="CWE-89",
        ))
        md = gen.generate_markdown(result)
        assert "# 🔒 Security Assessment Report" in md
        assert "SQL Injection" in md
        assert "CRITICAL" in md
        assert "parameterized queries" in md

    def test_empty_report(self):
        from src.scanner.report import ReportGenerator
        from src.scanner.findings import ScanResult
        gen = ReportGenerator()
        result = ScanResult(target="http://example.com")
        md = gen.generate_markdown(result)
        assert "No vulnerabilities found" in md

    def test_json_report(self):
        from src.scanner.report import ReportGenerator
        from src.scanner.findings import ScanResult, Finding
        import json
        gen = ReportGenerator()
        result = ScanResult(target="http://example.com")
        result.add(Finding(vuln_type="XSS", severity="HIGH"))
        j = gen.generate_json(result)
        data = json.loads(j)
        assert data["target"] == "http://example.com"
        assert len(data["findings"]) == 1


# =========================================================================
# SQLi Scanner
# =========================================================================

class TestSQLiScanner:
    def test_scanner_init(self):
        from src.scanner.sqli import SQLiScanner
        s = SQLiScanner()
        assert s.NAME == "sqli"

    def test_validate_sql_error_real(self):
        from src.scanner.sqli import SQLiScanner
        s = SQLiScanner()
        body = "You have an error in your SQL syntax; check the manual..."
        assert s._validate_sql_error(body, "SQL syntax", "SQL syntax") is True

    def test_validate_sql_error_false_positive(self):
        from src.scanner.sqli import SQLiScanner
        s = SQLiScanner()
        body = "This tutorial explains SQL syntax errors and how to fix them..."
        assert s._validate_sql_error(body, "SQL syntax", "SQL syntax") is False

    def test_build_url(self):
        from src.scanner.sqli import SQLiScanner
        s = SQLiScanner()
        url = s._build_url("http://example.com/api", {"id": "1", "name": "test"})
        assert "id=1" in url
        assert "name=test" in url


# =========================================================================
# XSS Scanner
# =========================================================================

class TestXSSScanner:
    def test_scanner_init(self):
        from src.scanner.xss import XSSScanner
        s = XSSScanner()
        assert s.NAME == "xss"

    def test_is_executable_context_html(self):
        from src.scanner.xss import XSSScanner
        s = XSSScanner()
        body = '<html><body><script>alert(1)</script></body></html>'
        assert s._is_executable_context(body, "<script>alert(1)</script>", "HTML", body.find("<script>")) is True

    def test_is_executable_context_comment(self):
        from src.scanner.xss import XSSScanner
        s = XSSScanner()
        body = '<html><!-- <script>alert(1)</script> --></html>'
        assert s._is_executable_context(body, "<script>alert(1)</script>", "HTML", body.find("<script>")) is False


# =========================================================================
# Secrets Scanner
# =========================================================================

class TestSecretsScanner:
    def test_find_aws_key(self):
        from src.scanner.secrets import SecretsScanner
        s = SecretsScanner()
        content = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        secrets = s._find_secrets(content)
        assert len(secrets) >= 1
        assert any("AWS" in t for t, v in secrets)

    def test_find_github_token(self):
        from src.scanner.secrets import SecretsScanner
        s = SecretsScanner()
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        secrets = s._find_secrets(content)
        assert len(secrets) >= 1

    def test_find_private_key(self):
        from src.scanner.secrets import SecretsScanner
        s = SecretsScanner()
        content = "some config with key: -----BEGIN RSA PRIVATE KEY----- and more content"
        secrets = s._find_secrets(content)
        assert len(secrets) >= 1
        assert any("Private Key" in t for t, v in secrets)

    def test_no_false_positives(self):
        from src.scanner.secrets import SecretsScanner
        s = SecretsScanner()
        content = 'This is a normal page with no secrets.'
        secrets = s._find_secrets(content)
        assert len(secrets) == 0


# =========================================================================
# Headers Scanner
# =========================================================================

class TestHeadersScanner:
    def test_scanner_init(self):
        from src.scanner.headers import HeadersScanner
        s = HeadersScanner()
        assert s.NAME == "headers"


# =========================================================================
# CORS Scanner
# =========================================================================

class TestCORSScanner:
    def test_scanner_init(self):
        from src.scanner.cors import CORSScanner
        s = CORSScanner()
        assert s.NAME == "cors"


# =========================================================================
# All Scanners Init
# =========================================================================

class TestAllScanners:
    def test_all_scanners_have_name(self):
        from src.scanner.sqli import SQLiScanner
        from src.scanner.xss import XSSScanner
        from src.scanner.ssrf import SSRFScanner
        from src.scanner.cmdi import CMDiScanner
        from src.scanner.idor import IDORScanner
        from src.scanner.secrets import SecretsScanner
        from src.scanner.headers import HeadersScanner
        from src.scanner.cors import CORSScanner
        from src.scanner.redirect import RedirectScanner
        from src.scanner.traversal import TraversalScanner
        from src.scanner.ssti import SSTIScanner
        from src.scanner.xxe import XXEScanner
        from src.scanner.smuggling import SmugglingScanner
        from src.scanner.race import RaceConditionScanner
        from src.scanner.auth import AuthBypassScanner

        scanners = [
            SQLiScanner(), XSSScanner(), SSRFScanner(), CMDiScanner(),
            IDORScanner(), SecretsScanner(), HeadersScanner(), CORSScanner(),
            RedirectScanner(), TraversalScanner(), SSTIScanner(), XXEScanner(),
            SmugglingScanner(), RaceConditionScanner(), AuthBypassScanner(),
        ]
        for s in scanners:
            assert hasattr(s, 'NAME'), f"{s.__class__} missing NAME"
            assert hasattr(s, 'scan_url'), f"{s.__class__} missing scan_url"


# =========================================================================
# Scan Runner
# =========================================================================

class TestScanRunner:
    def test_runner_init(self):
        from src.scanner.runner import ScanRunner
        r = ScanRunner()
        assert len(r.scanners) >= 10

    def test_runner_has_crawler(self):
        from src.scanner.runner import ScanRunner
        r = ScanRunner()
        assert r.crawler is not None
