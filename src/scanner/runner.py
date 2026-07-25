"""Scan Runner — orchestrates all scanners against a target.

Runs crawlers first to discover attack surface, then runs all
vulnerability scanners against discovered endpoints.
"""

import time
from typing import List, Dict, Any, Optional

from .crawler import WebCrawler, CrawlResult
from .findings import Finding, ScanResult
from .sqli import SQLiScanner
from .xss import XSSScanner
from .ssrf import SSRFScanner
from .cmdi import CMDiScanner
from .idor import IDORScanner
from .secrets import SecretsScanner
from .headers import HeadersScanner
from .cors import CORSScanner
from .redirect import RedirectScanner
from .traversal import TraversalScanner
from .ssti import SSTIScanner
from .xxe import XXEScanner
from .smuggling import SmugglingScanner
from .race import RaceConditionScanner
from .auth import AuthBypassScanner
from ..core.logger import console, log_finding
from ..core.ratelimit import get_limiter


class ScanRunner:
    """Orchestrates a full security scan against a target.

    Workflow:
    1. Crawl target to discover attack surface
    2. Run all scanners against discovered endpoints
    3. Aggregate and deduplicate findings
    4. Return verified findings only
    """

    def __init__(self, rps: float = 10.0):
        self.rps = rps
        self.crawler = WebCrawler(rps=rps)
        self.scanners = [
            HeadersScanner(),
            CORSScanner(),
            SecretsScanner(rps=rps),
            AuthBypassScanner(rps=rps),
            SQLiScanner(rps=rps),
            XSSScanner(rps=rps),
            SSRFScanner(rps=rps),
            CMDiScanner(rps=rps),
            IDORScanner(rps=rps),
            RedirectScanner(rps=rps),
            TraversalScanner(rps=rps),
            SSTIScanner(rps=rps),
            XXEScanner(rps=rps),
            SmugglingScanner(rps=rps),
            RaceConditionScanner(),
        ]

    def scan(self, target: str, full: bool = True) -> ScanResult:
        """Run a full security scan.

        Args:
            target: URL or domain to scan
            full: If True, crawl first and test all endpoints.
                  If False, only test the given URL.
        """
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        result = ScanResult(target=target)
        start = time.time()

        console.print(f"\n[bold blue]═══ Security Scan: {target} ═══[/bold blue]")

        # Phase 1: Crawl (if full scan)
        crawl_result = None
        if full:
            console.print("\n[bold]Phase 1: Crawling target...[/bold]")
            crawl_result = self.crawler.crawl(target)
            result.crawl = crawl_result
            console.print(
                f"  Found: {len(crawl_result.urls)} URLs, "
                f"{len(crawl_result.forms)} forms, "
                f"{len(crawl_result.endpoints)} endpoints, "
                f"{len(crawl_result.js_files)} JS files, "
                f"{len(crawl_result.api_endpoints)} API endpoints"
            )

            # Add emails and tech
            for email in crawl_result.emails:
                result.add(Finding(
                    vuln_type="Information Disclosure",
                    title=f"Email address found: {email}",
                    severity="INFO",
                    url=target,
                    evidence=email,
                    description="Email address found in page content.",
                    tool="crawler",
                    verified=True,
                    confidence="CONFIRMED",
                ))

        # Phase 2: Scan base URL + discovered endpoints
        console.print("\n[bold]Phase 2: Vulnerability scanning...[/bold]")

        # Always scan the base URL
        urls_to_scan = [target]

        # Add discovered endpoints with parameters
        if crawl_result:
            for endpoint in crawl_result.endpoints:
                if endpoint.params and endpoint.url not in urls_to_scan:
                    urls_to_scan.append(endpoint.url)

        # Run all scanners
        for scanner in self.scanners:
            scanner_name = scanner.NAME if hasattr(scanner, 'NAME') else scanner.__class__.__name__
            console.print(f"  [tool]▸ {scanner_name}[/tool]")

            for url in urls_to_scan[:10]:  # Limit to avoid excessive scanning
                try:
                    findings = scanner.scan_url(url)
                    for f in findings:
                        result.add(f)
                        log_finding(f.severity, f.vuln_type, f.url, f.title)
                except Exception as e:
                    console.print(f"    [error]✗ {scanner_name} error: {e}[/error]")

            # Also scan forms specifically for injection scanners
            if crawl_result and hasattr(scanner, 'scan_url'):
                for form in crawl_result.forms[:5]:
                    if form.inputs:
                        params = {inp["name"]: inp.get("value", "test") for inp in form.inputs if inp.get("name")}
                        try:
                            findings = scanner.scan_url(form.action, params=params)
                            for f in findings:
                                result.add(f)
                                log_finding(f.severity, f.vuln_type, f.url, f.title)
                        except Exception:
                            pass

        result.duration = time.time() - start

        # Summary
        summary = result.summary()
        console.print(f"\n[bold blue]═══ Scan Complete ═══[/bold blue]")
        console.print(f"  Duration: {summary['duration']}")
        console.print(f"  Total findings: {summary['total']}")
        if summary['critical']:
            console.print(f"  [critical]CRITICAL: {summary['critical']}[/critical]")
        if summary['high']:
            console.print(f"  [high]HIGH: {summary['high']}[/high]")
        if summary['medium']:
            console.print(f"  [medium]MEDIUM: {summary['medium']}[/medium]")
        if summary['low']:
            console.print(f"  [low]LOW: {summary['low']}[/low]")

        return result
