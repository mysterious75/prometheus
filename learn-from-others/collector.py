"""Bug Bounty Report Collector - Downloads 1000+ reports/blogs for AI learning.

Sources: HackerOne, Bugcrowd, Medium, PortSwigger, Reddit, Security blogs.
Stores in learn-from-others/ for pattern analysis.
"""

import json
import os
import re
import time
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import quote, urljoin

import httpx

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import logger, console


class ReportCollector:
    """Collects bug bounty reports from multiple sources."""

    BASE_DIR = Path(__file__).parent
    OUTPUT_DIR = BASE_DIR

    def __init__(self):
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=20,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )
        self.stats = {
            "hackerone": 0,
            "bugcrowd": 0,
            "medium": 0,
            "portswigger": 0,
            "reddit": 0,
            "writeups": 0,
            "total": 0,
        }
        self.downloaded_urls = set()
        self._load_downloaded()

    def _load_downloaded(self):
        """Load already downloaded URLs to avoid duplicates."""
        index_file = self.OUTPUT_DIR / "index.json"
        if index_file.exists():
            try:
                data = json.loads(index_file.read_text(encoding="utf-8"))
                self.downloaded_urls = set(data.get("urls", []))
            except Exception:
                pass

    def _save_index(self):
        """Save index of downloaded reports."""
        index_file = self.OUTPUT_DIR / "index.json"
        data = {
            "last_updated": datetime.now().isoformat(),
            "stats": self.stats,
            "urls": list(self.downloaded_urls),
            "total_reports": len(self.downloaded_urls),
        }
        index_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _safe_filename(self, name: str, max_len: int = 80) -> str:
        """Create safe filename."""
        name = re.sub(r'[<>:"/\\|?*]', '', name)
        name = re.sub(r'\s+', '_', name.strip())
        return name[:max_len]

    def _save_report(self, source: str, title: str, url: str, content: str,
                     vuln_type: str = "", severity: str = "", bounty: str = "",
                     extra: Dict = None):
        """Save a report to disk."""
        # Skip duplicates
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url in self.downloaded_urls:
            return False

        folder = self.OUTPUT_DIR / source
        folder.mkdir(parents=True, exist_ok=True)

        filename = self._safe_filename(title) + ".md"
        filepath = folder / filename

        # Avoid filename collision
        counter = 1
        while filepath.exists():
            filename = self._safe_filename(title) + f"_{counter}.md"
            filepath = folder / filename
            counter += 1

        # Build markdown content
        md_content = f"""# {title}

**Source:** {source}
**URL:** {url}
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Vuln Type:** {vuln_type}
**Severity:** {severity}
**Bounty:** {bounty}

---

{content}
"""
        if extra:
            md_content += f"\n\n## Extra Info\n```json\n{json.dumps(extra, indent=2)}\n```"

        filepath.write_text(md_content, encoding="utf-8")
        self.downloaded_urls.add(url)
        self.stats[source] = self.stats.get(source, 0) + 1
        self.stats["total"] = len(self.downloaded_urls)
        return True

    # ================================================================
    # HackerOne Hacktivity (Public Reports)
    # ================================================================
    def collect_hackerone(self, pages: int = 50):
        """Collect public reports from HackerOne Hacktivity."""
        logger.info("[bold cyan]Collecting HackerOne Hacktivity reports...[/bold cyan]")

        # HackerOne hacktivity RSS/API
        base_url = "https://hackerone.com/hacktivity"

        # Use the GraphQL API that hacktivity uses
        api_url = "https://hackerone.com/graphql"

        for page in range(1, pages + 1):
            try:
                # GraphQL query for hacktivity
                payload = {
                    "operationName": "HacktivityQuery",
                    "variables": {
                        "first": 20,
                        "after": f"page_{page}",
                        "queryString": "",
                        "sortField": "latest_disclosable_activity_at",
                        "sortDirection": "DESC",
                        "filterByState": "published",
                        "filterByDisclosurePolicy": ["HACKTIVITY_FEED"],
                    },
                    "query": """
                    query HacktivityQuery($first: Int, $after: String, $queryString: String, $sortField: UserPaginationOrderField, $sortDirection: OrderDirection, $filterByState: ProgramMembershipState, $filterByDisclosurePolicy: [DisclosurePolicy]) {
                        me { username }
                        hacktivity(first: $first, after: $after, query_string: $queryString, sort_field: $sortField, sort_direction: $sortDirection, filter_by_state: $filterByState, filter_by_disclosure_policy: $filterByDisclosurePolicy) {
                            edges {
                                node {
                                    id
                                    title
                                    vulnerability_information
                                    disclosed_at
                                    bounty_amount
                                    severity_rating
                                    structured_scope { identifier }
                                }
                            }
                            pageInfo { hasNextPage endCursor }
                        }
                    }
                    """
                }

                response = self.client.post(api_url, json=payload)

                if response.status_code != 200:
                    logger.warning(f"  HackerOne API returned {response.status_code}, page {page}")
                    # Fallback: scrape HTML
                    self._scrape_hackerone_html(page)
                    continue

                data = response.json()
                edges = data.get("data", {}).get("hacktivity", {}).get("edges", [])

                if not edges:
                    logger.info(f"  No more results at page {page}")
                    break

                for edge in edges:
                    node = edge.get("node", {})
                    title = node.get("title", "Untitled")
                    content = node.get("vulnerability_information", "")
                    vuln_type = self._extract_vuln_type(content)
                    severity = node.get("severity_rating", "unknown")
                    bounty = str(node.get("bounty_amount", ""))
                    url = f"https://hackerone.com/hacktivity/{node.get('id', '')}"

                    if content and len(content) > 100:
                        self._save_report("hackerone", title, url, content, vuln_type, severity, bounty)
                        logger.info(f"  [+] {title[:60]}...")

                logger.info(f"  Page {page}: {len(edges)} reports")
                time.sleep(1)  # Rate limit

            except Exception as e:
                logger.error(f"  HackerOne page {page} error: {e}")
                continue

        logger.info(f"[green]HackerOne: {self.stats['hackerone']} reports collected[/green]")

    def _scrape_hackerone_html(self, page: int):
        """Fallback HTML scraping for HackerOne."""
        try:
            url = f"https://hackerone.com/hacktivity?page={page}"
            response = self.client.get(url)
            # Extract report links
            links = re.findall(r'href="/hacktivity/(\d+)"', response.text)
            for report_id in links[:20]:
                report_url = f"https://hackerone.com/hacktivity/{report_id}"
                if report_url not in self.downloaded_urls:
                    try:
                        time.sleep(0.5)
                        detail = self.client.get(report_url)
                        title_match = re.search(r'<title>(.*?)</title>', detail.text)
                        title = title_match.group(1) if title_match else f"HackerOne-{report_id}"
                        # Extract main content
                        content_match = re.search(r'class="vulnerability-information[^"]*"[^>]*>(.*?)</div>', detail.text, re.DOTALL)
                        content = content_match.group(1) if content_match else detail.text[:5000]
                        content = re.sub(r'<[^>]+>', '', content).strip()
                        if len(content) > 100:
                            self._save_report("hackerone", title, report_url, content)
                    except Exception:
                        pass
        except Exception:
            pass

    # ================================================================
    # Bugcrowd Public Disclosures
    # ================================================================
    def collect_bugcrowd(self, pages: int = 50):
        """Collect public disclosures from Bugcrowd."""
        logger.info("[bold cyan]Collecting Bugcrowd disclosures...[/bold cyan]")

        for page in range(1, pages + 1):
            try:
                url = f"https://bugcrowd.com/engagements?page={page}"
                response = self.client.get(url)

                # Find disclosure links
                disclosure_links = re.findall(r'href="(/engagements/[^/]+/disclosures/[^"]+)"', response.text)

                if not disclosure_links:
                    # Try alternate pattern
                    disclosure_links = re.findall(r'href="(/engagements/[^"]+/reports/[^"]+)"', response.text)

                if not disclosure_links and page > 5:
                    break

                for link in disclosure_links[:20]:
                    try:
                        full_url = f"https://bugcrowd.com{link}"
                        if full_url in self.downloaded_urls:
                            continue

                        time.sleep(0.5)
                        detail = self.client.get(full_url)

                        title_match = re.search(r'<title>(.*?)</title>', detail.text)
                        title = title_match.group(1) if title_match else link.split("/")[-1]

                        # Extract content
                        content = re.sub(r'<[^>]+>', ' ', detail.text)
                        content = re.sub(r'\s+', ' ', content).strip()

                        if len(content) > 200:
                            vuln_type = self._extract_vuln_type(content)
                            self._save_report("bugcrowd", title, full_url, content[:10000], vuln_type)
                            logger.info(f"  [+] {title[:60]}...")
                    except Exception:
                        continue

                logger.info(f"  Page {page} done")
                time.sleep(1)

            except Exception as e:
                logger.error(f"  Bugcrowd page {page} error: {e}")
                continue

        logger.info(f"[green]Bugcrowd: {self.stats['bugcrowd']} reports collected[/green]")

    # ================================================================
    # Medium Bug Bounty Blogs
    # ================================================================
    def collect_medium(self, queries: List[str] = None, pages: int = 30):
        """Collect Medium blogs about bug bounty."""
        logger.info("[bold cyan]Collecting Medium bug bounty blogs...[/bold cyan]")

        if not queries:
            queries = [
                "bug bounty writeup",
                "bug bounty report",
                "hackerone disclosure",
                "sql injection bug bounty",
                "xss bug bounty writeup",
                "ssrf bug bounty",
                "idor vulnerability writeup",
                "authentication bypass bug bounty",
                "race condition bug bounty",
                "subdomain takeover writeup",
                "jwt vulnerability bug bounty",
                "api security bug bounty",
                "csrf bug bounty writeup",
                "file upload vulnerability",
                "command injection writeup",
                "xxe vulnerability writeup",
                "prototype pollution bug bounty",
                "graphql vulnerability writeup",
                "oauth vulnerability bug bounty",
                "business logic bug bounty",
            ]

        for query in queries:
            try:
                # Use Medium's search
                search_url = f"https://medium.com/search?q={quote(query)}"
                response = self.client.get(search_url)

                # Extract article links
                articles = re.findall(r'href="https://medium\.com/[^"]*?/[a-f0-9]{12}"', response.text)
                # Also try other patterns
                articles += re.findall(r'"canonicalUrl":"(https://medium\.com/[^"]+)"', response.text)
                # Also find from tag pages
                articles += re.findall(r'"url":"(https://medium\.com/@[^"]+/[^"]+)"', response.text)

                seen = set()
                for article_url in articles[:15]:
                    article_url = article_url.replace('href="', '').strip('"')

                    if article_url in self.downloaded_urls or article_url in seen:
                        continue
                    seen.add(article_url)

                    try:
                        time.sleep(1)
                        detail = self.client.get(article_url)

                        title_match = re.search(r'<title>(.*?)</title>', detail.text)
                        title = title_match.group(1) if title_match else article_url.split("/")[-1]

                        # Extract article content
                        content = self._extract_medium_content(detail.text)

                        if len(content) > 200:
                            vuln_type = self._extract_vuln_type(content)
                            self._save_report("medium", title, article_url, content[:15000], vuln_type)
                            logger.info(f"  [+] {title[:60]}...")
                    except Exception:
                        continue

                logger.info(f"  Query '{query}' done")
                time.sleep(1)

            except Exception as e:
                logger.error(f"  Medium query error: {e}")
                continue

        logger.info(f"[green]Medium: {self.stats['medium']} blogs collected[/green]")

    def _extract_medium_content(self, html: str) -> str:
        """Extract article content from Medium HTML."""
        # Try article tag
        article = re.search(r'<article[^>]*>(.*?)</article>', html, re.DOTALL)
        if article:
            content = article.group(1)
        else:
            # Try main content area
            content = re.search(r'<div[^>]*class="[^"]*postArticle[^"]*"[^>]*>(.*?)</div>\s*</div>\s*</div>', html, re.DOTALL)
            content = content.group(1) if content else html

        # Clean HTML
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
        content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL)
        content = re.sub(r'<[^>]+>', '\n', content)
        content = re.sub(r'\n{3,}', '\n\n', content)
        content = re.sub(r'[ \t]+', ' ', content)
        return content.strip()

    # ================================================================
    # PortSwigger Research
    # ================================================================
    def collect_portswigger(self, pages: int = 20):
        """Collect PortSwigger research articles and writeups."""
        logger.info("[bold cyan]Collecting PortSwigger research...[/bold cyan]")

        try:
            # PortSwigger research blog
            url = "https://portswigger.net/research"
            response = self.client.get(url)

            # Extract article links
            articles = re.findall(r'href="(/research/[^"]+)"', response.text)
            articles = list(set(articles))

            for link in articles[:50]:
                try:
                    full_url = f"https://portswigger.net{link}"
                    if full_url in self.downloaded_urls:
                        continue

                    time.sleep(0.5)
                    detail = self.client.get(full_url)

                    title_match = re.search(r'<title>(.*?)</title>', detail.text)
                    title = title_match.group(1) if title_match else link.split("/")[-1]

                    content = re.sub(r'<[^>]+>', ' ', detail.text)
                    content = re.sub(r'\s+', ' ', content).strip()

                    if len(content) > 200:
                        vuln_type = self._extract_vuln_type(content)
                        self._save_report("portswigger", title, full_url, content[:15000], vuln_type)
                        logger.info(f"  [+] {title[:60]}...")
                except Exception:
                    continue

            # Also get daily swig posts
            daily_url = "https://portswigger.net/research/daily-swig"
            try:
                response = self.client.get(daily_url)
                daily_links = re.findall(r'href="(/research/daily-swig/[^"]+)"', response.text)
                for link in daily_links[:30]:
                    try:
                        full_url = f"https://portswigger.net{link}"
                        if full_url in self.downloaded_urls:
                            continue
                        time.sleep(0.5)
                        detail = self.client.get(full_url)
                        title_match = re.search(r'<title>(.*?)</title>', detail.text)
                        title = title_match.group(1) if title_match else link.split("/")[-1]
                        content = re.sub(r'<[^>]+>', ' ', detail.text)
                        content = re.sub(r'\s+', ' ', content).strip()
                        if len(content) > 200:
                            vuln_type = self._extract_vuln_type(content)
                            self._save_report("portswigger", title, full_url, content[:15000], vuln_type)
                            logger.info(f"  [+] {title[:60]}...")
                    except Exception:
                        continue
            except Exception:
                pass

        except Exception as e:
            logger.error(f"  PortSwigger error: {e}")

        logger.info(f"[green]PortSwigger: {self.stats['portswigger']} articles collected[/green]")

    # ================================================================
    # Reddit Security/BugBounty
    # ================================================================
    def collect_reddit(self, subreddits: List[str] = None, pages: int = 30):
        """Collect writeups from Reddit."""
        logger.info("[bold cyan]Collecting Reddit bug bounty posts...[/bold cyan]")

        if not subreddits:
            subreddits = ["bugbounty", "netsec", "howtohack", "cybersecurity", "whitehat"]

        for sub in subreddits:
            try:
                for page in range(1, pages + 1):
                    url = f"https://www.reddit.com/r/{sub}/top.json?t=year&limit=100"
                    response = self.client.get(url, headers={"User-Agent": "PrometheusBot/1.0"})

                    if response.status_code != 200:
                        continue

                    data = response.json()
                    posts = data.get("data", {}).get("children", [])

                    if not posts:
                        break

                    for post in posts:
                        post_data = post.get("data", {})
                        title = post_data.get("title", "")
                        selftext = post_data.get("selftext", "")
                        post_url = post_data.get("url", "")
                        permalink = f"https://reddit.com{post_data.get('permalink', '')}"

                        # Only collect writeup-like posts
                        if any(kw in title.lower() for kw in ["writeup", "disclosure", "bug bounty", "payout",
                                                               "hackerone", "bugcrowd", "vulnerability",
                                                               "sql injection", "xss", "ssrf", "idor",
                                                               "rce", "authentication bypass"]):

                            content = selftext if len(selftext) > 200 else ""
                            if not content and post_url:
                                try:
                                    time.sleep(0.5)
                                    ext = self.client.get(post_url)
                                    content = re.sub(r'<[^>]+>', ' ', ext.text)
                                    content = re.sub(r'\s+', ' ', content).strip()
                                except Exception:
                                    pass

                            if len(content) > 200:
                                vuln_type = self._extract_vuln_type(title + " " + content)
                                self._save_report("reddit", title, permalink, content[:10000], vuln_type)
                                logger.info(f"  [+] {title[:60]}...")

                    time.sleep(2)  # Rate limit

            except Exception as e:
                logger.error(f"  Reddit r/{sub} error: {e}")
                continue

        logger.info(f"[green]Reddit: {self.stats['reddit']} posts collected[/green]")

    # ================================================================
    # Security Blog Aggregator
    # ================================================================
    def collect_writeups(self, pages: int = 30):
        """Collect from security blog aggregators."""
        logger.info("[bold cyan]Collecting security writeups...[/bold cyan]")

        sources = [
            ("https://infosecwriteups.com/tagged/bug-bounty", "InfoSec Writeups"),
            ("https://www.hackingarticles.in/category/bug-bounty/", "Hacking Articles"),
            ("https://pentester.land/list-of-bug-bounty-writeups/", "Pentester Land"),
            ("https://secnhack.in/category/bug-bounty/", "SecNHack"),
            ("https://www.sonarsource.com/blog/", "SonarSource"),
            ("https://blog.assetnote.io/", "Assetnote"),
            ("https://blog.securityinnovation.com/", "Security Innovation"),
            ("https://www.invicti.com/blog/", "Invicti"),
            ("https://www.acunetix.com/blog/", "Acunetix"),
            ("https://snyk.io/blog/", "Snyk"),
        ]

        for source_url, source_name in sources:
            try:
                response = self.client.get(source_url)
                # Extract article links
                links = re.findall(r'href="(https?://[^"]*(?:bug|bounty|vulnerability|writeup|disclosure|security|cve|injection|xss|ssrf)[^"]*)"', response.text, re.IGNORECASE)
                links += re.findall(r'href="(https?://[^"]*)"', response.text)

                seen = set()
                for link in links[:20]:
                    if link in self.downloaded_urls or link in seen:
                        continue
                    if any(skip in link for skip in ["twitter.com", "facebook.com", "linkedin.com", "javascript:", "#"]):
                        continue
                    seen.add(link)

                    try:
                        time.sleep(0.5)
                        detail = self.client.get(link)
                        title_match = re.search(r'<title>(.*?)</title>', detail.text)
                        title = title_match.group(1) if title_match else link.split("/")[-1]

                        content = re.sub(r'<[^>]+>', ' ', detail.text)
                        content = re.sub(r'\s+', ' ', content).strip()

                        if len(content) > 300:
                            vuln_type = self._extract_vuln_type(content)
                            self._save_report("writeups", f"{source_name}: {title}", link, content[:15000], vuln_type)
                            logger.info(f"  [+] [{source_name}] {title[:50]}...")
                    except Exception:
                        continue

            except Exception as e:
                logger.error(f"  {source_name} error: {e}")
                continue

        logger.info(f"[green]Writeups: {self.stats['writeups']} collected[/green]")

    # ================================================================
    # Utilities
    # ================================================================
    def _extract_vuln_type(self, text: str) -> str:
        """Extract vulnerability type from text."""
        text_lower = text.lower()

        vuln_keywords = {
            "SQL Injection": ["sql injection", "sqlmap", "sqli", "blind sql", "union select", "mysql"],
            "XSS": ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "alert("],
            "SSRF": ["server-side request forgery", "ssrf", "internal request", "cloud metadata"],
            "IDOR": ["insecure direct object", "idor", "authorization bypass", "access control"],
            "RCE": ["remote code execution", "rce", "command injection", "os command", "shell injection"],
            "Authentication Bypass": ["authentication bypass", "auth bypass", "login bypass", "no auth"],
            "Privilege Escalation": ["privilege escalation", "privesc", "escalate", "root access"],
            "XXE": ["xml external entity", "xxe", "xml injection", "external entity"],
            "CSRF": ["cross-site request forgery", "csrf", "cross site request"],
            "File Upload": ["file upload", "unrestricted upload", "webshell", "upload shell"],
            "Subdomain Takeover": ["subdomain takeover", "dangling", "unclaimed"],
            "Open Redirect": ["open redirect", "url redirect", "forward", "unvalidated redirect"],
            "Information Disclosure": ["info disclosure", "information leak", "sensitive data", "exposed"],
            "Race Condition": ["race condition", "concurrent", "race condition"],
            "Business Logic": ["business logic", "logic flaw", "workflow bypass"],
            "JWT Vulnerability": ["jwt", "json web token", "token forgery", "weak secret"],
            "GraphQL": ["graphql", "introspection", "query complexity"],
            "API Vulnerability": ["api vulnerability", "api security", "rest api", "api bypass"],
            "Prototype Pollution": ["prototype pollution", "__proto__", "object injection"],
            "Deserialization": ["deserialization", "unsafe deserialization", "object injection", "pickle"],
            "Cache Poisoning": ["cache poisoning", "web cache", "cache deception"],
            "CRLF Injection": ["crlf", "header injection", "response splitting"],
            "Template Injection": ["template injection", "ssti", "server-side template"],
            "LFI/RFI": ["local file inclusion", "remote file inclusion", "lfi", "rfi", "path traversal"],
            "Memory Corruption": ["buffer overflow", "memory corruption", "heap", "stack overflow"],
        }

        scores = {}
        for vuln_type, keywords in vuln_keywords.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > 0:
                scores[vuln_type] = score

        if scores:
            return max(scores, key=scores.get)
        return "Unknown"

    def get_stats(self) -> str:
        """Get collection statistics."""
        lines = [
            "Report Collection Stats:",
            f"  HackerOne: {self.stats['hackerone']}",
            f"  Bugcrowd: {self.stats['bugcrowd']}",
            f"  Medium: {self.stats['medium']}",
            f"  PortSwigger: {self.stats['portswigger']}",
            f"  Reddit: {self.stats['reddit']}",
            f"  Writeups: {self.stats['writeups']}",
            f"  TOTAL: {self.stats['total']}",
        ]
        return "\n".join(lines)

    def collect_all(self):
        """Collect from all sources."""
        logger.info("[bold blue]Starting full report collection...[/bold blue]")
        start = time.time()

        self.collect_hackerone(pages=40)
        self.collect_bugcrowd(pages=30)
        self.collect_medium(pages=20)
        self.collect_portswigger(pages=15)
        self.collect_reddit(pages=20)
        self.collect_writeups(pages=20)

        self._save_index()

        elapsed = time.time() - start
        logger.info(f"\n[bold green]Collection complete in {elapsed:.0f}s[/bold green]")
        logger.info(self.get_stats())


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Report Collector")
    parser.add_argument("--source", choices=["hackerone", "bugcrowd", "medium", "portswigger", "reddit", "writeups", "all"],
                       default="all", help="Source to collect from")
    parser.add_argument("--pages", type=int, default=20, help="Pages to scrape per source")
    args = parser.parse_args()

    collector = ReportCollector()

    if args.source == "all":
        collector.collect_all()
    elif args.source == "hackerone":
        collector.collect_hackerone(args.pages)
    elif args.source == "bugcrowd":
        collector.collect_bugcrowd(args.pages)
    elif args.source == "medium":
        collector.collect_medium(pages=args.pages)
    elif args.source == "portswigger":
        collector.collect_portswigger(args.pages)
    elif args.source == "reddit":
        collector.collect_reddit(pages=args.pages)
    elif args.source == "writeups":
        collector.collect_writeups(args.pages)

    collector._save_index()
    print(collector.get_stats())


if __name__ == "__main__":
    main()
