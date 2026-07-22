"""Pattern Analyzer - Reads collected reports and extracts patterns for AI learning.

Analyzes 1000+ bug bounty reports to understand:
- Common vulnerability patterns
- Attack techniques
- Impact assessment
- Fix recommendations
- Bounty ranges
"""

import json
import os
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple
from collections import Counter, defaultdict

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import logger, console


class PatternAnalyzer:
    """Analyzes bug bounty reports to extract patterns for AI learning."""

    BASE_DIR = Path(__file__).parent

    VULN_PATTERNS = {
        "SQL Injection": {
            "keywords": ["sql injection", "sqli", "sqlmap", "blind sql", "union select", "mysql", "postgresql", "oracle", "database"],
            "payloads": ["' OR 1=1--", "' UNION SELECT", "1' AND SLEEP", "WAITFOR DELAY", "1' AND 1=1"],
            "tools": ["sqlmap", "havij", "jSQL", "BBQSQL"],
            "impact": "Data theft, authentication bypass, full database compromise",
            "bounty_range": "$500-$15,000",
        },
        "XSS": {
            "keywords": ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "alert(", "onerror=", "onload="],
            "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"],
            "tools": ["XSStrike", "dalfox", "kxss", "reflected-xss"],
            "impact": "Session hijacking, credential theft, defacement",
            "bounty_range": "$100-$5,000",
        },
        "SSRF": {
            "keywords": ["server-side request forgery", "ssrf", "internal request", "cloud metadata", "169.254.169.254", "localhost"],
            "payloads": ["http://127.0.0.1", "http://169.254.169.254", "file:///etc/passwd", "http://localhost"],
            "tools": ["SSRFmap", "Gopherus"],
            "impact": "Cloud credential theft, internal network access, RCE",
            "bounty_range": "$500-$25,000",
        },
        "IDOR": {
            "keywords": ["insecure direct object", "idor", "authorization bypass", "access control", "vertical access", "horizontal access"],
            "payloads": ["id=1", "id=2", "user_id=", "account="],
            "tools": ["Autorize", "Burp"],
            "impact": "Unauthorized data access, account takeover",
            "bounty_range": "$100-$10,000",
        },
        "RCE": {
            "keywords": ["remote code execution", "rce", "command injection", "os command", "shell injection", "eval(", "system("],
            "payloads": ["; ls", "| cat /etc/passwd", "$(whoami)", "`id`"],
            "tools": ["commix", "Metasploit"],
            "impact": "Full server compromise, data breach",
            "bounty_range": "$1,000-$50,000",
        },
        "Authentication Bypass": {
            "keywords": ["authentication bypass", "auth bypass", "login bypass", "no auth", "unauthenticated", "bypass auth"],
            "payloads": ["admin:admin", "admin:password", "default credentials"],
            "tools": ["Hydra", "Medusa", "patator"],
            "impact": "Full account takeover, admin access",
            "bounty_range": "$500-$20,000",
        },
        "Privilege Escalation": {
            "keywords": ["privilege escalation", "privesc", "escalate", "root access", "admin panel", "horizontal", "vertical"],
            "payloads": ["role=admin", "is_admin=true", "admin=1"],
            "tools": ["LinPEAS", "WinPEAS"],
            "impact": "Admin access, full system compromise",
            "bounty_range": "$500-$15,000",
        },
        "XXE": {
            "keywords": ["xml external entity", "xxe", "xml injection", "external entity", "document type"],
            "payloads": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "&xxe;"],
            "tools": ["XXEinjector", "Burp"],
            "impact": "File read, SSRF, DoS",
            "bounty_range": "$300-$10,000",
        },
        "CSRF": {
            "keywords": ["cross-site request forgery", "csrf", "cross site request", "no csrf token"],
            "payloads": ["<form action=", "<img src=", "XMLHttpRequest"],
            "tools": ["CSRF-Scanner"],
            "impact": "Unauthorized actions, account takeover",
            "bounty_range": "$100-$5,000",
        },
        "File Upload": {
            "keywords": ["file upload", "unrestricted upload", "webshell", "upload shell", "malicious file"],
            "payloads": ["shell.php", "shell.php.jpg", ".htaccess", "web.config"],
            "tools": ["upload-scanner"],
            "impact": "RCE, full server compromise",
            "bounty_range": "$500-$15,000",
        },
        "Subdomain Takeover": {
            "keywords": ["subdomain takeover", "dangling", "unclaimed", "cname", "pointing to"],
            "payloads": ["There isn't a GitHub Pages site here", "NoSuchBucket", "No such app"],
            "tools": ["subjack", "subover", "nuclei"],
            "impact": "Cookie theft, phishing, brand impersonation",
            "bounty_range": "$200-$10,000",
        },
        "Open Redirect": {
            "keywords": ["open redirect", "url redirect", "forward", "unvalidated redirect", "redirect to"],
            "payloads": ["https://evil.com", "//evil.com"],
            "tools": ["OpenRedireX"],
            "impact": "Phishing, OAuth token theft",
            "bounty_range": "$50-$2,000",
        },
        "Business Logic": {
            "keywords": ["business logic", "logic flaw", "workflow bypass", "negative price", "coupon", "balance"],
            "payloads": ["price=-1", "quantity=-1", "discount=100"],
            "tools": ["Manual testing"],
            "impact": "Financial loss, unauthorized access",
            "bounty_range": "$200-$25,000",
        },
        "JWT Vulnerability": {
            "keywords": ["jwt", "json web token", "token forgery", "weak secret", "none algorithm", "alg:none"],
            "payloads": ["alg:none", "HS256", "RS256"],
            "tools": ["jwt_tool", "hashcat"],
            "impact": "Authentication bypass, impersonation",
            "bounty_range": "$300-$10,000",
        },
        "GraphQL": {
            "keywords": ["graphql", "introspection", "query complexity", "graphiql", "__schema"],
            "payloads": ["{__schema{types{name}}}", "query{users{id email}}"],
            "tools": ["GraphQLMap", "InQL"],
            "impact": "Data exposure, DoS, unauthorized access",
            "bounty_range": "$200-$8,000",
        },
        "Race Condition": {
            "keywords": ["race condition", "concurrent", "race", "double spend", "time-of-check"],
            "payloads": ["concurrent requests", "parallel"],
            "tools": ["Turbo Intruder", "race-condition"],
            "impact": "Double spending, balance manipulation",
            "bounty_range": "$100-$15,000",
        },
        "Cache Poisoning": {
            "keywords": ["cache poisoning", "web cache", "cache deception", "unkeyed header"],
            "payloads": ["X-Forwarded-Host", "X-Original-URL"],
            "tools": ["webcache-deception"],
            "impact": "XSS, open redirect, DoS",
            "bounty_range": "$200-$5,000",
        },
        "Template Injection": {
            "keywords": ["template injection", "ssti", "server-side template", "freemarker", "jinja", "twig"],
            "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            "tools": ["tplmap"],
            "impact": "RCE, full server compromise",
            "bounty_range": "$500-$20,000",
        },
        "LFI/Path Traversal": {
            "keywords": ["local file inclusion", "path traversal", "directory traversal", "lfi", "../", "file inclusion"],
            "payloads": ["../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2f"],
            "tools": ["LFiFreak", "dotdotpwn"],
            "impact": "File read, RCE via log poisoning",
            "bounty_range": "$200-$10,000",
        },
        "CRLF Injection": {
            "keywords": ["crlf", "header injection", "response splitting", "newline injection"],
            "payloads": ["%0d%0a", "\r\n"],
            "tools": ["CRLF-Injection-Scanner"],
            "impact": "XSS, session fixation, cache poisoning",
            "bounty_range": "$50-$3,000",
        },
    }

    def __init__(self):
        self.reports = []
        self.patterns = {}
        self.stats = {
            "total_reports": 0,
            "by_type": Counter(),
            "by_severity": Counter(),
            "by_source": Counter(),
            "common_payloads": Counter(),
            "common_tools": Counter(),
            "common_bounty_ranges": Counter(),
        }

    def load_reports(self):
        """Load all reports from learn-from-others folder."""
        logger.info("[bold cyan]Loading reports...[/bold cyan]")

        source_dirs = ["hackerone", "bugcrowd", "medium", "writeups", "portswigger", "reddit"]

        for source in source_dirs:
            source_dir = self.BASE_DIR / source
            if not source_dir.exists():
                continue

            for md_file in source_dir.glob("*.md"):
                try:
                    content = md_file.read_text(encoding="utf-8")
                    report = self._parse_report(content, source, md_file.name)
                    if report:
                        self.reports.append(report)
                        self.stats["total_reports"] += 1
                        self.stats["by_source"][source] += 1
                except Exception:
                    continue

        logger.info(f"[green]Loaded {len(self.reports)} reports[/green]")

    def _parse_report(self, content: str, source: str, filename: str) -> Dict:
        """Parse a markdown report into structured data."""
        report = {
            "source": source,
            "filename": filename,
            "title": "",
            "url": "",
            "vuln_type": "",
            "severity": "",
            "bounty": "",
            "content": content,
        }

        # Extract metadata
        title_match = re.search(r'^# (.+)', content, re.MULTILINE)
        if title_match:
            report["title"] = title_match.group(1).strip()

        url_match = re.search(r'\*\*URL:\*\* (.+)', content)
        if url_match:
            report["url"] = url_match.group(1).strip()

        vuln_match = re.search(r'\*\*Vuln Type:\*\* (.+)', content)
        if vuln_match:
            report["vuln_type"] = vuln_match.group(1).strip()

        severity_match = re.search(r'\*\*Severity:\*\* (.+)', content)
        if severity_match:
            report["severity"] = severity_match.group(1).strip()

        bounty_match = re.search(r'\*\*Bounty:\*\* (.+)', content)
        if bounty_match:
            report["bounty"] = bounty_match.group(1).strip()

        # Classify vulnerability if not specified
        if not report["vuln_type"]:
            report["vuln_type"] = self._classify_vuln(content)

        return report

    def _classify_vuln(self, text: str) -> str:
        """Auto-classify vulnerability type."""
        text_lower = text.lower()
        scores = {}

        for vuln_type, info in self.VULN_PATTERNS.items():
            score = sum(1 for kw in info["keywords"] if kw in text_lower)
            if score > 0:
                scores[vuln_type] = score

        if scores:
            return max(scores, key=scores.get)
        return "Unknown"

    def analyze(self):
        """Run full analysis on all reports."""
        logger.info("[bold cyan]Analyzing patterns...[/bold cyan]")

        # Count vulnerability types
        for report in self.reports:
            vtype = report.get("vuln_type", "Unknown")
            self.stats["by_type"][vtype] += 1

            severity = report.get("severity", "unknown")
            self.stats["by_severity"][severity.lower()] += 1

        # Extract common patterns
        all_text = " ".join(r.get("content", "") for r in self.reports)
        all_text_lower = all_text.lower()

        # Common payloads found in reports
        common_payloads = [
            "' OR 1=1--", "<script>alert(1)</script>", "http://127.0.0.1",
            "<img src=x onerror=alert(1)>", "{{7*7}}", "../../../etc/passwd",
            "' UNION SELECT", "1' AND SLEEP(5)", "javascript:alert(1)",
            "' OR ''='", "%0d%0a", "file:///etc/passwd",
        ]
        for payload in common_payloads:
            count = all_text_lower.count(payload.lower())
            if count > 0:
                self.stats["common_payloads"][payload] = count

        # Common tools mentioned
        common_tools = [
            "sqlmap", "burp suite", "nmap", "nuclei", "subfinder", "httpx",
            "ffuf", "katana", "gau", "waybackurls", "XSStrike", "dalfox",
            "hashcat", "hydra", "Metasploit", "nmap", "masscan",
        ]
        for tool in common_tools:
            count = all_text_lower.count(tool.lower())
            if count > 0:
                self.stats["common_tools"][tool] = count

        # Extract attack techniques per vulnerability type
        self._extract_attack_techniques()

        logger.info("[green]Analysis complete[/green]")

    def _extract_attack_techniques(self):
        """Extract common attack techniques per vulnerability type."""
        techniques = defaultdict(lambda: {"examples": [], "count": 0, "keywords": Counter()})

        for report in self.reports:
            vtype = report.get("vuln_type", "Unknown")
            content = report.get("content", "").lower()

            techniques[vtype]["count"] += 1

            # Extract keywords
            words = re.findall(r'\b[a-z]{4,}\b', content)
            for word in words:
                if word not in ("this", "that", "with", "from", "have", "been", "were", "they", "their"):
                    techniques[vtype]["keywords"][word] += 1

            # Add title as example
            title = report.get("title", "")
            if title and len(techniques[vtype]["examples"]) < 5:
                techniques[vtype]["examples"].append(title)

        self.patterns = dict(techniques)

    def generate_report(self) -> str:
        """Generate analysis report."""
        lines = [
            "=" * 70,
            "BUG BOUNTY PATTERN ANALYSIS REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Total Reports Analyzed: {self.stats['total_reports']}",
            "=" * 70,
            "",
            "VULNERABILITY DISTRIBUTION:",
            "-" * 40,
        ]

        for vtype, count in self.stats["by_type"].most_common(20):
            pct = (count / self.stats["total_reports"] * 100) if self.stats["total_reports"] > 0 else 0
            bar = "#" * int(pct / 2)
            lines.append(f"  {vtype:30s} {count:4d} ({pct:.1f}%) {bar}")

        lines.extend([
            "",
            "SEVERITY BREAKDOWN:",
            "-" * 40,
        ])
        for sev, count in self.stats["by_severity"].most_common():
            lines.append(f"  {sev:15s} {count}")

        lines.extend([
            "",
            "SOURCE DISTRIBUTION:",
            "-" * 40,
        ])
        for src, count in self.stats["by_source"].most_common():
            lines.append(f"  {src:15s} {count}")

        lines.extend([
            "",
            "TOP PAYLOADS FOUND IN REPORTS:",
            "-" * 40,
        ])
        for payload, count in self.stats["common_payloads"].most_common(15):
            lines.append(f"  {count:3d}x  {payload}")

        lines.extend([
            "",
            "TOP TOOLS MENTIONED:",
            "-" * 40,
        ])
        for tool, count in self.stats["common_tools"].most_common(15):
            lines.append(f"  {count:3d}x  {tool}")

        # Per-type analysis
        lines.extend([
            "",
            "=" * 70,
            "VULNERABILITY-SPECIFIC PATTERNS",
            "=" * 70,
        ])

        for vtype, data in sorted(self.patterns.items(), key=lambda x: x[1]["count"], reverse=True)[:15]:
            lines.extend([
                f"\n[{vtype}] ({data['count']} reports)",
                "-" * 40,
                "Top keywords:",
            ])
            for word, count in data["keywords"].most_common(10):
                lines.append(f"  {word}: {count}")

            if data["examples"]:
                lines.append("Example reports:")
                for ex in data["examples"][:3]:
                    lines.append(f"  - {ex[:70]}")

        # Save patterns as JSON for AI consumption
        self._save_patterns_json()

        return "\n".join(lines)

    def _save_patterns_json(self):
        """Save patterns as JSON for AI to consume."""
        patterns_file = self.BASE_DIR / "patterns" / "learned_patterns.json"

        ai_patterns = {
            "generated": datetime.now().isoformat(),
            "total_reports": self.stats["total_reports"],
            "vulnerability_types": {},
            "attack_techniques": {},
            "common_payloads": dict(self.stats["common_payloads"].most_common(50)),
            "common_tools": dict(self.stats["common_tools"].most_common(30)),
        }

        # Add per-type patterns
        for vtype, data in self.patterns.items():
            ai_patterns["vulnerability_types"][vtype] = {
                "count": data["count"],
                "top_keywords": dict(data["keywords"].most_common(20)),
                "examples": data["examples"][:5],
            }

        # Add attack patterns from VULN_PATTERNS
        for vtype, info in self.VULN_PATTERNS.items():
            if vtype not in ai_patterns["attack_techniques"]:
                ai_patterns["attack_techniques"][vtype] = {
                    "payloads": info["payloads"],
                    "tools": info["tools"],
                    "impact": info["impact"],
                    "bounty_range": info["bounty_range"],
                }

        patterns_file.parent.mkdir(parents=True, exist_ok=True)
        patterns_file.write_text(json.dumps(ai_patterns, indent=2, default=str), encoding="utf-8")
        logger.info(f"[green]Patterns saved to {patterns_file}[/green]")


def main():
    """CLI entry point."""
    analyzer = PatternAnalyzer()
    analyzer.load_reports()
    analyzer.analyze()

    report = analyzer.generate_report()
    print(report)

    # Save report
    report_file = analyzer.BASE_DIR / "analysis" / "pattern_report.txt"
    report_file.write_text(report, encoding="utf-8")
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
