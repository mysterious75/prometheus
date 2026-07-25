"""Dorking Engine — Google, GitHub, Shodan, Bing, Yandex dorking.

Automates search engine dorking to find:
- Exposed admin panels
- Sensitive files
- Database dumps
- API keys in code
- Configuration files
- Login pages
- And much more
"""

import re
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


@dataclass
class DorkResult:
    """A dorking search result."""
    url: str
    title: str
    snippet: str
    source: str  # google, github, shodan, bing
    dork: str  # the dork used
    severity: str = "INFO"

    def to_dict(self):
        return {
            "url": self.url, "title": self.title, "snippet": self.snippet[:200],
            "source": self.source, "dork": self.dork,
        }


class DorkingEngine:
    """Automated search engine dorking for security research."""

    # Google Dorks — organized by vulnerability type
    GOOGLE_DORKS = {
        "sensitive_files": [
            'site:{target} filetype:env',
            'site:{target} filetype:log',
            'site:{target} filetype:sql',
            'site:{target} filetype:xml',
            'site:{target} filetype:conf',
            'site:{target} filetype:ini',
            'site:{target} filetype:yaml',
            'site:{target} filetype:yml',
            'site:{target} filetype:json',
            'site:{target} filetype:properties',
            'site:{target} filetype:cfg',
            'site:{target} filetype:config',
            'site:{target} filetype:bak',
            'site:{target} filetype:old',
            'site:{target} filetype:backup',
            'site:{target} filetype:dump',
            'site:{target} filetype:swp',
        ],
        "exposed_panels": [
            'site:{target} inurl:admin',
            'site:{target} inurl:login',
            'site:{target} inurl:panel',
            'site:{target} inurl:dashboard',
            'site:{target} inurl:console',
            'site:{target} inurl:manage',
            'site:{target} inurl:manager',
            'site:{target} inurl:wp-admin',
            'site:{target} inurl:phpmyadmin',
            'site:{target} inurl:adminer',
            'site:{target} inurl:cpanel',
            'site:{target} inurl:webmail',
        ],
        "info_disclosure": [
            'site:{target} intitle:"index of"',
            'site:{target} intitle:"directory listing"',
            'site:{target} intitle:"default page"',
            'site:{target} intext:"password" filetype:txt',
            'site:{target} intext:"username" filetype:txt',
            'site:{target} intext:"api_key" OR intext:"apikey"',
            'site:{target} intext:"secret" OR intext:"token"',
            'site:{target} intext:"database" filetype:sql',
            'site:{target} intext:"BEGIN RSA PRIVATE KEY"',
            'site:{target} ext:php inurl:info.php',
            'site:{target} ext:php inurl:test.php',
            'site:{target} ext:php inurl:phpinfo.php',
        ],
        "api_endpoints": [
            'site:{target} inurl:api',
            'site:{target} inurl:swagger',
            'site:{target} inurl:graphql',
            'site:{target} inurl:rest',
            'site:{target} inurl:v1 OR inurl:v2 OR inurl:v3',
            'site:{target} inurl:endpoint',
            'site:{target} filetype:wsdl',
        ],
        "error_pages": [
            'site:{target} intext:"sql syntax" OR intext:"mysql_fetch"',
            'site:{target} intext:"warning" intext:"mysql"',
            'site:{target} intext:"ORA-" intext:"oracle"',
            'site:{target} intext:"Microsoft OLE DB"',
            'site:{target} intext:"Traceback" intext:"Python"',
            'site:{target} intext:"Exception" intext:"stack trace"',
            'site:{target} intext:"Fatal error" intext:"PHP"',
        ],
        "login_pages": [
            'site:{target} inurl:login intext:"password"',
            'site:{target} inurl:signin',
            'site:{target} inurl:auth',
            'site:{target} inurl:sso',
            'site:{target} inurl:oauth',
        ],
        "documents": [
            'site:{target} filetype:pdf',
            'site:{target} filetype:doc OR filetype:docx',
            'site:{target} filetype:xls OR filetype:xlsx',
            'site:{target} filetype:ppt OR filetype:pptx',
            'site:{target} filetype:csv',
        ],
        "subdomains": [
            'site:*.{target} -www',
            'site:{target} inurl:dev OR inurl:staging OR inurl:test',
            'site:{target} inurl:api OR inurl:app',
        ],
        "technology": [
            'site:{target} "powered by"',
            'site:{target} "built with"',
            'site:{target} intext:"WordPress"',
            'site:{target} intext:"Drupal"',
            'site:{target} intext:"Joomla"',
        ],
    }

    # GitHub Dorks
    GITHUB_DORKS = [
        '{target} password',
        '{target} api_key',
        '{target} apikey',
        '{target} secret',
        '{target} token',
        '{target} credentials',
        '{target} aws_access_key',
        '{target} aws_secret',
        '{target} firebase',
        '{target} jdbc:',
        '{target} mongodb://',
        '{target} redis://',
        '{target} postgres://',
        '{target} mysql://',
        'org:{target} password',
        'org:{target} secret',
        'org:{target} api_key',
        '{target} filename:.env',
        '{target} filename:config.json',
        '{target} filename:.htpasswd',
        '{target} filename:id_rsa',
        '{target} "BEGIN RSA PRIVATE KEY"',
        '{target} filename:wp-config.php',
    ]

    # Shodan Dorks
    SHODAN_DORKS = [
        'hostname:{target}',
        'ssl.cert.subject.CN:{target}',
        'org:{target}',
        'hostname:{target} port:22',
        'hostname:{target} port:3389',
        'hostname:{target} port:3306',
        'hostname:{target} port:5432',
        'hostname:{target} port:6379',
        'hostname:{target} port:27017',
        'hostname:{target} port:9200',
        'hostname:{target} "admin"',
        'hostname:{target} "login"',
        'hostname:{target} http.title:"dashboard"',
        'hostname:{target} http.title:"index of"',
    ]

    # Bing Dorks
    BING_DORKS = [
        'site:{target} filetype:env',
        'site:{target} filetype:log',
        'site:{target} filetype:sql',
        'site:{target} intitle:"index of"',
        'site:{target} inurl:admin',
        'site:{target} inurl:login',
        'site:{target} ext:php inurl:phpinfo',
        'ip:{target} port:3389',
        'ip:{target} port:22',
    ]

    def __init__(self, rps: float = 2.0):
        self.limiter = get_limiter(rps)

    def google_dork(self, target: str, categories: List[str] = None) -> List[DorkResult]:
        """Run Google dorks against a target."""
        console.print(f"  [tool]▸ Google Dorking[/tool] → [target]{target}[/target]")

        results = []
        categories = categories or list(self.GOOGLE_DORKS.keys())

        for category in categories:
            dorks = self.GOOGLE_DORKS.get(category, [])
            for dork_template in dorks:
                dork = dork_template.format(target=target)
                self.limiter.wait("google.com")

                # We construct the URL but don't actually scrape Google
                # (that would violate ToS). Instead, provide the dork for manual use.
                results.append(DorkResult(
                    url=f"https://www.google.com/search?q={dork.replace(' ', '+')}",
                    title=f"Google Dork: {category}",
                    snippet=dork,
                    source="google",
                    dork=dork,
                ))

        console.print(f"  [tool]◂ Google Dorking[/tool] — {len(results)} dorks generated")
        return results

    def github_dork(self, target: str) -> List[DorkResult]:
        """Run GitHub dorks to find leaked secrets."""
        console.print(f"  [tool]▸ GitHub Dorking[/tool] → [target]{target}[/target]")

        results = []
        for dork_template in self.GITHUB_DORKS:
            dork = dork_template.format(target=target)
            results.append(DorkResult(
                url=f"https://github.com/search?q={dork.replace(' ', '+')}&type=code",
                title=f"GitHub Dork",
                snippet=dork,
                source="github",
                dork=dork,
            ))

        console.print(f"  [tool]◂ GitHub Dorking[/tool] — {len(results)} dorks generated")
        return results

    def shodan_dork(self, target: str) -> List[DorkResult]:
        """Run Shodan dorks."""
        console.print(f"  [tool]▸ Shodan Dorking[/tool] → [target]{target}[/target]")

        results = []
        for dork in self.SHODAN_DORKS:
            dork = dork.format(target=target)
            results.append(DorkResult(
                url=f"https://www.shodan.io/search?query={dork.replace(' ', '+')}",
                title=f"Shodan Dork",
                snippet=dork,
                source="shodan",
                dork=dork,
            ))

        console.print(f"  [tool]◂ Shodan Dorking[/tool] — {len(results)} dorks generated")
        return results

    def bing_dork(self, target: str) -> List[DorkResult]:
        """Run Bing dorks."""
        console.print(f"  [tool]▸ Bing Dorking[/tool] → [target]{target}[/target]")

        results = []
        for dork_template in self.BING_DORKS:
            dork = dork_template.format(target=target)
            results.append(DorkResult(
                url=f"https://www.bing.com/search?q={dork.replace(' ', '+')}",
                title=f"Bing Dork",
                snippet=dork,
                source="bing",
                dork=dork,
            ))

        console.print(f"  [tool]◂ Bing Dorking[/tool] — {len(results)} dorks generated")
        return results

    def full_dork(self, target: str) -> Dict[str, List[DorkResult]]:
        """Run all dorking engines against a target."""
        console.print(f"\n[bold cyan]═══ Dorking: {target} ═══[/bold cyan]")

        results = {
            "google": self.google_dork(target),
            "github": self.github_dork(target),
            "shodan": self.shodan_dork(target),
            "bing": self.bing_dork(target),
        }

        total = sum(len(v) for v in results.values())
        console.print(f"\n  [success]Dorking complete: {total} dorks generated[/success]")
        console.print(f"  [info]Copy-paste these URLs into your browser to check results[/info]")

        return results

    def get_dork_categories(self) -> List[str]:
        """List available Google dork categories."""
        return list(self.GOOGLE_DORKS.keys())

    def get_custom_dork(self, target: str, dork_type: str) -> str:
        """Generate a custom dork based on type."""
        custom_dorks = {
            "login": f'site:{target} inurl:login OR inurl:signin OR inurl:auth',
            "admin": f'site:{target} inurl:admin OR inurl:panel OR inurl:dashboard',
            "api": f'site:{target} inurl:api OR inurl:swagger OR inurl:graphql',
            "files": f'site:{target} filetype:pdf OR filetype:doc OR filetype:xls',
            "errors": f'site:{target} intext:"error" OR intext:"exception" OR intext:"warning"',
            "secrets": f'site:{target} intext:"password" OR intext:"api_key" OR intext:"secret"',
            "backup": f'site:{target} filetype:sql OR filetype:bak OR filetype:backup',
            "config": f'site:{target} filetype:env OR filetype:yml OR filetype:json OR filetype:xml',
            "subdomains": f'site:*.{target} -www',
        }
        return custom_dorks.get(dork_type, f'site:{target}')
