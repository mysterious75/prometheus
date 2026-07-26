"""Google Dorking Module — generates Google dorks for bug bounty reconnaissance.

Generates targeted Google dorks for:
- Exposed files and directories
- Login pages and admin panels
- Error pages and information disclosure
- Database dumps and config files
- Subdomain discovery
"""

from __future__ import annotations

from typing import List, Dict
from urllib.parse import urlparse, quote_plus


# ---------------------------------------------------------------------------
# Dork templates organized by category
# ---------------------------------------------------------------------------

DORK_TEMPLATES: Dict[str, List[tuple]] = {
    "sensitive_files": [
        ("site:{target} filetype:env", "Environment files"),
        ("site:{target} filetype:sql", "SQL dump files"),
        ("site:{target} filetype:bak", "Backup files"),
        ("site:{target} filetype:log", "Log files"),
        ("site:{target} filetype:conf", "Configuration files"),
        ("site:{target} filetype:yml OR filetype:yaml", "YAML config files"),
        ("site:{target} filetype:json inurl:config", "JSON config files"),
        ("site:{target} filetype:xml inurl:config", "XML config files"),
        ("site:{target} ext:php inurl:phpinfo", "PHP info pages"),
        ("site:{target} ext:php inurl:phpmyadmin", "phpMyAdmin"),
        ("site:{target} inurl:wp-config.php.bak", "WordPress config backup"),
        ("site:{target} inurl:.git", "Git repositories"),
        ("site:{target} inurl:.svn", "SVN repositories"),
        ("site:{target} inurl:.env", "Environment files"),
        ("site:{target} inurl:dump", "Database dumps"),
        ("site:{target} inurl:backup", "Backup files"),
        ("site:{target} inurl:debug", "Debug pages"),
        ("site:{target} inurl:trace", "Trace endpoints"),
        ("site:{target} inurl:swagger OR inurl:openapi", "API documentation"),
        ("site:{target} inurl:graphql", "GraphQL endpoints"),
    ],
    "login_admin": [
        ("site:{target} inurl:login", "Login pages"),
        ("site:{target} inurl:admin", "Admin panels"),
        ("site:{target} inurl:dashboard", "Dashboards"),
        ("site:{target} inurl:console", "Console pages"),
        ("site:{target} inurl:panel", "Control panels"),
        ("site:{target} inurl:manager", "Manager interfaces"),
        ("site:{target} inurl:portal", "Portal pages"),
        ("site:{target} intitle:\"admin login\"", "Admin login pages"),
        ("site:{target} intitle:\"control panel\"", "Control panels"),
        ("site:{target} inurl:wp-login.php", "WordPress login"),
        ("site:{target} inurl:administrator", "Joomla admin"),
        ("site:{target} inurl:user/login", "User login"),
        ("site:{target} inurl:auth/login", "Auth login"),
        ("site:{target} inurl:signin", "Sign-in pages"),
        ("site:{target} inurl:signup OR inurl:register", "Registration pages"),
    ],
    "info_disclosure": [
        ("site:{target} intitle:\"index of\"", "Directory listings"),
        ("site:{target} intitle:\"index of /\"", "Root directory listing"),
        ("site:{target} intitle:\"index of\" wp-content", "WordPress uploads listing"),
        ("site:{target} intitle:\"index of\" .git", "Git directory listing"),
        ("site:{target} intitle:\"error\" OR intitle:\"exception\"", "Error pages"),
        ("site:{target} intext:\"sql syntax\" OR intext:\"mysql_fetch\"", "SQL error messages"),
        ("site:{target} intext:\"Warning:\" intext:\"on line\"", "PHP error messages"),
        ("site:{target} intext:\"stack trace\" OR intext:\"Traceback\"", "Stack traces"),
        ("site:{target} intext:\"Internal Server Error\"", "Server errors"),
        ("site:{target} intext:\"Database Error\" OR intext:\"DB Error\"", "Database errors"),
        ("site:{target} intext:\"phpMyAdmin\" OR intext:\"MySQL\"", "Database interfaces"),
        ("site:{target} intext:\"API key\" OR intext:\"api_key\"", "API key exposure"),
        ("site:{target} intext:\"secret\" OR intext:\"password\" filetype:env", "Secrets in env files"),
    ],
    "subdomain_discovery": [
        ("site:*.{target} -www", "Subdomains"),
        ("site:*.{target}", "All subdomains"),
        ("site:*.{target} inurl:api", "API subdomains"),
        ("site:*.{target} inurl:admin", "Admin subdomains"),
        ("site:*.{target} inurl:dev OR inurl:staging", "Dev/staging subdomains"),
        ("site:*.{target} inurl:test OR inurl:sandbox", "Test subdomains"),
        ("site:*.{target} inurl:mail OR inurl:smtp", "Mail subdomains"),
        ("site:*.{target} inurl:cdn OR inurl:static", "CDN subdomains"),
    ],
    "sensitive_params": [
        ("site:{target} inurl:id= OR inurl:user= OR inurl:file=", "IDOR-prone parameters"),
        ("site:{target} inurl:redirect= OR inurl:url= OR inurl:next=", "Open redirect parameters"),
        ("site:{target} inurl:callback= OR inurl:cb=", "Callback parameters"),
        ("site:{target} inurl:token= OR inurl:key= OR inurl:secret=", "Token/key parameters"),
        ("site:{target} inurl:cmd= OR inurl:exec= OR inurl:command=", "Command injection parameters"),
        ("site:{target} inurl:include= OR inurl:path= OR inurl:file=", "File inclusion parameters"),
        ("site:{target} inurl:page= OR inurl:lang=", "LFI/RFI parameters"),
    ],
    "third_party_exposure": [
        ("site:pastebin.com \"{target}\"", "Pastebin leaks"),
        ("site:github.com \"{target}\"", "GitHub exposure"),
        ("site:gitlab.com \"{target}\"", "GitLab exposure"),
        ("site:bitbucket.org \"{target}\"", "Bitbucket exposure"),
        ("site:jsfiddle.net \"{target}\"", "JSFiddle exposure"),
        ("site:codepen.io \"{target}\"", "CodePen exposure"),
        ("site:docs.google.com \"{target}\"", "Google Docs exposure"),
        ("site:trello.com \"{target}\"", "Trello exposure"),
        ("site:slack.com \"{target}\"", "Slack exposure"),
    ],
}


class GoogleDorkingModule:
    """Generates Google dorks for bug bounty reconnaissance."""

    NAME = "google_dorking"

    def generate_dorks(self, target: str) -> List[Dict[str, str]]:
        """Generate Google dorks for a target domain.

        Args:
            target: Target domain (e.g., "example.com")

        Returns:
            List of dicts with 'category', 'dork', 'description', 'url'
        """
        # Clean target
        if target.startswith(("http://", "https://")):
            target = urlparse(target).netloc
        target = target.rstrip(".")

        results = []
        for category, templates in DORK_TEMPLATES.items():
            for template, description in templates:
                dork = template.format(target=target)
                google_url = f"https://www.google.com/search?q={quote_plus(dork)}"
                results.append({
                    "category": category,
                    "dork": dork,
                    "description": description,
                    "url": google_url,
                })

        return results

    def scan_url(self, url: str, **kwargs) -> list:
        """Scanner interface — generates dorks and returns as info findings."""
        from .findings import Finding

        findings = []
        parsed = urlparse(url)
        target = parsed.netloc

        dorks = self.generate_dorks(target)

        # Group by category
        categories = {}
        for d in dorks:
            cat = d["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(d)

        for cat, cat_dorks in categories.items():
            dork_list = "\n".join(f"  {d['dork']}" for d in cat_dorks[:10])
            findings.append(Finding(
                vuln_type="Google Dorking",
                title=f"Google dorks: {cat.replace('_', ' ')} ({len(cat_dorks)} dorks)",
                severity="INFO",
                url=url,
                evidence=dork_list[:500],
                description=f"Generated {len(cat_dorks)} Google dorks for {cat.replace('_', ' ')}.",
                remediation="Review exposed content and remove sensitive data from public access.",
                tool=self.NAME,
                confidence="INFO",
            ))

        return findings


__all__ = ["GoogleDorkingModule"]
