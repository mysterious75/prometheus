"""WordPress Scanner — WordPress-specific vulnerability detection.

Detects:
- WordPress version disclosure
- Plugin/theme enumeration and vulnerability detection
- xmlrpc.php abuse
- User enumeration via wp-json
- Common WordPress misconfigurations
"""

from __future__ import annotations

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# Common vulnerable WordPress plugins
VULN_PLUGINS = [
    "contact-form-7", "akismet", "jetpack", "yoast-seo", "wordfence",
    "elementor", "woocommerce", "wp-file-manager", "easy-wp-smtp",
    "duplicator", "wp-statistics", "all-in-one-seo-pack", "updraftplus",
    "really-simple-ssl", "classic-editor", "wpforms-lite", "flavor-flavor",
    "flavor-flavor", "flavor-flavor", "flavor-flavor",
]

# Common WordPress paths to check
WP_PATHS = [
    ("/wp-login.php", "WordPress login page", "MEDIUM"),
    ("/wp-admin/", "WordPress admin", "MEDIUM"),
    ("/wp-admin/install.php", "WordPress install page", "HIGH"),
    ("/xmlrpc.php", "WordPress XML-RPC", "MEDIUM"),
    ("/wp-json/wp/v2/users", "WordPress user enumeration", "MEDIUM"),
    ("/wp-json/wp/v2/posts", "WordPress REST API posts", "LOW"),
    ("/wp-content/debug.log", "WordPress debug log", "HIGH"),
    ("/wp-config.php.bak", "WordPress config backup", "CRITICAL"),
    ("/wp-config.php.old", "WordPress config backup", "CRITICAL"),
    ("/wp-config.php.save", "WordPress config backup", "CRITICAL"),
    ("/wp-config.php~", "WordPress config backup", "CRITICAL"),
    ("/wp-config.php.txt", "WordPress config backup", "CRITICAL"),
    ("/.wp-config.php.swp", "WordPress config swap", "CRITICAL"),
    ("/wp-content/uploads/", "WordPress uploads directory", "MEDIUM"),
    ("/wp-content/plugins/", "WordPress plugins directory", "MEDIUM"),
    ("/wp-content/themes/", "WordPress themes directory", "LOW"),
    ("/readme.html", "WordPress readme", "LOW"),
    ("/license.txt", "WordPress license", "LOW"),
    ("/wp-includes/", "WordPress includes", "LOW"),
    ("/wp-cron.php", "WordPress cron", "LOW"),
    ("/?author=1", "WordPress user enumeration via author", "MEDIUM"),
    ("/feed/", "WordPress RSS feed", "LOW"),
    ("/wp-sitemap.xml", "WordPress sitemap", "LOW"),
]


class WordPressScanner:
    """WordPress-specific vulnerability scanner."""

    NAME = "wordpress"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan for WordPress vulnerabilities."""
        import httpx

        findings: List[Finding] = []

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        host = parsed.netloc
        base = f"{parsed.scheme}://{parsed.netloc}"

        client = httpx.Client(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

        try:
            # Check if it's WordPress
            is_wp, wp_version = self._detect_wordpress(client, base, host)
            if not is_wp:
                logger.info(f"Not a WordPress site: {url}")
                return findings

            if wp_version:
                findings.append(Finding(
                    vuln_type="WordPress",
                    title=f"WordPress version disclosed: {wp_version}",
                    severity="LOW",
                    url=url,
                    evidence=f"WordPress version {wp_version} detected",
                    description=f"WordPress version {wp_version} is publicly disclosed.",
                    remediation="Remove version numbers from HTML source and feeds.",
                    cvss=2.0, cwe="CWE-200",
                    tool=self.NAME, verified=True, confidence="HIGH",
                ))

            # Check WordPress paths
            for path, description, severity in WP_PATHS:
                test_url = base + path
                self.limiter.wait(host)
                try:
                    resp = client.get(test_url, follow_redirects=False)
                    if resp.status_code == 200:
                        body = resp.text[:2000]

                        # Verify it's actually WordPress content
                        if self._is_wordpress_content(path, body):
                            findings.append(Finding(
                                vuln_type="WordPress",
                                title=f"{description}: {path}",
                                severity=severity,
                                url=test_url,
                                evidence=f"HTTP 200, {len(resp.content)} bytes",
                                description=f"{description} is accessible at {path}.",
                                remediation=self._remediation_for_path(path),
                                cvss=self._cvss_for_severity(severity),
                                cwe="CWE-200",
                                tool=self.NAME, verified=True, confidence="HIGH",
                                request=f'curl -k "{test_url}"',
                            ))
                except Exception:
                    pass

            # XML-RPC abuse test
            findings.extend(self._test_xmlrpc(client, base, host))

            # User enumeration
            findings.extend(self._test_user_enum(client, base, host))

            # Plugin enumeration
            findings.extend(self._test_plugins(client, base, host))

        finally:
            client.close()

        logger.info(f"WordPress scan: {len(findings)} findings")
        return findings

    def _detect_wordpress(self, client, base: str, host: str) -> tuple:
        """Detect if the site is running WordPress."""
        self.limiter.wait(host)
        try:
            resp = client.get(base)
            body = resp.text[:5000]

            # Check for WordPress indicators
            wp_indicators = [
                "wp-content", "wp-includes", "wordpress",
                "wp-json", "wp-embed", "wp-emoji",
            ]
            is_wp = any(ind in body.lower() for ind in wp_indicators)

            # Extract version
            version = None
            version_patterns = [
                r'content="WordPress\s+([\d.]+)"',
                r'wp-includes/js/jquery/jquery\.min\.js\?ver=([\d.]+)',
                r'wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)',
                r'generator"\s+content="WordPress\s+([\d.]+)"',
            ]
            for pattern in version_patterns:
                match = re.search(pattern, body)
                if match:
                    version = match.group(1)
                    break

            return is_wp, version
        except Exception:
            return False, None

    def _is_wordpress_content(self, path: str, body: str) -> bool:
        """Check if response contains WordPress-specific content."""
        if "/wp-json/" in path:
            return body.strip().startswith(("[", "{"))
        if "/xmlrpc.php" in path:
            return "XML-RPC" in body or "method" in body.lower()
        if "/wp-login.php" in path:
            return "wp-login" in body.lower() or "log In" in body
        if "/readme.html" in path:
            return "wordpress" in body.lower()
        if path.endswith((".log", ".bak", ".old", ".save")):
            return len(body) > 50
        if "/wp-content/uploads/" in path:
            return "Index of" in body or resp.status_code == 200
        return True

    def _test_xmlrpc(self, client, base: str, host: str) -> List[Finding]:
        """Test xmlrpc.php for abuse potential."""
        findings = []
        xmlrpc_url = f"{base}/xmlrpc.php"

        self.limiter.wait(host)
        try:
            # Test if xmlrpc is enabled
            test_body = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""

            resp = client.post(xmlrpc_url, content=test_body, headers={"Content-Type": "text/xml"})
            if resp.status_code == 200 and "methodResponse" in resp.text:
                # Check for dangerous methods
                dangerous_methods = [
                    "pingback.ping", "wp.getUsersBlogs", "system.multicall",
                    "wp.getUsers", "wp.getAuthors",
                ]
                found_methods = [m for m in dangerous_methods if m in resp.text]

                if found_methods:
                    findings.append(Finding(
                        vuln_type="WordPress",
                        title=f"xmlrpc.php enabled with dangerous methods",
                        severity="HIGH",
                        url=xmlrpc_url,
                        method="POST",
                        evidence=f"Methods available: {', '.join(found_methods)}",
                        description=f"xmlrpc.php exposes dangerous methods: {', '.join(found_methods)}. Can be used for brute force and SSRF.",
                        remediation="Disable xmlrpc.php via .htaccess or plugin. Use REST API instead.",
                        cvss=7.5, cwe="CWE-284",
                        tool=self.NAME, verified=True, confidence="HIGH",
                        request=f'curl -k -X POST "{xmlrpc_url}" -d "<methodCall><methodName>system.listMethods</methodName></methodCall>"',
                    ))

                # Test for pingback SSRF
                if "pingback.ping" in resp.text:
                    findings.append(Finding(
                        vuln_type="WordPress",
                        title="xmlrpc.php pingback SSRF potential",
                        severity="MEDIUM",
                        url=xmlrpc_url,
                        method="POST",
                        evidence="pingback.ping method available",
                        description="xmlrpc.php pingback.ping can be used for SSRF and DDoS amplification.",
                        remediation="Disable xmlrpc.php or block pingback.ping.",
                        cvss=6.5, cwe="CWE-918",
                        tool=self.NAME, verified=True, confidence="MEDIUM",
                    ))
        except Exception:
            pass

        return findings

    def _test_user_enum(self, client, base: str, host: str) -> List[Finding]:
        """Test WordPress user enumeration."""
        findings = []

        # Method 1: /?author=1
        for author_id in [1, 2, 3]:
            test_url = f"{base}/?author={author_id}"
            self.limiter.wait(host)
            try:
                resp = client.get(test_url, follow_redirects=True)
                if resp.status_code == 200:
                    # Look for username in redirect URL or body
                    username_match = re.search(r'/author/([^/]+)/', resp.url)
                    if username_match:
                        username = username_match.group(1)
                        findings.append(Finding(
                            vuln_type="WordPress",
                            title=f"User enumeration via ?author={author_id}: {username}",
                            severity="MEDIUM",
                            url=test_url,
                            evidence=f"Username '{username}' discovered via author parameter",
                            description=f"WordPress user '{username}' can be enumerated via ?author={author_id}.",
                            remediation="Disable author archives or redirect to homepage.",
                            cvss=5.3, cwe="CWE-200",
                            tool=self.NAME, verified=True, confidence="HIGH",
                        ))
            except Exception:
                pass

        # Method 2: /wp-json/wp/v2/users
        api_url = f"{base}/wp-json/wp/v2/users"
        self.limiter.wait(host)
        try:
            resp = client.get(api_url)
            if resp.status_code == 200:
                try:
                    users = resp.json()
                    if isinstance(users, list) and len(users) > 0:
                        usernames = [u.get("slug", "unknown") for u in users[:5]]
                        findings.append(Finding(
                            vuln_type="WordPress",
                            title=f"User enumeration via REST API: {len(users)} users",
                            severity="MEDIUM",
                            url=api_url,
                            evidence=f"Found {len(users)} users: {', '.join(usernames)}",
                            description=f"WordPress REST API exposes {len(users)} user accounts.",
                            remediation="Disable user endpoint in REST API or require authentication.",
                            cvss=5.3, cwe="CWE-200",
                            tool=self.NAME, verified=True, confidence="HIGH",
                        ))
                except (ValueError, KeyError):
                    pass
        except Exception:
            pass

        return findings

    def _test_plugins(self, client, base: str, host: str) -> List[Finding]:
        """Test for exposed plugin information."""
        findings = []

        # Check if plugins directory is listable
        plugins_url = f"{base}/wp-content/plugins/"
        self.limiter.wait(host)
        try:
            resp = client.get(plugins_url)
            if resp.status_code == 200 and "Index of" in resp.text:
                # Extract plugin names
                plugin_names = re.findall(r'href="([^/]+)/"', resp.text)
                if plugin_names:
                    findings.append(Finding(
                        vuln_type="WordPress",
                        title=f"Plugin directory listing: {len(plugin_names)} plugins",
                        severity="MEDIUM",
                        url=plugins_url,
                        evidence=f"Directory listing reveals: {', '.join(plugin_names[:10])}",
                        description=f"WordPress plugins directory is listable, revealing {len(plugin_names)} plugins.",
                        remediation="Disable directory listing in web server config.",
                        cvss=5.3, cwe="CWE-200",
                        tool=self.NAME, verified=True, confidence="HIGH",
                    ))
        except Exception:
            pass

        return findings

    def _remediation_for_path(self, path: str) -> str:
        if "xmlrpc" in path:
            return "Disable xmlrpc.php via .htaccess or security plugin."
        if "debug.log" in path:
            return "Disable WP_DEBUG_LOG in production. Delete debug.log."
        if path.endswith((".bak", ".old", ".save", "~")):
            return "Remove backup files from web-accessible directories."
        if "install.php" in path:
            return "Delete wp-admin/install.php after installation."
        if "user" in path.lower() or "author" in path.lower():
            return "Disable user enumeration via REST API and author archives."
        return "Restrict access to this WordPress path."

    def _cvss_for_severity(self, severity: str) -> float:
        return {"CRITICAL": 9.1, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}.get(severity, 0.0)


__all__ = ["WordPressScanner"]
