"""Nuclei Wrapper — template-based vulnerability scanner by ProjectDiscovery.

Runs nuclei via subprocess with JSON output parsing.
Falls back to built-in HTTP checks if nuclei binary is not installed.
"""

import json
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


# Sensitive paths to probe in fallback mode
_SENSITIVE_PATHS = [
    ("/.env", "Environment Configuration Exposed", "HIGH",
     "Application environment file accessible — may contain secrets, API keys, and credentials.",
     "Restrict access to .env files via web server configuration; place outside web root."),
    ("/.env.local", "Local Environment File Exposed", "HIGH",
     "Local environment override file accessible.",
     "Move .env.local outside the web-accessible directory."),
    ("/.env.production", "Production Environment Exposed", "CRITICAL",
     "Production environment file with live credentials accessible.",
     "Never deploy .env files to web-accessible paths; use secrets manager."),
    ("/.git/config", "Git Repository Exposed", "HIGH",
     "Git configuration file accessible — repository may be fully downloadable.",
     "Block .git directory access in web server config (e.g., deny all on /.git)."),
    ("/.git/HEAD", "Git HEAD Reference Exposed", "HIGH",
     "Git HEAD file accessible — confirms repository exposure.",
     "Block .git directory access in web server configuration."),
    ("/.svn/entries", "SVN Repository Exposed", "HIGH",
     "Subversion metadata accessible — source code may leak.",
     "Remove .svn directories from deployments or block via web server."),
    ("/.hg/dirstate", "Mercurial Repository Exposed", "HIGH",
     "Mercurial repository metadata accessible.",
     "Remove .hg directory from web-accessible paths."),
    ("/robots.txt", "Robots.txt Disclosure", "INFO",
     "Robots.txt reveals hidden paths and crawl directives.",
     "Review robots.txt for sensitive path disclosures; remove sensitive entries."),
    ("/sitemap.xml", "Sitemap Disclosure", "INFO",
     "Sitemap reveals site structure and hidden endpoints.",
     "Review sitemap for unintended path disclosures."),
    ("/.htaccess", "Htaccess File Exposed", "MEDIUM",
     "Apache htaccess configuration file accessible — may reveal rewrite rules and access controls.",
     "Deny access to .ht* files via Apache configuration."),
    ("/.htpasswd", "Htpasswd File Exposed", "CRITICAL",
     "Apache password file exposed — contains hashed credentials.",
     "Deny access to .htpasswd and move outside web root."),
    ("/server-status", "Apache Server Status Page", "MEDIUM",
     "Apache mod_status accessible — reveals server metrics and connections.",
     "Restrict /server-status to internal IPs only."),
    ("/server-info", "Apache Server Info Page", "MEDIUM",
     "Apache mod_info accessible — reveals server configuration.",
     "Restrict /server-info to internal IPs only."),
    ("/phpinfo.php", "PHP Info Exposed", "MEDIUM",
     "phpinfo() page accessible — reveals full server configuration, paths, and extensions.",
     "Remove phpinfo.php from production; disable in php.ini."),
    ("/info.php", "PHP Info Exposed (alt)", "MEDIUM",
     "Alternative phpinfo() page accessible.",
     "Remove info.php from production deployments."),
    ("/wp-admin/", "WordPress Admin Panel", "MEDIUM",
     "WordPress admin login page accessible.",
     "Restrict wp-admin access; add IP allowlist or 2FA."),
    ("/wp-login.php", "WordPress Login Page", "MEDIUM",
     "WordPress login page exposed to brute force.",
     "Implement rate limiting, CAPTCHA, or IP restriction on wp-login.php."),
    ("/wp-json/wp/v2/users", "WordPress User Enumeration", "MEDIUM",
     "WordPress REST API user enumeration endpoint accessible.",
     "Disable user enumeration via REST API or restrict access."),
    ("/admin/", "Admin Panel Accessible", "MEDIUM",
     "Administrative interface accessible at default path.",
     "Move admin panel to non-standard path; restrict by IP and add authentication."),
    ("/administrator/", "Joomla Admin Panel", "MEDIUM",
     "Joomla administrator panel accessible.",
     "Restrict access to administrator panel by IP."),
    ("/api-docs", "API Documentation Exposed", "LOW",
     "API documentation publicly accessible.",
     "Restrict API docs to internal/staging environments."),
    ("/swagger.json", "Swagger Specification Exposed", "LOW",
     "OpenAPI/Swagger spec accessible — reveals full API surface.",
     "Restrict Swagger endpoint; remove from production."),
    ("/swagger-ui/", "Swagger UI Exposed", "LOW",
     "Interactive Swagger UI accessible.",
     "Remove Swagger UI from production environments."),
    ("/graphql", "GraphQL Endpoint Exposed", "LOW",
     "GraphQL endpoint accessible — may allow introspection queries.",
     "Disable introspection in production; implement query depth limiting."),
    ("/graphiql", "GraphiQL Interface Exposed", "LOW",
     "Interactive GraphQL IDE accessible.",
     "Remove GraphiQL from production environments."),
    ("/.DS_Store", "macOS DS_Store File Exposed", "LOW",
     "macOS .DS_Store file accessible — may reveal directory structure.",
     "Add .DS_Store to .gitignore and block via web server."),
    ("/.well-known/security.txt", "Security.txt Found", "INFO",
     "security.txt file found with vulnerability disclosure information.",
     "No remediation needed — this is intentional."),
    ("/crossdomain.xml", "Cross-Domain Policy File", "LOW",
     "Flash cross-domain policy file may allow unauthorized cross-origin requests.",
     "Restrict crossdomain.xml to trusted domains only."),
    ("/clientaccesspolicy.xml", "Silverlight Cross-Domain Policy", "LOW",
     "Silverlight cross-domain policy accessible.",
     "Remove or restrict clientaccesspolicy.xml."),
    ("/.npmrc", "NPM Configuration Exposed", "HIGH",
     "NPM configuration file may contain registry tokens.",
     "Remove .npmrc from web-accessible paths."),
    ("/.dockerenv", "Docker Environment File", "MEDIUM",
     "Docker environment file accessible.",
     "Remove Docker-specific files from web root."),
    ("/Dockerfile", "Dockerfile Exposed", "MEDIUM",
     "Dockerfile accessible — reveals application build configuration.",
     "Exclude Dockerfile from deployment artifacts."),
    ("/docker-compose.yml", "Docker Compose Config Exposed", "MEDIUM",
     "Docker Compose file accessible — reveals infrastructure setup.",
     "Exclude docker-compose.yml from deployments."),
    ("/.ssh/authorized_keys", "SSH Authorized Keys Exposed", "CRITICAL",
     "SSH authorized_keys file accessible — potential unauthorized access.",
     "Ensure .ssh directory is not within web root."),
    ("/backup.sql", "Database Backup Exposed", "CRITICAL",
     "SQL database backup file accessible.",
     "Remove database backups from web-accessible storage."),
    ("/dump.sql", "Database Dump Exposed", "CRITICAL",
     "SQL dump file accessible.",
     "Never store database dumps in web-accessible paths."),
    ("/db.sql", "Database File Exposed", "CRITICAL",
     "SQL database file accessible.",
     "Remove database files from web root."),
    ("/.bash_history", "Bash History Exposed", "HIGH",
     "Shell history file accessible — may contain passwords and commands.",
     "Ensure home directories are not web-accessible."),
    ("/.bashrc", "Shell Configuration Exposed", "MEDIUM",
     "Shell configuration file accessible.",
     "Ensure dotfiles are not served by the web server."),
    ("/wp-config.php", "WordPress Config Exposed", "CRITICAL",
     "WordPress configuration file accessible — contains database credentials.",
     "Block PHP config files; place wp-config.php outside web root."),
    ("/config.php", "PHP Config Exposed", "CRITICAL",
     "PHP configuration file with potential credentials accessible.",
     "Move config files outside web root; block via server config."),
    ("/config.yml", "Application Config Exposed", "HIGH",
     "YAML configuration file accessible.",
     "Move config files outside web root."),
    ("/config.json", "JSON Config Exposed", "HIGH",
     "JSON configuration file accessible.",
     "Move config files outside web root."),
    ("/.gitignore", "Gitignore Exposed", "INFO",
     ".gitignore file accessible — reveals project structure.",
     "Remove .gitignore from production deployments."),
    ("/readme.md", "README File Exposed", "INFO",
     "README file accessible — may contain setup details.",
     "Remove README from production if it contains sensitive info."),
    ("/CHANGELOG.md", "Changelog Exposed", "INFO",
     "Changelog accessible — reveals version history.",
     "Remove changelog from production if not needed."),
    ("/.idea/", "IDE Configuration Exposed", "MEDIUM",
     "JetBrains IDE configuration directory accessible.",
     "Exclude .idea/ from deployments."),
    ("/.vscode/", "VS Code Configuration Exposed", "MEDIUM",
     "VS Code configuration directory accessible.",
     "Exclude .vscode/ from deployments."),

    # === API ENDPOINTS ===
    ("/api", "API Root Endpoint", "LOW", "API root endpoint accessible.", "Restrict API access in production."),
    ("/api/v1", "API v1 Endpoint", "LOW", "API v1 root accessible.", "Restrict API access."),
    ("/api/v2", "API v2 Endpoint", "LOW", "API v2 root accessible.", "Restrict API access."),
    ("/graphql", "GraphQL Endpoint", "MEDIUM", "GraphQL endpoint accessible — may allow introspection.", "Disable introspection in production; restrict access."),
    ("/graphiql", "GraphiQL Interface", "MEDIUM", "Interactive GraphQL IDE accessible.", "Remove GraphiQL from production."),
    ("/swagger-ui", "Swagger UI", "LOW", "Swagger UI accessible.", "Remove from production."),
    ("/openapi.json", "OpenAPI Spec", "LOW", "OpenAPI specification exposed.", "Restrict access to API specs."),
    ("/api/docs", "API Documentation", "LOW", "API docs accessible.", "Restrict to internal environments."),
    ("/api/swagger", "API Swagger", "LOW", "Swagger API docs accessible.", "Remove from production."),

    # === CONFIG FILES ===
    ("/config.php", "PHP Config Exposed", "HIGH", "PHP configuration file accessible.", "Move config outside web root."),
    ("/config.yml", "YAML Config Exposed", "HIGH", "YAML configuration file accessible.", "Move config outside web root."),
    ("/config.json", "JSON Config Exposed", "HIGH", "JSON configuration file accessible.", "Move config outside web root."),
    ("/config.js", "JS Config Exposed", "HIGH", "JavaScript configuration file accessible.", "Move config outside web root."),
    ("/config.xml", "XML Config Exposed", "HIGH", "XML configuration file accessible.", "Move config outside web root."),
    ("/settings.py", "Django Settings Exposed", "CRITICAL", "Django settings file with secrets accessible.", "Never expose settings.py to web."),
    ("/application.yml", "Spring Config Exposed", "HIGH", "Spring application config accessible.", "Move config outside web root."),
    ("/database.yml", "Database Config Exposed", "CRITICAL", "Database credentials file accessible.", "Never expose database config to web."),
    ("/wp-config.php", "WordPress Config Exposed", "CRITICAL", "WordPress config with DB credentials accessible.", "Move wp-config.php above web root."),
    ("/.env.backup", "Env Backup Exposed", "CRITICAL", "Environment backup file with credentials accessible.", "Never deploy backup files to web root."),
    ("/.env.staging", "Staging Env Exposed", "HIGH", "Staging environment file accessible.", "Remove staging configs from production."),
    ("/.env.development", "Dev Env Exposed", "HIGH", "Development environment file accessible.", "Remove dev configs from production."),

    # === BACKUP FILES ===
    ("/backup.zip", "Backup Archive Exposed", "CRITICAL", "Backup zip file accessible.", "Never deploy backups to web-accessible paths."),
    ("/backup.tar.gz", "Backup Archive Exposed", "CRITICAL", "Backup tar.gz file accessible.", "Never deploy backups to web root."),
    ("/backup.sql", "SQL Backup Exposed", "CRITICAL", "SQL database backup accessible.", "Never deploy DB backups to web root."),
    ("/db.sql", "Database Dump Exposed", "CRITICAL", "Database dump file accessible.", "Remove database dumps from web root."),
    ("/dump.sql", "Database Dump Exposed", "CRITICAL", "Database dump file accessible.", "Remove database dumps from web root."),
    ("/database.sql", "Database Backup Exposed", "CRITICAL", "Database backup file accessible.", "Remove database backups from web root."),
    ("/site.zip", "Site Backup Exposed", "CRITICAL", "Site backup archive accessible.", "Remove site backups from web root."),
    ("/www.zip", "WWW Backup Exposed", "CRITICAL", "Web root backup accessible.", "Remove web root backups."),
    ("/backup.rar", "Backup Archive Exposed", "CRITICAL", "RAR backup file accessible.", "Remove backup archives from web root."),
    ("/data.sql", "Data Dump Exposed", "CRITICAL", "Data dump file accessible.", "Remove data dumps from web root."),
    ("/export.sql", "Export File Exposed", "CRITICAL", "Database export file accessible.", "Remove export files from web root."),

    # === DEBUG/STATUS ===
    ("/debug", "Debug Endpoint", "MEDIUM", "Debug endpoint accessible.", "Disable debug endpoints in production."),
    ("/trace", "Trace Endpoint", "MEDIUM", "Trace endpoint accessible.", "Disable trace in production."),
    ("/status", "Status Page", "LOW", "Application status page accessible.", "Restrict status page access."),
    ("/health", "Health Check Endpoint", "INFO", "Health check endpoint accessible.", "Health checks are generally OK but review exposed data."),
    ("/info", "Info Endpoint", "MEDIUM", "Application info endpoint accessible.", "Restrict info endpoints."),
    ("/metrics", "Metrics Endpoint", "MEDIUM", "Prometheus metrics endpoint accessible.", "Restrict metrics to internal networks."),
    ("/actuator", "Spring Actuator", "HIGH", "Spring Boot Actuator accessible.", "Restrict actuator endpoints to internal IPs."),
    ("/actuator/env", "Spring Actuator Env", "CRITICAL", "Spring Actuator environment exposed — contains secrets.", "Disable actuator/env in production."),
    ("/actuator/health", "Spring Actuator Health", "LOW", "Spring Actuator health check.", "Review exposed health data."),
    ("/actuator/beans", "Spring Actuator Beans", "MEDIUM", "Spring Actuator beans exposed.", "Disable actuator/beans in production."),
    ("/h2-console", "H2 Database Console", "CRITICAL", "H2 database console accessible — allows RCE.", "Disable H2 console in production."),
    ("/console", "Console Endpoint", "HIGH", "Console/admin interface accessible.", "Restrict console access."),

    # === LOG FILES ===
    ("/logs", "Log Directory", "MEDIUM", "Log directory listing accessible.", "Restrict access to log directory."),
    ("/log.txt", "Log File Exposed", "MEDIUM", "Log file accessible.", "Move logs outside web root."),
    ("/error.log", "Error Log Exposed", "MEDIUM", "Error log file accessible.", "Move logs outside web root."),
    ("/access.log", "Access Log Exposed", "MEDIUM", "Access log file accessible.", "Move logs outside web root."),
    ("/debug.log", "Debug Log Exposed", "MEDIUM", "Debug log file accessible.", "Move logs outside web root."),
    ("/app.log", "Application Log", "MEDIUM", "Application log file accessible.", "Move logs outside web root."),

    # === SOURCE MAPS ===
    ("/app.js.map", "Source Map Exposed", "MEDIUM", "JavaScript source map accessible — reveals source code.", "Remove source maps from production builds."),
    ("/main.js.map", "Source Map Exposed", "MEDIUM", "JavaScript source map accessible.", "Remove source maps from production."),
    ("/bundle.js.map", "Source Map Exposed", "MEDIUM", "Bundle source map accessible.", "Remove source maps from production."),

    # === DOCKER ===
    ("/Dockerfile", "Dockerfile Exposed", "MEDIUM", "Dockerfile accessible — reveals build process.", "Exclude Dockerfile from deployments."),
    ("/docker-compose.yml", "Docker Compose Exposed", "HIGH", "Docker Compose config accessible — may contain secrets.", "Exclude docker-compose from deployments."),

    # === CI/CD ===
    ("/.github/workflows", "GitHub Actions Exposed", "MEDIUM", "GitHub Actions workflows accessible.", "Review workflows for secret leaks."),
    ("/.gitlab-ci.yml", "GitLab CI Exposed", "MEDIUM", "GitLab CI configuration accessible.", "Review CI config for secret leaks."),
    ("/Jenkinsfile", "Jenkinsfile Exposed", "MEDIUM", "Jenkins pipeline file accessible.", "Review Jenkinsfile for credentials."),
    ("/.travis.yml", "Travis CI Config", "LOW", "Travis CI configuration accessible.", "Review for secret leaks."),

    # === PACKAGE FILES ===
    ("/package.json", "Package.json Exposed", "LOW", "Node.js package.json accessible.", "Review for internal package names."),
    ("/composer.json", "Composer.json Exposed", "LOW", "PHP composer.json accessible.", "Review for internal packages."),
    ("/requirements.txt", "Requirements.txt", "LOW", "Python requirements file accessible.", "Review for internal packages."),
    ("/Gemfile", "Gemfile Exposed", "LOW", "Ruby Gemfile accessible.", "Review for internal gems."),
    ("/pom.xml", "Maven POM Exposed", "LOW", "Maven POM file accessible.", "Review for internal dependencies."),
    ("/build.gradle", "Gradle Build Exposed", "LOW", "Gradle build file accessible.", "Review for internal dependencies."),
    ("/yarn.lock", "Yarn Lock Exposed", "LOW", "Yarn lock file accessible.", "Review for dependency versions."),
    ("/package-lock.json", "Package Lock Exposed", "LOW", "npm lock file accessible.", "Review for dependency versions."),

    # === UPLOAD/TEMP DIRS ===
    ("/uploads", "Upload Directory", "MEDIUM", "Upload directory listing accessible.", "Disable directory listing; restrict access."),
    ("/upload", "Upload Directory", "MEDIUM", "Upload directory accessible.", "Disable directory listing."),
    ("/files", "Files Directory", "MEDIUM", "Files directory listing accessible.", "Disable directory listing."),
    ("/media", "Media Directory", "LOW", "Media directory listing accessible.", "Disable directory listing."),
    ("/static", "Static Directory", "LOW", "Static files directory listing accessible.", "Disable directory listing."),
    ("/tmp", "Temp Directory", "HIGH", "Temporary directory listing accessible.", "Restrict temp directory access."),
    ("/temp", "Temp Directory", "HIGH", "Temporary directory accessible.", "Restrict temp directory access."),

    # === COMMON PAGES ===
    ("/login", "Login Page", "INFO", "Login page accessible.", "Ensure proper rate limiting and CAPTCHA."),
    ("/register", "Registration Page", "INFO", "Registration page accessible.", "Ensure proper validation."),
    ("/signup", "Signup Page", "INFO", "Signup page accessible.", "Ensure proper validation."),
    ("/signin", "Signin Page", "INFO", "Signin page accessible.", "Ensure proper rate limiting."),
    ("/auth", "Auth Endpoint", "INFO", "Authentication endpoint accessible.", "Review auth implementation."),
    ("/forgot-password", "Password Reset", "INFO", "Password reset page accessible.", "Ensure rate limiting on reset."),
    ("/reset-password", "Password Reset", "INFO", "Password reset page accessible.", "Ensure rate limiting."),

    # === SECURITY ===
    ("/.well-known/security.txt", "Security.txt", "INFO", "Security.txt file accessible.", "Good practice — review content."),
    ("/security.txt", "Security.txt", "INFO", "Security.txt accessible.", "Good practice."),
    ("/humans.txt", "Humans.txt", "INFO", "Humans.txt accessible.", "Review for information disclosure."),

    # === FRAMEWORK-SPECIFIC ===
    ("/_profiler", "Symfony Profiler", "HIGH", "Symfony web profiler accessible.", "Disable profiler in production."),
    ("/_debug", "Debug Toolbar", "HIGH", "Debug toolbar accessible.", "Disable debug toolbar in production."),
    ("/debugbar", "Laravel Debugbar", "HIGH", "Laravel Debugbar accessible.", "Disable Debugbar in production."),
    ("/telescope", "Laravel Telescope", "HIGH", "Laravel Telescope accessible.", "Restrict Telescope to local environments."),
    ("/horizon", "Laravel Horizon", "MEDIUM", "Laravel Horizon dashboard accessible.", "Restrict Horizon access."),
    ("/pulse", "Laravel Pulse", "MEDIUM", "Laravel Pulse dashboard accessible.", "Restrict Pulse access."),

    # === WORDPRESS ===
    ("/wp-content", "WordPress Content Directory", "LOW", "WordPress content directory listing accessible.", "Disable directory listing in wp-content."),
    ("/wp-includes", "WordPress Includes", "LOW", "WordPress includes directory accessible.", "Restrict access to wp-includes."),
    ("/xmlrpc.php", "WordPress XML-RPC", "MEDIUM", "WordPress XML-RPC endpoint accessible — enables brute force.", "Disable XML-RPC if not needed."),
    ("/wp-json", "WordPress REST API", "MEDIUM", "WordPress REST API accessible.", "Restrict REST API endpoints."),
    ("/?author=1", "WordPress User Enum", "MEDIUM", "WordPress author enumeration via query parameter.", "Disable author enumeration."),

    # === LARAVEL ===
    ("/storage", "Laravel Storage", "MEDIUM", "Laravel storage directory accessible.", "Restrict storage access."),
    ("/vendor", "Vendor Directory", "MEDIUM", "PHP vendor directory accessible.", "Exclude vendor from web root."),
    ("/artisan", "Laravel Artisan", "MEDIUM", "Laravel artisan endpoint accessible.", "Remove artisan from web root."),

    # === DJANGO ===
    ("/admin", "Django Admin", "MEDIUM", "Django admin panel accessible.", "Restrict admin access."),
    ("/__debug__", "Django Debug Toolbar", "HIGH", "Django debug toolbar accessible.", "Disable debug toolbar in production."),

    # === NODE.JS ===
    ("/node_modules", "Node Modules Exposed", "MEDIUM", "node_modules directory accessible.", "Exclude node_modules from web root."),

    # === ADMIN PANELS ===
    ("/phpmyadmin", "phpMyAdmin", "HIGH", "phpMyAdmin interface accessible.", "Restrict phpMyAdmin to internal IPs."),
    ("/adminer", "Adminer Database", "HIGH", "Adminer database manager accessible.", "Remove Adminer from production."),
    ("/cpanel", "cPanel", "MEDIUM", "cPanel accessible.", "Restrict cPanel access."),
    ("/webmail", "Webmail Interface", "MEDIUM", "Webmail interface accessible.", "Restrict webmail access."),
    ("/manager", "Manager Panel", "MEDIUM", "Manager interface accessible.", "Restrict manager access."),
    ("/dashboard", "Dashboard", "MEDIUM", "Dashboard accessible.", "Restrict dashboard access."),
    ("/panel", "Admin Panel", "MEDIUM", "Admin panel accessible.", "Restrict panel access."),
    ("/backoffice", "Back Office", "MEDIUM", "Back office interface accessible.", "Restrict back office access."),
    ("/cms", "CMS Interface", "MEDIUM", "CMS interface accessible.", "Restrict CMS access."),

    # === MISC ===
    ("/test", "Test Endpoint", "MEDIUM", "Test endpoint accessible.", "Remove test endpoints from production."),
    ("/test.html", "Test Page", "LOW", "Test HTML page accessible.", "Remove test pages from production."),
    ("/search", "Search Endpoint", "INFO", "Search endpoint accessible.", "Review for injection vulnerabilities."),
    ("/feed", "RSS Feed", "INFO", "RSS feed accessible.", "Review feed content."),
    ("/rss", "RSS Feed", "INFO", "RSS feed accessible.", "Review feed content."),
    ("/atom.xml", "Atom Feed", "INFO", "Atom feed accessible.", "Review feed content."),
    ("/.well-known", "Well-Known Directory", "INFO", ".well-known directory accessible.", "Review for sensitive files."),
    ("/cgi-bin", "CGI Directory", "MEDIUM", "CGI bin directory accessible.", "Restrict CGI directory."),
    ("/bin", "Binary Directory", "MEDIUM", "Binary directory accessible.", "Restrict binary directory."),
    ("/scripts", "Scripts Directory", "MEDIUM", "Scripts directory accessible.", "Restrict scripts directory."),
    ("/includes", "Includes Directory", "MEDIUM", "Includes directory accessible.", "Restrict includes directory."),
    ("/classes", "Classes Directory", "MEDIUM", "Classes directory accessible.", "Restrict classes directory."),
    ("/lib", "Library Directory", "MEDIUM", "Library directory accessible.", "Restrict library directory."),
    ("/src", "Source Directory", "HIGH", "Source code directory accessible.", "Never expose source code to web."),
    ("/app", "App Directory", "HIGH", "Application directory accessible.", "Restrict app directory."),
    ("/internal", "Internal Endpoint", "MEDIUM", "Internal endpoint accessible.", "Restrict internal endpoints."),
    ("/private", "Private Directory", "HIGH", "Private directory accessible.", "Restrict private directory."),
    ("/secret", "Secret Endpoint", "HIGH", "Secret endpoint accessible.", "Restrict secret endpoints."),
    ("/hidden", "Hidden Endpoint", "MEDIUM", "Hidden endpoint accessible.", "Restrict hidden endpoints."),
]

# Security headers to check
_SECURITY_HEADERS = {
    "x-frame-options": ("Clickjacking Protection", "MEDIUM",
                        "Missing X-Frame-Options allows clickjacking attacks.",
                        "Add X-Frame-Options: DENY or SAMEORIGIN header."),
    "x-content-type-options": ("MIME Sniffing Protection", "LOW",
                               "Missing X-Content-Type-Options allows MIME-type attacks.",
                               "Add X-Content-Type-Options: nosniff header."),
    "strict-transport-security": ("HSTS Missing", "MEDIUM",
                                  "No HSTS header — users may be downgraded to HTTP.",
                                  "Add Strict-Transport-Security header with max-age >= 31536000."),
    "content-security-policy": ("CSP Missing", "MEDIUM",
                                "No Content-Security-Policy — vulnerable to XSS.",
                                "Implement a Content-Security-Policy header."),
    "x-xss-protection": ("XSS Protection Missing", "LOW",
                         "Missing X-XSS-Protection header.",
                         "Add X-XSS-Protection: 1; mode=block header."),
    "referrer-policy": ("Referrer Policy Missing", "LOW",
                        "No Referrer-Policy — may leak URLs in Referer header.",
                        "Add Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": ("Permissions Policy Missing", "LOW",
                           "No Permissions-Policy header.",
                           "Add Permissions-Policy to restrict browser features."),
    "x-permitted-cross-domain-policies": ("Cross-Domain Policy Missing", "LOW",
                                          "No cross-domain policy header.",
                                          "Add X-Permitted-Cross-Domain-Policies: none header."),
}


class NucleiScanner(BaseTool):
    """Wrapper around the nuclei vulnerability scanner."""

    name = "nuclei"
    binary = "nuclei"
    description = "Template-based vulnerability scanner (12,000+ YAML templates)"

    def scan(
        self,
        target: str,
        severity: str = "critical,high,medium",
        templates: Optional[str] = None,
        tags: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        """Run nuclei against a target."""
        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(target, **kwargs)

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ]
        if templates:
            cmd.extend(["-t", templates])
        if tags:
            cmd.extend(["-tags", tags])
        if kwargs.get("rate_limit"):
            cmd.extend(["-rate-limit", str(kwargs["rate_limit"])])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 600))
        duration = time.time() - start

        findings = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    info = entry.get("info", {})
                    findings.append({
                        "title": info.get("name", "Unknown Finding"),
                        "severity": info.get("severity", "info").upper(),
                        "description": info.get("description", ""),
                        "evidence": entry.get("matcher-name", entry.get("matched-at", "")),
                        "url": entry.get("matched-at", target),
                        "template_id": entry.get("template-id", ""),
                        "template_url": entry.get("template-url", ""),
                        "reference": info.get("reference", []),
                        "classification": info.get("classification", {}),
                        "extracted_results": entry.get("extracted-results", []),
                        "curl_command": entry.get("curl-command", ""),
                        "remediation": info.get("remediation", "Review and remediate the finding."),
                    })
                except json.JSONDecodeError:
                    continue

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, target: str, **kwargs) -> ToolResult:
        """Built-in HTTP checks when nuclei binary is not installed."""
        try:
            import httpx as httpx_lib
        except ImportError:
            try:
                import httpx
            except ImportError:
                return ToolResult(
                    tool=f"{self.name}(fallback)",
                    target=target,
                    success=False,
                    error="httpx not installed. Run: pip install httpx",
                )

        findings: List[Dict[str, Any]] = []
        start = time.time()
        limiter = get_limiter(rps=5.0)

        base = target.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"

        parsed = urlparse(base)
        host = parsed.hostname or base

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            client = httpx.Client(
                follow_redirects=True,
                timeout=8,
                verify=ssl_verify(),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
        except Exception as e:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error=f"Failed to create HTTP client: {e}",
                duration=time.time() - start,
            )

        # Probe sensitive paths
        for path, title, severity, description, remediation in _SENSITIVE_PATHS:
            limiter.wait(host)
            try:
                url = f"{base}{path}"
                resp = client.get(url)
                body = resp.text
                body_lower = body.lower()
                status = resp.status_code

                # Skip obvious non-findings
                if status in (403, 401, 404, 500, 502, 503):
                    continue

                if status == 200 and len(body) > 20:
                    # Filter false positives — check for error page signatures
                    false_positive_patterns = [
                        "404 not found", "page not found", "the page you requested",
                        "error 404", "not found", "does not exist",
                    ]
                    if any(fp in body_lower for fp in false_positive_patterns):
                        continue

                    # Validate specific content for certain paths
                    if path == "/.git/config" and "[core]" not in body:
                        continue
                    if path == "/.env" and "=" not in body:
                        continue
                    if path == "/.htpasswd" and ":" not in body:
                        continue
                    if path in ("/backup.sql", "/dump.sql", "/db.sql"):
                        sql_markers = ["create table", "insert into", "drop table", "alter table"]
                        if not any(m in body_lower for m in sql_markers):
                            continue

                    evidence = body[:300].replace("\n", " ").strip()
                    findings.append({
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "evidence": evidence,
                        "url": url,
                        "status_code": status,
                        "content_length": len(body),
                        "remediation": remediation,
                    })

            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError):
                continue
            except Exception as e:
                logger.debug(f"[{self.name}] Error checking {path}: {e}")
                continue

        # Check security headers on base URL
        limiter.wait(host)
        try:
            resp = client.get(base)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            for header_name, (title, severity, description, remediation) in _SECURITY_HEADERS.items():
                if header_name not in resp_headers:
                    missing.append(header_name)
                    findings.append({
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "evidence": f"Header '{header_name}' not present in response",
                        "url": base,
                        "header": header_name,
                        "remediation": remediation,
                    })

            # Check for server information leakage
            server = resp_headers.get("server", "")
            if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "tomcat/"]):
                findings.append({
                    "title": "Server Version Disclosure",
                    "severity": "LOW",
                    "description": f"Server header reveals software version: {server}",
                    "evidence": f"Server: {server}",
                    "url": base,
                    "remediation": "Remove or obfuscate the Server header version information.",
                })

            x_powered = resp_headers.get("x-powered-by", "")
            if x_powered:
                findings.append({
                    "title": "Technology Stack Disclosure",
                    "severity": "LOW",
                    "description": f"X-Powered-By header reveals technology: {x_powered}",
                    "evidence": f"X-Powered-By: {x_powered}",
                    "url": base,
                    "remediation": "Remove the X-Powered-By header.",
                })

        except Exception as e:
            logger.debug(f"[{self.name}] Header check failed: {e}")

        client.close()
        duration = time.time() - start

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )
