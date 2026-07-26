"""Sensitive File Disclosure Scanner — probes for 100+ exposed paths.

Detects exposed environment files, config files, version control,
backups, admin panels, debug endpoints, cloud credentials, etc.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


# ---------------------------------------------------------------------------
# Sensitive paths organized by category
# (path, description, severity)
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    # === Environment & Config ===
    ("/.env", "Environment file", "CRITICAL"),
    ("/.env.local", "Local environment file", "CRITICAL"),
    ("/.env.production", "Production environment file", "CRITICAL"),
    ("/.env.development", "Development environment file", "CRITICAL"),
    ("/.env.staging", "Staging environment file", "CRITICAL"),
    ("/.env.backup", "Backup environment file", "CRITICAL"),
    ("/.env.old", "Old environment file", "CRITICAL"),
    ("/.env.save", "Saved environment file", "CRITICAL"),
    ("/.env.dist", "Distribution environment file", "HIGH"),
    ("/.env.example", "Example environment file", "MEDIUM"),
    ("/config.json", "JSON configuration", "HIGH"),
    ("/config.yml", "YAML configuration", "HIGH"),
    ("/config.yaml", "YAML configuration", "HIGH"),
    ("/config.php", "PHP configuration", "HIGH"),
    ("/config.inc.php", "PHP include configuration", "CRITICAL"),
    ("/configuration.php", "Joomla configuration", "CRITICAL"),
    ("/settings.json", "Settings file", "HIGH"),
    ("/settings.yml", "Settings file", "HIGH"),
    ("/appsettings.json", "ASP.NET settings", "HIGH"),
    ("/appsettings.Development.json", "ASP.NET dev settings", "HIGH"),
    ("/local_settings.py", "Django local settings", "CRITICAL"),
    ("/application.properties", "Spring Boot properties", "HIGH"),
    ("/application.yml", "Spring Boot YAML", "HIGH"),
    ("/application-dev.yml", "Spring Boot dev config", "HIGH"),

    # === Version Control ===
    ("/.git/config", "Git configuration", "CRITICAL"),
    ("/.git/HEAD", "Git HEAD reference", "HIGH"),
    ("/.gitignore", "Git ignore rules", "LOW"),
    ("/.svn/entries", "SVN entries", "HIGH"),
    ("/.svn/wc.db", "SVN working copy database", "HIGH"),
    ("/.hg/dirstate", "Mercurial state", "HIGH"),

    # === Backup Files ===
    ("/backup.zip", "Backup archive", "HIGH"),
    ("/backup.tar.gz", "Backup archive", "HIGH"),
    ("/backup.sql", "Database backup", "CRITICAL"),
    ("/backup.bak", "Backup file", "HIGH"),
    ("/dump.sql", "Database dump", "CRITICAL"),
    ("/db.sql", "Database dump", "CRITICAL"),
    ("/database.sql", "Database dump", "CRITICAL"),
    ("/data.sql", "Data export", "CRITICAL"),
    ("/export.sql", "SQL export", "CRITICAL"),
    ("/site.zip", "Site backup", "HIGH"),
    ("/www.zip", "WWW backup", "HIGH"),
    ("/public.zip", "Public backup", "HIGH"),
    ("/html.zip", "HTML backup", "HIGH"),
    ("/backup.rar", "RAR backup", "HIGH"),
    ("/db.sqlite", "SQLite database", "CRITICAL"),
    ("/db.sqlite3", "SQLite3 database", "CRITICAL"),

    # === Server & Admin ===
    ("/server-status", "Apache server status", "HIGH"),
    ("/server-info", "Apache server info", "HIGH"),
    ("/info.php", "PHP info page", "HIGH"),
    ("/phpinfo.php", "PHP info page", "HIGH"),
    ("/test.php", "Test PHP file", "MEDIUM"),
    ("/debug", "Debug interface", "HIGH"),
    ("/debug/vars", "Debug variables", "HIGH"),
    ("/debug/pprof", "Go pprof debug", "HIGH"),
    ("/actuator", "Spring Actuator", "HIGH"),
    ("/actuator/env", "Spring environment", "CRITICAL"),
    ("/actuator/health", "Spring health", "MEDIUM"),
    ("/actuator/beans", "Spring beans", "HIGH"),
    ("/actuator/configprops", "Spring config properties", "HIGH"),
    ("/actuator/mappings", "Spring URL mappings", "MEDIUM"),
    ("/actuator/info", "Spring info", "LOW"),
    ("/console", "Admin console", "HIGH"),
    ("/admin-console", "Admin console", "HIGH"),
    ("/manager/html", "Tomcat manager", "CRITICAL"),
    ("/host-manager/html", "Tomcat host manager", "CRITICAL"),
    ("/jmx-console", "JMX console", "CRITICAL"),
    ("/web-console", "Web console", "HIGH"),

    # === Docker & DevOps ===
    ("/.dockerenv", "Docker environment", "MEDIUM"),
    ("/Dockerfile", "Dockerfile exposed", "MEDIUM"),
    ("/docker-compose.yml", "Docker Compose config", "HIGH"),
    ("/docker-compose.yaml", "Docker Compose config", "HIGH"),
    ("/.dockerignore", "Docker ignore file", "LOW"),

    # === SSH & Keys ===
    ("/id_rsa", "SSH private key", "CRITICAL"),
    ("/id_rsa.pub", "SSH public key", "MEDIUM"),
    ("/id_dsa", "DSA private key", "CRITICAL"),
    ("/id_ecdsa", "ECDSA private key", "CRITICAL"),
    ("/.ssh/authorized_keys", "SSH authorized keys", "HIGH"),
    ("/.ssh/config", "SSH configuration", "HIGH"),
    ("/.ssh/known_hosts", "SSH known hosts", "MEDIUM"),

    # === Package Files ===
    ("/package.json", "Node.js package", "LOW"),
    ("/package-lock.json", "Node.js lock file", "LOW"),
    ("/composer.json", "PHP Composer file", "LOW"),
    ("/composer.lock", "PHP Composer lock", "LOW"),
    ("/Gemfile", "Ruby Gemfile", "LOW"),
    ("/Gemfile.lock", "Ruby lock file", "LOW"),
    ("/requirements.txt", "Python requirements", "LOW"),
    ("/Pipfile", "Python Pipfile", "LOW"),
    ("/Pipfile.lock", "Python lock file", "LOW"),
    ("/go.mod", "Go module file", "LOW"),
    ("/Cargo.toml", "Rust Cargo file", "LOW"),
    ("/pom.xml", "Maven POM", "LOW"),
    ("/build.gradle", "Gradle build", "LOW"),

    # === NPM/Node ===
    ("/.npmrc", "NPM config with tokens", "HIGH"),
    ("/.yarnrc", "Yarn config", "MEDIUM"),
    ("/yarn.lock", "Yarn lock file", "LOW"),
    ("/.nvmrc", "Node version manager config", "LOW"),

    # === CI/CD ===
    ("/.github/workflows", "GitHub Actions workflows", "MEDIUM"),
    ("/.gitlab-ci.yml", "GitLab CI config", "MEDIUM"),
    ("/Jenkinsfile", "Jenkins pipeline", "MEDIUM"),
    ("/.travis.yml", "Travis CI config", "MEDIUM"),
    ("/.circleci/config.yml", "CircleCI config", "MEDIUM"),
    ("/azure-pipelines.yml", "Azure Pipelines config", "MEDIUM"),
    ("/bitbucket-pipelines.yml", "Bitbucket Pipelines config", "MEDIUM"),
    ("/buildspec.yml", "AWS CodeBuild spec", "MEDIUM"),
    ("/cloudbuild.yaml", "Google Cloud Build", "MEDIUM"),

    # === Cloud Credentials ===
    ("/.aws/credentials", "AWS credentials", "CRITICAL"),
    ("/.aws/config", "AWS config", "HIGH"),
    ("/service-account.json", "GCP service account", "CRITICAL"),
    ("/.gcloud/credentials", "GCP credentials", "CRITICAL"),
    ("/.azure/credentials", "Azure credentials", "CRITICAL"),

    # === Database ===
    ("/dump.rdb", "Redis dump", "CRITICAL"),
    ("/redis.conf", "Redis configuration", "HIGH"),
    ("/mongod.conf", "MongoDB configuration", "HIGH"),
    ("/.db", "Database file", "HIGH"),

    # === WordPress ===
    ("/wp-config.php", "WordPress configuration", "CRITICAL"),
    ("/wp-content/debug.log", "WordPress debug log", "HIGH"),
    ("/xmlrpc.php", "WordPress XML-RPC", "MEDIUM"),
    ("/wp-json/wp/v2/users", "WordPress user enumeration", "MEDIUM"),

    # === Laravel ===
    ("/storage/logs/laravel.log", "Laravel log file", "HIGH"),
    ("/bootstrap/cache/config.php", "Laravel cached config", "HIGH"),

    # === Django ===
    ("/settings.py", "Django settings", "CRITICAL"),
    ("/static/admin/css/base.css", "Django admin static", "LOW"),

    # === Well-Known ===
    ("/.well-known/security.txt", "Security contact", "LOW"),
    ("/.well-known/openid-configuration", "OpenID configuration", "MEDIUM"),
    ("/.well-known/assetlinks.json", "Android asset links", "LOW"),
    ("/.well-known/apple-app-site-association", "Apple app association", "LOW"),

    # === Miscellaneous ===
    ("/robots.txt", "Robots file", "LOW"),
    ("/sitemap.xml", "Sitemap", "LOW"),
    ("/crossdomain.xml", "Flash cross-domain policy", "MEDIUM"),
    ("/clientaccesspolicy.xml", "Silverlight policy", "MEDIUM"),
    ("/humans.txt", "Humans.txt", "LOW"),
    ("/security.txt", "Security contact", "LOW"),
    ("/ads.txt", "Ads.txt", "LOW"),
    ("/.DS_Store", "macOS directory metadata", "MEDIUM"),
    ("/Thumbs.db", "Windows thumbnail cache", "LOW"),
    ("/.editorconfig", "Editor configuration", "LOW"),
    ("/.prettierrc", "Prettier config", "LOW"),
    ("/tsconfig.json", "TypeScript config", "LOW"),
    ("/webpack.config.js", "Webpack config", "LOW"),
    ("/next.config.js", "Next.js config", "LOW"),
    ("/nuxt.config.js", "Nuxt.js config", "LOW"),
    ("/vite.config.js", "Vite config", "LOW"),

    # === Exposed APIs ===
    ("/swagger.json", "Swagger/OpenAPI spec", "HIGH"),
    ("/swagger-ui.html", "Swagger UI", "MEDIUM"),
    ("/api-docs", "API documentation", "MEDIUM"),
    ("/openapi.json", "OpenAPI spec", "HIGH"),
    ("/openapi.yaml", "OpenAPI spec", "HIGH"),
    ("/graphiql", "GraphQL IDE", "MEDIUM"),
    ("/graphql", "GraphQL endpoint", "MEDIUM"),

    # === Debug & Monitoring ===
    ("/metrics", "Prometheus metrics", "HIGH"),
    ("/prometheus", "Prometheus UI", "HIGH"),
    ("/grafana", "Grafana dashboard", "HIGH"),
    ("/kibana", "Kibana dashboard", "HIGH"),
    ("/.env.test", "Test environment file", "HIGH"),
]


# ---------------------------------------------------------------------------
# Content patterns for deeper analysis
# ---------------------------------------------------------------------------

ENV_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*\s*=\s*.+$", re.MULTILINE)
GIT_HEAD_PATTERN = re.compile(r"^ref: refs/heads/.+$", re.MULTILINE)
KEY_PATTERN = re.compile(r"(?i)(password|secret|key|token|api_key|apikey|private)\s*[:=]\s*\S+", re.MULTILINE)


class FileDisclosureScanner(BaseScanner):
    """Probes for sensitive files that shouldn't be publicly accessible."""

    NAME = "file_disclosure"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Probe a target for exposed sensitive files."""
        import httpx

        findings: List[Finding] = []
        base = url.rstrip("/")
        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=ssl_verify(), timeout=self.timeout, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

        try:
            for path, description, severity in SENSITIVE_PATHS:
                test_url = base + path
                self.limiter.wait(host)

                try:
                    resp = client.get(test_url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                body = resp.text if hasattr(resp, "text") else ""
                body_bytes = resp.content

                # Minimum content check
                if len(body_bytes) < 10:
                    continue

                # False positive filtering
                body_lower = body[:500].lower()
                if any(fp in body_lower for fp in [
                    "404", "not found", "error page", "page not found",
                    "the page you requested", "does not exist",
                ]):
                    continue

                # Content-based verification
                verified, content_evidence = self._verify_content(path, body, body_bytes)

                if not verified:
                    continue

                # Build evidence
                evidence = f"HTTP {resp.status_code}, {len(body_bytes)} bytes"
                if content_evidence:
                    evidence += f" | {content_evidence}"

                # Scan for embedded secrets
                secrets = self._find_embedded_secrets(body)
                secret_evidence = ""
                if secrets:
                    secret_evidence = f" | Secrets found: {', '.join(s[0] for s in secrets[:3])}"

                findings.append(Finding(
                    vuln_type="Information Disclosure",
                    title=f"Sensitive file exposed: {path}",
                    severity=severity,
                    url=test_url,
                    method="GET",
                    evidence=(evidence + secret_evidence)[:500],
                    description=f"{description} is publicly accessible at {path}.",
                    remediation=f"Restrict access to {path}. Block via web server config or remove if not needed.",
                    cvss=self._cvss_for_severity(severity),
                    cwe="CWE-538",
                    tool=self.NAME,
                    verified=True,
                    confidence="HIGH",
                    request=f'curl -k "{test_url}"',
                    response_snippet=body[:500],
                ))

                # Add separate findings for embedded secrets
                for secret_type, secret_value in secrets:
                    findings.append(Finding(
                        vuln_type="Exposed Secret",
                        title=f"{secret_type} found in {path}",
                        severity="CRITICAL",
                        url=test_url,
                        method="GET",
                        payload=secret_value[:30] + "..." if len(secret_value) > 30 else secret_value,
                        evidence=f"{secret_type}: {secret_value[:50]}...",
                        description=f"{secret_type} is exposed in {path}. Immediate rotation required.",
                        remediation=f"Rotate the {secret_type} immediately. Remove from publicly accessible files.",
                        cvss=9.1,
                        cwe="CWE-798",
                        tool=self.NAME,
                        verified=True,
                        confidence="CONFIRMED",
                        request=f'curl -k "{test_url}"',
                    ))

        finally:
            client.close()

        logger.info(f"File disclosure scan: {len(findings)} findings from {len(SENSITIVE_PATHS)} paths checked")
        return findings

    def _verify_content(self, path: str, body: str, body_bytes: bytes) -> Tuple[bool, str]:
        """Verify the response is actually the sensitive file, not a false positive."""
        lower_path = path.lower()

        # .env files: should have KEY=*** patterns
        if ".env" in lower_path:
            matches = ENV_PATTERN.findall(body)
            if matches:
                return True, f"{len(matches)} env vars found"
            return False, ""

        # .git/HEAD
        if path == "/.git/HEAD":
            if GIT_HEAD_PATTERN.match(body.strip()):
                return True, f"Git ref: {body.strip()}"
            return False, ""

        # .git/config
        if path == "/.git/config":
            if "[core]" in body or "[remote" in body:
                return True, "Git config structure detected"
            return False, ""

        # SQL dumps
        if lower_path.endswith(".sql"):
            if any(kw in body[:1000].upper() for kw in [
                "CREATE TABLE", "INSERT INTO", "DROP TABLE", "ALTER TABLE", "mysqldump",
            ]):
                return True, "SQL dump structure detected"
            return False, ""

        # ZIP/archive files
        if lower_path.endswith((".zip", ".rar", ".tar.gz", ".gz")):
            # Check magic bytes
            if body_bytes[:4] in [
                b"PK\x03\x04",  # ZIP
                b"Rar!\x1a",    # RAR
                b"\x1f\x8b",    # GZIP
            ]:
                return True, "Archive magic bytes confirmed"
            return False, ""

        # Private keys
        if "PRIVATE KEY" in body:
            return True, "Private key header detected"
        if "-----BEGIN" in body:
            return True, "Certificate/key header detected"

        # PHP files with config-like content
        if lower_path.endswith(".php") and path in ["/wp-config.php", "/configuration.php", "/config.php"]:
            if any(kw in body for kw in ["DB_PASSWORD", "db_password", "define(", "$password", "secret_key"]):
                return True, "PHP config with credentials detected"
            return False, ""

        # JSON/YAML config files
        if lower_path.endswith((".json", ".yml", ".yaml")):
            body_stripped = body.strip()
            if body_stripped.startswith(("{", "[")):
                return True, "Valid JSON/YAML structure"
            # YAML without braces
            if ":" in body[:200] and not body_stripped.startswith("<"):
                return True, "YAML-like structure"
            return False, ""

        # SSH keys
        if "id_rsa" in path or "id_dsa" in path or "id_ecdsa" in path:
            if "PRIVATE KEY" in body or "ssh-" in body:
                return True, "SSH key content"
            return False, ""

        # Docker/compose files
        if "docker" in lower_path or "compose" in lower_path:
            if any(kw in body[:500] for kw in ["version:", "services:", "image:", "FROM "]):
                return True, "Docker config structure"
            return False, ""

        # Generic: if it has sensitive content patterns
        key_matches = KEY_PATTERN.findall(body[:2000])
        if key_matches:
            return True, f"Sensitive keys found: {len(key_matches)}"

        # Default: accept 200 responses with substantial content
        if len(body_bytes) > 100:
            return True, ""

        return False, ""

    def _find_embedded_secrets(self, body: str) -> List[Tuple[str, str]]:
        """Find secrets embedded in file content."""
        secrets = []
        patterns = [
            ("AWS Key", r"AKIA[0-9A-Z]{16}"),
            ("AWS Secret", r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
            ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}"),
            ("Stripe Key", r"[sr]k_live_[0-9a-zA-Z]{24,}"),
            ("Generic Password", r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{6,})'),
            ("API Key", r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
            ("Secret Key", r'(?i)(?:secret[_-]?key|secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
            ("DB Connection", r'(?i)(?:database_url|db_host|db_pass)\s*[:=]\s*["\']?([^"\'\s]+)'),
        ]
        for name, pattern in patterns:
            matches = re.findall(pattern, body)
            for match in matches[:2]:
                if len(match) > 5:
                    secrets.append((name, match if isinstance(match, str) else match[0] if match else ""))
        return secrets

    def _cvss_for_severity(self, severity: str) -> float:
        return {"CRITICAL": 9.1, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}.get(severity, 0.0)


__all__ = ["FileDisclosureScanner"]
