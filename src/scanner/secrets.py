"""Secrets Scanner — finds exposed API keys, tokens, and credentials."""

import re
from typing import List
from urllib.parse import urlparse

from .findings import Finding
from ..core.ratelimit import get_limiter


class SecretsScanner:
    """Finds exposed secrets, API keys, and credentials."""

    NAME = "secrets"

    # Regex patterns for common secrets
    PATTERNS = {
        "AWS Access Key": (r'AKIA[0-9A-Z]{16}', "CRITICAL"),
        "AWS Secret Key": (r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}', "CRITICAL"),
        "GitHub Token": (r'gh[ps]_[A-Za-z0-9_]{36,}', "HIGH"),
        "GitHub Fine-grained Token": (r'github_pat_[A-Za-z0-9_]{22,}', "HIGH"),
        "GitLab Token": (r'glpat-[A-Za-z0-9\-_]{20,}', "HIGH"),
        "Slack Token": (r'xox[bpsorta]-[0-9A-Za-z\-]{10,}', "HIGH"),
        "Slack Webhook": (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH"),
        "Stripe Key": (r'[sr]k_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
        "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', "HIGH"),
        "Heroku API Key": (r'(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "HIGH"),
        "Generic API Key": (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "MEDIUM"),
        "Generic Secret": (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "MEDIUM"),
        "Private Key": (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "CRITICAL"),
        "JWT Token": (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+', "HIGH"),
        "Basic Auth": (r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}', "HIGH"),
        "Firebase": (r'(?i)firebase[A-Za-z0-9_\-]*\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "MEDIUM"),
        "Twilio": (r'(?i)twilio.*[0-9a-fA-F]{32}', "HIGH"),
        "SendGrid": (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', "HIGH"),
        "Mailgun": (r'key-[0-9a-zA-Z]{32}', "HIGH"),
        "Algolia": (r'(?i)algolia.*[0-9a-fA-F]{32}', "MEDIUM"),
    }

    # Sensitive file paths to check
    SENSITIVE_PATHS = [
        ("/.env", "Environment file with secrets", "CRITICAL"),
        ("/.env.local", "Local environment file", "CRITICAL"),
        ("/.env.production", "Production environment file", "CRITICAL"),
        ("/.git/config", "Git configuration", "HIGH"),
        ("/.git/HEAD", "Git HEAD reference", "MEDIUM"),
        ("/config.json", "Configuration file", "MEDIUM"),
        ("/config.yml", "YAML configuration", "MEDIUM"),
        ("/wp-config.php", "WordPress configuration", "CRITICAL"),
        ("/configuration.php", "Joomla configuration", "CRITICAL"),
        ("/sites/default/settings.php", "Drupal settings", "CRITICAL"),
        ("/.htpasswd", "Password file", "HIGH"),
        ("/backup.zip", "Backup archive", "HIGH"),
        ("/backup.sql", "Database backup", "CRITICAL"),
        ("/dump.sql", "Database dump", "CRITICAL"),
        ("/db.sql", "Database dump", "CRITICAL"),
        ("/.dockerenv", "Docker environment", "MEDIUM"),
        ("/Dockerfile", "Dockerfile exposed", "LOW"),
        ("/docker-compose.yml", "Docker Compose config", "MEDIUM"),
        ("/package.json", "Node.js package file", "LOW"),
        ("/composer.json", "PHP Composer file", "LOW"),
        ("/yarn.lock", "Yarn lock file", "LOW"),
        ("/Gemfile", "Ruby Gemfile", "LOW"),
        ("/.npmrc", "NPM config with tokens", "HIGH"),
        ("/.npmrc", "NPM config", "HIGH"),
        ("/id_rsa", "SSH private key", "CRITICAL"),
        ("/.ssh/authorized_keys", "SSH authorized keys", "HIGH"),
    ]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan a URL for exposed secrets."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=10, verify=True,
                              headers={"User-Agent": "Mozilla/5.0"})
        base = url.rstrip("/")

        # Check sensitive files
        for path, desc, severity in self.SENSITIVE_PATHS:
            self.limiter.wait(urlparse(url).netloc)
            try:
                resp = client.get(f"{base}{path}")
                if resp.status_code == 200 and len(resp.text) > 20:
                    body = resp.text
                    # Filter out error pages
                    if any(fp in body.lower()[:200] for fp in ["404", "not found", "error page"]):
                        continue

                    # Scan content for secrets
                    secrets_found = self._find_secrets(body)

                    findings.append(Finding(
                        vuln_type="Information Disclosure",
                        title=f"Sensitive file exposed: {path}",
                        severity=severity,
                        url=f"{base}{path}",
                        method="GET",
                        evidence=body[:200],
                        description=f"{desc} is publicly accessible.",
                        remediation=f"Restrict access to {path}. Add to .gitignore if applicable.",
                        cvss=7.5 if severity == "CRITICAL" else 5.3,
                        cwe="CWE-538",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                    ))

                    # Add separate findings for discovered secrets
                    for secret_type, secret_value in secrets_found:
                        findings.append(Finding(
                            vuln_type="Exposed Secret",
                            title=f"{secret_type} found in {path}",
                            severity="CRITICAL",
                            url=f"{base}{path}",
                            method="GET",
                            payload=secret_value[:20] + "...",
                            evidence=f"{secret_type}: {secret_value[:50]}...",
                            description=f"{secret_type} is exposed in {path}. Immediate rotation required.",
                            remediation=f"Rotate the {secret_type} immediately. Remove from public files.",
                            cvss=9.1,
                            cwe="CWE-798",
                            tool=self.NAME,
                            verified=True,
                            confidence="CONFIRMED",
                        ))

            except Exception:
                continue

        return findings

    def scan_content(self, url: str, content: str) -> List[Finding]:
        """Scan page content for embedded secrets."""
        findings = []
        secrets = self._find_secrets(content)

        for secret_type, secret_value in secrets:
            findings.append(Finding(
                vuln_type="Exposed Secret",
                title=f"{secret_type} embedded in page content",
                severity="HIGH",
                url=url,
                evidence=f"{secret_type}: {secret_value[:50]}...",
                description=f"{secret_type} found in page source.",
                remediation="Remove secrets from client-side code. Use environment variables.",
                cvss=7.5,
                cwe="CWE-798",
                tool=self.NAME,
                verified=True,
                confidence="HIGH",
            ))

        return findings

    def _find_secrets(self, content: str) -> List[tuple]:
        """Find secrets in content. Returns [(type, value), ...]"""
        found = []
        for secret_type, (pattern, severity) in self.PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches[:3]:  # limit per type
                if len(match) > 5:  # filter noise
                    found.append((secret_type, match))
        return found
