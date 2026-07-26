"""Subfinder Wrapper — passive subdomain enumeration by ProjectDiscovery.

Runs subfinder via subprocess with -silent flag.
Falls back to crt.sh API + DNS brute force with 50+ common subdomain prefixes.
"""

import json
import time
import socket
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ──────────────────────────────────────────────────────────────────────
# 50+ common subdomain prefixes for DNS brute force fallback
# ──────────────────────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    # Core infrastructure
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "mx", "mx1", "mx2", "dns", "dns1", "dns2",
    # Development & staging
    "dev", "dev2", "development", "staging", "stage", "stg", "test",
    "testing", "qa", "uat", "sandbox", "demo", "preview", "pre",
    "beta", "alpha", "rc", "canary", "nightly",
    # Applications & services
    "api", "api2", "api3", "app", "app2", "apps", "web", "web2",
    "portal", "dashboard", "panel", "console", "admin", "administrator",
    "manage", "management", "cms", "backend", "frontend",
    # DevOps & CI/CD
    "jenkins", "ci", "cd", "gitlab", "github", "git", "svn", "hg",
    "jira", "confluence", "bitbucket", "bamboo", "teamcity", "travis",
    "drone", "argo", "argo-cd", "tekton", "buildkite",
    # Monitoring & observability
    "grafana", "kibana", "prometheus", "alertmanager", "elk", "splunk",
    "nagios", "zabbix", "datadog", "newrelic", "sentry", "status",
    "monitor", "monitoring", "metrics", "logs", "trace",
    # Databases & storage
    "db", "database", "mysql", "postgres", "postgresql", "mongo",
    "mongodb", "redis", "elasticsearch", "elastic", "memcached",
    "influxdb", "influx", "cassandra", "couchdb",
    # CDN & static
    "cdn", "static", "assets", "media", "img", "images", "files",
    "upload", "uploads", "downloads", "download", "content",
    # Security
    "vpn", "ssl", "cert", "auth", "sso", "oauth", "ldap", "ad",
    "ids", "waf", "firewall", "siem",
    # Communication
    "chat", "im", "irc", "slack", "teams", "zoom", "meet", "video",
    "voip", "sip", "pbx", "telephony",
    # Common services
    "shop", "store", "ecommerce", "pay", "payment", "billing",
    "support", "help", "helpdesk", "docs", "documentation", "wiki",
    "kb", "knowledge", "blog", "news", "forum", "community",
    # Infrastructure
    "proxy", "gateway", "lb", "load", "balancer", "haproxy", "nginx",
    "apache", "tomcat", "node", "nodejs", "php", "python", "ruby",
    "go", "java", "spring", "django", "flask", "rails",
    # Cloud & container
    "docker", "k8s", "kubernetes", "kube", "rancher", "mesos",
    "aws", "azure", "gcp", "cloud", "s3", "blob", "storage",
    "registry", "harbor", "ecr",
    # Misc
    "old", "new", "backup", "bak", "temp", "tmp", "archive",
    "internal", "intranet", "extranet", "private", "public",
    "mobile", "m", "wap", "touch", "amp",
    "cdn1", "cdn2", "edge", "origin",
    "ws", "websocket", "socket", "rpc", "grpc", "graphql",
    "search", "sphinx", "solr", "es",
    "queue", "rabbit", "rabbitmq", "kafka", "mq", "amqp",
    "cache", "memcache", "varnish",
    "log", "graylog", "fluentd", "filebeat",
    "crm", "erp", "hr", "finance", "accounting",
    "maps", "geo", "location",
]


class SubdomainEnumerator(BaseTool):
    """Wrapper around subfinder for passive subdomain enumeration."""

    name = "subfinder"
    binary = "subfinder"
    description = "Passive subdomain enumeration (40+ sources)"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Enumerate subdomains for a target domain."""
        domain = target.strip().lower()
        # Strip protocol if provided
        if "://" in domain:
            domain = domain.split("://", 1)[1].split("/")[0].split(":")[0]

        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(domain, **kwargs)

        cmd = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-all",
        ]
        if kwargs.get("recursive"):
            cmd.append("-recursive")
        if kwargs.get("sources"):
            cmd.extend(["-sources", kwargs["sources"]])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 180))
        duration = time.time() - start

        subdomains = []
        if result.returncode == 0 and result.stdout:
            subdomains = sorted(set(
                line.strip().lower()
                for line in result.stdout.strip().split("\n")
                if line.strip() and "." in line.strip()
            ))

        findings = [
            {
                "title": "Subdomain Discovered",
                "severity": "INFO",
                "description": f"Subdomain {sub} found for {domain}",
                "evidence": sub,
                "subdomain": sub,
                "remediation": "Review discovered subdomains for unauthorized or forgotten services.",
            }
            for sub in subdomains
        ]

        return ToolResult(
            tool=self.name,
            target=domain,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, domain: str, **kwargs) -> ToolResult:
        """Fallback: crt.sh certificate transparency + DNS brute force with 50+ prefixes."""
        subdomains: Set[str] = set()
        start = time.time()
        limiter = get_limiter(rps=10.0)

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # ── Method 1: crt.sh Certificate Transparency ──
        logger.info(f"[{self.name}(fallback)] Querying crt.sh for {domain}")
        try:
            import httpx
            client = httpx.Client(timeout=20, verify=False)
            resp = client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for line in name_value.split("\n"):
                            sub = line.strip().lower()
                            # Remove wildcards
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub.endswith(domain) and "*" not in sub:
                                # Validate it's a proper subdomain
                                if "." in sub and len(sub) < 255:
                                    subdomains.add(sub)
                except json.JSONDecodeError:
                    logger.warning(f"[{self.name}(fallback)] crt.sh returned invalid JSON")
            client.close()
        except Exception as e:
            logger.warning(f"[{self.name}(fallback)] crt.sh query failed: {e}")

        # ── Method 2: DNS brute force with thread pool ──
        logger.info(f"[{self.name}(fallback)] DNS brute force with {len(COMMON_SUBDOMAINS)} prefixes")

        def resolve_sub(prefix: str) -> Optional[str]:
            """Try to resolve a subdomain via DNS."""
            hostname = f"{prefix}.{domain}"
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(hostname)
                return hostname
            except (socket.gaierror, socket.timeout, OSError):
                return None

        # Threaded DNS resolution for speed
        resolved = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(resolve_sub, prefix): prefix for prefix in COMMON_SUBDOMAINS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resolved.append(result)

        subdomains.update(resolved)

        # ── Method 3: Try common DNS records via socket ──
        logger.info(f"[{self.name}(fallback)] Checking DNS records")
        try:
            # Try to get MX records (often reveal subdomains)
            import subprocess
            for cmd in [
                ["host", "-t", "MX", domain],
                ["host", "-t", "NS", domain],
                ["host", "-t", "TXT", domain],
            ]:
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if proc.returncode == 0:
                        for word in proc.stdout.split():
                            word = word.strip().rstrip(".")
                            if word.endswith(domain) and "." in word:
                                subdomains.add(word.lower())
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        except Exception:
            pass

        duration = time.time() - start

        # Deduplicate and sort
        sorted_subs = sorted(subdomains)

        findings = [
            {
                "title": "Subdomain Discovered",
                "severity": "INFO",
                "description": f"Subdomain {sub} found for {domain} via fallback enumeration",
                "evidence": sub,
                "subdomain": sub,
                "remediation": "Review discovered subdomains for unauthorized or forgotten services.",
            }
            for sub in sorted_subs
        ]

        raw_output = "\n".join(sorted_subs)

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=domain,
            success=True,
            findings=findings,
            raw_output=raw_output,
            duration=duration,
        )
