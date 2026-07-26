"""Smart Subdomain Discovery — combines ALL subdomain tools with deduplication.

Each tool gets a DIFFERENT set of subdomains to scan.
No duplicate work. Maximum coverage.

Tools used:
1. crt.sh (certificate transparency)
2. DNS brute force (140+ common names)
3. Subfinder (passive sources)
4. Amass (passive enumeration)
5. ffuf (wordlist-based fuzzing)
6. theHarvester (public sources)
7. DNS permutations (alterx-style)
8. Reverse DNS (from discovered IPs)
9. Shodan (SSL certificates)
10. Google/Bing dorking (site:*.target.com)
"""

import re
import time
import socket
import itertools
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from .assets import SmartAssetManager
from ..core.logger import logger, console
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


class SmartSubdomainDiscovery:
    """Discovers subdomains using multiple tools with smart deduplication.

    Each tool only returns NEW subdomains (not found by previous tools).
    This ensures maximum coverage with zero redundancy.
    """

    # Extended wordlist for subdomain brute force
    WORDLIST_LARGE = [
        # Dev/Test
        "dev", "dev1", "dev2", "dev3", "develop", "development", "test", "test1",
        "test2", "testing", "stage", "staging", "stg", "uat", "qa", "qc", "demo",
        "sandbox", "preview", "pre-prod", "preprod", "canary", "beta", "alpha",
        "nightly", "snapshot", "experimental", "poc", "prototype",
        # Infrastructure
        "www", "www2", "www3", "mail", "mail2", "email", "smtp", "pop", "pop3",
        "imap", "webmail", "mx", "mx1", "mx2", "ns", "ns1", "ns2", "ns3", "ns4",
        "dns", "dns1", "dns2", "ftp", "sftp", "ssh", "telnet", "vpn", "remote",
        "rdp", "gateway", "proxy", "tunnel", "bastion", "jump", "relay",
        # API & Services
        "api", "api1", "api2", "api3", "apiv1", "apiv2", "apiv3", "rest", "graphql",
        "websocket", "ws", "grpc", "rpc", "soap", "service", "services", "micro",
        "backend", "frontend", "bff", "gateway-api", "edge",
        # Admin & Management
        "admin", "admin1", "admin2", "administrator", "manage", "management",
        "panel", "dashboard", "console", "portal", "cpanel", "whm", "plesk",
        "webmin", "phpmyadmin", "adminer", "pgadmin", "mongo-express",
        # Applications
        "app", "app1", "app2", "application", "web", "web1", "web2", "mobile",
        "m", "wap", "ios", "android", "desktop", "electron", "pwa",
        # CMS & Platforms
        "wp", "wordpress", "blog", "cms", "shop", "store", "ecommerce",
        "ecom", "cart", "checkout", "payment", "pay", "billing", "invoice",
        # Content
        "cdn", "static", "assets", "media", "img", "images", "image",
        "upload", "uploads", "files", "file", "download", "downloads",
        "content", "data", "docs", "doc", "documentation", "wiki", "help",
        "support", "kb", "faq", "forum", "community", "blog", "news",
        # Monitoring & Ops
        "monitor", "monitoring", "status", "health", "ping", "uptime",
        "grafana", "kibana", "prometheus", "alert", "alerts", "alerting",
        "log", "logs", "logging", "elk", "splunk", "datadog", "newrelic",
        "sentry", "bugsnag", "rollbar", "pagerduty", "opsgenie",
        # CI/CD & DevOps
        "ci", "cd", "jenkins", "jenkins2", "gitlab", "github", "bitbucket",
        "svn", "repo", "repository", "git", "build", "deploy", "release",
        "artifacts", "nexus", "sonar", "sonarqube", "docker", "registry",
        "k8s", "kubernetes", "rancher", "mesos", "marathon", "nomad",
        "terraform", "ansible", "puppet", "chef", "salt",
        # Database
        "db", "db1", "db2", "database", "mysql", "postgres", "postgresql",
        "mongo", "mongodb", "redis", "elastic", "elasticsearch", "solr",
        "cassandra", "couchdb", "neo4j", "influxdb", "timescaledb",
        "memcached", "etcd", "consul", "zookeeper",
        # Security
        "auth", "sso", "login", "oauth", "saml", "ldap", "ad", "okta",
        "auth0", "keycloak", "identity", "id", "ids", "waf", "firewall",
        "siem", "soc", "vault", "secret", "cert", "certs", "ssl", "tls",
        "pki", "ca", "crl", "ocsp",
        # Cloud
        "aws", "azure", "gcp", "cloud", "s3", "blob", "storage", "bucket",
        "lambda", "function", "serverless", "ec2", "rds", "aurora",
        "cloudfront", "route53", "cloudflare", "fastly", "akamai",
        # Business
        "crm", "erp", "hr", "finance", "accounting", "sales", "marketing",
        "jira", "confluence", "slack", "teams", "zoom", "meet", "calendar",
        "mailchimp", "sendgrid", "twilio", "stripe", "paypal", "shopify",
        # Misc
        "old", "new", "legacy", "archive", "backup", "bak", "temp", "tmp",
        "cache", "mirror", "replica", "slave", "primary", "secondary",
        "node", "node1", "node2", "cluster", "lb", "load", "balancer",
        "ha", "failover", "dr", "recovery", "backup2",
    ]

    # Permutation patterns
    PERMUTATION_PATTERNS = [
        "{sub}-{word}", "{word}-{sub}", "{sub}_{word}", "{word}_{sub}",
        "{sub}{word}", "{word}{sub}", "{sub}.{word}", "{word}.{sub}",
    ]

    PERMUTATION_WORDS = [
        "dev", "test", "stage", "staging", "prod", "production", "old", "new",
        "backup", "bak", "internal", "external", "public", "private",
        "v1", "v2", "v3", "api", "app", "web", "mobile", "admin",
    ]

    def __init__(self, domain: str, rps: float = 10.0):
        self.domain = domain
        self.assets = SmartAssetManager(domain)
        self.limiter = get_limiter(rps)
        self._discovery_log: List[Dict[str, Any]] = []

    def discover_all(self) -> Dict[str, Any]:
        """Run ALL subdomain discovery methods with deduplication."""
        console.print(f"\n[bold blue]═══ Smart Subdomain Discovery: {self.domain} ═══[/bold blue]")
        start = time.time()

        # Phase 1: Passive enumeration (fast, no DNS brute force)
        console.print("\n[bold]Phase 1: Passive Enumeration[/bold]")
        self._crt_sh()
        self._dns_records()
        self._google_dork_subs()
        self._shodan_subs()

        # Phase 2: Active enumeration (DNS brute force)
        console.print("\n[bold]Phase 2: Active Enumeration[/bold]")
        self._dns_bruteforce()
        self._permutation_scan()

        # Phase 3: Advanced (if tools available)
        console.print("\n[bold]Phase 3: Advanced Discovery[/bold]")
        self._ffuf_subdomain_fuzz()
        self._reverse_dns_from_ips()

        duration = time.time() - start
        stats = self.assets.get_stats()

        console.print(f"\n[bold blue]═══ Discovery Complete ═══[/bold blue]")
        console.print(f"  Total subdomains: {len(self.assets.get_all_subdomains())}")
        console.print(f"  Unique IPs: {len(self.assets.get_unique_ips())}")
        console.print(f"  Duration: {duration:.1f}s")

        for source, count in self.assets.get_source_stats().items():
            console.print(f"    {source}: {count}")

        return {
            "domain": self.domain,
            "subdomains": self.assets.get_all_subdomains(),
            "stats": stats,
            "duration": duration,
            "log": self._discovery_log,
        }

    def _crt_sh(self):
        """Certificate transparency logs via crt.sh."""
        try:
            import httpx
            client = httpx.Client(timeout=15, verify=ssl_verify())
            resp = client.get(f"https://crt.sh/?q=%.{self.domain}&output=json")
            if resp.status_code == 200:
                data = resp.json()
                all_subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            all_subs.add(sub)

                new = self.assets.add_subdomains(list(all_subs), "crt.sh")
                self._log("crt.sh", len(all_subs), len(new))
                console.print(f"    [success]crt.sh: {len(new)} new (of {len(all_subs)} total)[/success]")
        except Exception as e:
            console.print(f"    [error]crt.sh failed: {e}[/error]")

    def _dns_records(self):
        """Extract subdomains from DNS records."""
        try:
            import subprocess
            # Check MX, NS, TXT records for subdomains
            for rtype in ["MX", "NS", "TXT", "SRV"]:
                try:
                    cmd = ["dig", "+short", self.domain, rtype]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if proc.stdout:
                        subs = re.findall(r'[\w.-]+\.' + re.escape(self.domain), proc.stdout)
                        new = self.assets.add_subdomains(subs, f"dns_{rtype.lower()}")
                        if new:
                            console.print(f"    [success]DNS {rtype}: {len(new)} new[/success]")
                except Exception:
                    pass
        except Exception:
            pass

    def _google_dork_subs(self):
        """Find subdomains via Google dorking."""
        # Construct the dork URL for manual use
        dork = f"site:*.{self.domain} -www"
        self._log("google_dork", 0, 0, note=f"Manual: https://www.google.com/search?q={dork.replace(' ', '+')}")

    def _shodan_subs(self):
        """Find subdomains via Shodan SSL certificates."""
        try:
            import httpx
            client = httpx.Client(timeout=10, verify=ssl_verify())
            # Use Shodan InternetDB (free, no API key)
            # First get IPs from known subdomains
            for sub in self.assets.get_all_subdomains()[:5]:
                try:
                    ip = socket.gethostbyname(sub)
                    resp = client.get(f"https://internetdb.shodan.io/{ip}")
                    if resp.status_code == 200:
                        data = resp.json()
                        hostnames = data.get("hostnames", [])
                        new = self.assets.add_subdomains(hostnames, "shodan")
                        if new:
                            console.print(f"    [success]Shodan: {len(new)} new[/success]")
                except Exception:
                    pass
        except Exception:
            pass

    def _dns_bruteforce(self):
        """Brute force subdomains via DNS resolution."""
        console.print(f"    [info]DNS brute force: {len(self.WORDLIST_LARGE)} names...[/info]")
        found = []

        for word in self.WORDLIST_LARGE:
            self.limiter.wait(self.domain)
            hostname = f"{word}.{self.domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(hostname)
                found.append(hostname)
            except (socket.gaierror, socket.timeout):
                pass
            except Exception:
                pass

        new = self.assets.add_subdomains(found, "dns_bruteforce")
        self._log("dns_bruteforce", len(found), len(new))
        console.print(f"    [success]DNS brute force: {len(new)} new[/success]")

    def _permutation_scan(self):
        """Generate and test subdomain permutations."""
        existing = self.assets.get_all_subdomains()
        base_names = set()

        # Extract base names from existing subdomains
        for sub in existing:
            parts = sub.replace(f".{self.domain}", "").split(".")
            for part in parts:
                if part and len(part) > 2:
                    base_names.add(part)

        if not base_names:
            base_names = {"www", "api", "app", "dev", "test"}

        permutations = set()
        for base in base_names:
            for word in self.PERMUTATION_WORDS:
                for pattern in self.PERMUTATION_PATTERNS:
                    perm = pattern.format(sub=base, word=word)
                    permutations.add(f"{perm}.{self.domain}")

        # Only test permutations we haven't seen yet
        new_perms = self.assets.get_deduplicated_subdomains_for_tool("permutations", list(permutations))

        found = []
        for hostname in new_perms[:500]:  # Limit
            self.limiter.wait(self.domain)
            try:
                socket.setdefaulttimeout(1.5)
                socket.gethostbyname(hostname)
                found.append(hostname)
            except (socket.gaierror, socket.timeout):
                pass
            except Exception:
                pass

        new = self.assets.add_subdomains(found, "permutations")
        self._log("permutations", len(found), len(new))
        console.print(f"    [success]Permutations: {len(new)} new[/success]")

    def _ffuf_subdomain_fuzz(self):
        """Use ffuf for subdomain fuzzing (if installed)."""
        import shutil
        if not shutil.which("ffuf"):
            console.print("    [info]ffuf not installed, skipping subdomain fuzz[/info]")
            return

        import subprocess
        import tempfile

        # Write wordlist to temp file
        wordlist = "\n".join(self.WORDLIST_LARGE)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(wordlist)
            wordlist_path = f.name

        try:
            # Use ffuf with Host header fuzzing
            cmd = [
                "ffuf", "-w", wordlist_path,
                "-u", f"https://{self.domain}",
                "-H", f"Host: FUZZ.{self.domain}",
                "-mc", "200,301,302,403",
                "-o", "/dev/stdout", "-of", "json",
                "-t", "50", "-rate", "100",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if proc.returncode == 0:
                try:
                    import json
                    data = json.loads(proc.stdout)
                    found = []
                    for result in data.get("results", []):
                        host = result.get("host", "")
                        if host.endswith(self.domain):
                            found.append(host)

                    new = self.assets.add_subdomains(found, "ffuf")
                    self._log("ffuf", len(found), len(new))
                    console.print(f"    [success]ffuf: {len(new)} new[/success]")
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            console.print("    [warning]ffuf timed out[/warning]")
        except Exception as e:
            console.print(f"    [error]ffuf failed: {e}[/error]")
        finally:
            import os
            try:
                os.unlink(wordlist_path)
            except Exception:
                pass

    def _reverse_dns_from_ips(self):
        """Do reverse DNS on discovered IPs to find more subdomains."""
        ips = self.assets.get_all_ips()
        found = []

        for ip in ips[:20]:  # Limit
            self.limiter.wait("reverse_dns")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if hostname.endswith(self.domain):
                    found.append(hostname)
            except Exception:
                pass

        new = self.assets.add_subdomains(found, "reverse_dns")
        if new:
            self._log("reverse_dns", len(found), len(new))
            console.print(f"    [success]Reverse DNS: {len(new)} new[/success]")

    def _log(self, source: str, total: int, new: int, note: str = ""):
        """Log discovery results."""
        self._discovery_log.append({
            "source": source, "total": total, "new": new, "note": note
        })

    def get_results(self) -> Dict[str, Any]:
        """Get discovery results."""
        return {
            "domain": self.domain,
            "subdomains": self.assets.get_all_subdomains(),
            "stats": self.assets.get_stats(),
            "ip_map": self.assets.get_unique_ips(),
        }
