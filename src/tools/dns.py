"""DNS Tools — dig, nslookup, dnsenum, fierce, dnsrecon, amass.

Discovers DNS records, zone transfers, subdomains, and DNS-based attacks.
"""

import subprocess
import socket
import time
import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


@dataclass
class DNSRecord:
    """A DNS record."""
    type: str  # A, AAAA, MX, NS, TXT, CNAME, SOA, SRV
    name: str
    value: str
    ttl: int = 0
    priority: int = 0


@dataclass
class DNSResult:
    """DNS enumeration result."""
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    zone_transfer: bool = False
    zone_data: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self):
        return {
            "domain": self.domain,
            "records": [{"type": r.type, "name": r.name, "value": r.value} for r in self.records],
            "nameservers": self.nameservers,
            "zone_transfer": self.zone_transfer,
            "subdomains": self.subdomains[:50],
        }


class DNSTools:
    """Comprehensive DNS enumeration and analysis."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR"]

    # Common subdomains for brute force
    BRUTE_SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
        "test", "beta", "alpha", "demo", "sandbox", "uat", "qa", "ci", "cd",
        "admin", "panel", "dashboard", "portal", "console", "manage", "internal",
        "app", "web", "mobile", "ios", "android", "m", "wap",
        "blog", "news", "forum", "community", "support", "help", "docs",
        "cdn", "static", "media", "img", "images", "assets", "files",
        "shop", "store", "ecommerce", "pay", "billing", "invoice",
        "vpn", "remote", "ssh", "rdp", "gateway", "proxy", "tunnel",
        "git", "gitlab", "github", "bitbucket", "svn", "repo", "code",
        "jenkins", "ci", "build", "deploy", "release", "artifacts",
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
        "log", "logs", "monitor", "grafana", "kibana", "prometheus", "alert",
        "backup", "bak", "old", "archive", "legacy", "v1", "v2", "v3",
        "auth", "sso", "login", "oauth", "saml", "ldap", "ad",
        "k8s", "kubernetes", "docker", "container", "registry", "helm",
        "aws", "azure", "gcp", "cloud", "s3", "blob", "storage",
        "status", "health", "ping", "uptime", "metrics",
        "webmail", "email", "mx", "exchange", "outlook", "zimbra",
        "crm", "erp", "hr", "finance", "jira", "confluence", "slack",
    ]

    def __init__(self, rps: float = 10.0):
        self.limiter = get_limiter(rps)

    def full_enum(self, domain: str) -> DNSResult:
        """Full DNS enumeration on a domain."""
        start = time.time()
        result = DNSResult(domain=domain)

        console.print(f"  [tool]▸ DNS Enumeration[/tool] → [target]{domain}[/target]")

        # 1. Basic DNS records
        result.records = self.get_records(domain)

        # 2. Nameservers
        result.nameservers = self.get_nameservers(domain)

        # 3. Zone transfer attempt
        if result.nameservers:
            zone_result = self.try_zone_transfer(domain, result.nameservers)
            result.zone_transfer = zone_result[0]
            result.zone_data = zone_result[1]
            if result.zone_transfer:
                result.subdomains.extend(zone_result[1])

        # 4. Subdomain brute force
        brute_subs = self.brute_force_subdomains(domain)
        result.subdomains.extend(brute_subs)

        # 5. Certificate transparency
        ct_subs = self.crt_sh_enum(domain)
        result.subdomains.extend(ct_subs)

        # Deduplicate
        result.subdomains = list(dict.fromkeys(result.subdomains))
        result.duration = time.time() - start

        console.print(f"  [tool]◂ DNS[/tool] — {len(result.records)} records, {len(result.subdomains)} subdomains, zone_transfer={result.zone_transfer}")

        return result

    def get_records(self, domain: str) -> List[DNSRecord]:
        """Get all DNS record types for a domain."""
        records = []
        for rtype in self.RECORD_TYPES:
            try:
                cmd = ["dig", "+short", "+noall", "+answer", domain, rtype]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if line:
                            # Parse dig output
                            value = line
                            priority = 0
                            if rtype == "MX" and " " in line:
                                parts = line.split()
                                priority = int(parts[0])
                                value = parts[1]
                            records.append(DNSRecord(
                                type=rtype, name=domain, value=value, priority=priority
                            ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback to Python socket
                records.extend(self._python_dns_lookup(domain, rtype))
            except Exception:
                continue

        return records

    def _python_dns_lookup(self, domain: str, rtype: str) -> List[DNSRecord]:
        """Fallback DNS lookup using Python socket."""
        records = []
        try:
            if rtype == "A":
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    records.append(DNSRecord(type="A", name=domain, value=ip))
            elif rtype == "MX":
                # Try nslookup fallback
                try:
                    result = subprocess.run(
                        ["nslookup", "-type=MX", domain],
                        capture_output=True, text=True, timeout=10
                    )
                    for line in result.stdout.split("\n"):
                        if "mail exchanger" in line.lower():
                            match = re.search(r'mail exchanger = (\d+)\s+(\S+)', line)
                            if match:
                                records.append(DNSRecord(
                                    type="MX", name=domain,
                                    value=match.group(2), priority=int(match.group(1))
                                ))
                except Exception:
                    pass
        except Exception:
            pass
        return records

    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain."""
        ns_records = []
        try:
            cmd = ["dig", "+short", domain, "NS"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                ns_records = [line.strip().rstrip('.') for line in result.stdout.strip().split("\n") if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                result = subprocess.run(
                    ["nslookup", "-type=NS", domain],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "nameserver" in line.lower():
                        match = re.search(r'nameserver = (\S+)', line)
                        if match:
                            ns_records.append(match.group(1))
            except Exception:
                pass
        except Exception:
            pass

        return ns_records

    def try_zone_transfer(self, domain: str, nameservers: List[str]) -> tuple:
        """Attempt DNS zone transfer (AXFR)."""
        for ns in nameservers:
            try:
                cmd = ["dig", f"@{ns}", domain, "AXFR"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and "XFR size" in result.stdout:
                    # Zone transfer successful!
                    records = []
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if line and not line.startswith(";") and "\t" in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                records.append(parts[0].rstrip('.'))
                    console.print(f"  [critical]⚠ ZONE TRANSFER SUCCESSFUL on {ns}[/critical]")
                    return (True, list(set(records)))
            except Exception:
                continue

        return (False, [])

    def brute_force_subdomains(self, domain: str) -> List[str]:
        """Brute force subdomains via DNS resolution."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _check_sub(sub):
            self.limiter.wait(domain)
            hostname = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(hostname)
                return hostname
            except (socket.gaierror, socket.timeout):
                return None
            except Exception:
                return None

        found = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_check_sub, sub): sub for sub in self.BRUTE_SUBDOMAINS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    console.print(f"    [success]+ {result}[/success]")

        return found

    def crt_sh_enum(self, domain: str) -> List[str]:
        """Enumerate subdomains via crt.sh certificate transparency."""
        try:
            import httpx
        except ImportError:
            return []

        subdomains = set()
        try:
            client = httpx.Client(timeout=15, verify=ssl_verify())
            resp = client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")

        return sorted(subdomains)

    def dns_enum_dig(self, domain: str) -> Dict[str, Any]:
        """Detailed DNS enumeration using dig."""
        results = {}
        for rtype in self.RECORD_TYPES:
            try:
                cmd = ["dig", "+noall", "+answer", "+authority", "+additional", domain, rtype]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.stdout.strip():
                    results[rtype] = result.stdout.strip()
            except Exception:
                continue
        return results

    def reverse_dns(self, ip: str) -> List[str]:
        """Reverse DNS lookup."""
        hostnames = []
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            hostnames.append(hostname)
        except Exception:
            pass

        # Also try dig
        try:
            cmd = ["dig", "+short", "-x", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    h = line.strip().rstrip('.')
                    if h and h not in hostnames:
                        hostnames.append(h)
        except Exception:
            pass

        return hostnames

    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC configuration."""
        try:
            cmd = ["dig", "+dnssec", "+short", domain, "DNSKEY"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            has_dnssec = bool(result.stdout.strip())

            cmd2 = ["dig", "+short", domain, "RRSIG"]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)

            return {
                "has_dnssec": has_dnssec,
                "dnskey_records": result.stdout.strip().split("\n") if has_dnssec else [],
                "rrsig_records": result2.stdout.strip().split("\n") if result2.stdout.strip() else [],
            }
        except Exception:
            return {"has_dnssec": False}
