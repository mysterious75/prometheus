"""Subdomain Takeover Scanner — detects dangling DNS records.

Checks if subdomains point to services that can be hijacked.
"""

import re
import time
import socket
from typing import List, Dict, Any
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


@dataclass
class TakeoverResult:
    """Subdomain takeover check result."""
    subdomain: str
    vulnerable: bool
    service: str = ""
    cname: str = ""
    fingerprint: str = ""
    severity: str = "HIGH"

    def to_dict(self):
        return {
            "subdomain": self.subdomain, "vulnerable": self.vulnerable,
            "service": self.service, "cname": self.cname,
        }


class SubdomainTakeoverScanner:
    """Detects subdomain takeover vulnerabilities."""

    # Fingerprints for vulnerable services
    VULNERABLE_FINGERPRINTS = {
        "GitHub Pages": {
            "cname_patterns": [r"\.github\.io$", r"\.github\.com$"],
            "body_patterns": ["There isn't a GitHub Pages site here.", "For root URLs"],
            "status_codes": [404],
        },
        "Heroku": {
            "cname_patterns": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
            "body_patterns": ["No such app", "herokucdn.com/error-pages"],
            "status_codes": [404],
        },
        "AWS S3": {
            "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-website"],
            "body_patterns": ["NoSuchBucket", "The specified bucket does not exist"],
            "status_codes": [404],
        },
        "Azure Blob": {
            "cname_patterns": [r"\.blob\.core\.windows\.net$"],
            "body_patterns": ["BlobNotFound", "The specified container does not exist"],
            "status_codes": [404],
        },
        "Shopify": {
            "cname_patterns": [r"\.myshopify\.com$"],
            "body_patterns": ["Sorry, this shop is currently unavailable"],
            "status_codes": [404],
        },
        "Fastly": {
            "cname_patterns": [r"\.fastly\.net$"],
            "body_patterns": ["Fastly error: unknown domain"],
            "status_codes": [404],
        },
        "Pantheon": {
            "cname_patterns": [r"\.pantheonsite\.io$"],
            "body_patterns": ["404 error unknown site"],
            "status_codes": [404],
        },
        "Tumblr": {
            "cname_patterns": [r"\.tumblr\.com$"],
            "body_patterns": ["Whatever you were looking for doesn't currently exist"],
            "status_codes": [404],
        },
        "WordPress.com": {
            "cname_patterns": [r"\.wordpress\.com$"],
            "body_patterns": ["Do you want to register"],
            "status_codes": [404],
        },
        "Zendesk": {
            "cname_patterns": [r"\.zendesk\.com$"],
            "body_patterns": ["Help Center Closed"],
            "status_codes": [404],
        },
        "Ghost": {
            "cname_patterns": [r"\.ghost\.io$"],
            "body_patterns": ["The thing you were looking for is no longer here"],
            "status_codes": [404],
        },
        "Surge.sh": {
            "cname_patterns": [r"\.surge\.sh$"],
            "body_patterns": ["project not found"],
            "status_codes": [404],
        },
        "Bitbucket": {
            "cname_patterns": [r"\.bitbucket\.io$"],
            "body_patterns": ["Repository not found"],
            "status_codes": [404],
        },
        "Netlify": {
            "cname_patterns": [r"\.netlify\.com$", r"\.netlify\.app$"],
            "body_patterns": ["Not Found - Request ID"],
            "status_codes": [404],
        },
        "Vercel": {
            "cname_patterns": [r"\.vercel\.app$", r"\.now\.sh$"],
            "body_patterns": ["The deployment could not be found"],
            "status_codes": [404],
        },
    }

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_subdomains(self, subdomains: List[str]) -> List[TakeoverResult]:
        """Check a list of subdomains for takeover vulnerabilities."""
        results = []
        console.print(f"  [tool]▸ Subdomain Takeover[/tool] → [target]{len(subdomains)} subdomains[/target]")

        for subdomain in subdomains:
            result = self.check_subdomain(subdomain)
            if result.vulnerable:
                results.append(result)
                console.print(f"    [critical]⚠ TAKEOVER: {subdomain} → {result.service}[/critical]")

        console.print(f"  [tool]◂ Takeover[/tool] — {len(results)} vulnerable")
        return results

    def check_subdomain(self, subdomain: str) -> TakeoverResult:
        """Check a single subdomain for takeover."""
        result = TakeoverResult(subdomain=subdomain, vulnerable=False)

        # Step 1: Get CNAME record
        cname = self._get_cname(subdomain)
        result.cname = cname

        if not cname:
            # No CNAME, check if it resolves to an IP
            try:
                ip = socket.gethostbyname(subdomain)
                # Direct A record, less likely to be takeover-able
                return result
            except socket.gaierror:
                # Doesn't resolve at all — potential takeover
                result.vulnerable = True
                result.service = "Dangling DNS (no resolution)"
                result.severity = "CRITICAL"
                return result

        # Step 2: Check CNAME against known vulnerable services
        for service, fingerprints in self.VULNERABLE_FINGERPRINTS.items():
            for pattern in fingerprints["cname_patterns"]:
                if re.search(pattern, cname, re.I):
                    result.service = service
                    # Step 3: Verify with HTTP request
                    if self._verify_takeover(subdomain, fingerprints):
                        result.vulnerable = True
                        result.fingerprint = fingerprints["body_patterns"][0] if fingerprints["body_patterns"] else ""
                        result.severity = "HIGH"
                    return result

        return result

    def _get_cname(self, subdomain: str) -> str:
        """Get CNAME record for a subdomain."""
        try:
            import subprocess
            cmd = ["dig", "+short", subdomain, "CNAME"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip().rstrip('.')
        except Exception:
            pass

        # Fallback: Python DNS
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            pass

        return ""

    def _verify_takeover(self, subdomain: str, fingerprints: Dict) -> bool:
        """Verify takeover vulnerability with HTTP request."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=8, verify=True)

            for scheme in ["https", "http"]:
                try:
                    resp = client.get(f"{scheme}://{subdomain}")

                    # Check status code
                    if resp.status_code in fingerprints.get("status_codes", []):
                        # Check body patterns
                        body = resp.text
                        for pattern in fingerprints.get("body_patterns", []):
                            if pattern.lower() in body.lower():
                                return True

                except Exception:
                    continue

        except ImportError:
            pass

        return False
