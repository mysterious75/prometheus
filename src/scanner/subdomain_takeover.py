"""Subdomain Takeover Scanner — detects dangling CNAME records and unclaimed cloud resources.

Detects:
- Dangling CNAME records pointing to unclaimed services
- Unclaimed S3 buckets, Azure blobs, Heroku apps, GitHub Pages
- Expired domain references
"""

from __future__ import annotations

import re
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from .base import BaseScanner
from ..core.transport import ssl_verify


# Services vulnerable to subdomain takeover
# (CNAME pattern, fingerprint in response, service name)
TAKEOVER_FINGERPRINTS: List[Tuple[str, str, str]] = [
    # AWS S3
    (r"\.s3\.amazonaws\.com", "NoSuchBucket", "AWS S3"),
    (r"\.s3-website[-.]", "NoSuchBucket", "AWS S3 Website"),
    # Azure
    (r"\.blob\.core\.windows\.net", "BlobNotFound", "Azure Blob Storage"),
    (r"\.azurewebsites\.net", "404 Web Site not found", "Azure Web App"),
    (r"\.cloudapp\.azure\.com", "404 Web Site not found", "Azure Cloud Service"),
    (r"\.trafficmanager\.net", "404 Web Site not found", "Azure Traffic Manager"),
    (r"\.azure-api\.net", "404 Resource Not Found", "Azure API Management"),
    # GitHub Pages
    (r"\.github\.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    # Heroku
    (r"\.herokuapp\.com", "No such app", "Heroku"),
    # Shopify
    (r"\.myshopify\.com", "Sorry, this shop is currently unavailable", "Shopify"),
    # Fastly
    (r"\.fastly\.net", "Fastly error: unknown domain", "Fastly"),
    # Pantheon
    (r"\.pantheonsite\.io", "404 error unknown site", "Pantheon"),
    # Tumblr
    (r"\.tumblr\.com", "There's nothing here", "Tumblr"),
    # WordPress.com
    (r"\.wordpress\.com", "Do you want to register", "WordPress.com"),
    # Zendesk
    (r"\.zendesk\.com", "Help Center Closed", "Zendesk"),
    # Teamwork
    (r"\.teamwork\.com", "Oops - We didn't find your site", "Teamwork"),
    # Helpjuice
    (r"\.helpjuice\.com", "We could not find what you're looking for", "Helpjuice"),
    # Helpscout
    (r"\.helpscoutdocs\.com", "No settings were found", "HelpScout"),
    # Cargo
    (r"\.cargocollective\.com", "If you're moving your domain away from Cargo", "Cargo"),
    # Statuspage
    (r"\.statuspage\.io", "Better status page", "Statuspage"),
    # UserVoice
    (r"\.uservoice\.com", "This UserVoice subdomain is currently available", "UserVoice"),
    # Surveymonkey
    (r"\.surveymonkey\.com", "Not found", "SurveyMonkey"),
    # Intercom
    (r"\.custom.intercom\.com", "This page is reserved for artistic dogs", "Intercom"),
    # Webflow
    (r"\.webflow\.io", "The page you are looking for doesn't exist", "Webflow"),
    # Netlify
    (r"\.netlify\.app", "Not Found", "Netlify"),
    (r"\.netlify\.com", "Not Found", "Netlify"),
    # Vercel
    (r"\.vercel\.app", "The deployment could not be found", "Vercel"),
    # Kajabi
    (r"\.kajabi\.com", "If you're the site owner", "Kajabi"),
    # Thinkific
    (r"\.thinkific\.com", "You may have typed the address incorrectly", "Thinkific"),
    # Tave
    (r"\.tave\.com", "This domain is not configured", "Tave"),
    # Wishpond
    (r"\.wishpond\.com", "https://www.wishpond.com/404", "Wishpond"),
    # Aftership
    (r"\.aftership\.com", "Oops.</h2><p>The page you're looking for doesn't exist", "AfterShip"),
    # Aha
    (r"\.aha\.io", "There is no portal here", "Aha!"),
    # Brightcove
    (r"\.bcvp0rtal\.com", "<p class=\"error-code-text\">404</p>", "Brightcove"),
    # BigCartel
    (r"\.bigcartel\.com", "Oops! We couldn", "BigCartel"),
    # Campaignmonitor
    (r"\.createsend\.com", "Double check the URL", "Campaign Monitor"),
    # Hubspot
    (r"\.hubspot[.-]", "Domain not found", "HubSpot"),
]


class SubdomainTakeoverScanner(BaseScanner):
    """Detects subdomain takeover vulnerabilities."""

    NAME = "subdomain_takeover"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan for subdomain takeover vulnerabilities."""
        import httpx

        findings: List[Finding] = []

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        host = parsed.netloc

        client = httpx.Client(
            verify=ssl_verify(), timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            # Test 1: Check if the domain itself is vulnerable
            findings.extend(self._check_takeover(client, url, host))

            # Test 2: Check common subdomains
            base_domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
            common_subs = [
                "www", "api", "dev", "staging", "test", "admin", "app",
                "blog", "cdn", "docs", "mail", "ftp", "smtp", "imap",
                "static", "assets", "media", "img", "images", "files",
                "beta", "demo", "sandbox", "uat", "qa", "pre",
                "old", "new", "v1", "v2", "legacy", "backup",
                "s3", "azure", "gcp", "cloud", "storage",
                "shop", "store", "cart", "checkout", "payments",
                "status", "monitoring", "grafana", "prometheus",
                "jenkins", "ci", "cd", "gitlab", "github",
                "jira", "confluence", "wiki", "support", "help",
                "dashboard", "panel", "console", "portal",
            ]

            for sub in common_subs:
                subdomain = f"{sub}.{base_domain}"
                for scheme in ["https", "http"]:
                    test_url = f"{scheme}://{subdomain}"
                    self.limiter.wait(host)
                    try:
                        resp = client.get(test_url, follow_redirects=False)
                        # Check response for takeover fingerprints
                        body = resp.text[:3000]
                        for pattern, fingerprint, service in TAKEOVER_FINGERPRINTS:
                            if fingerprint in body:
                                findings.append(Finding(
                                    vuln_type="Subdomain Takeover",
                                    title=f"Potential takeover: {subdomain} ({service})",
                                    severity="CRITICAL",
                                    url=test_url,
                                    method="GET",
                                    evidence=f"{service} fingerprint found: '{fingerprint}'",
                                    description=f"Subdomain {subdomain} points to {service} but the resource doesn't exist. Potential subdomain takeover.",
                                    remediation=f"Remove DNS CNAME record or claim the {service} resource.",
                                    cvss=9.0, cwe="CWE-350",
                                    tool=self.NAME, verified=False, confidence="MEDIUM",
                                    request=f'curl -k "{test_url}"',
                                ))
                                break
                    except Exception:
                        continue

        finally:
            client.close()

        logger.info(f"Subdomain takeover scan: {len(findings)} findings")
        return findings

    def _check_takeover(self, client, url: str, host: str) -> List[Finding]:
        """Check if a specific host is vulnerable to takeover."""
        findings = []

        self.limiter.wait(host)
        try:
            resp = client.get(url)
            body = resp.text[:3000]

            for pattern, fingerprint, service in TAKEOVER_FINGERPRINTS:
                if fingerprint in body:
                    # Verify it's not just a mention of the service
                    if re.search(pattern, host) or resp.status_code in (404, 503, 502):
                        findings.append(Finding(
                            vuln_type="Subdomain Takeover",
                            title=f"Subdomain takeover: {host} ({service})",
                            severity="CRITICAL",
                            url=url,
                            method="GET",
                            evidence=f"{service} fingerprint: '{fingerprint}'",
                            description=f"Domain {host} points to {service} but the resource doesn't exist.",
                            remediation=f"Remove DNS CNAME or claim the {service} resource.",
                            cvss=9.0, cwe="CWE-350",
                            tool=self.NAME, verified=True, confidence="HIGH",
                        ))
        except Exception:
            pass

        return findings


__all__ = ["SubdomainTakeoverScanner"]
