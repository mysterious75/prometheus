"""httpx Wrapper — fast HTTP probing by ProjectDiscovery.

Runs httpx via subprocess with -status-code -title -tech-detect -json.
Falls back to Python httpx/requests for status, title, headers, tech detection.
"""

import json
import time
import re
import ssl
import socket
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ── Technology fingerprint signatures ──
TECH_SIGNATURES = {
    # Headers-based detection
    "headers": {
        "server": {
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "Microsoft IIS",
            "lighttpd": "Lighttpd",
            "caddy": "Caddy",
            "openresty": "OpenResty",
            "litespeed": "LiteSpeed",
            "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn",
            "envoy": "Envoy",
            "istio-envoy": "Istio/Envoy",
            "cloudflare": "Cloudflare",
            "akamaighost": "Akamai",
            "amazons3": "Amazon S3",
            "amazons3AmazonS3": "Amazon S3",
            "microsoft-iis": "Microsoft IIS",
            "tomcat": "Apache Tomcat",
            "jetty": "Jetty",
            "vertx": "Vert.x",
            "bunny": "BunnyCDN",
            "fastly": "Fastly",
            "varnish": "Varnish",
        },
        "x-powered-by": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "django": "Django",
            "flask": "Flask",
            "rails": "Ruby on Rails",
            "sinatra": "Sinatra",
            "spring": "Spring",
            "laravel": "Laravel",
            "strapi": "Strapi",
            "graphql": "GraphQL",
        },
        "x-aspnet-version": {
            "": "ASP.NET",
        },
        "x-generator": {
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "ghost": "Ghost",
            "hugo": "Hugo",
            "gatsby": "Gatsby",
        },
    },
    # Body-based detection patterns
    "body": {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "wp-json": "WordPress (REST API)",
        "/drupal/": "Drupal",
        "Joomla": "Joomla",
        "content=\"Joomla": "Joomla",
        "generator\" content=\"WordPress": "WordPress",
        "generator\" content=\"Drupal": "Drupal",
        "react-root": "React",
        "__NEXT_DATA__": "Next.js",
        "__nuxt": "Nuxt.js",
        "ng-version": "Angular",
        "vue-router": "Vue.js",
        "ember-application": "Ember.js",
        "backbone": "Backbone.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "tailwindcss": "Tailwind CSS",
        "font-awesome": "Font Awesome",
        "google-analytics": "Google Analytics",
        "gtag": "Google Tag Manager",
        "googletagmanager": "Google Tag Manager",
        "facebook.net": "Facebook Pixel",
        "hotjar": "Hotjar",
        "intercom": "Intercom",
        "drift": "Drift",
        "zendesk": "Zendesk",
        "recaptcha": "reCAPTCHA",
        "hcaptcha": "hCaptcha",
        "cloudflare": "Cloudflare",
        "Shopify": "Shopify",
        "squarespace": "Squarespace",
        "wix.com": "Wix",
        "webflow": "Webflow",
        "grafana": "Grafana",
        "kibana": "Kibana",
        "jenkins": "Jenkins",
        "gitlab": "GitLab",
        "gitea": "Gitea",
        "sonarqube": "SonarQube",
        "swagger": "Swagger/OpenAPI",
        "redoc": "ReDoc",
    },
    # Cookie-based detection
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "ASPXAUTH": "ASP.NET",
        "csrftoken": "Django",
        "connect.sid": "Express.js",
        "_rails_session": "Ruby on Rails",
        "rack.session": "Rack",
        "laravel_session": "Laravel",
        "XSRF-TOKEN": "Angular/Laravel",
        "_gitlab_session": "GitLab",
        "grafana_session": "Grafana",
        "_ga": "Google Analytics",
        "_gid": "Google Analytics",
        "__cfduid": "Cloudflare",
        "cf_clearance": "Cloudflare",
        "wordpress_logged_in": "WordPress",
        "wp-settings": "WordPress",
    },
}


class HttpProber(BaseTool):
    """Wrapper around httpx for HTTP service probing."""

    name = "httpx"
    binary = "httpx"
    description = "Fast HTTP probing, status codes, tech detection, titles"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Probe a target for HTTP services."""
        targets = kwargs.get("targets", [target])
        if isinstance(targets, str):
            targets = [targets]

        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(targets, **kwargs)

        # Write targets to temp file for httpx
        import tempfile
        import os
        targets_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, dir="/tmp"
            ) as f:
                f.write("\n".join(targets))
                targets_file = f.name

            cmd = [
                "httpx",
                "-l", targets_file,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-no-color",
            ]

            if kwargs.get("ports"):
                cmd.extend(["-ports", ",".join(str(p) for p in kwargs["ports"])])

            start = time.time()
            result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 120))
            duration = time.time() - start

            findings = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append({
                            "title": "HTTP Service Detected",
                            "severity": "INFO",
                            "description": (
                                f"HTTP service at {entry.get('url', '')} "
                                f"— Status: {entry.get('status-code', 'N/A')}, "
                                f"Title: {entry.get('title', 'N/A')}"
                            ),
                            "evidence": json.dumps({
                                k: entry.get(k) for k in
                                ["url", "status-code", "title", "tech", "webserver",
                                 "content-type", "content-length", "host"]
                                if entry.get(k)
                            }),
                            "url": entry.get("url", ""),
                            "status_code": entry.get("status-code", 0),
                            "title": entry.get("title", ""),
                            "tech": entry.get("tech", []),
                            "content_length": entry.get("content-length", 0),
                            "webserver": entry.get("webserver", ""),
                            "content_type": entry.get("content-type", ""),
                            "host": entry.get("host", ""),
                            "method": entry.get("method", ""),
                            "final_url": entry.get("final-url", ""),
                            "a": entry.get("a", []),
                            "aaaa": entry.get("aaaa", []),
                            "cnames": entry.get("cnames", []),
                            "tls": entry.get("tls", {}),
                            "remediation": "Review exposed services for misconfigurations.",
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
        finally:
            if targets_file:
                try:
                    os.unlink(targets_file)
                except OSError:
                    pass

    def _fallback_scan(self, targets: List[str], **kwargs) -> ToolResult:
        """Fallback using Python httpx library with tech detection."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=targets[0] if targets else "",
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings: List[Dict[str, Any]] = []
        start = time.time()
        limiter = get_limiter(rps=10.0)

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        client = httpx.Client(
            follow_redirects=True,
            timeout=10,
            verify=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

        for url in targets:
            # Ensure URL has scheme
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            parsed = urlparse(url)
            host = parsed.hostname or url
            limiter.wait(host)

            try:
                resp = client.get(url)
                body = resp.text
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # ── Detect technologies ──
                techs: List[str] = []

                # Header-based detection
                for header_name, signatures in TECH_SIGNATURES["headers"].items():
                    header_value = headers.get(header_name, "").lower()
                    if header_value:
                        for keyword, tech_name in signatures.items():
                            if keyword in header_value and tech_name not in techs:
                                techs.append(tech_name)

                # Cookie-based detection
                set_cookies = headers.get("set-cookie", "")
                for cookie_keyword, tech_name in TECH_SIGNATURES["cookies"].items():
                    if cookie_keyword in set_cookies and tech_name not in techs:
                        techs.append(tech_name)

                # Also check response.cookies
                for cookie_name in resp.cookies.keys():
                    for cookie_keyword, tech_name in TECH_SIGNATURES["cookies"].items():
                        if cookie_keyword in cookie_name and tech_name not in techs:
                            techs.append(tech_name)

                # Body-based detection (first 50KB)
                body_sample = body[:50000].lower()
                for keyword, tech_name in TECH_SIGNATURES["body"].items():
                    if keyword.lower() in body_sample and tech_name not in techs:
                        techs.append(tech_name)

                # ── Extract title ──
                title = ""
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>", body, re.I | re.S
                )
                if title_match:
                    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200]

                # ── Extract meta description ──
                description = ""
                desc_match = re.search(
                    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)',
                    body, re.I,
                )
                if desc_match:
                    description = desc_match.group(1).strip()[:300]

                # ── Get SSL certificate info ──
                tls_info = {}
                if parsed.scheme == "https":
                    tls_info = self._get_tls_info(parsed.hostname, parsed.port or 443)

                # ── Build finding ──
                server = headers.get("server", "")
                powered_by = headers.get("x-powered-by", "")
                if powered_by and powered_by not in techs:
                    techs.append(powered_by)

                findings.append({
                    "title": "HTTP Service Detected",
                    "severity": "INFO",
                    "description": (
                        f"HTTP service at {str(resp.url)} "
                        f"— Status: {resp.status_code}, Title: {title or 'N/A'}"
                    ),
                    "evidence": json.dumps({
                        "url": str(resp.url),
                        "status_code": resp.status_code,
                        "title": title,
                        "tech": techs,
                        "server": server,
                    }),
                    "url": str(resp.url),
                    "requested_url": url,
                    "status_code": resp.status_code,
                    "title": title,
                    "description_meta": description,
                    "tech": techs,
                    "content_length": len(body),
                    "content_type": headers.get("content-type", ""),
                    "webserver": server,
                    "powered_by": powered_by,
                    "redirected": str(resp.url) != url,
                    "final_url": str(resp.url),
                    "tls": tls_info,
                    "headers": dict(resp.headers),
                    "remediation": "Review exposed services for misconfigurations.",
                })

            except httpx.ConnectError as e:
                findings.append({
                    "title": "HTTP Connection Failed",
                    "severity": "INFO",
                    "description": f"Could not connect to {url}: {e}",
                    "evidence": str(e),
                    "url": url,
                    "status_code": 0,
                    "error": "connect_error",
                    "remediation": "N/A",
                })
            except httpx.TimeoutException:
                findings.append({
                    "title": "HTTP Timeout",
                    "severity": "INFO",
                    "description": f"Connection to {url} timed out",
                    "evidence": "Timeout after 10s",
                    "url": url,
                    "status_code": 0,
                    "error": "timeout",
                    "remediation": "N/A",
                })
            except Exception as e:
                findings.append({
                    "title": "HTTP Probe Error",
                    "severity": "INFO",
                    "description": f"Error probing {url}: {e}",
                    "evidence": str(e)[:200],
                    "url": url,
                    "status_code": 0,
                    "error": str(e),
                    "remediation": "N/A",
                })

        client.close()
        duration = time.time() - start

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=targets[0] if targets else "",
            success=True,
            findings=findings,
            duration=duration,
        )

    @staticmethod
    def _get_tls_info(hostname: Optional[str], port: int) -> Dict[str, Any]:
        """Retrieve TLS certificate information for a host."""
        if not hostname:
            return {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert is None:
                        # Try binary form
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            return {"raw": "DER certificate available"}
                        return {}
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "version": cert.get("version", ""),
                        "san": [entry[1] for entry in cert.get("subjectAltName", ())],
                    }
        except Exception:
            return {}
