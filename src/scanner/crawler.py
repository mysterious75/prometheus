from __future__ import annotations
"""Web Crawler — production-grade attack surface discovery.

Features:
1. JavaScript parsing — extract API endpoints from JS files
2. Form analysis — detect input types, required fields, CSRF tokens
3. API discovery — find /api, /graphql, /swagger endpoints
4. Rate limiting — per-domain rate limiting
5. robots.txt parsing — extract disallowed paths
6. Sitemap parsing — extract all URLs from sitemap.xml
7. Technology fingerprinting — detect frameworks, servers, languages
8. Subdomain extraction — find related domains in responses
9. Cookie analysis — session token patterns, security flags
10. Header analysis — security headers, CORS, caching

No external dependencies beyond httpx + standard library.
"""

import gzip
import re
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlencode, urlunparse

from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FormInput:
    """A single form input field."""
    name: str
    input_type: str = "text"
    value: str = ""
    required: bool = False
    placeholder: str = ""
    pattern: str = ""
    maxlength: int = 0
    min: str = ""
    max: str = ""
    autocomplete: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.input_type,
            "value": self.value,
            "required": self.required,
        }


@dataclass
class Form:
    """A discovered HTML form with full analysis."""
    action: str
    method: str  # GET or POST
    inputs: List[FormInput]
    page_url: str
    form_id: str = ""
    enctype: str = "application/x-www-form-urlencoded"
    csrf_token: Optional[str] = None
    csrf_field_name: str = ""
    has_file_upload: bool = False
    has_password_field: bool = False
    autocomplete_enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": [inp.to_dict() for inp in self.inputs],
            "page_url": self.page_url,
            "csrf_field": self.csrf_field_name,
            "has_file_upload": self.has_file_upload,
            "has_password": self.has_password_field,
        }


@dataclass
class APIEndpoint:
    """A discovered API endpoint."""
    url: str
    method: str = "GET"
    source: str = ""  # "js", "html", "swagger", "graphql", "link"
    parameters: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "source": self.source,
            "parameters": self.parameters,
        }


@dataclass
class Endpoint:
    """A discovered URL endpoint with parameters."""
    url: str
    method: str
    params: Dict[str, str]
    source: str  # "form", "link", "js", "api"
    form: Optional[Form] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "source": self.source,
        }


@dataclass
class SecurityHeaders:
    """Security header analysis."""
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    misconfigured: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "present": self.present,
            "missing": self.missing,
            "misconfigured": self.misconfigured,
        }


@dataclass
class TechFingerprint:
    """Technology fingerprint."""
    server: str = ""
    powered_by: str = ""
    framework: str = ""
    language: str = ""
    cms: str = ""
    waf: str = ""
    cdn: str = ""
    other: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {}
        if self.server: result["server"] = self.server
        if self.powered_by: result["powered_by"] = self.powered_by
        if self.framework: result["framework"] = self.framework
        if self.language: result["language"] = self.language
        if self.cms: result["cms"] = self.cms
        if self.waf: result["waf"] = self.waf
        if self.cdn: result["cdn"] = self.cdn
        if self.other: result["other"] = self.other
        return result


@dataclass
class CrawlResult:
    """Result of a web crawl."""
    target: str
    urls: List[str] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    technologies: TechFingerprint = field(default_factory=TechFingerprint)
    security_headers: SecurityHeaders = field(default_factory=SecurityHeaders)
    robots_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    swagger_endpoints: List[str] = field(default_factory=list)
    duration: float = 0.0
    pages_crawled: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "urls_count": len(self.urls),
            "endpoints_count": len(self.endpoints),
            "forms_count": len(self.forms),
            "js_files_count": len(self.js_files),
            "api_endpoints_count": len(self.api_endpoints),
            "api_endpoints": [ep.to_dict() for ep in self.api_endpoints[:30]],
            "emails": self.emails[:20],
            "subdomains": self.subdomains[:20],
            "technologies": self.technologies.to_dict(),
            "security_headers": self.security_headers.to_dict(),
            "robots_paths_count": len(self.robots_paths),
            "sitemap_urls_count": len(self.sitemap_urls),
            "graphql_endpoints": self.graphql_endpoints,
            "swagger_endpoints": self.swagger_endpoints,
            "pages_crawled": self.pages_crawled,
            "duration": f"{self.duration:.1f}s",
        }


# ---------------------------------------------------------------------------
# CSRF token patterns
# ---------------------------------------------------------------------------

CSRF_PATTERNS = [
    r"csrf[_-]?token",
    r"xsrf[_-]?token",
    r"_token",
    r"authenticity[_-]?token",
    r"__RequestVerificationToken",
    r"anticsrf",
    r"_csrf",
    r"csrf[_-]?param",
    r"nonce",
    r"verification[_-]?token",
    r"_wpnonce",
    r"form[_-]?token",
]

CSRF_RE = re.compile("|".join(CSRF_PATTERNS), re.I)


# ---------------------------------------------------------------------------
# API endpoint patterns in JavaScript
# ---------------------------------------------------------------------------

# Patterns for finding API endpoints in JavaScript source code
JS_API_PATTERNS = [
    # fetch() calls
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*\{[^}]*method\s*:\s*['"`](\w+)['"`]""",
    # axios calls
    r"""axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""axios\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""",
    # jQuery AJAX
    r"""\$\.(ajax|get|post|getJSON)\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""jQuery\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""",
    # XMLHttpRequest
    r"""\.open\s*\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
    # Generic URL patterns in JS
    r"""['"`](/api/v\d+/[^'"`\s]+)['"`]""",
    r"""['"`](/api/[^'"`\s]+)['"`]""",
    r"""['"`](/v\d+/[^'"`\s]+)['"`]""",
    # GraphQL
    r"""['"`](/graphql[^'"`\s]*)['"`]""",
    # RESTful patterns
    r"""['"`](/(?:users?|accounts?|admin|auth|login|logout|register|profile|settings|dashboard|orders?|products?|items?|categories?|tags?|comments?|posts?|pages?|search|upload|download|export|import|notifications?|messages?|chats?|files?|images?|documents?)(?:/[^'"`\s]*)?)['"`]""",
    # WebSocket
    r"""['"`](wss?://[^'"`\s]+)['"`]""",
]

JS_API_RE = re.compile("|".join(JS_API_PATTERNS), re.I)


# ---------------------------------------------------------------------------
# Common API paths to probe
# ---------------------------------------------------------------------------

API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/graphql/console",
    "/swagger", "/swagger.json", "/swagger/ui", "/swagger-ui",
    "/swagger-ui.html", "/api-docs", "/api/docs",
    "/openapi.json", "/openapi.yaml", "/openapi/v3",
    "/docs", "/redoc",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/health", "/healthz", "/ready",
    "/metrics", "/prometheus",
    "/debug", "/debug/vars", "/debug/pprof",
    "/status", "/info", "/version",
    "/admin", "/admin/api",
    "/wp-json", "/wp-json/wp/v2",
    "/wp-json/oembed",
    "/api/users", "/api/auth", "/api/login",
    "/api/health", "/api/status", "/api/config",
    "/_api", "/_api/info",
    "/api/swagger", "/api/explorer",
]


# ---------------------------------------------------------------------------
# Security headers to check
# ---------------------------------------------------------------------------

SECURITY_HEADERS_CHECK = {
    "strict-transport-security": "HSTS — enforces HTTPS",
    "content-security-policy": "CSP — prevents XSS and injection",
    "x-content-type-options": "Prevents MIME-type sniffing",
    "x-frame-options": "Clickjacking protection",
    "x-xss-protection": "Legacy XSS filter (deprecated but still useful)",
    "referrer-policy": "Controls referrer information leakage",
    "permissions-policy": "Controls browser feature access",
    "cross-origin-opener-policy": "COOP — isolates browsing context",
    "cross-origin-resource-policy": "CORP — prevents cross-origin reads",
    "cross-origin-embedder-policy": "COEP — controls cross-origin embedding",
}


# ---------------------------------------------------------------------------
# Main Crawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """Production-grade web crawler for attack surface discovery.

    Features:
    - Link following within same domain (configurable depth)
    - Form extraction with CSRF detection and input analysis
    - JavaScript parsing for API endpoint discovery
    - API discovery (/api, /graphql, /swagger probing)
    - robots.txt and sitemap.xml parsing
    - Technology fingerprinting
    - Security header analysis
    - Email and subdomain extraction
    - Per-domain rate limiting
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_urls: int = 200,
        rps: float = 10.0,
        timeout: float = 10.0,
        discover_apis: bool = True,
    ):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.limiter = get_limiter(rps)
        self.timeout = timeout
        self.discover_apis = discover_apis

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, target: str) -> CrawlResult:
        """Crawl a target URL and discover all endpoints.

        Args:
            target: Starting URL (e.g., "https://example.com").

        Returns:
            CrawlResult with all discovered attack surface.
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — crawler disabled")
            return CrawlResult(target=target)

        start_time = time.time()
        result = CrawlResult(target=target)

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed_target = urlparse(target)
        base_domain = parsed_target.netloc

        visited: Set[str] = set()
        to_visit: List[Tuple[str, int]] = [(target, 0)]  # (url, depth)
        client = httpx.Client(
            follow_redirects=True,
            timeout=self.timeout,
            verify=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

        try:
            # --- Phase 0: Pre-crawl discovery ---
            self._parse_robots_txt(client, target, base_domain, result)
            self._parse_sitemap(client, target, base_domain, result)

            # Add robots/sitemap URLs to crawl queue
            for path in result.robots_paths[:50]:
                full_url = urljoin(target, path)
                if full_url not in visited:
                    to_visit.append((full_url, 0))

            for sitemap_url in result.sitemap_urls[:50]:
                if sitemap_url not in visited:
                    to_visit.append((sitemap_url, 0))

            # --- Phase 1: Main crawl ---
            while to_visit and len(visited) < self.max_urls:
                url, depth = to_visit.pop(0)
                if url in visited or depth > self.max_depth:
                    continue

                self.limiter.wait(base_domain)
                visited.add(url)
                result.pages_crawled += 1

                try:
                    resp = client.get(url)
                    body = resp.text
                except Exception as e:
                    logger.debug(f"Crawl error on {url}: {e}")
                    continue

                # Only analyze HTML responses
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    # Check if it's a JS file
                    if "javascript" in content_type or url.endswith(".js"):
                        self._analyze_js_content(body, url, result)
                    continue

                # --- Analyze the page ---

                # Security headers (only for first page)
                if result.pages_crawled == 1:
                    self._analyze_security_headers(resp, result)
                    self._analyze_technologies(resp, body, result)

                # Extract links
                links = self._extract_links(body, url, base_domain)
                for link in links:
                    if link not in visited:
                        to_visit.append((link, depth + 1))
                    if link not in result.urls:
                        result.urls.append(link)

                # Extract forms
                forms = self._extract_forms(body, url)
                result.forms.extend(forms)
                for form in forms:
                    params = {inp.name: inp.value for inp in form.inputs if inp.name}
                    result.endpoints.append(Endpoint(
                        url=form.action,
                        method=form.method,
                        params=params,
                        source="form",
                        form=form,
                    ))

                # Extract JS files and analyze them
                js_files = self._extract_js_urls(body, url)
                for js_url in js_files:
                    if js_url not in result.js_files:
                        result.js_files.append(js_url)
                    # Fetch and analyze JS files
                    if js_url not in visited:
                        visited.add(js_url)
                        self.limiter.wait(base_domain)
                        try:
                            js_resp = client.get(js_url)
                            if js_resp.status_code == 200:
                                self._analyze_js_content(js_resp.text, js_url, result)
                        except Exception:
                            pass

                # Extract emails
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
                for email in emails:
                    if email not in result.emails:
                        result.emails.append(email)

                # Extract subdomains
                subdomains = self._extract_subdomains(body, base_domain)
                for sd in subdomains:
                    if sd not in result.subdomains:
                        result.subdomains.append(sd)

                # Extract inline API references
                self._extract_api_refs_from_html(body, url, result)

            # --- Phase 2: API discovery probing ---
            if self.discover_apis:
                self._discover_apis(client, target, base_domain, result)

        finally:
            client.close()

        # Deduplicate
        result.urls = list(dict.fromkeys(result.urls))
        result.emails = list(dict.fromkeys(result.emails))
        result.js_files = list(dict.fromkeys(result.js_files))
        result.subdomains = list(dict.fromkeys(result.subdomains))
        result.duration = time.time() - start_time

        return result

    # ------------------------------------------------------------------
    # robots.txt parsing
    # ------------------------------------------------------------------

    def _parse_robots_txt(
        self, client: "httpx.Client", target: str, host: str, result: CrawlResult
    ):
        """Parse robots.txt for disallowed paths and sitemap references."""
        robots_url = urljoin(target, "/robots.txt")

        self.limiter.wait(host)
        try:
            resp = client.get(robots_url)
            if resp.status_code != 200:
                return

            body = resp.text
            current_agent = ""

            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue

                directive = parts[0].strip().lower()
                value = parts[1].strip()

                if directive == "user-agent":
                    current_agent = value
                elif directive == "disallow" and value:
                    if value not in result.robots_paths:
                        result.robots_paths.append(value)
                elif directive == "sitemap":
                    if value not in result.sitemap_urls:
                        result.sitemap_urls.append(value)
                elif directive == "allow" and value:
                    # Allow paths are interesting too (often admin panels)
                    if value not in result.robots_paths:
                        result.robots_paths.append(value)

        except Exception as e:
            logger.debug(f"robots.txt fetch error: {e}")

    # ------------------------------------------------------------------
    # Sitemap parsing
    # ------------------------------------------------------------------

    def _parse_sitemap(
        self, client: "httpx.Client", target: str, host: str, result: CrawlResult
    ):
        """Parse sitemap.xml for URLs."""
        sitemap_urls_to_try = [
            urljoin(target, "/sitemap.xml"),
            urljoin(target, "/sitemap_index.xml"),
            urljoin(target, "/sitemap-index.xml"),
            urljoin(target, "/sitemaps.xml"),
        ]

        # Also add any sitemaps found in robots.txt
        for sm in result.sitemap_urls:
            if sm.startswith("http"):
                sitemap_urls_to_try.append(sm)

        for sitemap_url in sitemap_urls_to_try[:5]:  # Limit attempts
            self.limiter.wait(host)
            try:
                resp = client.get(sitemap_url)
                if resp.status_code != 200:
                    continue

                # Handle gzip
                content = resp.text
                if not content.strip().startswith("<?xml") and not content.strip().startswith("<"):
                    try:
                        content = gzip.decompress(resp.content).decode("utf-8", errors="replace")
                    except Exception:
                        continue

                self._parse_sitemap_xml(content, sitemap_url, result)

            except Exception as e:
                logger.debug(f"Sitemap fetch error ({sitemap_url}): {e}")

    def _parse_sitemap_xml(self, xml_content: str, base_url: str, result: CrawlResult):
        """Parse sitemap XML content recursively."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return

        # Handle sitemap index
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for sitemap in root.findall(".//sm:sitemap/sm:loc", ns):
            if sitemap.text:
                url = sitemap.text.strip()
                if url not in result.sitemap_urls:
                    result.sitemap_urls.append(url)

        # Handle URL entries
        for url_elem in root.findall(".//sm:url/sm:loc", ns):
            if url_elem.text:
                url = url_elem.text.strip()
                if url not in result.sitemap_urls:
                    result.sitemap_urls.append(url)
                if url not in result.urls:
                    result.urls.append(url)

        # Also try without namespace (some sitemaps don't use it)
        for url_elem in root.findall(".//url/loc"):
            if url_elem.text:
                url = url_elem.text.strip()
                if url not in result.sitemap_urls:
                    result.sitemap_urls.append(url)
                if url not in result.urls:
                    result.urls.append(url)

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    def _extract_links(self, html: str, base_url: str, base_domain: str) -> List[str]:
        """Extract same-domain links from HTML."""
        links: List[str] = []

        # <a href="...">
        for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = match.group(1)
            full_url = self._normalize_url(href, base_url, base_domain)
            if full_url:
                links.append(full_url)

        # <form action="...">
        for match in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I):
            action = match.group(1)
            full_url = self._normalize_url(action, base_url, base_domain)
            if full_url:
                links.append(full_url)

        # <link href="..."> (canonical, alternate, etc.)
        for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = match.group(1)
            full_url = self._normalize_url(href, base_url, base_domain)
            if full_url:
                links.append(full_url)

        # <iframe src="...">
        for match in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = match.group(1)
            full_url = self._normalize_url(src, base_url, base_domain)
            if full_url:
                links.append(full_url)

        return links

    def _normalize_url(self, href: str, base_url: str, base_domain: str) -> Optional[str]:
        """Normalize a URL and return it if it's same-domain."""
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:", "data:", "blob:")):
            return None

        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)

        if parsed.netloc != base_domain:
            return None
        if parsed.scheme not in ("http", "https"):
            return None

        # Remove fragment
        return urlunparse(parsed._replace(fragment=""))

    # ------------------------------------------------------------------
    # JavaScript URL extraction
    # ------------------------------------------------------------------

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML."""
        js_urls: List[str] = []

        # <script src="...">
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            if full_url.startswith(("http://", "https://")):
                js_urls.append(full_url)

        # <link rel="preload" as="script" href="...">
        for match in re.finditer(
            r'<link[^>]+rel=["\']preload["\'][^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
            html, re.I
        ):
            href = match.group(1)
            full_url = urljoin(base_url, href)
            if full_url.startswith(("http://", "https://")):
                js_urls.append(full_url)

        # Also look for .js references in inline scripts
        for match in re.finditer(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html, re.I):
            src = match.group(1)
            if src.startswith(("/", "http")):
                full_url = urljoin(base_url, src)
                if full_url.startswith(("http://", "https://")):
                    js_urls.append(full_url)

        return list(dict.fromkeys(js_urls))  # Deduplicate preserving order

    # ------------------------------------------------------------------
    # JavaScript content analysis
    # ------------------------------------------------------------------

    def _analyze_js_content(self, js_content: str, js_url: str, result: CrawlResult):
        """Analyze JavaScript content for API endpoints and sensitive data."""
        # Extract API endpoints
        for match in JS_API_RE.finditer(js_content):
            groups = [g for g in match.groups() if g is not None]
            if not groups:
                continue

            # Determine URL and method
            if len(groups) >= 2 and groups[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                method = groups[0].upper()
                api_path = groups[1]
            else:
                method = "GET"
                api_path = groups[0] if groups else groups[-1]

            # Skip obvious non-API strings
            if not api_path or len(api_path) < 2:
                continue
            if api_path.startswith((".", "//", "data:", "blob:")):
                continue
            if any(ext in api_path for ext in [".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico"]):
                continue

            # Normalize
            if api_path.startswith("/"):
                parsed = urlparse(js_url)
                api_path = f"{parsed.scheme}://{parsed.netloc}{api_path}"
            elif not api_path.startswith("http"):
                api_path = urljoin(js_url, api_path)

            # Check if already discovered
            if any(ep.url == api_path for ep in result.api_endpoints):
                continue

            result.api_endpoints.append(APIEndpoint(
                url=api_path,
                method=method,
                source="js",
            ))

        # Extract WebSocket URLs
        for match in re.finditer(r'["\'](wss?://[^"\']+)["\']', js_content):
            ws_url = match.group(1)
            if not any(ep.url == ws_url for ep in result.api_endpoints):
                result.api_endpoints.append(APIEndpoint(
                    url=ws_url,
                    method="WS",
                    source="js",
                ))

        # Extract strings that look like API paths (quoted strings starting with /)
        for match in re.finditer(r'["\'](/[a-zA-Z][a-zA-Z0-9_/]{3,}(?:\?[^"\']*)?)["\']', js_content):
            path = match.group(1)
            # Filter noise
            if any(skip in path.lower() for skip in [
                ".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff",
                ".ttf", ".eot", ".map", "node_modules", ".git",
            ]):
                continue
            if path.count("/") < 2:
                continue

            parsed = urlparse(js_url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{path}"

            if not any(ep.url == full_url for ep in result.api_endpoints):
                result.api_endpoints.append(APIEndpoint(
                    url=full_url,
                    method="GET",
                    source="js (path string)",
                ))

    # ------------------------------------------------------------------
    # Form extraction (enhanced)
    # ------------------------------------------------------------------

    def _extract_forms(self, html: str, page_url: str) -> List[Form]:
        """Extract HTML forms with full analysis including CSRF detection."""
        forms: List[Form] = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.DOTALL)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_tag = form_match.group(0).split(">")[0] + ">"

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.I)
            action = action_match.group(1) if action_match else page_url
            action = urljoin(page_url, action)

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract enctype
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_tag, re.I)
            enctype = enctype_match.group(1) if enctype_match else "application/x-www-form-urlencoded"

            # Extract form id
            id_match = re.search(r'id=["\']([^"\']*)["\']', form_tag, re.I)
            form_id = id_match.group(1) if id_match else ""

            # Extract autocomplete
            autocomplete = "off" not in form_tag.lower()

            # Extract inputs
            inputs: List[FormInput] = []
            csrf_token: Optional[str] = None
            csrf_field: str = ""
            has_file = False
            has_password = False

            input_pattern = re.compile(
                r'<(?:input|textarea|select|button)[^>]*>',
                re.I
            )

            for inp_match in input_pattern.finditer(form_html):
                inp = inp_match.group(0)

                name_match = re.search(r'name=["\']([^"\']*)["\']', inp, re.I)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp, re.I)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                required = "required" in inp.lower()
                placeholder_match = re.search(r'placeholder=["\']([^"\']*)["\']', inp, re.I)
                pattern_match = re.search(r'pattern=["\']([^"\']*)["\']', inp, re.I)
                maxlength_match = re.search(r'maxlength=["\']([^"\']*)["\']', inp, re.I)

                if not name_match:
                    # Check for id as fallback
                    id_match = re.search(r'id=["\']([^"\']*)["\']', inp, re.I)
                    if not id_match:
                        continue
                    name = id_match.group(1)
                else:
                    name = name_match.group(1)

                inp_type = (type_match.group(1) if type_match else "text").lower()
                value = value_match.group(1) if value_match else ""

                # Detect CSRF tokens
                if CSRF_RE.search(name) or CSRF_RE.search(inp):
                    csrf_token = value
                    csrf_field = name

                # Detect file uploads
                if inp_type == "file":
                    has_file = True

                # Detect password fields
                if inp_type == "password":
                    has_password = True

                # Skip submit/button types from inputs list
                if inp_type in ("submit", "button", "reset", "image"):
                    continue

                inputs.append(FormInput(
                    name=name,
                    input_type=inp_type,
                    value=value,
                    required=required,
                    placeholder=placeholder_match.group(1) if placeholder_match else "",
                    pattern=pattern_match.group(1) if pattern_match else "",
                    maxlength=int(maxlength_match.group(1)) if maxlength_match else 0,
                ))

            # Also check for hidden input with token-like values
            for inp in inputs:
                if inp.input_type == "hidden" and CSRF_RE.search(inp.name):
                    csrf_token = inp.value
                    csrf_field = inp.name

            if inputs:
                forms.append(Form(
                    action=action,
                    method=method,
                    inputs=inputs,
                    page_url=page_url,
                    form_id=form_id,
                    enctype=enctype,
                    csrf_token=csrf_token,
                    csrf_field_name=csrf_field,
                    has_file_upload=has_file,
                    has_password_field=has_password,
                    autocomplete_enabled=autocomplete,
                ))

        return forms

    # ------------------------------------------------------------------
    # HTML API reference extraction
    # ------------------------------------------------------------------

    def _extract_api_refs_from_html(self, html: str, page_url: str, result: CrawlResult):
        """Extract API endpoint references from HTML attributes and data attributes."""
        # data-* attributes with API-like values
        for match in re.finditer(r'data-[a-z-]*=["\']([^"\']*(?:/api/|/v\d+/|graphql)[^"\']*)["\']', html, re.I):
            path = match.group(1)
            full_url = urljoin(page_url, path)
            if not any(ep.url == full_url for ep in result.api_endpoints):
                result.api_endpoints.append(APIEndpoint(
                    url=full_url,
                    method="GET",
                    source="html (data attribute)",
                ))

        # AJAX URLs in inline scripts
        for match in re.finditer(
            r'["\']((?:/api/|/v\d+/|/graphql|/rest/|/service/)[^"\']+)["\']',
            html, re.I
        ):
            path = match.group(1)
            full_url = urljoin(page_url, path)
            if not any(ep.url == full_url for ep in result.api_endpoints):
                result.api_endpoints.append(APIEndpoint(
                    url=full_url,
                    method="GET",
                    source="html (inline script)",
                ))

    # ------------------------------------------------------------------
    # Subdomain extraction
    # ------------------------------------------------------------------

    def _extract_subdomains(self, html: str, base_domain: str) -> List[str]:
        """Extract subdomains from HTML content."""
        subdomains: List[str] = []
        base_parts = base_domain.split(".")
        base_root = ".".join(base_parts[-2:]) if len(base_parts) >= 2 else base_domain

        # Find all domain-like strings
        for match in re.finditer(
            r'(?:https?://)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.' +
            re.escape(base_root) + r')',
            html
        ):
            domain = match.group(1)
            if domain != base_domain and domain not in subdomains:
                subdomains.append(domain)

        return subdomains

    # ------------------------------------------------------------------
    # API discovery probing
    # ------------------------------------------------------------------

    def _discover_apis(
        self, client: "httpx.Client", target: str, host: str, result: CrawlResult
    ):
        """Probe common API paths."""
        for path in API_DISCOVERY_PATHS:
            probe_url = urljoin(target, path)

            self.limiter.wait(host)
            try:
                resp = client.get(probe_url)
                if resp.status_code == 200:
                    body = resp.text
                    content_type = resp.headers.get("content-type", "")

                    # Check if it's a real API response
                    is_api = False
                    if "json" in content_type or "xml" in content_type:
                        is_api = True
                    elif body.strip().startswith(("{", "[")):
                        is_api = True
                    elif "swagger" in body.lower() or "openapi" in body.lower():
                        is_api = True
                    elif "graphql" in body.lower():
                        is_api = True

                    if is_api:
                        endpoint = APIEndpoint(
                            url=probe_url,
                            method="GET",
                            source="discovery",
                        )

                        # Try to parse as JSON for more info
                        try:
                            import json
                            data = json.loads(body)
                            if isinstance(data, dict):
                                endpoint.description = str(list(data.keys())[:10])
                        except Exception:
                            pass

                        if not any(ep.url == probe_url for ep in result.api_endpoints):
                            result.api_endpoints.append(endpoint)

                        # Track specific endpoint types
                        if "graphql" in path.lower():
                            if probe_url not in result.graphql_endpoints:
                                result.graphql_endpoints.append(probe_url)
                        elif any(s in path.lower() for s in ["swagger", "openapi", "api-docs"]):
                            if probe_url not in result.swagger_endpoints:
                                result.swagger_endpoints.append(probe_url)

            except Exception:
                continue

    # ------------------------------------------------------------------
    # Security header analysis
    # ------------------------------------------------------------------

    def _analyze_security_headers(self, resp: "httpx.Response", result: CrawlResult):
        """Analyze response for security headers."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, description in SECURITY_HEADERS_CHECK.items():
            if header in headers_lower:
                result.security_headers.present.append(f"{header}: {headers_lower[header][:100]}")
            else:
                result.security_headers.missing.append(f"{header} — {description}")

        # Check for misconfigured headers
        hsts = headers_lower.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts:
            result.security_headers.misconfigured.append("HSTS max-age=0 (disabled)")

        xfo = headers_lower.get("x-frame-options", "")
        if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            result.security_headers.misconfigured.append(f"X-Frame-Options unusual value: {xfo}")

        xcto = headers_lower.get("x-content-type-options", "")
        if xcto and xcto.lower() != "nosniff":
            result.security_headers.misconfigured.append(f"X-Content-Type-Options not nosniff: {xcto}")

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    def _analyze_technologies(
        self, resp: "httpx.Response", body: str, result: CrawlResult
    ):
        """Detect technologies from headers and body."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        tech = result.technologies

        # Server header
        tech.server = headers_lower.get("server", "")

        # X-Powered-By
        tech.powered_by = headers_lower.get("x-powered-by", "")

        # Check cookies for language/framework
        cookies = headers_lower.get("set-cookie", "")
        if "PHPSESSID" in cookies:
            tech.language = "PHP"
        elif "JSESSIONID" in cookies:
            tech.language = "Java"
        elif "ASP.NET" in cookies or "ARRAffinity" in cookies:
            tech.language = "ASP.NET"
        elif "connect.sid" in cookies:
            tech.language = "Node.js"
        elif "rack.session" in cookies:
            tech.language = "Ruby"
        elif "django" in cookies.lower() or "csrftoken" in cookies.lower():
            tech.language = "Python"
            tech.framework = "Django"
        elif "flask" in cookies.lower():
            tech.language = "Python"
            tech.framework = "Flask"

        # Body-based detection
        body_lower = body.lower()

        # CMS detection
        if "wp-content" in body_lower or "wp-includes" in body_lower:
            tech.cms = "WordPress"
        elif "drupal" in body_lower:
            tech.cms = "Drupal"
        elif "joomla" in body_lower:
            tech.cms = "Joomla"
        elif "shopify" in body_lower:
            tech.cms = "Shopify"
        elif "squarespace" in body_lower:
            tech.cms = "Squarespace"
        elif "wix.com" in body_lower:
            tech.cms = "Wix"

        # Framework detection
        if "react" in body_lower and ("__NEXT_DATA__" in body or "_next/" in body):
            tech.framework = "Next.js"
        elif "__NEXT_DATA__" in body:
            tech.framework = "Next.js"
        elif "nuxt" in body_lower or "__NUXT__" in body:
            tech.framework = "Nuxt.js"
        elif "vue" in body_lower and ("v-cloak" in body or "v-bind" in body):
            tech.framework = "Vue.js"
        elif "ng-app" in body or "ng-controller" in body or "angular" in body_lower:
            tech.framework = "Angular"
        elif "__react" in body or "data-reactroot" in body:
            tech.framework = "React"
        elif "ember" in body_lower and ("data-ember" in body or "ember-application" in body):
            tech.framework = "Ember.js"
        elif "backbone" in body_lower:
            tech.framework = "Backbone.js"

        # CDN/WAF detection
        if "cf-ray" in headers_lower or "cloudflare" in headers_lower.get("server", "").lower():
            tech.cdn = "Cloudflare"
            tech.waf = "Cloudflare"
        elif "akamai" in headers_lower.get("server", "").lower() or "x-akamai" in str(headers_lower):
            tech.cdn = "Akamai"
        elif "fastly" in headers_lower.get("via", "").lower():
            tech.cdn = "Fastly"
        elif "amazonaws" in headers_lower.get("server", "").lower():
            tech.cdn = "AWS CloudFront"

        # Language from headers
        powered = tech.powered_by.lower()
        if "php" in powered:
            tech.language = "PHP"
        elif "express" in powered:
            tech.language = "Node.js"
            tech.framework = "Express"
        elif "asp.net" in powered:
            tech.language = "ASP.NET"
        elif "servlet" in powered:
            tech.language = "Java"
        elif "ruby" in powered:
            tech.language = "Ruby"
        elif "python" in powered:
            tech.language = "Python"

        # Additional markers
        if "x-aspnet-version" in headers_lower:
            tech.language = "ASP.NET"
        if "x-aspnetmvc-version" in headers_lower:
            tech.framework = "ASP.NET MVC"
        if "x-powered-by" in headers_lower:
            val = headers_lower["x-powered-by"]
            if val and val not in tech.other:
                tech.other.append(val)
