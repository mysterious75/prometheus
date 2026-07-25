"""Web Crawler — discovers URLs, forms, parameters, and API endpoints.

No external dependencies — uses Python httpx + regex.
Critical for finding real attack surface.
"""

import re
import time
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from ..core.logger import logger
from ..core.ratelimit import get_limiter


@dataclass
class Form:
    """A discovered HTML form."""
    action: str
    method: str  # GET or POST
    inputs: List[Dict[str, str]]  # [{name, type, value}]
    page_url: str

    def to_dict(self):
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "page_url": self.page_url,
        }


@dataclass
class Endpoint:
    """A discovered URL endpoint with parameters."""
    url: str
    method: str
    params: Dict[str, str]
    source: str  # "form", "link", "js", "api"
    form: Optional[Form] = None

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "source": self.source,
        }


@dataclass
class CrawlResult:
    """Result of a web crawl."""
    target: str
    urls: List[str] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self):
        return {
            "target": self.target,
            "urls_count": len(self.urls),
            "endpoints_count": len(self.endpoints),
            "forms_count": len(self.forms),
            "js_files_count": len(self.js_files),
            "api_endpoints": self.api_endpoints[:20],
            "emails": self.emails[:10],
            "technologies": self.technologies,
        }


class WebCrawler:
    """Crawls a target to discover attack surface.

    Features:
    - Follows links within same domain
    - Extracts forms and their parameters
    - Discovers JS files and API endpoints
    - Extracts emails and tech stack info
    - Rate-limited to avoid overwhelming target
    """

    def __init__(self, max_depth: int = 3, max_urls: int = 200, rps: float = 10.0):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.limiter = get_limiter(rps)

    def crawl(self, target: str) -> CrawlResult:
        """Crawl a target URL and discover all endpoints."""
        try:
            import httpx
        except ImportError:
            return CrawlResult(target=target)

        start = time.time()
        result = CrawlResult(target=target)

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed_target = urlparse(target)
        base_domain = parsed_target.netloc

        visited: Set[str] = set()
        to_visit: List[tuple] = [(target, 0)]  # (url, depth)
        client = httpx.Client(
            follow_redirects=True, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )

        while to_visit and len(visited) < self.max_urls:
            url, depth = to_visit.pop(0)
            if url in visited or depth > self.max_depth:
                continue

            self.limiter.wait(base_domain)
            visited.add(url)

            try:
                resp = client.get(url)
                body = resp.text

                # Extract links
                links = self._extract_links(body, url, base_domain)
                for link in links:
                    if link not in visited:
                        to_visit.append((link, depth + 1))
                        result.urls.append(link)

                # Extract forms
                forms = self._extract_forms(body, url)
                result.forms.extend(forms)
                for form in forms:
                    params = {inp["name"]: inp.get("value", "") for inp in form.inputs if inp.get("name")}
                    result.endpoints.append(Endpoint(
                        url=form.action, method=form.method,
                        params=params, source="form", form=form,
                    ))

                # Extract JS files
                js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
                result.js_files.extend([urljoin(url, js) for js in js_files])

                # Extract emails
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
                result.emails.extend([e for e in emails if e not in result.emails])

                # Detect technology
                self._detect_tech(resp, result)

                # Extract API endpoints from HTML/JS
                api_patterns = re.findall(
                    r'["\'](/api/[^"\']+)["\']|["\']https?://[^"\']*(/api/[^"\']+)["\']',
                    body, re.I
                )
                for match in api_patterns:
                    api_path = match[0] or match[1]
                    if api_path and api_path not in result.api_endpoints:
                        result.api_endpoints.append(api_path)

            except Exception as e:
                logger.debug(f"Crawl error on {url}: {e}")
                continue

        # Deduplicate
        result.urls = list(dict.fromkeys(result.urls))
        result.emails = list(dict.fromkeys(result.emails))
        result.js_files = list(dict.fromkeys(result.js_files))
        result.duration = time.time() - start

        return result

    def _extract_links(self, html: str, base_url: str, base_domain: str) -> List[str]:
        """Extract same-domain links from HTML."""
        links = []
        for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = match.group(1)
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            # Same domain only
            if parsed.netloc != base_domain:
                continue
            # Skip non-HTTP
            if parsed.scheme not in ("http", "https"):
                continue
            # Skip fragments, mailto, javascript
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue

            links.append(full_url.split("#")[0])  # remove fragment

        return links

    def _extract_forms(self, html: str, page_url: str) -> List[Form]:
        """Extract HTML forms with their inputs."""
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.I | re.DOTALL
        )

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_match.group(1) if action_match else page_url
            action = urljoin(page_url, action)

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract inputs
            inputs = []
            input_pattern = re.compile(
                r'<(?:input|textarea|select)[^>]*>', re.I
            )
            for inp_match in input_pattern.finditer(form_html):
                inp = inp_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', inp, re.I)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp, re.I)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)

                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                        "value": value_match.group(1) if value_match else "",
                    })

            if inputs:
                forms.append(Form(
                    action=action,
                    method=method,
                    inputs=inputs,
                    page_url=page_url,
                ))

        return forms

    def _detect_tech(self, resp, result: CrawlResult):
        """Detect technology from HTTP response."""
        headers = {k.lower(): v for k, v in resp.headers.items()}

        server = headers.get("server", "")
        if server and server not in result.technologies:
            result.technologies.append(server)

        powered = headers.get("x-powered-by", "")
        if powered and powered not in result.technologies:
            result.technologies.append(powered)

        # Check cookies for session tech
        cookies = headers.get("set-cookie", "")
        if "PHPSESSID" in cookies:
            result.technologies.append("PHP")
        elif "JSESSIONID" in cookies:
            result.technologies.append("Java")
        elif "ASP.NET" in cookies:
            result.technologies.append("ASP.NET")
        elif "connect.sid" in cookies:
            result.technologies.append("Express.js")

        # Check body for framework signatures
        body_lower = resp.text.lower()
        if "wp-content" in body_lower:
            result.technologies.append("WordPress")
        elif "drupal" in body_lower:
            result.technologies.append("Drupal")
        elif "joomla" in body_lower:
            result.technologies.append("Joomla")
