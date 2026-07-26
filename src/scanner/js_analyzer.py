"""Deep JavaScript Static Analyzer — security-focused JS analysis.

Detects:
1. API endpoints (REST, GraphQL, OAuth)
2. Cloud storage URLs (S3, Azure, GCP)
3. OAuth/auth URLs
4. Secrets (AWS keys, GitHub tokens, Stripe keys, JWTs)
5. Sensitive file references
6. Email addresses
7. Internal/private URLs
8. Developer comments with sensitive content
9. Hardcoded credentials
10. DOM XSS sources and sinks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from ..core.logger import logger, log_tool_start, log_tool_result
from .findings import Finding


# ---------------------------------------------------------------------------
# Finding category constants
# ---------------------------------------------------------------------------

CAT_API_ENDPOINT = "api_endpoint"
CAT_CLOUD_STORAGE = "cloud_storage"
CAT_OAUTH_URL = "oauth_url"
CAT_SECRET = "secret"
CAT_SENSITIVE_FILE = "sensitive_file"
CAT_EMAIL = "email"
CAT_INTERNAL_URL = "internal_url"
CAT_COMMENT = "developer_comment"
CAT_HARDCODED_CREDS = "hardcoded_credential"
CAT_DOM_XSS = "dom_xss"


# Severity mapping per category
_CATEGORY_SEVERITY: Dict[str, str] = {
    CAT_SECRET: "CRITICAL",
    CAT_HARDCODED_CREDS: "CRITICAL",
    CAT_INTERNAL_URL: "HIGH",
    CAT_CLOUD_STORAGE: "HIGH",
    CAT_OAUTH_URL: "MEDIUM",
    CAT_DOM_XSS: "HIGH",
    CAT_SENSITIVE_FILE: "MEDIUM",
    CAT_API_ENDPOINT: "INFO",
    CAT_EMAIL: "LOW",
    CAT_COMMENT: "LOW",
}


# ---------------------------------------------------------------------------
# JSFinding dataclass
# ---------------------------------------------------------------------------

@dataclass
class JSFinding:
    """A single finding from JS analysis."""
    category: str
    value: str
    source_file: str = ""
    line_number: int = 0
    context: str = ""  # surrounding code snippet
    severity: str = "INFO"
    description: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Noise filters — things to skip
# ---------------------------------------------------------------------------

_NOISE_PATTERNS = [
    # XML namespaces
    re.compile(r"^https?://www\.w3\.org/"),
    re.compile(r"^https?://schemas\."),
    re.compile(r"^https?://xmlns\."),
    # Common CDN / library paths
    re.compile(r"node_modules/"),
    re.compile(r"\.min\.js$"),
    re.compile(r"webpack://"),
    re.compile(r"webpack:///"),
    # Source map references
    re.compile(r"^//#\s*sourceMappingURL"),
    # Module imports
    re.compile(r"^import\s"),
    re.compile(r"^export\s"),
    re.compile(r"^require\("),
    # Build artifacts
    re.compile(r"__webpack_"),
    re.compile(r"__esModule"),
    re.compile(r"\.css$"),
    re.compile(r"\.woff2?$"),
    re.compile(r"\.ttf$"),
    re.compile(r"\.eot$"),
    re.compile(r"\.map$"),
]

# Internal URL patterns
_INTERNAL_URL_RE = re.compile(
    r"""(?:https?://)"""
    r"""(?:"""
    r"""localhost"""
    r"""|127\.0\.0\.\d{1,3}"""
    r"""|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    r"""|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"""
    r"""|192\.168\.\d{1,3}\.\d{1,3}"""
    r"""|0\.0\.0\.0"""
    r"""|\[::1\]"""
    r"""|internal\.[a-zA-Z0-9.-]+"""
    r"""|intranet\.[a-zA-Z0-9.-]+"""
    r"""|staging\.[a-zA-Z0-9.-]+"""
    r"""|dev\.[a-zA-Z0-9.-]+"""
    r"""|local\.[a-zA-Z0-9.-]+"""
    r""")"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s"'<>]*)?""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Regex patterns for each detection category
# ---------------------------------------------------------------------------

# 1. API Endpoints
_API_ENDPOINT_PATTERNS = [
    # fetch/axios/$.ajax with URL
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:ajax|get|post|getJSON))\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # .open(method, url) — XHR
    re.compile(r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]"""),
    # URL-like strings: /api/v1/..., /rest/..., /graphql
    re.compile(r"""['"`](/api/v\d+/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/api/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/v\d+/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""['"`](/rest/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/oauth2?/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/auth/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/token[^'"`\s]*)['"`]"""),
    re.compile(r"""['"`](/callback[^'"`\s]*)['"`]"""),
]

# 2. Cloud storage URLs
_CLOUD_STORAGE_RE = re.compile(
    r"""(?:"""
    r"""(?:https?://)?[a-zA-Z0-9._-]+\.s3[.-](?:[a-zA-Z0-9-]+\.)*amazonaws\.com(?:/\S*)?"""
    r"""|(?:https?://)?s3://[a-zA-Z0-9._-]+/\S*"""
    r"""|(?:https?://)?[a-zA-Z0-9._-]+\.blob\.core\.windows\.net(?:/\S*)?"""
    r"""|(?:https?://)?storage\.googleapis\.com/[a-zA-Z0-9._-]+(?:/\S*)?"""
    r"""|(?:https?://)?[a-zA-Z0-9._-]+\.storage\.googleapis\.com(?:/\S*)?"""
    r"""|(?:https?://)?[a-zA-Z0-9._-]+\.s3\.amazonaws\.com(?:/\S*)?"""
    r""")""",
    re.IGNORECASE,
)

# 3. OAuth / Auth URLs
_OAUTH_URL_RE = re.compile(
    "[\x27\x22\x60](https?://[^\x27\x22\x60\\s]*(?:oauth2?/authorize|oauth2?/token|openid-configuration|\\.well-known/oauth|/auth/login|/auth/callback|/signin|/signup|/register|/sso/|/saml/)[^\x27\x22\x60\\s]*)[\x27\x22\x60]",
    re.IGNORECASE,
)

# 4. Secrets — high-confidence patterns
_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS Temporary Access Key"),
    (re.compile(r"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"`]?([A-Za-z0-9/+=]{40})"), "AWS Secret Access Key"),
    # GitHub
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "GitHub Fine-grained PAT"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "GitHub App Token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36}"), "GitHub Refresh Token"),
    # Stripe
    (re.compile(r"sk_live_[A-Za-z0-9]{24}"), "Stripe Live Secret Key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{24}"), "Stripe Live Restricted Key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{24}"), "Stripe Test Secret Key"),
    (re.compile(r"pk_live_[A-Za-z0-9]{24}"), "Stripe Live Publishable Key"),
    # OpenAI
    (re.compile(r"sk-[A-Za-z0-9]{48}"), "OpenAI API Key"),
    # Google
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "Google OAuth Token"),
    # Slack
    (re.compile(r"xox[bporas]-[A-Za-z0-9\-]+"), "Slack Token"),
    # GitLab
    (re.compile(r"glpat-[A-Za-z0-9\-]{20}"), "GitLab Personal Access Token"),
    # SendGrid
    (re.compile(r"SG\.[A-Za-z0-9\-]{22}\.[A-Za-z0-9\-]{43}"), "SendGrid API Key"),
    # Twilio
    (re.compile(r"AC[a-z0-9]{32}"), "Twilio Account SID"),
    # JWT
    (re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"), "JSON Web Token (JWT)"),
    # Private keys
    (re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"), "Private Key"),
    # Generic high-entropy secrets
    (re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"`]?([A-Za-z0-9\-_]{20,})""", re.IGNORECASE), "Generic API Key/Secret"),
]

# 5. Sensitive file references
_SENSITIVE_FILE_RE = re.compile(
    r"""['"`]([^'"`\s]*\.(?:sql|csv|bak|env|pdf|pem|key|p12|pfx|jks|keystore|secret|config|cfg|ini|yml|yaml|json|xml|properties|credentials|dump|tar\.gz|zip|rar|7z|db|sqlite|mdb))['"`]""",
    re.IGNORECASE,
)

# 6. Email addresses
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# 8. Developer comments
_COMMENT_PATTERNS = [
    # Single-line: // ... and # ...
    re.compile(r"""(?://|#)\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|WARNING|SECURITY|VULN)\b.*$""", re.IGNORECASE | re.MULTILINE),
    # Multi-line: /* ... */
    re.compile(r"""/\*\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|WARNING|SECURITY|VULN)\b.*?\*/""", re.IGNORECASE | re.DOTALL),
    # HTML-style comments
    re.compile(r"""<!--\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|WARNING|SECURITY|VULN)\b.*?-->""", re.IGNORECASE | re.DOTALL),
]

# 9. Hardcoded credentials
_HARDCODED_CREDS_RE = re.compile(
    r"""(?:password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key|auth)\s*[:=]\s*['\"`]([^'"`\s]{4,})['\"`]""",
    re.IGNORECASE,
)

# 10. DOM XSS sources and sinks
_DOM_XSS_SOURCES = [
    "document.location",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.location",
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "location.assign",
    "location.replace",
    "postMessage",
    "onmessage",
    "addEventListener.*message",
    "URLSearchParams",
    "history.pushState",
    "history.replaceState",
]

_DOM_XSS_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "execScript",
    "crypto.subtle",
    "insertAdjacentHTML",
    "jQuery.html",
    "$.html",
    ".html(",
    "dangerouslySetInnerHTML",
    "v-html",
    "[innerHTML]",
]


# ---------------------------------------------------------------------------
# Main Analyzer
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """Deep JavaScript static analysis for security findings."""

    NAME = "js_analyzer"

    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, content: str, source_file: str = "<inline>") -> List[JSFinding]:
        """Analyze JavaScript content for security findings.

        Args:
            content: JavaScript source code (minified or not).
            source_file: Origin filename or URL for context.

        Returns:
            List of JSFinding objects.
        """
        findings: List[JSFinding] = []
        lines = content.split("\n")

        # Run all detectors
        findings.extend(self._detect_api_endpoints(content, source_file))
        findings.extend(self._detect_cloud_storage(content, source_file))
        findings.extend(self._detect_oauth_urls(content, source_file))
        findings.extend(self._detect_secrets(content, source_file))
        findings.extend(self._detect_sensitive_files(content, source_file))
        findings.extend(self._detect_emails(content, source_file))
        findings.extend(self._detect_internal_urls(content, source_file))
        findings.extend(self._detect_comments(content, source_file))
        findings.extend(self._detect_hardcoded_creds(content, source_file))
        findings.extend(self._detect_dom_xss(content, source_file))

        # Filter noise
        findings = self._filter_noise(findings)

        return findings

    def analyze_from_url(self, url: str) -> List[JSFinding]:
        """Fetch and analyze a JavaScript file from a URL.

        Args:
            url: URL to the JS file.

        Returns:
            List of JSFinding objects.
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — JS URL analysis disabled")
            return []

        try:
            resp = httpx.get(url, timeout=15, follow_redirects=True, verify=False)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch JS from {url}: {e}")
            return []

        return self.analyze(resp.text, source_file=url)

    def findings_to_prometheus(self, findings: List[JSFinding]) -> List[Finding]:
        """Convert JSFinding objects to Prometheus Finding objects."""
        results: List[Finding] = []
        for jsf in findings:
            sev = _CATEGORY_SEVERITY.get(jsf.category, "INFO")
            results.append(Finding(
                vuln_type=f"js_{jsf.category}",
                title=f"JS Analysis: {jsf.category.replace('_', ' ').title()}",
                severity=sev,
                url=jsf.source_file,
                payload=jsf.value[:200],
                evidence=jsf.evidence or jsf.value[:500],
                description=jsf.description or f"Found {jsf.category} in JavaScript",
                tool=self.NAME,
                confidence="MEDIUM" if jsf.category in (CAT_SECRET, CAT_HARDCODED_CREDS) else "LOW",
                remediation=self._remediation_for(jsf.category),
                cwe=self._cwe_for(jsf.category),
            ))
        return results

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------

    def _detect_api_endpoints(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for pattern in _API_ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                groups = [g for g in match.groups() if g is not None]
                if not groups:
                    continue
                value = groups[-1]
                if value in seen or len(value) < 3:
                    continue
                # Filter obvious non-API
                if any(ext in value.lower() for ext in [".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".map"]):
                    continue
                seen.add(value)
                ctx = self._get_context(content, match.start(), match.end())
                findings.append(JSFinding(
                    category=CAT_API_ENDPOINT,
                    value=value,
                    source_file=source,
                    line_number=self._line_of(content, match.start()),
                    context=ctx,
                    description=f"API endpoint found: {value}",
                    evidence=ctx,
                ))
        return findings

    def _detect_cloud_storage(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _CLOUD_STORAGE_RE.finditer(content):
            value = match.group(0).strip("\"'`")
            if value in seen:
                continue
            seen.add(value)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_CLOUD_STORAGE,
                value=value,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                description=f"Cloud storage URL: {value}",
                evidence=ctx,
            ))
        return findings

    def _detect_oauth_urls(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _OAUTH_URL_RE.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip("\"'`")
            if value in seen:
                continue
            seen.add(value)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_OAUTH_URL,
                value=value,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                description=f"OAuth/auth URL: {value}",
                evidence=ctx,
            ))
        return findings

    def _detect_secrets(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for pattern, label in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0)
                # Redact the actual secret for safety
                if len(value) > 16:
                    redacted = value[:8] + "..." + value[-4:]
                else:
                    redacted = value[:4] + "..."
                if redacted in seen:
                    continue
                seen.add(redacted)
                ctx = self._get_context(content, match.start(), match.end())
                findings.append(JSFinding(
                    category=CAT_SECRET,
                    value=redacted,
                    source_file=source,
                    line_number=self._line_of(content, match.start()),
                    context=ctx,
                    severity="CRITICAL",
                    description=f"{label} found in JavaScript",
                    evidence=f"{label}: {redacted} | Context: {ctx}",
                ))
        return findings

    def _detect_sensitive_files(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _SENSITIVE_FILE_RE.finditer(content):
            value = match.group(1)
            if value in seen:
                continue
            seen.add(value)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_SENSITIVE_FILE,
                value=value,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                description=f"Sensitive file reference: {value}",
                evidence=ctx,
            ))
        return findings

    def _detect_emails(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _EMAIL_RE.finditer(content):
            value = match.group(0)
            if value in seen:
                continue
            # Skip obviously fake emails
            if value.endswith((".example.com", ".test", ".invalid", ".localhost")):
                continue
            seen.add(value)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_EMAIL,
                value=value,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                description=f"Email address: {value}",
                evidence=ctx,
            ))
        return findings

    def _detect_internal_urls(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _INTERNAL_URL_RE.finditer(content):
            value = match.group(0).strip("\"'`")
            if value in seen:
                continue
            seen.add(value)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_INTERNAL_URL,
                value=value,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                description=f"Internal/private URL: {value}",
                evidence=ctx,
            ))
        return findings

    def _detect_comments(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for pattern in _COMMENT_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0).strip()
                if value in seen:
                    continue
                seen.add(value)
                findings.append(JSFinding(
                    category=CAT_COMMENT,
                    value=value[:200],
                    source_file=source,
                    line_number=self._line_of(content, match.start()),
                    context=value[:300],
                    description=f"Developer comment with sensitive keyword: {value[:100]}",
                    evidence=value[:300],
                ))
        return findings

    def _detect_hardcoded_creds(self, content: str, source: str) -> List[JSFinding]:
        findings = []
        seen = set()
        for match in _HARDCODED_CREDS_RE.finditer(content):
            value = match.group(0)
            # Redact
            secret_val = match.group(1) if match.lastindex else ""
            if len(secret_val) > 8:
                redacted_val = secret_val[:4] + "..." + secret_val[-2:]
            else:
                redacted_val = secret_val
            redacted = value.replace(secret_val, redacted_val)
            if redacted in seen:
                continue
            seen.add(redacted)
            ctx = self._get_context(content, match.start(), match.end())
            findings.append(JSFinding(
                category=CAT_HARDCODED_CREDS,
                value=redacted,
                source_file=source,
                line_number=self._line_of(content, match.start()),
                context=ctx,
                severity="CRITICAL",
                description=f"Hardcoded credential: {redacted}",
                evidence=f"Hardcoded credential found: {redacted} | Context: {ctx}",
            ))
        return findings

    def _detect_dom_xss(self, content: str, source: str) -> List[JSFinding]:
        findings = []

        # Check for sources
        source_matches = []
        for src_pattern in _DOM_XSS_SOURCES:
            try:
                pat = re.compile(re.escape(src_pattern), re.IGNORECASE)
            except re.error:
                pat = re.compile(src_pattern, re.IGNORECASE)
            for match in pat.finditer(content):
                source_matches.append((src_pattern, match))

        # Check for sinks
        sink_matches = []
        for sink_pattern in _DOM_XSS_SINKS:
            try:
                pat = re.compile(re.escape(sink_pattern), re.IGNORECASE)
            except re.error:
                pat = re.compile(sink_pattern, re.IGNORECASE)
            for match in pat.finditer(content):
                sink_matches.append((sink_pattern, match))

        # If both sources and sinks exist, report as potential DOM XSS
        if source_matches and sink_matches:
            # Find closest source-sink pairs
            for src_name, src_match in source_matches[:5]:  # limit to avoid noise
                ctx = self._get_context(content, src_match.start(), src_match.end())
                findings.append(JSFinding(
                    category=CAT_DOM_XSS,
                    value=f"Source: {src_name}",
                    source_file=source,
                    line_number=self._line_of(content, src_match.start()),
                    context=ctx,
                    severity="HIGH",
                    description=f"DOM XSS source found: {src_name} (sinks also present in file)",
                    evidence=f"Source: {src_name} | Context: {ctx}",
                ))

            for sink_name, sink_match in sink_matches[:5]:
                ctx = self._get_context(content, sink_match.start(), sink_match.end())
                findings.append(JSFinding(
                    category=CAT_DOM_XSS,
                    value=f"Sink: {sink_name}",
                    source_file=source,
                    line_number=self._line_of(content, sink_match.start()),
                    context=ctx,
                    severity="HIGH",
                    description=f"DOM XSS sink found: {sink_name} (sources also present in file)",
                    evidence=f"Sink: {sink_name} | Context: {ctx}",
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_context(self, content: str, start: int, end: int, window: int = 100) -> str:
        """Extract surrounding context from content."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(content), end + window)
        snippet = content[ctx_start:ctx_end].strip()
        # Clean up for readability
        snippet = snippet.replace("\n", " ").replace("\r", "")
        return snippet[:300]

    def _line_of(self, content: str, pos: int) -> int:
        """Get 1-based line number for a position in content."""
        return content[:pos].count("\n") + 1

    def _filter_noise(self, findings: List[JSFinding]) -> List[JSFinding]:
        """Remove findings that match noise patterns."""
        filtered = []
        for f in findings:
            is_noise = False
            for pat in _NOISE_PATTERNS:
                if pat.search(f.value):
                    is_noise = True
                    break
            if not is_noise:
                filtered.append(f)
        return filtered

    def _remediation_for(self, category: str) -> str:
        remediations = {
            CAT_SECRET: "Remove secrets from client-side code. Use environment variables and server-side API calls instead.",
            CAT_HARDCODED_CREDS: "Never hardcode credentials. Use secure secret management (vault, env vars, etc.).",
            CAT_INTERNAL_URL: "Remove internal URLs from client-side code. They reveal internal infrastructure.",
            CAT_CLOUD_STORAGE: "Review cloud storage URLs for public access. Use signed URLs and proper IAM policies.",
            CAT_DOM_XSS: "Sanitize all user input before using in DOM sinks. Use textContent instead of innerHTML.",
            CAT_SENSITIVE_FILE: "Remove references to sensitive files from client-side code.",
            CAT_OAUTH_URL: "Review OAuth endpoints for proper security configuration.",
            CAT_API_ENDPOINT: "Ensure API endpoints have proper authentication and authorization.",
            CAT_EMAIL: "Remove email addresses from client-side code if not needed.",
            CAT_COMMENT: "Remove developer comments with sensitive information before deployment.",
        }
        return remediations.get(category, "Review and remediate the finding.")

    def _cwe_for(self, category: str) -> str:
        cwes = {
            CAT_SECRET: "CWE-798",
            CAT_HARDCODED_CREDS: "CWE-798",
            CAT_INTERNAL_URL: "CWE-200",
            CAT_CLOUD_STORAGE: "CWE-538",
            CAT_DOM_XSS: "CWE-79",
            CAT_SENSITIVE_FILE: "CWE-200",
            CAT_OAUTH_URL: "CWE-287",
            CAT_API_ENDPOINT: "CWE-200",
            CAT_EMAIL: "CWE-200",
            CAT_COMMENT: "CWE-200",
        }
        return cwes.get(category, "CWE-200")
