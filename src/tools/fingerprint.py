"""Web Fingerprinting — whatweb, wappalyzer, builtwith, WAF detection.

Identifies technologies, frameworks, CMS, servers, and libraries.
"""

import subprocess
import re
import time
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..core.logger import logger, console


@dataclass
class TechFingerprint:
    """Detected technology."""
    name: str
    version: str = ""
    category: str = ""  # cms, framework, server, language, library, etc.
    confidence: str = "medium"  # low, medium, high
    source: str = ""  # whatweb, wappalyzer, headers, html


@dataclass
class FingerprintResult:
    """Fingerprinting result."""
    target: str
    technologies: List[TechFingerprint] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    meta_tags: List[Dict[str, str]] = field(default_factory=list)
    waf_detected: Optional[str] = None
    cms: str = ""
    server: str = ""
    language: str = ""
    framework: str = ""
    duration: float = 0.0

    def to_dict(self):
        return {
            "target": self.target,
            "technologies": [{"name": t.name, "version": t.version, "category": t.category} for t in self.technologies],
            "server": self.server,
            "cms": self.cms,
            "language": self.language,
            "framework": self.framework,
            "waf": self.waf_detected,
            "headers": dict(list(self.headers.items())[:20]),
        }


class WebFingerprinter:
    """Web technology fingerprinting using multiple methods."""

    # Header-based detection patterns
    HEADER_PATTERNS = {
        "Server": {
            "nginx": ("Nginx", "server"),
            "apache": ("Apache", "server"),
            "iis": ("IIS", "server"),
            "litespeed": ("LiteSpeed", "server"),
            "caddy": ("Caddy", "server"),
            "gunicorn": ("Gunicorn", "server"),
            "uvicorn": ("Uvicorn", "server"),
            "cloudflare": ("Cloudflare", "cdn"),
            "amazonS3": ("Amazon S3", "storage"),
            "Vercel": ("Vercel", "platform"),
            "Netlify": ("Netlify", "platform"),
        },
        "X-Powered-By": {
            "PHP": ("PHP", "language"),
            "Express": ("Express.js", "framework"),
            "ASP.NET": ("ASP.NET", "framework"),
            "Next.js": ("Next.js", "framework"),
            "NestJS": ("NestJS", "framework"),
            "Django": ("Django", "framework"),
            "Ruby on Rails": ("Rails", "framework"),
            "Laravel": ("Laravel", "framework"),
        },
    }

    # WAF signatures (header-based)
    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
        "Incapsula/Imperva": ["x-iinfo", "incap_ses"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BIG-IP": ["bigipserver", "x-wa-info"],
        "Barracuda": ["barra_counter_session"],
        "Wordfence": ["wordfence"],
        "Fortinet": ["fortigate"],
    }

    # HTML patterns for CMS detection
    CMS_PATTERNS = {
        "WordPress": [
            r'wp-content', r'wp-includes', r'wp-json', r'/xmlrpc\.php',
            r'name="generator" content="WordPress',
        ],
        "Drupal": [
            r'Drupal\.settings', r'sites/default/files', r'core/misc/drupal\.js',
            r'name="generator" content="Drupal',
        ],
        "Joomla": [
            r'/media/jui/', r'/components/com_', r'Joomla!',
            r'name="generator" content="Joomla',
        ],
        "Shopify": [
            r'cdn\.shopify\.com', r'Shopify\.theme', r'shopify-section',
        ],
        "Magento": [
            r'/skin/frontend/', r'Mage\.Cookies', r'magento',
        ],
        "Ghost": [
            r'ghost-', r'content/themes/', r'ghost-url',
        ],
        "Hugo": [
            r'powered by Hugo', r'hugo\.min\.css',
        ],
        "Gatsby": [
            r'gatsby-', r'___gatsby',
        ],
    }

    # JavaScript framework patterns
    JS_FRAMEWORK_PATTERNS = {
        "React": [r'react', r'__NEXT_DATA__', r'_reactRootContainer'],
        "Vue.js": [r'vue\.js', r'Vue\(', r'__vue__', r'v-cloak'],
        "Angular": [r'ng-version', r'angular', r'ng-app'],
        "jQuery": [r'jquery', r'jQuery'],
        "Bootstrap": [r'bootstrap', r'Bootstrap'],
        "Tailwind CSS": [r'tailwindcss', r'tailwind'],
        "Svelte": [r'svelte', r'__svelte'],
        "Next.js": [r'__NEXT_DATA__', r'/_next/'],
        "Nuxt.js": [r'__NUXT__', r'/_nuxt/'],
    }

    def __init__(self):
        pass

    def fingerprint(self, target: str) -> FingerprintResult:
        """Full fingerprinting of a target."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        start = time.time()
        result = FingerprintResult(target=target)

        console.print(f"  [tool]▸ Fingerprinting[/tool] → [target]{target}[/target]")

        # Method 1: HTTP headers analysis
        self._analyze_headers(target, result)

        # Method 2: HTML content analysis
        self._analyze_html(target, result)

        # Method 3: WAF detection
        self._detect_waf(target, result)

        # Method 4: Try whatweb if installed
        self._run_whatweb(target, result)

        # Consolidate
        result.duration = time.time() - start
        result.server = next((t.name for t in result.technologies if t.category == "server"), "")
        result.cms = next((t.name for t in result.technologies if t.category == "cms"), "")
        result.language = next((t.name for t in result.technologies if t.category == "language"), "")
        result.framework = next((t.name for t in result.technologies if t.category == "framework"), "")

        tech_names = [t.name for t in result.technologies]
        console.print(f"  [tool]◂ Fingerprint[/tool] — {', '.join(tech_names[:8]) or 'basic detection'}")

        return result

    def _analyze_headers(self, target: str, result: FingerprintResult):
        """Analyze HTTP headers for technology detection."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10, verify=True,
                                  headers={"User-Agent": "Mozilla/5.0"})
            resp = client.get(target)
            result.headers = dict(resp.headers)
            result.cookies = resp.headers.get("set-cookie", "").split(",") if "set-cookie" in resp.headers else []

            header_techs = {}
            for header_name, patterns in self.HEADER_PATTERNS.items():
                header_value = resp.headers.get(header_name, "")
                if header_value:
                    for pattern, (tech_name, category) in patterns.items():
                        if pattern.lower() in header_value.lower():
                            header_techs.setdefault(tech_name, TechFingerprint(
                                name=tech_name,
                                version=self._extract_version(header_value, pattern),
                                category=category,
                                confidence="high",
                                source="headers",
                            ))
            result.technologies.extend(header_techs.values())

            # Check for specific cookie patterns
            cookies = resp.headers.get("set-cookie", "")
            if "PHPSESSID" in cookies:
                result.technologies.append(TechFingerprint(name="PHP", category="language", source="cookies"))
            elif "JSESSIONID" in cookies:
                result.technologies.append(TechFingerprint(name="Java", category="language", source="cookies"))
            elif "ASP.NET" in cookies or ".AspNetCore" in cookies:
                result.technologies.append(TechFingerprint(name="ASP.NET", category="framework", source="cookies"))
            elif "connect.sid" in cookies:
                result.technologies.append(TechFingerprint(name="Express.js", category="framework", source="cookies"))
            elif "_rails_session" in cookies:
                result.technologies.append(TechFingerprint(name="Rails", category="framework", source="cookies"))

        except Exception as e:
            logger.debug(f"Header analysis failed: {e}")

    def _analyze_html(self, target: str, result: FingerprintResult):
        """Analyze HTML content for technology detection."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10)
            resp = client.get(target)
            body = resp.text

            html_techs = {}

            # CMS detection
            for cms, patterns in self.CMS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.I):
                        html_techs.setdefault(cms, TechFingerprint(
                            name=cms, category="cms", confidence="high", source="html"
                        ))
                        break

            # JS framework detection
            for framework, patterns in self.JS_FRAMEWORK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.I):
                        html_techs.setdefault(framework, TechFingerprint(
                            name=framework, category="framework", confidence="medium", source="html"
                        ))
                        break

            # Meta tags
            for match in re.finditer(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', body, re.I):
                result.meta_tags.append({"name": match.group(1), "content": match.group(2)})
                if match.group(1).lower() == "generator":
                    gen = match.group(2)
                    if gen not in [t.name for t in result.technologies]:
                        result.technologies.append(TechFingerprint(
                            name=gen, category="cms", confidence="high", source="meta"
                        ))

            # JavaScript file analysis
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
            for js in js_files[:10]:
                js_lower = js.lower()
                if "react" in js_lower:
                    html_techs.setdefault("React", TechFingerprint(name="React", category="framework", source="js"))
                elif "vue" in js_lower:
                    html_techs.setdefault("Vue.js", TechFingerprint(name="Vue.js", category="framework", source="js"))
                elif "angular" in js_lower:
                    html_techs.setdefault("Angular", TechFingerprint(name="Angular", category="framework", source="js"))
                elif "jquery" in js_lower:
                    html_techs.setdefault("jQuery", TechFingerprint(name="jQuery", category="library", source="js"))
                elif "bootstrap" in js_lower:
                    html_techs.setdefault("Bootstrap", TechFingerprint(name="Bootstrap", category="library", source="js"))

            result.technologies.extend(html_techs.values())

        except Exception as e:
            logger.debug(f"HTML analysis failed: {e}")

    def _detect_waf(self, target: str, result: FingerprintResult):
        """Detect Web Application Firewall."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10)

            # Normal request
            resp = client.get(target)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    for header_name, header_value in headers_lower.items():
                        if sig.lower() in header_name.lower() or sig.lower() in str(header_value).lower():
                            result.waf_detected = waf_name
                            result.technologies.append(TechFingerprint(
                                name=waf_name, category="waf", confidence="high", source="headers"
                            ))
                            return

            # Try a malicious request to trigger WAF
            try:
                test_url = f"{target.rstrip('/')}?q=<script>alert(1)</script>"
                waf_resp = client.get(test_url)
                if waf_resp.status_code in (403, 406, 419, 429, 503):
                    body_lower = waf_resp.text.lower()
                    for waf_name in self.WAF_SIGNATURES:
                        if waf_name.lower() in body_lower:
                            result.waf_detected = waf_name
                            return
                    if waf_resp.status_code == 403:
                        result.waf_detected = "Unknown WAF (403 on malicious request)"
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")

    def _run_whatweb(self, target: str, result: FingerprintResult):
        """Run whatweb if installed."""
        import shutil
        if not shutil.which("whatweb"):
            return

        try:
            cmd = ["whatweb", "--color=never", "--log-json=-", target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout.strip().split("\n")[0])
                    plugins = data.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        if plugin_name in ("IP", "Country", "UncommonHeaders"):
                            continue
                        version = ""
                        if isinstance(plugin_data, dict):
                            versions = plugin_data.get("version", [])
                            if versions:
                                version = versions[0] if isinstance(versions, list) else str(versions)
                        result.technologies.append(TechFingerprint(
                            name=plugin_name, version=version,
                            category="detected", confidence="high", source="whatweb"
                        ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except Exception as e:
            logger.debug(f"whatweb failed: {e}")

    def _extract_version(self, value: str, tech: str) -> str:
        """Extract version number from header value."""
        # Common version patterns: "nginx/1.21.0", "PHP/8.1.2"
        match = re.search(rf'{re.escape(tech)}/([\d.]+)', value, re.I)
        if match:
            return match.group(1)
        match = re.search(r'([\d]+\.[\d]+\.[\d]+)', value)
        if match:
            return match.group(1)
        return ""
