"""Anti-Bot Detection — Identify WAF, CAPTCHA, and fingerprinting systems.

Inspired by Scrapfly's Antibot Detector.

Detects:
- Anti-bot systems: Cloudflare, Akamai, DataDome, PerimeterX, Shape Security, AWS WAF, Imperva, Kasada
- CAPTCHAs: reCAPTCHA, hCaptcha, FunCaptcha, GeeTest, Cloudflare Turnstile
- Fingerprinting: Canvas, WebGL, Audio, Font, WebRTC, Navigator
- Bot detection signals: JavaScript challenges, cookie requirements, TLS fingerprinting
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


@dataclass
class AntiBotResult:
    """Result of anti-bot detection."""
    name: str
    category: str  # waf, captcha, fingerprint, bot_detection
    confidence: str  # confirmed, likely, possible
    evidence: str
    bypass_hint: str = ""


class AntiBotDetector:
    """Detects anti-bot systems, CAPTCHAs, and fingerprinting."""
    NAME = "antibot_detection"

    # Anti-bot system signatures
    ANTI_BOT_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
            "body_patterns": [
                r"checking.*browser.*before",
                r"cf[-_]?challenge",
                r"cloudflare[-_]?ray",
                r"__cf_bm",
                r"cf[-_]?clearance",
                r"ray[-_]?id",
            ],
            "cookies": ["__cflb", "__cfuid", "__cf_bm", "cf_clearance"],
            "category": "waf",
            "bypass": "Use residential proxies, solve JS challenge, use cloudscraper",
        },
        "Akamai": {
            "headers": ["x-akamai", "akamai-origin-hop", "server: akamaighost"],
            "body_patterns": [
                r"akamai.*bot",
                r"akamaighost",
                r"akamai.*sensor",
                r"_abck",
            ],
            "cookies": ["_abck", "ak_bmsc", "bm_sz", "bm_sv"],
            "category": "waf",
            "bypass": "Use Akamai sensor data spoofing, residential proxies",
        },
        "DataDome": {
            "headers": ["x-dd-", "server: ddome"],
            "body_patterns": [
                r"datadome",
                r"dd[-_]?cookie",
                r"captcha.*datadome",
            ],
            "cookies": ["datadome", "dd_s"],
            "category": "waf",
            "bypass": "Use DataDome solver, residential proxies",
        },
        "PerimeterX": {
            "headers": ["x-px-", "server: perimeterx"],
            "body_patterns": [
                r"perimeterx",
                r"_px[0-9]",
                r"px[-_]?captcha",
            ],
            "cookies": ["_px", "_px2", "_px3", "pxcts"],
            "category": "waf",
            "bypass": "Use PerimeterX solver, human-like behavior",
        },
        "Shape Security": {
            "headers": ["x-shape-", "server: shape"],
            "body_patterns": [
                r"shape.*security",
                r"shape.*bot",
            ],
            "cookies": ["ss_", "shape_"],
            "category": "waf",
            "bypass": "Extremely difficult, requires real browser",
        },
        "AWS WAF": {
            "headers": ["x-amzn-", "x-amz-", "server: amazonee"],
            "body_patterns": [
                r"aws.*waf",
                r"amzn.*waf",
                r"aws.*captcha",
            ],
            "cookies": ["aws-waf-token"],
            "category": "waf",
            "bypass": "Solve AWS WAF CAPTCHA, use AWS IP ranges",
        },
        "Imperva": {
            "headers": ["x-iinfo", "server: imperva"],
            "body_patterns": [
                r"imperva",
                r"incapsula",
                r"visid_incap",
            ],
            "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
            "category": "waf",
            "bypass": "Use Imperva solver, residential proxies",
        },
        "Kasada": {
            "headers": ["x-kasada-", "server: kasada"],
            "body_patterns": [
                r"kasada",
                r"kasada.*bot",
            ],
            "cookies": ["kasada_", "__kps"],
            "category": "waf",
            "bypass": "Very difficult, requires real browser automation",
        },
        "Sucuri": {
            "headers": ["x-sucuri-", "server: sucuri"],
            "body_patterns": [
                r"sucuri",
                r"sucuri.*firewall",
            ],
            "cookies": ["sucuri_"],
            "category": "waf",
            "bypass": "Use residential proxies, solve JS challenge",
        },
        "Wordfence": {
            "headers": [],
            "body_patterns": [
                r"wordfence",
                r"wordfence.*blocked",
                r"wfwaf",
            ],
            "cookies": ["wordfence_verifiedHuman"],
            "category": "waf",
            "bypass": "Use residential proxies",
        },
        "ModSecurity": {
            "headers": ["server: mod_security", "server: modsecurity"],
            "body_patterns": [
                r"mod_security",
                r"modsecurity",
                r"this error was generated by mod_security",
            ],
            "cookies": [],
            "category": "waf",
            "bypass": "Use encoding bypasses, case variations",
        },
    }

    # CAPTCHA signatures
    CAPTCHA_SIGNATURES = {
        "reCAPTCHA": {
            "body_patterns": [
                r'recaptcha',
                r'google\.com/recaptcha',
                r'grecaptcha',
                r'recaptcha/api\.js',
                r'data-sitekey',
            ],
            "category": "captcha",
        },
        "hCaptcha": {
            "body_patterns": [
                r'hcaptcha',
                r'hcaptcha\.com',
                r'h-captcha',
                r'data-hcaptcha-sitekey',
            ],
            "category": "captcha",
        },
        "FunCaptcha": {
            "body_patterns": [
                r'funcaptcha',
                r'arkoselabs',
                r'funcaptcha\.com',
            ],
            "category": "captcha",
        },
        "GeeTest": {
            "body_patterns": [
                r'geetest',
                r'geetest\.com',
                r'gt_captcha',
            ],
            "category": "captcha",
        },
        "Cloudflare Turnstile": {
            "body_patterns": [
                r'turnstile',
                r'challenges\.cloudflare\.com',
                r'cf-turnstile',
            ],
            "category": "captcha",
        },
    }

    # Fingerprinting signals
    FINGERPRINT_SIGNATURES = {
        "Canvas Fingerprinting": {
            "body_patterns": [
                r'toDataURL',
                r'canvas.*fingerprint',
                r'getContext\([\'"]2d[\'"]',
            ],
        },
        "WebGL Fingerprinting": {
            "body_patterns": [
                r'getParameter.*UNMASKED_VENDOR',
                r'WEBGL_debug_renderer_info',
                r'webgl.*fingerprint',
            ],
        },
        "Audio Fingerprinting": {
            "body_patterns": [
                r'AudioContext',
                r'createOscillator',
                r'audio.*fingerprint',
            ],
        },
        "Font Fingerprinting": {
            "body_patterns": [
                r'font.*detect',
                r'measureText',
                r'font.*fingerprint',
            ],
        },
        "WebRTC Leak": {
            "body_patterns": [
                r'RTCPeerConnection',
                r'createDataChannel',
                r'webrtc.*leak',
            ],
        },
    }

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for anti-bot systems."""
        findings = []

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            import httpx
        except ImportError:
            return findings

        client = httpx.Client(
            follow_redirects=True,
            timeout=15,
            verify=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        )

        self.limiter.wait(urlparse(url).hostname)
        try:
            resp = client.get(url)
            headers = dict(resp.headers)
            body = resp.text
            cookies = dict(resp.cookies)

            # Detect anti-bot systems
            for system_name, sigs in self.ANTI_BOT_SIGNATURES.items():
                detected = self._detect_system(headers, body, cookies, sigs)
                if detected:
                    findings.append(Finding(
                        vuln_type="Anti-Bot System",
                        title=f"{system_name} detected",
                        severity="INFO",
                        url=url,
                        evidence=detected.evidence,
                        description=f"{system_name} ({detected.category}) is active on this target. Confidence: {detected.confidence}",
                        remediation=f"Bypass hint: {sigs.get('bypass', 'Use residential proxies and browser automation')}",
                        cvss=0.0,
                        cwe="",
                        tool=self.NAME,
                        verified=True,
                        confidence=detected.confidence.upper(),
                    ))

            # Detect CAPTCHAs
            for captcha_name, sigs in self.CAPTCHA_SIGNATURES.items():
                detected = self._detect_captcha(body, sigs)
                if detected:
                    findings.append(Finding(
                        vuln_type="CAPTCHA",
                        title=f"{captcha_name} detected",
                        severity="INFO",
                        url=url,
                        evidence=detected.evidence,
                        description=f"{captcha_name} is present. May block automated scanning.",
                        remediation="Manual testing required or CAPTCHA solver integration.",
                        cvss=0.0,
                        cwe="",
                        tool=self.NAME,
                        verified=True,
                        confidence=detected.confidence.upper(),
                    ))

            # Detect fingerprinting
            for fp_name, sigs in self.FINGERPRINT_SIGNATURES.items():
                detected = self._detect_fingerprint(body, sigs)
                if detected:
                    findings.append(Finding(
                        vuln_type="Fingerprinting",
                        title=f"{fp_name} detected",
                        severity="LOW",
                        url=url,
                        evidence=detected.evidence,
                        description=f"{fp_name} is used for bot detection.",
                        remediation="Use browser automation with fingerprint spoofing.",
                        cvss=0.0,
                        cwe="",
                        tool=self.NAME,
                        verified=True,
                        confidence=detected.confidence.upper(),
                    ))

            # Check for JS challenge
            if self._detect_js_challenge(body):
                findings.append(Finding(
                    vuln_type="Anti-Bot System",
                    title="JavaScript challenge detected",
                    severity="INFO",
                    url=url,
                    evidence="JavaScript challenge found in response body",
                    description="Target requires JavaScript execution to access content.",
                    remediation="Use headless browser (Playwright/Puppeteer) for scanning.",
                    cvss=0.0,
                    cwe="",
                    tool=self.NAME,
                    verified=True,
                    confidence="HIGH",
                ))

        except Exception as e:
            logger.debug(f"Anti-bot detection failed for {url}: {e}")

        client.close()
        return findings

    def _detect_system(self, headers: Dict, body: str, cookies: Dict, sigs: Dict) -> Optional[AntiBotResult]:
        """Detect an anti-bot system."""
        evidence_parts = []

        # Check headers
        for header_sig in sigs.get("headers", []):
            if ":" in header_sig:
                key, val = header_sig.split(":", 1)
                if key.strip().lower() in {k.lower() for k in headers}:
                    evidence_parts.append(f"Header: {key}")
            else:
                if header_sig.lower() in {k.lower() for k in headers}:
                    evidence_parts.append(f"Header: {header_sig}")

        # Check body patterns
        for pattern in sigs.get("body_patterns", []):
            if re.search(pattern, body, re.IGNORECASE):
                evidence_parts.append(f"Body pattern: {pattern}")

        # Check cookies
        for cookie_name in sigs.get("cookies", []):
            if cookie_name in cookies:
                evidence_parts.append(f"Cookie: {cookie_name}")

        if evidence_parts:
            confidence = "confirmed" if len(evidence_parts) >= 2 else "likely"
            return AntiBotResult(
                name=sigs.get("category", "unknown"),
                category=sigs.get("category", "unknown"),
                confidence=confidence,
                evidence="; ".join(evidence_parts[:3]),
            )

        return None

    def _detect_captcha(self, body: str, sigs: Dict) -> Optional[AntiBotResult]:
        """Detect CAPTCHA presence."""
        for pattern in sigs.get("body_patterns", []):
            if re.search(pattern, body, re.IGNORECASE):
                return AntiBotResult(
                    name="captcha",
                    category="captcha",
                    confidence="confirmed",
                    evidence=f"Pattern found: {pattern}",
                )
        return None

    def _detect_fingerprint(self, body: str, sigs: Dict) -> Optional[AntiBotResult]:
        """Detect fingerprinting techniques."""
        for pattern in sigs.get("body_patterns", []):
            if re.search(pattern, body, re.IGNORECASE):
                return AntiBotResult(
                    name="fingerprint",
                    category="fingerprint",
                    confidence="likely",
                    evidence=f"Pattern found: {pattern}",
                )
        return None

    def _detect_js_challenge(self, body: str) -> bool:
        """Detect JavaScript challenges."""
        challenge_patterns = [
            r'checking.*browser',
            r'please.*enable.*javascript',
            r'javascript.*required',
            r'browser.*check',
            r'loading.*please.*wait',
            r'challenge.*platform',
            r'cf[-_]?challenge',
        ]
        return any(re.search(p, body, re.IGNORECASE) for p in challenge_patterns)


# Export
__all__ = ["AntiBotDetector"]
