"""Intent Parser - Understands natural language and maps to actions."""

import re
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ParsedIntent:
    """Parsed user intent."""
    action: str           # what to do
    target: str           # what to do it on
    raw_input: str        # original input
    confidence: float     # how sure we are
    params: Dict[str, Any] = None

    def __post_init__(self):
        if self.params is None:
            self.params = {}


class IntentParser:
    """Parses natural language into executable actions."""

    # Intent patterns - order matters (first match wins)
    PATTERNS = [
        # Bug Bounty - Full recon
        (r"(?:full\s+recon|recon\s+full|complete\s+recon)\s+(.+)", "full_recon"),
        (r"(?:full\s+recon|recon\s+full|complete\s+recon)", "full_recon"),

        # Bug Bounty - Scan
        (r"(?:scan|recon|bug\s*bounty|vulnerability)\s+(?:on\s+)?(.+)", "bugbounty_scan"),
        (r"(?:nuclei|scan)\s+(.+)", "bugbounty_scan"),

        # Vulnerability Scanner (automated SQLi/XSS/SSRF)
        (r"(?:exploit|vuln\s*scan|auto\s*scan)\s+(.+)", "vuln_scan"),
        (r"(?:exploit|vuln\s*scan|auto\s*scan)", "vuln_scan"),

        # Proxy Intercept
        (r"(?:intercept|proxy)\s+(.+)", "proxy_intercept"),
        (r"(?:intercept|proxy)", "proxy_stats"),

        # Replay
        (r"(?:replay)\s+(\d+)", "proxy_replay"),

        # OSINT
        (r"(?:osint|recon|intel|info)\s+(.+)", "osint"),
        (r"(?:osint|recon|intel|info)", "osint_help"),

        # Brute Force
        (r"(?:brute|brute\s*force|crack)\s+(.+)", "brute_force"),
        (r"(?:brute|brute\s*force|crack)", "brute_help"),

        # Browser
        (r"(?:browse|open|visit|khol)\s+(.+)", "browse"),

        # Toolkit - Full Audit (pure Python, no tools needed)
        (r"(?:full\s*audit|audit\s*full|complete\s*audit)\s+(.+)", "full_audit"),
        (r"(?:full\s*audit|audit\s*full|complete\s*audit)", "full_audit_help"),

        # Toolkit - WAF Detection
        (r"(?:waf|waf\s*detect)\s+(.+)", "waf_detect"),

        # Toolkit - CORS Check
        (r"(?:cors|cors\s*check)\s+(.+)", "cors_check"),

        # Toolkit - Header Check
        (r"(?:headers?|security\s*headers?)\s+(.+)", "header_check"),

        # Toolkit - SSL Check
        (r"(?:ssl|tls|certificate)\s+(.+)", "ssl_check"),

        # Toolkit - SQLMap
        (r"(?:sqlmap|sql\s*inject)\s+(.+)", "sqlmap"),

        # Toolkit - Info Disclosure
        (r"(?:leak|disclosure|exposed|sensitive)\s+(.+)", "info_disclosure"),

        # Toolkit - Open Redirect
        (r"(?:redirect|open\s*redirect)\s+(.+)", "open_redirect"),

        # Toolkit - XSS
        (r"(?:xss|xss\s*check)\s+(.+)", "xss_check"),

        # Toolkit - Subdomain Takeover
        (r"(?:takeover|subdomain\s*takeover)\s+(.+)", "subdomain_takeover"),

        # Code Generation
        (r"(?:generate|banao|banao|create|likh|write)\s+(?:code|program|script)?\s*(?:for|of|to)?\s*(.+)", "generate_code"),
        (r"(?:code|program)\s+(?:for|of|to)\s+(.+)", "generate_code"),
        (r"banao\s+(.+)", "generate_code"),

        # Thinking / Reflection
        (r"(?:think|soch|vichaar)\s+(?:about|ke baare mein|pe)\s+(.+)", "think"),
        (r"(?:kya\s+lagta\s+hai|what\s+do\s+you\s+think)\s+(?:about|ke baare mein)?\s*(.+)?", "think"),

        # Dream / Consolidate
        (r"(?:dream|sapna|consolidate|yaadein)\s*$", "dream"),

        # Status
        (r"(?:status|hal|kya\s+haal|system\s+info)", "status"),

        # Emotional
        (r"(?:kaisa\s+feel|how\s+do\s+you\s+feel|mood\s+kaisa)", "mood"),
        (r"(?:tumhara\s+naam|your\s+name|kaun\s+ho)", "identity"),

        # Memory recall
        (r"(?:yaad\s+karo|recall|remember|pichli\s+baar|last\s+time)\s*(.*)", "recall"),
        (r"(?:kya\s+hua\s+tha|what\s+happened)\s*(.*)", "recall"),

        # Self evolution
        (r"(?:evolve|upgrade|improve|khud\s+ko\s+sudhar|self\s+improve)", "evolve"),

        # Goals
        (r"(?:goal|lakshya|target| Objective)\s+(.+)", "set_goal"),
        (r"(?:goals?\s+dekh|show\s+goals?|goal\s+status)", "show_goals"),

        # Code execution
        (r"(?:run|chala|execute)\s+(.+)", "run_code"),

        # Learning
        (r"(?:seekh|learn|study|research)\s+(.+)", "learn"),

        # Quit
        (r"(?:quit|exit|band|close|bye|alvida)", "quit"),
    ]

    def parse(self, text: str) -> ParsedIntent:
        """Parse user input into an intent."""
        text_lower = text.lower().strip()

        for pattern, action in self.PATTERNS:
            match = re.search(pattern, text_lower)
            if match:
                target = match.group(1) if match.lastindex and match.group(1) else ""
                return ParsedIntent(
                    action=action,
                    target=target.strip(),
                    raw_input=text,
                    confidence=0.8
                )

        # No pattern matched - treat as general chat
        return ParsedIntent(
            action="chat",
            target=text,
            raw_input=text,
            confidence=0.5
        )

    def get_available_commands(self) -> str:
        """Return human-readable list of what Prometheus can do."""
        return """
Mujhe ye sab commands samajh aa jaate hain:

  BUG BOUNTY & SCANNING
  ─────────────────────────────── ──────────────────────────────
  "scan google.com"               Bug bounty scan chalega
  "full recon google.com"         Full recon + vuln scan
  "exploit google.com"            Auto SQLi/XSS/SSRF scan
  "vuln scan http://x.com"       Vulnerability scan

  PURE PYTHON AUDIT (koi tool install nahi chahiye!)
  "full audit http://x.com"       Sab kuch check karega
  "waf http://x.com"              WAF/CDN detect karega
  "cors http://x.com"             CORS misconfig check
  "headers http://x.com"          Security headers check
  "ssl google.com"                SSL/TLS check
  "sqlmap http://x.com"           SQLMap auto injection
  "leak http://x.com"             Sensitive files check
  "redirect http://x.com"         Open redirect check
  "xss http://x.com"              Reflected XSS check
  "takeover google.com"           Subdomain takeover check

  OSINT & RECON
  "osint username123"             Username 20+ platforms pe dhundhega
  "osint google.com"              Domain OSINT - subdomains, emails
  "recon target.com"              Full OSINT recon

  PROXY & INTERCEPT
  "intercept GET http://x.com"   Request intercept karega
  "replay 1"                      Last request replay
  "proxy"                         Proxy stats

  BRUTE FORCE
  "brute http://x.com login"     OSINT-powered brute force
  "crack http://x.com"           Smart password attack

  BROWSER
  "browse http://x.com"          Cloudflare bypass ke saath khol

  CODE & THINKING
  "code banao for todo app"      Code generate karega
  "soch about AI"                 Sochega aur batayega
  "dream"                         Yaadein compress karega

  SYSTEM
  "status"                        System status dega
  "kaisa feel kar raha hai"       Apna mood batayega
  "yaad karo"                     Pichli baatein yaad karega
  "evolve"                        Khud ko upgrade karega
  "seekh machine learning"        Research karega
  "bye"                           Band karega

  Ya kuch bhi normally baat karo - main samajh jaunga!
"""
