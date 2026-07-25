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
        # Authorization management (highest priority)
        (r"(?:authorize|auth|allow|whitelist)\s+(.+)", "authorize"),
        (r"(?:targets?|authorized|allowed)", "targets"),

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

        # OSINT (passive - no auth needed)
        (r"(?:osint|intel|info)\s+(.+)", "osint"),
        (r"(?:osint|intel|info)", "osint_help"),

        # Browser
        (r"(?:browse|open|visit|khol)\s+(.+)", "browse"),

        # Toolkit - Full Audit
        (r"(?:full\s*audit|audit\s*full|complete\s*audit)\s+(.+)", "full_audit"),
        (r"(?:full\s*audit|audit\s*full|complete\s*audit)", "full_audit_help"),

        # Toolkit - Individual checks
        (r"(?:waf|waf\s*detect)\s+(.+)", "waf_detect"),
        (r"(?:cors|cors\s*check)\s+(.+)", "cors_check"),
        (r"(?:headers?|security\s*headers?)\s+(.+)", "header_check"),
        (r"(?:ssl|tls|certificate)\s+(.+)", "ssl_check"),
        (r"(?:sqlmap|sql\s*inject)\s+(.+)", "sqlmap"),
        (r"(?:leak|disclosure|exposed|sensitive)\s+(.+)", "info_disclosure"),
        (r"(?:redirect|open\s*redirect)\s+(.+)", "open_redirect"),
        (r"(?:xss|xss\s*check)\s+(.+)", "xss_check"),
        (r"(?:takeover|subdomain\s*takeover)\s+(.+)", "subdomain_takeover"),

        # Knowledge Base
        (r"(?:seekh|learn|study)\s+(.+)", "learn_from_kb"),
        (r"(?:cheatsheet|cheat\s*sheet)\s+(.+)", "cheatsheet"),
        (r"(?:playbook|attack)\s+(.+)", "playbook"),
        (r"(?:payloads?|payload)\s+(.+)", "get_payloads"),
        (r"(?:bounty|payout)\s+(.+)", "bounty_info"),
        (r"(?:kb\s*stats|knowledge)", "kb_stats"),

        # Code Generation
        (r"(?:generate|banao|create|likh|write)\s+(?:code|program|script)?\s*(?:for|of|to)?\s*(.+)", "generate_code"),
        (r"(?:code|program)\s+(?:for|of|to)\s+(.+)", "generate_code"),

        # Thinking / Reflection
        (r"(?:think|soch|vichaar)\s+(?:about|ke baare mein|pe)\s+(.+)", "think"),
        (r"(?:kya\s+lagta\s+hai|what\s+do\s+you\s+think)\s+(?:about|ke baare mein)?\s*(.+)?", "think"),

        # Dream / Consolidate
        (r"(?:dream|sapna|consolidate|yaadein)\s*$", "dream"),

        # Status
        (r"(?:status|hal|kya\s+haal|system\s+info)", "status"),
        (r"(?:providers?|ai\s*status|models?|keys?)", "providers"),

        # Emotional
        (r"(?:kaisa\s+feel|how\s+do\s+you\s+feel|mood\s+kaisa)", "mood"),
        (r"(?:tumhara\s+naam|your\s+name|kaun\s+ho)", "identity"),

        # Memory recall
        (r"(?:yaad\s+karo|recall|remember|pichli\s+baar|last\s+time)\s*(.*)", "recall"),
        (r"(?:kya\s+hua\s+tha|what\s+happened)\s*(.*)", "recall"),

        # Goals
        (r"(?:goal|lakshya|target)\s+(.+)", "set_goal"),
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
        """Return human-readable list of available commands."""
        return """
COMMANDS:

  AUTHORIZATION (pehle target authorize karo!)
  ─────────────────────────────────────────────
  "authorize google.com"          Target ko allow karo
  "targets"                       Authorized targets dekho

  BUG BOUNTY & SCANNING (authorized targets only)
  ─────────────────────────────────────────────
  "scan google.com"               Bug bounty scan
  "full recon google.com"         Full recon + vuln scan
  "exploit google.com"            Auto SQLi/XSS/SSRF scan

  PASSIVE RECON (no auth needed)
  ─────────────────────────────────────────────
  "osint username123"             Username search 20+ platforms
  "osint google.com"              Domain OSINT
  "headers google.com"            Security headers check
  "ssl google.com"                SSL/TLS check
  "cors http://x.com"             CORS misconfig check
  "waf http://x.com"              WAF detection

  ACTIVE SCANNING (auth required)
  ─────────────────────────────────────────────
  "full audit http://x.com"       Complete audit
  "sqlmap http://x.com"           SQL injection test
  "xss http://x.com"              XSS check
  "leak http://x.com"             Sensitive files check
  "redirect http://x.com"         Open redirect check
  "takeover google.com"           Subdomain takeover

  PROXY & BROWSER
  ─────────────────────────────────────────────
  "intercept GET http://x.com"    Request intercept
  "browse http://x.com"           Browser navigation

  KNOWLEDGE BASE
  ─────────────────────────────────────────────
  "cheatsheet sqli"               Vulnerability cheatsheet
  "playbook xss"                  Attack playbook
  "payloads sqli"                 Attack payloads
  "bounty xss"                    Bounty ranges

  SYSTEM
  ─────────────────────────────────────────────
  "status"                        System status
  "mood"                          Emotional state
  "recall"                        Past conversations
  "goals"                         Active goals
  "code banao for todo app"       Code generation
  "think about AI"                Reflection
  "quit"                          Exit

  Ya kuch bhi normally baat karo!
"""
