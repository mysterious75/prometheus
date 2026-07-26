"""Payload Importer — import payloads from external sources.

Supports:
- PayloadsAllTheThings cloned repo (directory structure)
- Individual text/markdown files
- Remote URLs
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from ..core.logger import logger
from .payload_engine import PayloadEngine, Payload


# ---------------------------------------------------------------------------
# Mapping from PayloadsAllTheThings folder names → our vuln types
# ---------------------------------------------------------------------------

PATT_FOLDER_MAP: Dict[str, str] = {
    "SQL Injection": "sqli",
    "NoSQL Injection": "sqli",
    "XSS Injection": "xss",
    "Cross Site Scripting (XSS)": "xss",
    "SSRF Injection": "ssrf",
    "Server Side Request Forgery": "ssrf",
    "Command Injection": "cmdi",
    "OS Command Injection": "cmdi",
    "Server Side Template Injection": "ssti",
    "SSTI": "ssti",
    "XXE Injection": "xxe",
    "XML External Entity": "xxe",
    "Directory Traversal": "traversal",
    "Path Traversal": "traversal",
    "Local File Inclusion": "traversal",
    "Open Redirect": "redirect",
    "Unvalidated Redirects": "redirect",
    "CORS Misconfiguration": "cors",
    "Insecure Direct Object Reference": "idor",
    "IDOR": "idor",
    "JWT": "auth",
    "JSON Web Token": "auth",
    "API Keys": "secrets",
    "Secrets": "secrets",
    "GraphQL Injection": "sqli",
    "LDAP Injection": "cmdi",
    "CRLF Injection": "redirect",
    "HTTP Request Smuggling": "smuggling",
    "Race Condition": "race",
    "Upload Insecure Files": "traversal",
    "Insecure Deserialization": "cmdi",
}

# Also match common sub-folder / file names
PATT_SUBTYPE_MAP: Dict[str, str] = {
    "README.md": "",
    "Cheatsheet": "cheatsheet",
    "Bypass": "waf_bypass",
    "WAF Bypass": "waf_bypass",
    "Detection": "detection",
    "Exploitation": "exploit",
    "Methodology": "methodology",
    "Tools": "tools",
    "References": "references",
}


class PayloadImporter:
    """Imports payloads from external sources."""

    def __init__(self, engine: Optional[PayloadEngine] = None):
        self.engine = engine or PayloadEngine()
        self._seen_hashes: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def import_from_payloadsallthethings(self, base_dir: str) -> int:
        """Import from a cloned PayloadsAllTheThings repo.

        Args:
            base_dir: Path to the cloned repo root.

        Returns:
            Total number of payloads imported.
        """
        base = Path(base_dir)
        if not base.exists():
            logger.warning(f"PayloadsAllTheThings directory not found: {base_dir}")
            return 0

        total = 0
        # Walk the directory looking for known vulnerability folders
        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue

            folder_name = entry.name
            vuln_type = self._map_folder_to_type(folder_name)
            if not vuln_type:
                # Try partial matching
                vuln_type = self._fuzzy_map_folder(folder_name)
            if not vuln_type:
                continue

            logger.info(f"Importing from {folder_name} → {vuln_type}")
            for md_file in sorted(entry.rglob("*.md")):
                count = self._parse_markdown_payloads(md_file, vuln_type, folder_name)
                total += count

            # Also import .txt files
            for txt_file in sorted(entry.rglob("*.txt")):
                count = self._import_text_file(txt_file, vuln_type)
                total += count

        logger.info(f"PayloadsAllTheThings import complete: {total} payloads")
        return total

    def import_from_file(self, filepath: str, vuln_type: str) -> int:
        """Import payloads from a text or markdown file.

        Args:
            filepath: Path to the file.
            vuln_type: Vulnerability type (sqli, xss, ssrf, etc.).

        Returns:
            Number of payloads imported.
        """
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"File not found: {filepath}")
            return 0

        if path.suffix == ".md":
            return self._parse_markdown_payloads(path, vuln_type, path.stem)
        else:
            return self._import_text_file(path, vuln_type)

    def import_from_url(self, url: str, vuln_type: str) -> int:
        """Import payloads from a URL.

        Args:
            url: URL to fetch payloads from.
            vuln_type: Vulnerability type.

        Returns:
            Number of payloads imported.
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — URL import disabled")
            return 0

        try:
            resp = httpx.get(url, timeout=15, follow_redirects=True)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return 0

        content = resp.text
        count = self._parse_content_payloads(content, vuln_type, url)
        logger.info(f"Imported {count} payloads from {url}")
        return count

    # ------------------------------------------------------------------
    # Internal: folder mapping
    # ------------------------------------------------------------------

    def _map_folder_to_type(self, folder_name: str) -> Optional[str]:
        """Map a PayloadsAllTheThings folder name to our vuln type."""
        # Exact match
        if folder_name in PATT_FOLDER_MAP:
            return PATT_FOLDER_MAP[folder_name]
        return None

    def _fuzzy_map_folder(self, folder_name: str) -> Optional[str]:
        """Fuzzy match folder name to vuln type."""
        lower = folder_name.lower()
        keywords = {
            "sqli": ["sql", "nosql", "injection"],
            "xss": ["xss", "cross-site script", "cross site script"],
            "ssrf": ["ssrf", "server side request"],
            "cmdi": ["command injection", "os command", "code injection"],
            "ssti": ["template injection", "ssti"],
            "xxe": ["xxe", "xml external"],
            "traversal": ["traversal", "path traversal", "directory traversal", "file inclusion", "lfi", "upload"],
            "redirect": ["redirect", "crlf"],
            "cors": ["cors"],
            "idor": ["idor", "direct object"],
            "smuggling": ["smuggling"],
            "race": ["race condition", "race"],
            "auth": ["jwt", "token", "authentication", "auth bypass"],
            "secrets": ["secret", "api key", "credential"],
        }
        for vuln_type, kws in keywords.items():
            for kw in kws:
                if kw in lower:
                    return vuln_type
        return None

    # ------------------------------------------------------------------
    # Internal: parsing
    # ------------------------------------------------------------------

    def _parse_markdown_payloads(
        self, filepath: Path, vuln_type: str, source_label: str
    ) -> int:
        """Parse payloads from a PayloadsAllTheThings markdown file.

        Extracts content from:
        - Fenced code blocks (``` ... ```)
        - Inline code that looks like payloads
        - Bullet lists with payload-like content
        """
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"Failed to read {filepath}: {e}")
            return 0

        return self._parse_content_payloads(
            content, vuln_type, f"{source_label}/{filepath.name}"
        )

    def _parse_content_payloads(
        self, content: str, vuln_type: str, source: str
    ) -> int:
        """Parse payloads from raw content string."""
        payloads: List[str] = []

        # Extract from fenced code blocks
        in_code_block = False
        code_block_lang = ""
        code_lines: List[str] = []

        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("```"):
                if in_code_block:
                    # End of code block
                    payloads.extend(self._extract_payloads_from_block(
                        "\n".join(code_lines), code_block_lang
                    ))
                    code_lines = []
                    code_block_lang = ""
                    in_code_block = False
                else:
                    # Start of code block
                    in_code_block = True
                    code_block_lang = stripped[3:].strip().lower()
                continue

            if in_code_block:
                code_lines.append(line)

        # Also look for inline code patterns
        inline_pattern = re.compile(r'`([^`\n]{3,200})`')
        for match in inline_pattern.finditer(content):
            candidate = match.group(1).strip()
            if self._looks_like_payload(candidate, vuln_type):
                payloads.append(candidate)

        # Look for bullet list items that are payloads
        bullet_pattern = re.compile(r'^\s*[-*+]\s+`?([^`\n]{3,200})`?', re.MULTILINE)
        for match in bullet_pattern.finditer(content):
            candidate = match.group(1).strip()
            if self._looks_like_payload(candidate, vuln_type):
                payloads.append(candidate)

        # Deduplicate and import
        return self._import_payloads(payloads, vuln_type, source)

    def _extract_payloads_from_block(
        self, block: str, lang: str
    ) -> List[str]:
        """Extract payload strings from a code block."""
        payloads: List[str] = []

        # Skip non-payload blocks
        skip_langs = {"python", "bash", "sh", "shell", "powershell", "ruby", "java", "go", "rust", "c", "cpp", "yaml", "json", "xml", "html", "css"}
        if lang in skip_langs:
            # For code blocks, only extract if they look like they contain payloads
            # (e.g., SQL injection examples in Python code)
            pass

        for line in block.split("\n"):
            line = line.strip()
            if not line or len(line) < 3:
                continue
            # Skip comments
            if line.startswith("#") or line.startswith("//") or line.startswith("/*"):
                continue
            # Skip lines that are clearly not payloads
            if line.startswith("import ") or line.startswith("from "):
                continue
            if line.startswith("def ") or line.startswith("class "):
                continue
            if line.startswith("print(") or line.startswith("console."):
                continue
            payloads.append(line)

        return payloads

    def _looks_like_payload(self, candidate: str, vuln_type: str) -> bool:
        """Heuristic: does this string look like a security payload?"""
        if len(candidate) < 3 or len(candidate) > 500:
            return False

        # Skip common non-payload patterns
        skip_patterns = [
            r"^https?://",
            r"^\w+\.\w+\.\w+",  # domain names
            r"^[A-Z_]+$",  # CONSTANTS
            r"^\d+$",  # pure numbers
            r"^\w+$",  # single words
        ]
        for pat in skip_patterns:
            if re.match(pat, candidate):
                return False

        # Positive indicators by vuln type
        indicators = {
            "sqli": ["'", '"', "UNION", "SELECT", "OR", "AND", "--", "#", "SLEEP", "BENCHMARK", "CONVERT", "CAST", "DROP", "INSERT", "UPDATE", "DELETE"],
            "xss": ["<", ">", "script", "alert", "onerror", "onload", "img", "svg", "javascript:", "prompt", "confirm"],
            "ssrf": ["127.0.0.1", "localhost", "169.254", "metadata", "file://", "gopher://", "dict://"],
            "cmdi": [";", "|", "`", "$(", "&&", "||", "cat ", "whoami", "id", "/etc/", "cmd", "powershell"],
            "ssti": ["{{", "${", "<%", "#{", ".__class__", ".__mro__", "popen"],
            "xxe": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://", "ENTITY"],
            "traversal": ["../", "..\\", "%2e%2e", "/etc/passwd", "win.ini", "..;/"],
        }

        vuln_indicators = indicators.get(vuln_type, [])
        candidate_upper = candidate.upper()
        for indicator in vuln_indicators:
            if indicator.upper() in candidate_upper:
                return True

        return False

    def _import_text_file(self, filepath: Path, vuln_type: str) -> int:
        """Import payloads from a plain text file (one per line)."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"Failed to read {filepath}: {e}")
            return 0

        payloads: List[str] = []
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) > 2:
                payloads.append(line)

        return self._import_payloads(payloads, vuln_type, filepath.name)

    # ------------------------------------------------------------------
    # Internal: deduplication and storage
    # ------------------------------------------------------------------

    def _import_payloads(
        self, raw_payloads: List[str], vuln_type: str, source: str
    ) -> int:
        """Deduplicate and store payloads in the engine."""
        count = 0
        for value in raw_payloads:
            value = value.strip()
            if not value or len(value) < 2:
                continue

            # Deduplicate by hash
            h = hashlib.md5(value.encode("utf-8")).hexdigest()
            if h in self._seen_hashes:
                continue
            self._seen_hashes.add(h)

            # Check against existing payloads in engine
            existing = self.engine._payloads.get(vuln_type, [])
            if any(p.value == value for p in existing):
                continue

            # Add to engine
            if vuln_type not in self.engine._payloads:
                self.engine._payloads[vuln_type] = []

            self.engine._payloads[vuln_type].append(Payload(
                value=value,
                vuln_type=vuln_type,
                sub_type="imported",
                source=f"imported:{source}",
            ))
            count += 1

        return count

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_import_stats(self) -> Dict[str, int]:
        """Get statistics on imported payloads by type."""
        stats: Dict[str, int] = {}
        for vuln_type, payloads in self.engine._payloads.items():
            imported = [p for p in payloads if p.source.startswith("imported")]
            if imported:
                stats[vuln_type] = len(imported)
        return stats
