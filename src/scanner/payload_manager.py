"""
Prometheus Payload Management System

Centralized payload database with thousands of real security testing payloads
organized by vulnerability type. Supports context-aware selection, dynamic
encoding variants, and lazy loading with in-memory caching.
"""

import os
import re
import yaml
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from functools import lru_cache
from urllib.parse import quote, quote_plus, unquote

logger = logging.getLogger(__name__)

PAYLOADS_DIR = Path(__file__).parent.parent.parent / "payloads"


@dataclass
class Payload:
    """Represents a single security testing payload."""
    value: str
    description: str = ""
    severity: str = "info"          # critical, high, medium, low, info
    dbms: str = "generic"           # mysql, postgresql, mssql, oracle, sqlite, generic
    context: str = "generic"        # html, attribute, javascript, url, css, json, xml, generic
    encoding: str = "none"          # none, url, double_url, html_entity, unicode, base64
    source: str = "prometheus"      # prometheus, payloadallthethings, nuclei, custom
    tags: List[str] = field(default_factory=list)
    detection_pattern: str = ""     # regex to detect if payload executed
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Unique ID based on content hash."""
        return hashlib.md5(f"{self.value}:{self.dbms}:{self.context}".encode()).hexdigest()[:12]


@dataclass
class PayloadContext:
    """Context for payload selection."""
    dbms: str = "generic"               # mysql, postgresql, mssql, oracle, sqlite, generic
    waf_detected: bool = False
    parameter_type: str = "string"      # string, numeric, json, xml
    injection_context: str = "generic"  # html, attribute, javascript, url, css, json, xml, generic
    encoding_required: str = "none"     # none, url, double_url, html_entity, unicode
    os_type: str = "linux"              # linux, windows, generic
    tech_stack: List[str] = field(default_factory=list)
    max_payloads: int = 0               # 0 = unlimited


class PayloadManager:
    """
    Centralized payload management system for security testing.
    
    Features:
    - Lazy loading: payloads loaded on first access, not at startup
    - In-memory caching: loaded payloads cached for session lifetime
    - Context-aware selection: filter by DBMS, WAF, parameter type, etc.
    - Dynamic encoding: generate URL-encoded, double-encoded, unicode variants
    - Extensible: load external payload files (PayloadsAllTheThings format)
    """

    def __init__(self, payloads_dir: Optional[str] = None):
        self._payloads_dir = Path(payloads_dir) if payloads_dir else PAYLOADS_DIR
        self._cache: Dict[str, List[Payload]] = {}
        self._detection_cache: Dict[str, List[str]] = {}
        self._file_index: Optional[Dict[str, Path]] = None
        self._loaded_files: Set[str] = set()
        logger.info(f"PayloadManager initialized with dir: {self._payloads_dir}")

    # ─── Core API ───────────────────────────────────────────────────────

    def get_payloads(self, vuln_type: str, context: Optional[Dict[str, Any]] = None) -> List[Payload]:
        """
        Get payloads for a vulnerability type with optional context filtering.
        
        Args:
            vuln_type: Vulnerability type path, e.g. "sqli/error_based", "xss/reflected"
            context: Optional dict with keys: dbms, waf_detected, parameter_type,
                     injection_context, encoding_required, os_type, tech_stack, max_payloads
        
        Returns:
            List of Payload objects matching the context
        """
        ctx = self._parse_context(context or {})
        
        # Load payloads for this vuln type
        payloads = self._load_payloads(vuln_type)
        
        # Apply context filtering
        filtered = self._filter_by_context(payloads, ctx)
        
        # Generate encoding variants if requested
        if ctx.encoding_required != "none":
            filtered = self._apply_encoding(filtered, ctx.encoding_required)
        
        # Apply WAF bypass variants if WAF detected
        if ctx.waf_detected:
            waf_payloads = []
            for p in filtered:
                waf_payloads.extend(self.generate_waf_bypass(p.value, p.description))
            filtered.extend(waf_payloads)
        
        # Limit if requested
        if ctx.max_payloads > 0:
            filtered = filtered[:ctx.max_payloads]
        
        return filtered

    def get_detection_patterns(self, vuln_type: str) -> List[str]:
        """
        Get detection regex patterns for a vulnerability type.
        
        Args:
            vuln_type: Vulnerability type path, e.g. "sqli/error_based"
        
        Returns:
            List of regex pattern strings
        """
        if vuln_type in self._detection_cache:
            return self._detection_cache[vuln_type]

        payloads = self._load_payloads(vuln_type)
        patterns = []
        for p in payloads:
            if p.detection_pattern:
                patterns.append(p.detection_pattern)
        
        # Add built-in patterns if none found in file
        if not patterns:
            patterns = self._builtin_detection_patterns(vuln_type)
        
        self._detection_cache[vuln_type] = patterns
        return patterns

    def generate_waf_bypass(self, payload: str, description: str = "") -> List[Payload]:
        """
        Generate WAF bypass variants of a payload using multiple encoding techniques.
        
        Args:
            payload: Original payload string
            description: Optional description prefix
        
        Returns:
            List of Payload objects with WAF bypass variants
        """
        variants = []
        desc_prefix = f"{description} - " if description else ""

        # 1. Case variations
        variants.append(Payload(
            value=self._case_variations(payload),
            description=f"{desc_prefix}Case variation bypass",
            tags=["waf_bypass", "case_variation"],
        ))

        # 2. URL encoding
        variants.append(Payload(
            value=quote(payload, safe=''),
            description=f"{desc_prefix}URL encoded",
            encoding="url",
            tags=["waf_bypass", "url_encoded"],
        ))

        # 3. Double URL encoding
        variants.append(Payload(
            value=quote(quote(payload, safe=''), safe=''),
            description=f"{desc_prefix}Double URL encoded",
            encoding="double_url",
            tags=["waf_bypass", "double_url_encoded"],
        ))

        # 4. HTML entity encoding
        variants.append(Payload(
            value=self._html_entity_encode(payload),
            description=f"{desc_prefix}HTML entity encoded",
            encoding="html_entity",
            tags=["waf_bypass", "html_entity"],
        ))

        # 5. Unicode encoding
        variants.append(Payload(
            value=self._unicode_encode(payload),
            description=f"{desc_prefix}Unicode encoded",
            encoding="unicode",
            tags=["waf_bypass", "unicode"],
        ))

        # 6. Whitespace substitution
        for ws_char in ['%09', '%0a', '%0d', '%0b', '%0c']:
            variants.append(Payload(
                value=payload.replace(' ', ws_char),
                description=f"{desc_prefix}Whitespace substitution ({ws_char})",
                tags=["waf_bypass", "whitespace"],
            ))

        # 7. Comment injection (SQL-style)
        variants.append(Payload(
            value=payload.replace(' ', '/**/'),
            description=f"{desc_prefix}Comment injection (/**/)",
            tags=["waf_bypass", "comment_injection"],
        ))

        # 8. MySQL comment injection
        if any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE']):
            mysql_comment = payload
            for kw in ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'GROUP']:
                if kw in mysql_comment.upper():
                    mysql_comment = re.sub(
                        f'(?i){kw}',
                        f'/*!50000{kw}*/',
                        mysql_comment,
                        count=1
                    )
            variants.append(Payload(
                value=mysql_comment,
                description=f"{desc_prefix}MySQL version comment bypass",
                tags=["waf_bypass", "mysql_comment"],
            ))

        # 9. Null byte injection
        variants.append(Payload(
            value=payload.replace(' ', '%00'),
            description=f"{desc_prefix}Null byte injection",
            tags=["waf_bypass", "null_byte"],
        ))

        # 10. Mixed encoding
        mixed = ""
        for i, c in enumerate(payload):
            if i % 2 == 0:
                mixed += c
            else:
                mixed += f"%{ord(c):02x}"
        variants.append(Payload(
            value=mixed,
            description=f"{desc_prefix}Mixed encoding",
            tags=["waf_bypass", "mixed_encoding"],
        ))

        return variants

    def load_external(self, filepath: str) -> int:
        """
        Load payloads from an external file (PayloadsAllTheThings / custom format).
        
        Supports YAML and JSON formats. Returns count of loaded payloads.
        
        Args:
            filepath: Path to external payload file
        
        Returns:
            Number of payloads loaded
        """
        fpath = Path(filepath)
        if not fpath.exists():
            logger.warning(f"External file not found: {filepath}")
            return 0

        count = 0
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                if fpath.suffix in ('.yml', '.yaml'):
                    data = yaml.safe_load(f)
                elif fpath.suffix == '.json':
                    import json
                    data = json.load(f)
                else:
                    # Treat as plain text, one payload per line
                    lines = f.readlines()
                    vuln_type = fpath.stem
                    payloads = []
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(Payload(value=line, source="external"))
                    self._cache[f"external/{vuln_type}"] = payloads
                    return len(payloads)

            if isinstance(data, dict):
                # Check for standard format with metadata + payloads key
                if 'payloads' in data:
                    raw_payloads = data['payloads']
                else:
                    raw_payloads = data
                
                vuln_type = fpath.stem
                payloads = self._parse_payload_list(raw_payloads, source="external")
                cache_key = f"external/{vuln_type}"
                if cache_key in self._cache:
                    self._cache[cache_key].extend(payloads)
                else:
                    self._cache[cache_key] = payloads
                count = len(payloads)

            elif isinstance(data, list):
                vuln_type = fpath.stem
                payloads = self._parse_payload_list(data, source="external")
                cache_key = f"external/{vuln_type}"
                if cache_key in self._cache:
                    self._cache[cache_key].extend(payloads)
                else:
                    self._cache[cache_key] = payloads
                count = len(payloads)

        except Exception as e:
            logger.error(f"Error loading external file {filepath}: {e}")

        logger.info(f"Loaded {count} external payloads from {filepath}")
        return count

    def list_categories(self) -> List[str]:
        """List all available payload categories."""
        self._build_file_index()
        categories = set()
        for key in self._file_index:
            parts = key.split('/')
            if len(parts) >= 1:
                categories.add(parts[0])
        return sorted(categories)

    def list_payload_types(self) -> List[str]:
        """List all available payload type paths (e.g. 'sqli/error_based')."""
        self._build_file_index()
        return sorted(self._file_index.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get payload database statistics."""
        total = 0
        by_category = {}
        for key in self.list_payload_types():
            count = len(self._load_payloads(key))
            total += count
            cat = key.split('/')[0]
            by_category[cat] = by_category.get(cat, 0) + count
        return {
            "total_payloads": total,
            "categories": len(by_category),
            "files": len(self._file_index or {}),
            "cached": len(self._cache),
            "by_category": by_category,
        }

    # ─── Internal Methods ──────────────────────────────────────────────

    def _build_file_index(self):
        """Build index of available payload files."""
        if self._file_index is not None:
            return
        
        self._file_index = {}
        if not self._payloads_dir.exists():
            logger.warning(f"Payloads directory not found: {self._payloads_dir}")
            return

        for yml_file in self._payloads_dir.rglob("*.yml"):
            rel = yml_file.relative_to(self._payloads_dir)
            # Remove .yml extension, use / as separator
            key = str(rel.with_suffix('')).replace(os.sep, '/')
            self._file_index[key] = yml_file

        for yaml_file in self._payloads_dir.rglob("*.yaml"):
            rel = yaml_file.relative_to(self._payloads_dir)
            key = str(rel.with_suffix('')).replace(os.sep, '/')
            if key not in self._file_index:
                self._file_index[key] = yaml_file

        logger.debug(f"Indexed {len(self._file_index)} payload files")

    def _load_payloads(self, vuln_type: str) -> List[Payload]:
        """Load payloads for a vuln type, using cache if available."""
        if vuln_type in self._cache:
            return self._cache[vuln_type]

        self._build_file_index()

        if vuln_type not in self._file_index:
            # Try partial match
            matches = [k for k in (self._file_index or {}) if k.endswith(vuln_type) or vuln_type in k]
            if matches:
                vuln_type = matches[0]
            else:
                logger.debug(f"No payload file found for: {vuln_type}")
                self._cache[vuln_type] = []
                return []

        filepath = self._file_index[vuln_type]
        payloads = self._load_yaml_file(filepath)
        self._cache[vuln_type] = payloads
        self._loaded_files.add(vuln_type)
        logger.debug(f"Loaded {len(payloads)} payloads from {vuln_type}")
        return payloads

    def _load_yaml_file(self, filepath: Path) -> List[Payload]:
        """Load and parse a YAML payload file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return []

        if not data or not isinstance(data, dict):
            return []

        payloads = []
        # Navigate the YAML structure
        # Expected: {metadata: {...}, payloads: {dbms: [{...}, ...], ...}}
        # Or flat: {payloads: [{value: ..., ...}, ...]}
        
        raw_payloads = data.get('payloads', data)
        
        if isinstance(raw_payloads, dict):
            # Grouped by DBMS or sub-category
            for group_key, group_data in raw_payloads.items():
                if group_key in ('metadata', 'detection_patterns'):
                    continue
                if isinstance(group_data, list):
                    for item in group_data:
                        if isinstance(item, str):
                            payloads.append(Payload(
                                value=item,
                                dbms=group_key if group_key in self._known_dbms() else "generic",
                            ))
                        elif isinstance(item, dict):
                            p = self._dict_to_payload(item)
                            if p.dbms == "generic" and group_key in self._known_dbms():
                                p.dbms = group_key
                            payloads.append(p)
                elif isinstance(group_data, str):
                    # Single payload in a group
                    payloads.append(Payload(
                        value=group_data,
                        dbms=group_key if group_key in self._known_dbms() else "generic",
                    ))
        elif isinstance(raw_payloads, list):
            for item in raw_payloads:
                if isinstance(item, str):
                    payloads.append(Payload(value=item))
                elif isinstance(item, dict):
                    payloads.append(self._dict_to_payload(item))

        return payloads

    def _dict_to_payload(self, d: Dict[str, Any]) -> Payload:
        """Convert a dict to a Payload object."""
        return Payload(
            value=str(d.get('value', d.get('payload', ''))),
            description=str(d.get('description', d.get('desc', ''))),
            severity=str(d.get('severity', 'info')),
            dbms=str(d.get('dbms', d.get('database', 'generic'))),
            context=str(d.get('context', 'generic')),
            encoding=str(d.get('encoding', 'none')),
            source=str(d.get('source', 'prometheus')),
            tags=d.get('tags', []) if isinstance(d.get('tags'), list) else [],
            detection_pattern=str(d.get('detection_pattern', d.get('detect', ''))),
            metadata={k: v for k, v in d.items() if k not in (
                'value', 'payload', 'description', 'desc', 'severity',
                'dbms', 'database', 'context', 'encoding', 'source',
                'tags', 'detection_pattern', 'detect'
            )},
        )

    def _parse_payload_list(self, items: list, source: str = "prometheus") -> List[Payload]:
        """Parse a list of payload items."""
        payloads = []
        for item in items:
            if isinstance(item, str):
                payloads.append(Payload(value=item, source=source))
            elif isinstance(item, dict):
                p = self._dict_to_payload(item)
                p.source = source
                payloads.append(p)
        return payloads

    def _parse_context(self, ctx: Dict[str, Any]) -> PayloadContext:
        """Parse a context dict into PayloadContext."""
        return PayloadContext(
            dbms=ctx.get('dbms', 'generic'),
            waf_detected=ctx.get('waf_detected', False),
            parameter_type=ctx.get('parameter_type', 'string'),
            injection_context=ctx.get('injection_context', 'generic'),
            encoding_required=ctx.get('encoding_required', 'none'),
            os_type=ctx.get('os_type', 'linux'),
            tech_stack=ctx.get('tech_stack', []),
            max_payloads=ctx.get('max_payloads', 0),
        )

    def _filter_by_context(self, payloads: List[Payload], ctx: PayloadContext) -> List[Payload]:
        """Filter payloads by context."""
        filtered = []
        for p in payloads:
            # DBMS filter
            if ctx.dbms != "generic" and p.dbms not in ("generic", ctx.dbms):
                continue
            # Context filter
            if ctx.injection_context != "generic" and p.context not in ("generic", ctx.injection_context):
                continue
            # Parameter type filter
            if ctx.parameter_type == "numeric" and "numeric" not in p.tags and "string" in p.tags:
                continue
            # OS filter
            if ctx.os_type != "generic":
                if p.metadata.get('os') and p.metadata['os'] not in ("generic", ctx.os_type):
                    continue
            filtered.append(p)
        return filtered

    def _apply_encoding(self, payloads: List[Payload], encoding: str) -> List[Payload]:
        """Apply encoding to payloads."""
        encoded = []
        for p in payloads:
            if p.encoding != "none":
                encoded.append(p)
                continue
            if encoding == "url":
                encoded.append(Payload(
                    value=quote(p.value, safe=''),
                    description=f"{p.description} [URL encoded]",
                    severity=p.severity, dbms=p.dbms, context=p.context,
                    encoding="url", source=p.source, tags=p.tags + ["url_encoded"],
                    detection_pattern=p.detection_pattern,
                ))
            elif encoding == "double_url":
                encoded.append(Payload(
                    value=quote(quote(p.value, safe=''), safe=''),
                    description=f"{p.description} [Double URL encoded]",
                    severity=p.severity, dbms=p.dbms, context=p.context,
                    encoding="double_url", source=p.source, tags=p.tags + ["double_url"],
                    detection_pattern=p.detection_pattern,
                ))
            elif encoding == "html_entity":
                encoded.append(Payload(
                    value=self._html_entity_encode(p.value),
                    description=f"{p.description} [HTML entity encoded]",
                    severity=p.severity, dbms=p.dbms, context=p.context,
                    encoding="html_entity", source=p.source, tags=p.tags + ["html_entity"],
                    detection_pattern=p.detection_pattern,
                ))
            elif encoding == "unicode":
                encoded.append(Payload(
                    value=self._unicode_encode(p.value),
                    description=f"{p.description} [Unicode encoded]",
                    severity=p.severity, dbms=p.dbms, context=p.context,
                    encoding="unicode", source=p.source, tags=p.tags + ["unicode"],
                    detection_pattern=p.detection_pattern,
                ))
            else:
                encoded.append(p)
        return encoded

    def _case_variations(self, s: str) -> str:
        """Generate alternating case variation."""
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    def _html_entity_encode(self, s: str) -> str:
        """HTML entity encode a string."""
        return ''.join(f'&#{ord(c)};' for c in s)

    def _unicode_encode(self, s: str) -> str:
        """Unicode encode a string with \\uXXXX format."""
        return ''.join(f'\\u{ord(c):04x}' for c in s)

    def _known_dbms(self) -> set:
        return {'mysql', 'postgresql', 'mssql', 'oracle', 'sqlite', 'generic'}

    def _builtin_detection_patterns(self, vuln_type: str) -> List[str]:
        """Built-in detection patterns for common vulnerability types."""
        patterns = {
            'sqli/error_based': [
                r"SQL syntax.*?MySQL",
                r"Warning.*?\Wmysqli?_",
                r"PGSQL.*?ERROR",
                r"ORA-\d{5}",
                r"Unclosed quotation mark.*?character string",
                r"SQLITE_ERROR",
                r"Microsoft OLE DB Provider for ODBC Drivers",
                r"Unclosed quotation mark after the character string",
            ],
            'sqli/time_based': [
                r"(?i)sleep\(\d+\)",
                r"(?i)benchmark\(\d+",
                r"(?i)waitfor\s+delay",
                r"(?i)pg_sleep",
                r"(?i)dbms_pipe\.receive_message",
            ],
            'sqli/boolean_based': [
                r"(?i)or\s+1\s*=\s*1",
                r"(?i)and\s+1\s*=\s*1",
                r"(?i)or\s+'1'\s*=\s*'1'",
            ],
            'xss/reflected': [
                r"<script[^>]*>.*?alert\s*\(.*?\).*?</script>",
                r"on\w+\s*=\s*['\"]?alert",
                r"javascript\s*:\s*alert",
            ],
            'ssrf/cloud': [
                r"(?i)ami-id",
                r"(?i)instance-id",
                r"(?i)metadata.*?compute",
                r"(?i)169\.254\.169\.254",
            ],
            'cmdi/linux': [
                r"uid=\d+\(.*?\)",
                r"root:.*?:0:0:",
                r"Linux.*?\d+\.\d+",
            ],
            'cmdi/windows': [
                r"NT AUTHORITY\\SYSTEM",
                r"Volume Serial Number",
                r"Windows.*?\d+\.\d+",
            ],
            'ssti/jinja2': [
                r"49",
                r"<Config",
                r"class\s+.*?object",
            ],
            'xxe/basic': [
                r"root:.*?:0:0:",
                r"(?i)ENTITY",
            ],
            'traversal/linux': [
                r"root:.*?:0:0:",
                r"daemon:.*?:1:1:",
            ],
            'traversal/windows': [
                r"\[boot loader\]",
                r"\[operating systems\]",
            ],
        }
        return patterns.get(vuln_type, [])


# ─── Singleton ──────────────────────────────────────────────────────────

_manager_instance: Optional[PayloadManager] = None

def get_payload_manager(payloads_dir: Optional[str] = None) -> PayloadManager:
    """Get or create the global PayloadManager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = PayloadManager(payloads_dir)
    return _manager_instance
