"""Python-Native Hacker Toolkit - Autonomous security tools.

All tools are pip-installable, no Go/Binary dependencies needed.
AI can use these directly for full autonomous hacking.
"""

import subprocess
import shutil
import json
import re
import socket
import ssl
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx

from ..utils.logger import logger


@dataclass
class ToolResult:
    """Result from a toolkit tool."""
    tool: str
    target: str
    success: bool
    findings: List[Dict] = field(default_factory=list)
    raw_output: str = ""
    summary: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class PythonToolkit:
    """Autonomous hacker toolkit - all Python, no external binaries."""

    def __init__(self):
        self.client = httpx.Client(follow_redirects=True, timeout=15, verify=False)
        self.results: List[ToolResult] = []
        self._check_available_tools()

    def _check_available_tools(self):
        """Check which Python tools are available."""
        self.available = {}
        tools_to_check = {
            "wapiti": "wapiti",
            "dirsearch": "dirsearch",
            "whatweb": "whatweb",
            "wafw00f": "wafw00f",
            "arjun": "arjun",
            "corsy": "corsy",
            "cmseek": "cmseek",
            "sublist3r": "sublist3r",
            "dalfox": "dalfox",
            "katana": "katana",
        }
        for name, cmd in tools_to_check.items():
            self.available[name] = shutil.which(cmd) is not None

    def _run(self, cmd: List[str], timeout: int = 120) -> Tuple[str, str, int]:
        """Run command, return (stdout, stderr, returncode)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1
        except FileNotFoundError:
            return "", f"{cmd[0]} not found", -1
        except Exception as e:
            return "", str(e), -1

    def _run_python_module(self, module: str, args: List[str], timeout: int = 120) -> Tuple[str, str, int]:
        """Run a Python module via python -m."""
        return self._run(["python", "-m", module] + args, timeout)

    # ============================================================
    # SQLMAP - Automatic SQL Injection
    # ============================================================
    def sqlmap(self, url: str, param: str = "", level: int = 3, risk: int = 2,
               batch: bool = True, forms: bool = True) -> ToolResult:
        """Run SQLMap for automatic SQL injection detection and exploitation."""
        logger.info(f"[bold red]SQLMap: {url}[/bold red]")

        args = ["-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
        if forms:
            args.append("--forms")
        if param:
            args.extend(["-p", param])

        # Check if sqlmap is installed
        if shutil.which("sqlmap"):
            stdout, stderr, rc = self._run(["sqlmap"] + args)
        else:
            # Try python sqlmap
            stdout, stderr, rc = self._run(["python", "-c", f"import sqlmap; sqlmap.main()"] + args)

        findings = []
        if "is vulnerable" in stdout.lower() or "injectable" in stdout.lower():
            # Extract vulnerable parameters
            vuln_matches = re.findall(r"Parameter: (.+?) \(.*?\)", stdout)
            for v in vuln_matches:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "parameter": v.strip(),
                    "evidence": "SQLMap confirmed injection"
                })

        result = ToolResult(
            tool="sqlmap",
            target=url,
            success=rc == 0 or len(findings) > 0,
            findings=findings,
            raw_output=stdout[:3000],
            summary=f"SQLMap: {len(findings)} injections found" if findings else "SQLMap: No injection found"
        )
        self.results.append(result)
        return result

    # ============================================================
    # WAPITI - Web Application Scanner
    # ============================================================
    def wapiti(self, url: str, scope: str = "url", modules: str = "all") -> ToolResult:
        """Run Wapiti3 for comprehensive web vulnerability scanning."""
        logger.info(f"[bold red]Wapiti: {url}[/bold red]")

        args = ["-u", url, "-f", "json", "-o", "/dev/stdout", "--scope", scope]
        if modules != "all":
            args.extend(["-m", modules])

        stdout, stderr, rc = self._run_python_module("wapiti", args)

        findings = []
        try:
            data = json.loads(stdout)
            for vuln_type in data.get("vulnerabilities", []):
                for vuln in vuln_type.get("detail", []):
                    findings.append({
                        "type": vuln_type.get("module", "Unknown"),
                        "severity": "HIGH",
                        "url": vuln.get("path", ""),
                        "parameter": vuln.get("parameter", ""),
                        "evidence": vuln.get("info", "")[:200]
                    })
        except (json.JSONDecodeError, KeyError):
            # Parse text output
            for line in stdout.split("\n"):
                if "[VULN]" in line or "CRITICAL" in line.upper():
                    findings.append({
                        "type": "Wapiti Finding",
                        "severity": "HIGH",
                        "evidence": line.strip()[:200]
                    })

        result = ToolResult(
            tool="wapiti",
            target=url,
            success=rc == 0 or len(findings) > 0,
            findings=findings,
            raw_output=stdout[:3000],
            summary=f"Wapiti: {len(findings)} vulnerabilities found"
        )
        self.results.append(result)
        return result

    # ============================================================
    # DIRSEARCH - Directory Brute Force
    # ============================================================
    def dirsearch(self, url: str, extensions: str = "php,html,js,txt",
                  wordlist: str = "", threads: int = 30) -> ToolResult:
        """Run DirSearch for directory/file discovery."""
        logger.info(f"[bold yellow]DirSearch: {url}[/bold yellow]")

        args = ["-u", url, "-e", extensions, "-t", str(threads), "-q"]
        if wordlist:
            args.extend(["-w", wordlist])

        stdout, stderr, rc = self._run(["dirsearch"] + args)

        findings = []
        for line in stdout.split("\n"):
            if "200" in line or "301" in line or "302" in line or "403" in line:
                findings.append({
                    "type": "Directory Found",
                    "severity": "INFO" if "200" in line else "MEDIUM",
                    "evidence": line.strip()[:200]
                })

        result = ToolResult(
            tool="dirsearch",
            target=url,
            success=rc == 0,
            findings=findings,
            raw_output=stdout[:3000],
            summary=f"DirSearch: {len(findings)} paths found"
        )
        self.results.append(result)
        return result

    # ============================================================
    # PURE PYTHON - No external tools needed
    # ============================================================

    def detect_waf(self, url: str) -> ToolResult:
        """Detect WAF/CDN behind a target (pure Python, no tools)."""
        logger.info(f"[bold cyan]WAF Detection: {url}[/bold cyan]")

        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf_chl"],
            "Akamai": ["akamai", "x-akamai", "ak_bmsc"],
            "AWS WAF": ["x-amzn-requestid", "awswaf"],
            "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Wordfence": ["wordfence", "wf_loginalerted"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Barracuda": ["barra_counter_session", "bam_booll"],
            "F5 BIG-IP": ["bigip", "f5-cookie"],
            "FortiWeb": ["fortiweb", "fortiwb"],
            "DenyAll": ["denyall", "sessioncookie"],
            "StackPath": ["stackpath", "highwinds"],
            "Fastly": ["fastly", "x-served-by"],
            "Varnish": ["varnish", "x-varnish"],
        }

        detected = []
        try:
            response = self.client.get(url)
            headers_text = str(response.headers).lower()
            body_text = response.text[:5000].lower()
            cookies_text = str(response.cookies).lower()

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in headers_text or sig.lower() in body_text or sig.lower() in cookies_text:
                        detected.append(waf_name)
                        break
        except Exception as e:
            logger.error(f"WAF detection error: {e}")

        result = ToolResult(
            tool="waf_detector",
            target=url,
            success=True,
            findings=[{"type": "WAF Detected", "severity": "INFO", "waf": w} for w in detected],
            summary=f"WAFs: {', '.join(detected)}" if detected else "No WAF detected"
        )
        self.results.append(result)
        return result

    def cors_check(self, url: str) -> ToolResult:
        """Check for CORS misconfigurations (pure Python)."""
        logger.info(f"[bold cyan]CORS Check: {url}[/bold cyan]")

        payloads = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://subdomain." + urlparse(url).hostname,
        ]

        findings = []
        for origin in payloads:
            try:
                response = self.client.get(
                    url,
                    headers={"Origin": origin}
                )
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    findings.append({
                        "type": "CORS Misconfiguration",
                        "severity": "MEDIUM",
                        "evidence": f"ACAO: * (wildcard) with Origin: {origin}"
                    })
                elif acao == origin and origin not in ("null",):
                    severity = "CRITICAL" if acac == "true" else "HIGH"
                    findings.append({
                        "type": "CORS Misconfiguration",
                        "severity": severity,
                        "evidence": f"Reflects arbitrary origin: {origin}, Credentials: {acac}"
                    })
                elif acao == "null" and origin == "null":
                    findings.append({
                        "type": "CORS Misconfiguration",
                        "severity": "HIGH",
                        "evidence": "Reflects null origin"
                    })
            except Exception:
                continue

        result = ToolResult(
            tool="cors_check",
            target=url,
            success=True,
            findings=findings,
            summary=f"CORS: {len(findings)} misconfigs found" if findings else "CORS: Looks safe"
        )
        self.results.append(result)
        return result

    def header_check(self, url: str) -> ToolResult:
        """Check security headers (pure Python)."""
        logger.info(f"[bold cyan]Security Headers: {url}[/bold cyan]")

        required_headers = {
            "strict-transport-security": {"name": "HSTS", "severity": "HIGH"},
            "x-content-type-options": {"name": "X-Content-Type-Options", "severity": "MEDIUM"},
            "x-frame-options": {"name": "X-Frame-Options (Clickjacking)", "severity": "MEDIUM"},
            "x-xss-protection": {"name": "X-XSS-Protection", "severity": "LOW"},
            "content-security-policy": {"name": "CSP", "severity": "HIGH"},
            "referrer-policy": {"name": "Referrer-Policy", "severity": "LOW"},
            "permissions-policy": {"name": "Permissions-Policy", "severity": "LOW"},
        }

        findings = []
        try:
            response = self.client.get(url)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            for header, info in required_headers.items():
                if header not in headers_lower:
                    findings.append({
                        "type": f"Missing Header: {info['name']}",
                        "severity": info["severity"],
                        "evidence": f"Header '{header}' not set"
                    })
                else:
                    value = headers_lower[header]
                    # Check for weak configs
                    if header == "x-frame-options" and value.lower() == "allow-from":
                        findings.append({
                            "type": "Weak X-Frame-Options",
                            "severity": "LOW",
                            "evidence": f"AllowFrom is deprecated, use DENY or SAMEORIGIN"
                        })
                    if header == "content-security-policy" and "'unsafe-inline'" in value:
                        findings.append({
                            "type": "Weak CSP",
                            "severity": "MEDIUM",
                            "evidence": "CSP allows unsafe-inline"
                        })

            # Check for sensitive headers leaked
            sensitive = ["x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version"]
            for h in sensitive:
                if h in headers_lower:
                    findings.append({
                        "type": f"Info Disclosure: {h}",
                        "severity": "LOW",
                        "evidence": f"{h}: {headers_lower[h]}"
                    })

        except Exception as e:
            logger.error(f"Header check error: {e}")

        result = ToolResult(
            tool="header_check",
            target=url,
            success=True,
            findings=findings,
            summary=f"Headers: {len(findings)} issues found" if findings else "Headers: All good"
        )
        self.results.append(result)
        return result

    def ssl_check(self, hostname: str, port: int = 443) -> ToolResult:
        """Check SSL/TLS configuration (pure Python)."""
        logger.info(f"[bold cyan]SSL Check: {hostname}:{port}[/bold cyan]")

        findings = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check cert expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        from datetime import datetime
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 30:
                            findings.append({
                                "type": "SSL Certificate Expiring",
                                "severity": "HIGH",
                                "evidence": f"Expires in {days_left} days ({not_after})"
                            })

                    # Check protocol version
                    if "TLSv1.0" in version or "TLSv1.1" in version:
                        findings.append({
                            "type": "Outdated TLS Version",
                            "severity": "HIGH",
                            "evidence": f"Using {version} (should be TLSv1.2+)"
                        })

                    # Check cipher strength
                    if cipher and cipher[1] < 128:
                        findings.append({
                            "type": "Weak Cipher",
                            "severity": "MEDIUM",
                            "evidence": f"Cipher: {cipher[0]}, Bits: {cipher[1]}"
                        })

        except ssl.SSLCertVerificationError as e:
            findings.append({
                "type": "SSL Certificate Error",
                "severity": "CRITICAL",
                "evidence": str(e)[:200]
            })
        except Exception as e:
            findings.append({
                "type": "SSL Connection Failed",
                "severity": "INFO",
                "evidence": str(e)[:200]
            })

        result = ToolResult(
            tool="ssl_check",
            target=f"{hostname}:{port}",
            success=True,
            findings=findings,
            summary=f"SSL: {len(findings)} issues" if findings else "SSL: Looks good"
        )
        self.results.append(result)
        return result

    def subdomain_takeover_check(self, domain: str) -> ToolResult:
        """Check for subdomain takeover vulnerabilities (pure Python)."""
        logger.info(f"[bold red]Subdomain Takeover: {domain}[/bold red]")

        # Known vulnerable CNAME targets
        vulnerable_services = {
            "amazonaws.com": ["There isn't a GitHub Pages site here", "NoSuchBucket"],
            "herokuapp.com": ["No such app"],
            "ghost.io": ["The thing you were looking for is no longer here"],
            "shopify.com": ["Sorry, this shop is currently unavailable"],
            "fastly.net": ["Fastly error: unknown domain"],
            "pantheon.io": ["404 error unknown site"],
            "surge.sh": ["project not found"],
            "bitbucket.io": ["Repository not found"],
            "zendesk.com": ["Help Center Closed"],
            "readme.io": ["Project doesn't exist"],
            "cloudfront.net": ["Bad request"],
            "s3.amazonaws.com": ["NoSuchBucket"],
            "azurewebsites.net": ["404 Web Site not found"],
            "trafficmanager.net": ["Not Found"],
            "blob.core.windows.net": ["The requested content does not exist"],
            "azure-api.net": ["Gateway not found"],
            "azurehdinsight.net": ["HDI doesn't exist"],
            "search.windows.net": ["Service not found"],
            "azurecr.io": ["HTTP 401"],
            "redis.cache.windows.net": ["WRONGPASS"],
            "postgres.database.azure.com": ["Connection refused"],
            "cognitiveservices.azure.com": ["Resource not found"],
        }

        findings = []

        # Get CNAME records
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=CNAME", domain],
                capture_output=True, text=True, timeout=10
            )
            cname_records = re.findall(r"canonical name = (.+)", result.stdout.lower())

            for cname in cname_records:
                for service, indicators in vulnerable_services.items():
                    if service in cname:
                        # Verify the indicator
                        try:
                            resp = self.client.get(f"https://{domain}", timeout=5)
                            for indicator in indicators:
                                if indicator.lower() in resp.text.lower():
                                    findings.append({
                                        "type": "Subdomain Takeover",
                                        "severity": "CRITICAL",
                                        "evidence": f"CNAME: {cname}, Service: {service}, Indicator: {indicator}"
                                    })
                                    break
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"Subdomain takeover check error: {e}")

        result = ToolResult(
            tool="subdomain_takeover",
            target=domain,
            success=True,
            findings=findings,
            summary=f"Takeover: {len(findings)} vulns" if findings else "Takeover: No vulnerabilities"
        )
        self.results.append(result)
        return result

    def open_redirect_check(self, url: str) -> ToolResult:
        """Check for open redirect vulnerabilities (pure Python)."""
        logger.info(f"[bold yellow]Open Redirect: {url}[/bold yellow]")

        redirect_params = ["url", "redirect", "next", "return", "continue", "goto",
                          "redirect_uri", "return_to", "redir", "dest", "destination",
                          "checkout_url", "return_url", "forward", "forward_url"]

        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%00.example.com",
            "///evil.com",
            "https://evil.com@example.com",
            "javascript:alert(1)",
        ]

        findings = []
        parsed = urlparse(url)

        # Check each parameter
        for param in redirect_params:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.client.get(test_url, follow_redirects=False, timeout=5)
                    location = response.headers.get("location", "")

                    if response.status_code in (301, 302, 303, 307, 308):
                        if payload in location or "evil.com" in location:
                            findings.append({
                                "type": "Open Redirect",
                                "severity": "MEDIUM",
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Redirects to: {location}"
                            })
                            break  # Found for this param, move on
                except Exception:
                    continue

        result = ToolResult(
            tool="open_redirect",
            target=url,
            success=True,
            findings=findings,
            summary=f"Redirects: {len(findings)} found" if findings else "Redirects: None found"
        )
        self.results.append(result)
        return result

    def xss_reflected_check(self, url: str, param: str = "") -> ToolResult:
        """Check for reflected XSS (pure Python)."""
        logger.info(f"[bold red]XSS Check: {url}[/bold red]")

        markers = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
        ]

        findings = []

        # Try to find parameters
        if not param:
            # Try common param names
            for p in ["q", "search", "query", "name", "page", "id", "input", "text"]:
                for marker in markers:
                    try:
                        response = self.client.get(f"{url}?{p}={marker}", timeout=5)
                        if marker in response.text and marker not in response.text[:100]:
                            # Check if not properly encoded
                            if "<script>" in marker or "onerror" in marker or "onload" in marker:
                                findings.append({
                                    "type": "Reflected XSS",
                                    "severity": "HIGH",
                                    "parameter": p,
                                    "payload": marker,
                                    "evidence": "Payload reflected without encoding"
                                })
                                break
                    except Exception:
                        continue
        else:
            for marker in markers:
                try:
                    response = self.client.get(f"{url}?{param}={marker}", timeout=5)
                    if marker in response.text:
                        findings.append({
                            "type": "Reflected XSS",
                            "severity": "HIGH",
                            "parameter": param,
                            "payload": marker,
                            "evidence": "Payload reflected"
                        })
                        break
                except Exception:
                    continue

        result = ToolResult(
            tool="xss_check",
            target=url,
            success=True,
            findings=findings,
            summary=f"XSS: {len(findings)} found" if findings else "XSS: None found"
        )
        self.results.append(result)
        return result

    def info_disclosure_check(self, url: str) -> ToolResult:
        """Check for information disclosure (pure Python)."""
        logger.info(f"[bold cyan]Info Disclosure: {url}[/bold cyan]")

        sensitive_files = [
            ("/.env", "Environment variables", "CRITICAL"),
            ("/.git/config", "Git repository", "CRITICAL"),
            ("/.git/HEAD", "Git HEAD", "CRITICAL"),
            ("/robots.txt", "Robots.txt (may contain paths)", "INFO"),
            ("/.htaccess", "Apache htaccess", "HIGH"),
            ("/server-status", "Apache server status", "MEDIUM"),
            ("/server-info", "Apache server info", "MEDIUM"),
            ("/.DS_Store", "macOS DS_Store", "MEDIUM"),
            ("/wp-config.php.bak", "WordPress config backup", "CRITICAL"),
            ("/phpinfo.php", "PHP info exposed", "HIGH"),
            ("/backup.sql", "Database backup", "CRITICAL"),
            ("/dump.sql", "Database dump", "CRITICAL"),
            ("/swagger.json", "API docs exposed", "MEDIUM"),
            ("/api-docs", "API docs exposed", "MEDIUM"),
            ("/graphql", "GraphQL endpoint", "MEDIUM"),
            ("/.svn/entries", "SVN repository", "HIGH"),
            ("/WEB-INF/web.xml", "Java config exposed", "HIGH"),
            ("/crossdomain.xml", "Flash cross-domain", "LOW"),
            ("/.bash_history", "Bash history", "CRITICAL"),
            ("/.ssh/id_rsa", "SSH private key", "CRITICAL"),
            ("/config.php", "PHP config", "HIGH"),
            ("/configuration.php", "Joomla config", "HIGH"),
            ("/wp-config.php", "WordPress config", "CRITICAL"),
            ("/.htpasswd", "Password file", "CRITICAL"),
            ("/phpmyadmin/", "phpMyAdmin exposed", "HIGH"),
            ("/admin/", "Admin panel", "MEDIUM"),
            ("/.aws/credentials", "AWS credentials", "CRITICAL"),
            ("/.env.local", "Local env file", "CRITICAL"),
            ("/.env.production", "Production env", "CRITICAL"),
        ]

        findings = []
        for path, desc, severity in sensitive_files:
            try:
                response = self.client.get(f"{url.rstrip('/')}{path}", timeout=5)
                if response.status_code == 200 and len(response.text) > 10:
                    # Validate it's real content
                    if path == "/.env" and "=" in response.text:
                        findings.append({"type": desc, "severity": severity, "url": path, "evidence": response.text[:100]})
                    elif path == "/.git/config" and "[core]" in response.text:
                        findings.append({"type": desc, "severity": severity, "url": path, "evidence": response.text[:100]})
                    elif path == "/robots.txt" and ("disallow" in response.text.lower() or "allow" in response.text.lower()):
                        findings.append({"type": desc, "severity": severity, "url": path, "evidence": response.text[:100]})
                    elif path not in ("/robots.txt", "/.env", "/.git/config"):
                        if len(response.text) > 50:
                            findings.append({"type": desc, "severity": severity, "url": path, "evidence": response.text[:100]})
            except Exception:
                continue

        result = ToolResult(
            tool="info_disclosure",
            target=url,
            success=True,
            findings=findings,
            summary=f"Info Disc: {len(findings)} files exposed" if findings else "Info Disc: Clean"
        )
        self.results.append(result)
        return result

    def full_audit(self, url: str) -> Dict[str, Any]:
        """Run complete audit - all pure Python checks."""
        logger.info(f"[bold blue]Full Audit: {url}[/bold blue]")

        all_findings = []

        # Run all checks
        checks = [
            ("WAF Detection", lambda: self.detect_waf(url)),
            ("Security Headers", lambda: self.header_check(url)),
            ("CORS Check", lambda: self.cors_check(url)),
            ("SSL Check", lambda: self._ssl_check_from_url(url)),
            ("Info Disclosure", lambda: self.info_disclosure_check(url)),
            ("Open Redirect", lambda: self.open_redirect_check(url)),
            ("XSS Check", lambda: self.xss_reflected_check(url)),
            ("Subdomain Takeover", lambda: self.subdomain_takeover_check(urlparse(url).hostname or url)),
        ]

        for name, check_fn in checks:
            try:
                result = check_fn()
                all_findings.extend(result.findings)
            except Exception as e:
                logger.error(f"  {name} failed: {e}")

        report = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
            "low": len([f for f in all_findings if f.get("severity") == "LOW"]),
            "findings": all_findings
        }

        return report

    def _ssl_check_from_url(self, url: str) -> ToolResult:
        """Run SSL check from URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return self.ssl_check(hostname, port)

    def get_report(self) -> str:
        """Generate text report of all findings."""
        all_findings = []
        for result in self.results:
            all_findings.extend(result.findings)

        lines = ["=== Python Toolkit Audit Report ===", ""]
        lines.append(f"Total findings: {len(all_findings)}")

        by_severity = {}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_severity:
                lines.append(f"  {sev}: {by_severity[sev]}")

        lines.append("")
        for result in self.results:
            if result.findings:
                lines.append(f"[{result.tool}] {result.summary}")
                for f in result.findings[:5]:
                    lines.append(f"  [{f.get('severity', 'INFO')}] {f.get('type', 'Unknown')}")
                    if f.get("evidence"):
                        lines.append(f"    {f['evidence'][:100]}")
                lines.append("")

        return "\n".join(lines)
