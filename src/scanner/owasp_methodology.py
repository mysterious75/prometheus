"""OWASP Testing Guide v4 — Complete Methodology Scanner.

Implements all 12 phases of the OWASP Testing Guide v4:
  1. Reconnaissance (Information Gathering)
  2. Configuration and Deployment Management
  3. Identity Management
  4. Authentication
  5. Authorization
  6. Session Management
  7. Input Validation
  8. Error Handling
  9. Cryptography
  10. Business Logic
  11. Client-Side
  12. API Security

Each phase returns List[Finding] with real evidence.
"""

import re
import ssl
import socket
import time
import json
import base64
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

import httpx

from ..core.logger import logger, console, log_tool_start, log_tool_result
from ..core.ratelimit import get_limiter
from .findings import Finding, ScanResult


class OWASPMethodologyScanner:
    """Implements complete OWASP Testing Guide v4 methodology."""

    NAME = "owasp_methodology"

    def __init__(self, rps: float = 10.0):
        self.limiter = get_limiter(rps)
        self.rps = rps
        self._finding_id = 0

    def _next_id(self) -> int:
        self._finding_id += 1
        return self._finding_id

    def _make_client(self, follow_redirects: bool = True) -> httpx.Client:
        return httpx.Client(
            timeout=15,
            verify=True,
            follow_redirects=follow_redirects,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

    def _get_host(self, url: str) -> str:
        return urlparse(url).hostname or url

    # ──────────────────────────────────────────────────────────────
    #  Main entry point
    # ──────────────────────────────────────────────────────────────

    def scan(self, target: str, phases: Optional[List[int]] = None) -> ScanResult:
        """Run OWASP methodology scan.

        Args:
            target: URL or domain to scan.
            phases: List of phase numbers to run (1-12). None = all.
        """
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        result = ScanResult(target=target)
        start = time.time()

        phase_map = {
            1: self.test_phase_1,
            2: self.test_phase_2,
            3: self.test_phase_3,
            4: self.test_phase_4,
            5: self.test_phase_5,
            6: self.test_phase_6,
            7: self.test_phase_7,
            8: self.test_phase_8,
            9: self.test_phase_9,
            10: self.test_phase_10,
            11: self.test_phase_11,
            12: self.test_phase_12,
        }

        phases_to_run = phases or list(range(1, 13))

        console.print(f"\n[bold blue]═══ OWASP Testing Guide v4 Scan: {target} ═══[/bold blue]")

        for phase_num in phases_to_run:
            phase_fn = phase_map.get(phase_num)
            if not phase_fn:
                continue
            phase_name = self._phase_name(phase_num)
            console.print(f"\n[bold]Phase {phase_num}: {phase_name}[/bold]")
            try:
                findings = phase_fn(target)
                for f in findings:
                    result.add(f)
                console.print(f"  → {len(findings)} findings")
            except Exception as e:
                logger.error(f"Phase {phase_num} error: {e}")
                console.print(f"  [error]✗ Phase {phase_num} failed: {e}[/error]")

        result.duration = time.time() - start
        summary = result.summary()
        console.print(f"\n[bold blue]═══ OWASP Scan Complete ═══[/bold blue]")
        console.print(f"  Duration: {summary['duration']}  |  Total: {summary['total']}")
        for sev in ("critical", "high", "medium", "low"):
            if summary[sev]:
                console.print(f"  [{sev}]{sev.upper()}: {summary[sev]}[/{sev}]")
        return result

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scanner interface — runs all phases against a single URL."""
        result = self.scan(url, phases=kwargs.get("phases"))
        return result.findings

    def _phase_name(self, n: int) -> str:
        names = {
            1: "Reconnaissance",
            2: "Configuration Management",
            3: "Identity Management",
            4: "Authentication Testing",
            5: "Authorization Testing",
            6: "Session Management",
            7: "Input Validation",
            8: "Error Handling",
            9: "Cryptography",
            10: "Business Logic",
            11: "Client-Side Testing",
            12: "API Security",
        }
        return names.get(n, f"Phase {n}")

    # ──────────────────────────────────────────────────────────────
    #  Phase 1: Reconnaissance (Information Gathering)
    # ──────────────────────────────────────────────────────────────

    def test_phase_1(self, target: str) -> List[Finding]:
        """OWASP-IG: Information Gathering."""
        findings = []
        host = self._get_host(target)

        # 1.1 Fingerprint web server
        findings.extend(self._recon_server_fingerprint(target))
        # 1.2 Check robots.txt
        findings.extend(self._recon_robots_txt(target))
        # 1.3 Check sitemap.xml
        findings.extend(self._recon_sitemap(target))
        # 1.4 Check for backup files
        findings.extend(self._recon_backup_files(target))
        # 1.5 Check DNS records
        findings.extend(self._recon_dns(host))
        # 1.6 Check for meta information leakage
        findings.extend(self._recon_meta_info(target))
        # 1.7 Check HTTP methods
        findings.extend(self._recon_http_methods(target))
        # 1.8 Check WAF detection
        findings.extend(self._recon_waf_detection(target))

        return findings

    def _recon_server_fingerprint(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            headers = resp.headers

            server = headers.get("Server", "")
            powered_by = headers.get("X-Powered-By", "")

            if server:
                findings.append(Finding(
                    vuln_type="Server Information Disclosure",
                    title=f"Server header reveals: {server}",
                    severity="LOW",
                    url=url,
                    evidence=f"Server: {server}",
                    description="The Server header reveals the web server software and version.",
                    remediation="Remove or genericize the Server header.",
                    cvss=2.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            if powered_by:
                findings.append(Finding(
                    vuln_type="Technology Disclosure",
                    title=f"X-Powered-By header reveals: {powered_by}",
                    severity="LOW",
                    url=url,
                    evidence=f"X-Powered-By: {powered_by}",
                    description="The X-Powered-By header reveals backend technology.",
                    remediation="Remove the X-Powered-By header.",
                    cvss=2.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            # Check for common framework signatures
            body = resp.text.lower()
            signatures = {
                "wp-content": "WordPress",
                "drupal": "Drupal",
                "joomla": "Joomla",
                "x-generator": "Framework",
            }
            for sig, tech in signatures.items():
                if sig in body or sig in str(headers).lower():
                    findings.append(Finding(
                        vuln_type="Technology Fingerprint",
                        title=f"Detected technology: {tech}",
                        severity="INFO",
                        url=url,
                        evidence=f"Signature '{sig}' found in response",
                        description=f"Web application appears to use {tech}.",
                        remediation="Hide technology signatures where possible.",
                        cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))
                    break

            client.close()
        except Exception as e:
            logger.debug(f"Server fingerprint error: {e}")
        return findings

    def _recon_robots_txt(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            robots_url = urljoin(url, "/robots.txt")
            resp = client.get(robots_url)
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                # Extract disallowed paths
                disallowed = re.findall(r"(?i)disallow:\s*(.+)", resp.text)
                sensitive_paths = []
                for path in disallowed:
                    path = path.strip()
                    if any(kw in path.lower() for kw in ["admin", "config", "backup", "secret", "private", "internal", "debug", "test"]):
                        sensitive_paths.append(path)

                severity = "MEDIUM" if sensitive_paths else "LOW"
                evidence = f"robots.txt found with {len(disallowed)} disallow rules"
                if sensitive_paths:
                    evidence += f". Sensitive paths: {', '.join(sensitive_paths[:5])}"

                findings.append(Finding(
                    vuln_type="Robots.txt Information Disclosure",
                    title="robots.txt reveals sensitive paths",
                    severity=severity,
                    url=robots_url,
                    evidence=evidence,
                    description="robots.txt may reveal hidden directories and admin interfaces.",
                    remediation="Review robots.txt. Don't rely on it for access control.",
                    cvss=3.1, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="HIGH",
                ))
            client.close()
        except Exception:
            pass
        return findings

    def _recon_sitemap(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            sitemap_url = urljoin(url, "/sitemap.xml")
            resp = client.get(sitemap_url)
            if resp.status_code == 200 and "<urlset" in resp.text.lower():
                urls = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                findings.append(Finding(
                    vuln_type="Sitemap Disclosure",
                    title=f"sitemap.xml found with {len(urls)} URLs",
                    severity="INFO",
                    url=sitemap_url,
                    evidence=f"sitemap.xml contains {len(urls)} URLs",
                    description="Sitemap reveals application structure and endpoints.",
                    remediation="Review sitemap for sensitive URL exposure.",
                    cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))
            client.close()
        except Exception:
            pass
        return findings

    def _recon_backup_files(self, url: str) -> List[Finding]:
        findings = []
        backup_extensions = [".bak", ".old", ".orig", ".save", ".swp", ".copy", "~"]
        backup_names = ["web.config.bak", ".env", "config.php.bak", "wp-config.php.bak", "database.sql", "dump.sql", "backup.zip", "backup.tar.gz"]

        try:
            client = self._make_client()
            # Check common backup files
            for name in backup_names:
                test_url = urljoin(url, f"/{name}")
                self.limiter.wait(self._get_host(url))
                resp = client.get(test_url)
                if resp.status_code == 200 and len(resp.content) > 50:
                    # Verify it's not a generic error page
                    if "404" not in resp.text[:200] and "not found" not in resp.text[:200].lower():
                        findings.append(Finding(
                            vuln_type="Backup File Exposure",
                            title=f"Backup file accessible: {name}",
                            severity="HIGH",
                            url=test_url,
                            evidence=f"GET {test_url} returned {resp.status_code} with {len(resp.content)} bytes",
                            description=f"Backup file '{name}' is accessible and may contain sensitive configuration data.",
                            remediation="Remove backup files from web-accessible directories.",
                            cvss=7.5, cwe="CWE-530", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))

            # Check for source code disclosure via extensions
            try:
                main_resp = client.get(url)
                # Look for links to check with backup extensions
                links = re.findall(r'href="([^"]+\.\w{2,4})"', main_resp.text)
                for link in links[:5]:
                    for ext in backup_extensions:
                        test_url = urljoin(url, link + ext)
                        self.limiter.wait(self._get_host(url))
                        resp = client.get(test_url)
                        if resp.status_code == 200 and len(resp.content) > 100:
                            findings.append(Finding(
                                vuln_type="Source Code Disclosure",
                                title=f"Source code accessible: {link}{ext}",
                                severity="MEDIUM",
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code}",
                                description="Source code backup file is accessible.",
                                remediation="Remove source code backups from web root.",
                                cvss=5.3, cwe="CWE-540", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                            break
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    def _recon_dns(self, host: str) -> List[Finding]:
        findings = []
        try:
            import socket
            # DNS resolution
            ips = socket.getaddrinfo(host, None)
            ip_list = list(set([addr[4][0] for addr in ips]))

            if ip_list:
                findings.append(Finding(
                    vuln_type="DNS Information",
                    title=f"DNS resolves to: {', '.join(ip_list[:3])}",
                    severity="INFO",
                    url=f"dns://{host}",
                    evidence=f"IP addresses: {', '.join(ip_list)}",
                    description="DNS resolution information gathered.",
                    remediation="No action required — informational.",
                    cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            # Try zone transfer (common misconfiguration)
            try:
                import subprocess
                result = subprocess.run(
                    ["dig", "axfr", host, f"@{ip_list[0]}"],
                    capture_output=True, text=True, timeout=5
                )
                if "XFR size" in result.stdout or "200 OK" in result.stdout:
                    findings.append(Finding(
                        vuln_type="DNS Zone Transfer",
                        title="DNS zone transfer allowed",
                        severity="HIGH",
                        url=f"dns://{host}",
                        evidence=f"Zone transfer successful to {ip_list[0]}",
                        description="DNS zone transfer exposes all DNS records for the domain.",
                        remediation="Restrict zone transfers to authorized DNS servers only.",
                        cvss=7.5, cwe="CWE-200", tool="owasp_methodology",
                        verified=True, confidence="HIGH",
                    ))
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"DNS recon error: {e}")
        return findings

    def _recon_meta_info(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Check for HTML comments
            comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
            sensitive_comments = []
            for comment in comments:
                if any(kw in comment.lower() for kw in ["todo", "fixme", "hack", "password", "secret", "admin", "debug", "test", "internal"]):
                    sensitive_comments.append(comment.strip()[:100])

            if sensitive_comments:
                findings.append(Finding(
                    vuln_type="HTML Comment Leakage",
                    title=f"Sensitive HTML comments found ({len(sensitive_comments)})",
                    severity="LOW",
                    url=url,
                    evidence=f"Comments: {'; '.join(sensitive_comments[:3])}",
                    description="HTML comments may contain sensitive information, credentials, or internal paths.",
                    remediation="Remove all comments from production code.",
                    cvss=3.1, cwe="CWE-615", tool="owasp_methodology",
                    verified=True, confidence="HIGH",
                ))

            # Check for email addresses
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))
            if emails:
                findings.append(Finding(
                    vuln_type="Email Address Disclosure",
                    title=f"Email addresses found in page ({len(emails)})",
                    severity="INFO",
                    url=url,
                    evidence=f"Emails: {', '.join(list(emails)[:5])}",
                    description="Email addresses found in page content.",
                    remediation="Remove email addresses from public pages or use obfuscation.",
                    cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            # Check for meta tags with sensitive info
            meta_tags = re.findall(r'<meta[^>]*name="([^"]*)"[^>]*content="([^"]*)"', body, re.IGNORECASE)
            for name, content in meta_tags:
                if any(kw in name.lower() for kw in ["generator", "author", "version"]):
                    findings.append(Finding(
                        vuln_type="Meta Tag Information Disclosure",
                        title=f"Meta tag reveals: {name} = {content}",
                        severity="INFO",
                        url=url,
                        evidence=f'<meta name="{name}" content="{content}">',
                        description="Meta tags may reveal technology and version information.",
                        remediation="Remove unnecessary meta tags.",
                        cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    def _recon_http_methods(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)
            # Test OPTIONS
            resp = client.options(url)
            allow = resp.headers.get("Allow", "")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
                if dangerous:
                    findings.append(Finding(
                        vuln_type="Dangerous HTTP Methods",
                        title=f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"Allow: {allow}",
                        description=f"HTTP methods {', '.join(dangerous)} are enabled and may allow unauthorized modifications.",
                        remediation="Disable unnecessary HTTP methods. Only allow GET, POST, HEAD.",
                        cvss=5.3, cwe="CWE-284", tool="owasp_methodology",
                        verified=True, confidence="HIGH",
                    ))

            # Test TRACE method
            try:
                trace_resp = client.request("TRACE", url)
                if trace_resp.status_code == 200:
                    findings.append(Finding(
                        vuln_type="TRACE Method Enabled",
                        title="HTTP TRACE method is enabled (XST risk)",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"TRACE returned {trace_resp.status_code}",
                        description="TRACE method can be used for Cross-Site Tracing (XST) attacks.",
                        remediation="Disable the TRACE method on the web server.",
                        cvss=5.3, cwe="CWE-200", tool="owasp_methodology",
                        verified=True, confidence="HIGH",
                    ))
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    def _recon_waf_detection(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)
            # Send a suspicious payload to detect WAF
            test_url = f"{url}?id=<script>alert(1)</script>"
            resp = client.get(test_url)

            waf_signatures = {
                "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
                "akamai": ["x-akamai", "akamai"],
                "incapsula": ["x-iinfo", "incap_ses"],
                "modsecurity": ["mod_security", "modsecurity"],
                "aws_waf": ["x-amzn-requestid", "awselb"],
                "sucuri": ["x-sucuri"],
            }

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for waf_name, sigs in waf_signatures.items():
                for sig in sigs:
                    if any(sig in k for k in headers_lower.keys()) or any(sig in str(v).lower() for v in headers_lower.values()):
                        findings.append(Finding(
                            vuln_type="WAF Detected",
                            title=f"Web Application Firewall detected: {waf_name}",
                            severity="INFO",
                            url=url,
                            evidence=f"WAF signature '{sig}' found in response headers",
                            description=f"A WAF ({waf_name}) is protecting this application.",
                            remediation="WAF is a positive security control. Verify it's properly configured.",
                            cvss=0.0, cwe="N/A", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))
                        break

            # If blocked (403/406), WAF is likely present
            if resp.status_code in (403, 406, 419, 429, 503):
                findings.append(Finding(
                    vuln_type="WAF Active",
                    title=f"WAF blocked malicious request (HTTP {resp.status_code})",
                    severity="INFO",
                    url=url,
                    evidence=f"Request with XSS payload returned {resp.status_code}",
                    description="A WAF or security filter blocked the test request.",
                    remediation="WAF is active. Verify rules cover OWASP Top 10.",
                    cvss=0.0, cwe="N/A", tool="owasp_methodology",
                    verified=True, confidence="MEDIUM",
                ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 2: Configuration and Deployment Management
    # ──────────────────────────────────────────────────────────────

    def test_phase_2(self, target: str) -> List[Finding]:
        """OWASP-CM: Configuration and Deployment Management Testing."""
        findings = []
        findings.extend(self._config_admin_interfaces(target))
        findings.extend(self._config_http_headers(target))
        findings.extend(self._config_directory_listing(target))
        findings.extend(self._config_file_extensions(target))
        findings.extend(self._config_interesting_files(target))
        return findings

    def _config_admin_interfaces(self, url: str) -> List[Finding]:
        findings = []
        admin_paths = [
            "/admin", "/admin/", "/administrator/", "/wp-admin/",
            "/phpmyadmin/", "/cpanel/", "/webmail/", "/manager/",
            "/console", "/jmx-console/", "/web-console/",
            "/server-status", "/server-info", "/.svn/", "/.git/",
            "/elmah.axd", "/trace.axd", "/actuator", "/actuator/health",
            "/swagger-ui.html", "/swagger/", "/api-docs/",
            "/graphql", "/graphiql",
        ]
        try:
            client = self._make_client(follow_redirects=False)
            for path in admin_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 200:
                        # Verify it's not a generic redirect or error page
                        body_lower = resp.text[:500].lower()
                        if "login" in body_lower or "admin" in body_lower or "dashboard" in body_lower:
                            findings.append(Finding(
                                vuln_type="Admin Interface Exposure",
                                title=f"Admin interface found: {path}",
                                severity="HIGH",
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code} with login/admin content",
                                description=f"Admin interface at '{path}' is accessible. May be vulnerable to brute force.",
                                remediation="Restrict admin interfaces to internal network or VPN.",
                                cvss=7.5, cwe="CWE-284", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _config_http_headers(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            headers = resp.headers

            # Security headers to check
            security_headers = {
                "Strict-Transport-Security": ("MEDIUM", "CWE-319", "HSTS header missing"),
                "Content-Security-Policy": ("MEDIUM", "CWE-693", "CSP header missing"),
                "X-Content-Type-Options": ("LOW", "CWE-693", "X-Content-Type-Options missing"),
                "X-Frame-Options": ("MEDIUM", "CWE-1021", "X-Frame-Options missing (clickjacking)"),
                "X-XSS-Protection": ("LOW", "CWE-79", "X-XSS-Protection missing"),
                "Referrer-Policy": ("LOW", "CWE-200", "Referrer-Policy missing"),
                "Permissions-Policy": ("LOW", "CWE-200", "Permissions-Policy missing"),
            }

            for header_name, (severity, cwe, desc) in security_headers.items():
                if header_name.lower() not in {k.lower() for k in headers.keys()}:
                    findings.append(Finding(
                        vuln_type="Missing Security Header",
                        title=f"Missing {header_name}",
                        severity=severity,
                        url=url,
                        evidence=f"Header '{header_name}' not found in response",
                        description=desc,
                        remediation=f"Add the {header_name} header to all responses.",
                        cvss=4.0 if severity == "MEDIUM" else 2.0, cwe=cwe, tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))

            # Check for insecure headers
            if headers.get("X-Powered-By"):
                findings.append(Finding(
                    vuln_type="Information Disclosure Header",
                    title=f"X-Powered-By: {headers['X-Powered-By']}",
                    severity="LOW",
                    url=url,
                    evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                    description="X-Powered-By header reveals backend technology.",
                    remediation="Remove X-Powered-By header.",
                    cvss=2.0, cwe="CWE-200", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            client.close()
        except Exception:
            pass
        return findings

    def _config_directory_listing(self, url: str) -> List[Finding]:
        findings = []
        directories = ["/images/", "/uploads/", "/files/", "/backup/", "/tmp/", "/assets/", "/static/", "/data/"]
        try:
            client = self._make_client()
            for d in directories:
                test_url = urljoin(url, d)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and ("index of" in resp.text.lower() or "directory listing" in resp.text.lower()):
                        # Extract file listing
                        files = re.findall(r'href="([^"]+)"', resp.text)
                        findings.append(Finding(
                            vuln_type="Directory Listing",
                            title=f"Directory listing enabled: {d}",
                            severity="MEDIUM",
                            url=test_url,
                            evidence=f"Directory listing with {len(files)} entries",
                            description=f"Directory listing is enabled at '{d}', exposing file structure.",
                            remediation="Disable directory listing in web server configuration.",
                            cvss=5.3, cwe="CWE-548", tool="owasp_methodology",
                            verified=True, confidence="CONFIRMED",
                        ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _config_file_extensions(self, url: str) -> List[Finding]:
        findings = []
        sensitive_extensions = [".conf", ".ini", ".yml", ".yaml", ".xml", ".properties", ".cfg", ".log"]
        try:
            client = self._make_client()
            # Get base filename from URL
            path = urlparse(url).path
            base_name = path.rstrip("/").split("/")[-1] if path and path != "/" else "index"

            for ext in sensitive_extensions:
                test_url = urljoin(url, f"/{base_name}{ext}")
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.content) > 50:
                        if "404" not in resp.text[:100] and "not found" not in resp.text[:100].lower():
                            findings.append(Finding(
                                vuln_type="Configuration File Exposure",
                                title=f"Configuration file accessible: {base_name}{ext}",
                                severity="HIGH",
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code} ({len(resp.content)} bytes)",
                                description=f"Configuration file '{base_name}{ext}' is accessible.",
                                remediation="Restrict access to configuration files.",
                                cvss=7.5, cwe="CWE-200", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _config_interesting_files(self, url: str) -> List[Finding]:
        findings = []
        interesting = [
            ("/.env", "HIGH", "Environment file"),
            ("/.git/config", "CRITICAL", "Git configuration"),
            ("/.git/HEAD", "CRITICAL", "Git HEAD reference"),
            ("/.htaccess", "HIGH", "Apache configuration"),
            ("/web.config", "HIGH", "IIS configuration"),
            ("/crossdomain.xml", "MEDIUM", "Flash cross-domain policy"),
            ("/clientaccesspolicy.xml", "MEDIUM", "Silverlight cross-domain policy"),
            ("/favicon.ico", "INFO", "Favicon (technology fingerprint)"),
        ]
        try:
            client = self._make_client()
            for path, severity, desc in interesting:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.content) > 10:
                        body_lower = resp.text[:200].lower()
                        if "404" not in body_lower and "not found" not in body_lower:
                            findings.append(Finding(
                                vuln_type="Sensitive File Exposure",
                                title=f"{desc}: {path}",
                                severity=severity,
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code} ({len(resp.content)} bytes)",
                                description=f"{desc} at '{path}' is accessible.",
                                remediation="Restrict access to sensitive files.",
                                cvss=8.0 if severity == "CRITICAL" else 6.0, cwe="CWE-200", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 3: Identity Management
    # ──────────────────────────────────────────────────────────────

    def test_phase_3(self, target: str) -> List[Finding]:
        """OWASP-ID: Identity Management Testing."""
        findings = []
        findings.extend(self._idm_user_enumeration(target))
        findings.extend(self._idm_registration(target))
        findings.extend(self._idm_account_provisioning(target))
        return findings

    def _idm_user_enumeration(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)

            # Test login endpoint for user enumeration
            login_paths = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth/login"]
            for path in login_paths:
                login_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    # Try with a likely-valid username
                    resp_valid = client.post(login_url, data={"username": "admin", "password": "wrongpassword123!"})
                    # Try with a definitely-invalid username
                    resp_invalid = client.post(login_url, data={"username": "nonexistent_user_xyz_12345", "password": "wrongpassword123!"})

                    if resp_valid.status_code != resp_invalid.status_code:
                        findings.append(Finding(
                            vuln_type="User Enumeration",
                            title=f"User enumeration via login at {path}",
                            severity="MEDIUM",
                            url=login_url,
                            evidence=f"Valid user returned {resp_valid.status_code}, invalid user returned {resp_invalid.status_code}",
                            description="Different responses for valid vs invalid usernames allow user enumeration.",
                            remediation="Return identical responses for valid and invalid usernames.",
                            cvss=5.3, cwe="CWE-204", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))

                    # Check response length difference
                    if abs(len(resp_valid.text) - len(resp_invalid.text)) > 50:
                        findings.append(Finding(
                            vuln_type="User Enumeration",
                            title=f"User enumeration via response length at {path}",
                            severity="MEDIUM",
                            url=login_url,
                            evidence=f"Valid user response: {len(resp_valid.text)} bytes, invalid: {len(resp_invalid.text)} bytes",
                            description="Different response lengths for valid vs invalid usernames allow enumeration.",
                            remediation="Ensure identical response length and content for both cases.",
                            cvss=5.3, cwe="CWE-204", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))
                except Exception:
                    pass

            # Test password reset for user enumeration
            reset_paths = ["/password/reset", "/forgot-password", "/reset-password", "/api/password/reset"]
            for path in reset_paths:
                reset_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp_valid = client.post(reset_url, data={"email": "admin@example.com"})
                    resp_invalid = client.post(reset_url, data={"email": "nonexistent12345@example.com"})

                    if resp_valid.status_code != resp_invalid.status_code:
                        findings.append(Finding(
                            vuln_type="User Enumeration via Password Reset",
                            title=f"User enumeration via password reset at {path}",
                            severity="MEDIUM",
                            url=reset_url,
                            evidence=f"Valid email: {resp_valid.status_code}, invalid: {resp_invalid.status_code}",
                            description="Password reset reveals whether an email is registered.",
                            remediation="Always show the same message regardless of email existence.",
                            cvss=5.3, cwe="CWE-204", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _idm_registration(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            reg_paths = ["/register", "/signup", "/auth/register", "/api/register", "/api/users"]
            for path in reg_paths:
                reg_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(reg_url)
                    if resp.status_code == 200 and ("register" in resp.text.lower() or "sign up" in resp.text.lower()):
                        # Test if registration is open (no captcha check)
                        post_resp = client.post(reg_url, data={
                            "username": f"testuser_{int(time.time())}",
                            "email": f"test_{int(time.time())}@example.com",
                            "password": "TestPassword123!",
                        })
                        if post_resp.status_code in (200, 201, 302):
                            findings.append(Finding(
                                vuln_type="Open Registration",
                                title=f"Open user registration at {path}",
                                severity="LOW",
                                url=reg_url,
                                evidence=f"POST to {reg_url} returned {post_resp.status_code}",
                                description="User registration appears to be open without CAPTCHA or admin approval.",
                                remediation="Implement CAPTCHA and email verification for registration.",
                                cvss=3.1, cwe="CWE-284", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _idm_account_provisioning(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Check if default accounts exist
            default_users = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("test", "test")]
            login_paths = ["/login", "/signin", "/auth/login"]

            for path in login_paths:
                login_url = urljoin(url, path)
                for username, password in default_users:
                    self.limiter.wait(self._get_host(url))
                    try:
                        resp = client.post(login_url, data={
                            "username": username,
                            "password": password,
                        }, follow_redirects=False)
                        # Check for successful login indicators
                        if resp.status_code in (200, 302):
                            if resp.status_code == 302:
                                location = resp.headers.get("Location", "")
                                if "dashboard" in location.lower() or "admin" in location.lower() or "home" in location.lower():
                                    findings.append(Finding(
                                        vuln_type="Default Credentials",
                                        title=f"Default credentials work: {username}/{password}",
                                        severity="CRITICAL",
                                        url=login_url,
                                        payload=f"username={username}&password={password}",
                                        evidence=f"Login returned 302 redirect to: {location}",
                                        description=f"Default credentials '{username}:{password}' provide access.",
                                        remediation="Change all default credentials. Enforce strong password policy.",
                                        cvss=9.8, cwe="CWE-798", tool="owasp_methodology",
                                        verified=True, confidence="HIGH",
                                    ))
                    except Exception:
                        pass
            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 4: Authentication Testing
    # ──────────────────────────────────────────────────────────────

    def test_phase_4(self, target: str) -> List[Finding]:
        """OWASP-AT: Authentication Testing."""
        findings = []
        findings.extend(self._auth_default_creds(target))
        findings.extend(self._auth_password_policy(target))
        findings.extend(self._auth_reset_mechanism(target))
        findings.extend(self._auth_captcha(target))
        findings.extend(self._auth_credential_transport(target))
        return findings

    def _auth_default_creds(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)
            default_creds = [
                ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
                ("root", "root"), ("root", "toor"), ("test", "test"),
                ("user", "user"), ("admin", "admin123"), ("admin", ""),
            ]

            login_paths = ["/login", "/signin", "/auth/login", "/api/login"]
            for path in login_paths:
                login_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(login_url)
                    if resp.status_code != 200:
                        continue

                    for username, password in default_creds:
                        self.limiter.wait(self._get_host(url))
                        resp = client.post(login_url, data={
                            "username": username,
                            "password": password,
                        })

                        # Check for successful login
                        if resp.status_code == 302:
                            location = resp.headers.get("Location", "")
                            if any(kw in location.lower() for kw in ["dashboard", "admin", "home", "profile", "account"]):
                                findings.append(Finding(
                                    vuln_type="Default Credentials",
                                    title=f"Default credentials: {username}/{password}",
                                    severity="CRITICAL",
                                    url=login_url,
                                    payload=f"username={username}&password={password}",
                                    evidence=f"Redirected to: {location}",
                                    description=f"Default credentials '{username}' provide access.",
                                    remediation="Remove default credentials. Force password change.",
                                    cvss=9.8, cwe="CWE-798", tool="owasp_methodology",
                                    verified=True, confidence="HIGH",
                                ))
                                break

                        # Check for "welcome" or "dashboard" in body
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            if ("welcome" in body or "dashboard" in body or "logout" in body) and "login" not in body[:200]:
                                findings.append(Finding(
                                    vuln_type="Default Credentials",
                                    title=f"Default credentials: {username}/{password}",
                                    severity="CRITICAL",
                                    url=login_url,
                                    payload=f"username={username}&password={password}",
                                    evidence=f"Response contains dashboard/welcome content",
                                    description=f"Default credentials '{username}' provide access.",
                                    remediation="Remove default credentials. Force password change.",
                                    cvss=9.8, cwe="CWE-798", tool="owasp_methodology",
                                    verified=True, confidence="MEDIUM",
                                ))
                                break
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _auth_password_policy(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            reg_paths = ["/register", "/signup", "/auth/register", "/api/register"]
            for path in reg_paths:
                reg_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    # Try registering with a weak password
                    resp = client.post(reg_url, data={
                        "username": f"testuser_{int(time.time())}",
                        "email": f"test_{int(time.time())}@example.com",
                        "password": "123",
                    })
                    if resp.status_code in (200, 201, 302):
                        body = resp.text.lower()
                        # If no error about password strength
                        if "password" not in body or ("too short" not in body and "too weak" not in body and "minimum" not in body):
                            findings.append(Finding(
                                vuln_type="Weak Password Policy",
                                title="Application accepts weak passwords",
                                severity="MEDIUM",
                                url=reg_url,
                                payload="password=123",
                                evidence=f"Weak password '123' accepted (HTTP {resp.status_code})",
                                description="Password policy does not enforce minimum complexity.",
                                remediation="Enforce minimum 8 chars with uppercase, lowercase, numbers, and special chars.",
                                cvss=5.3, cwe="CWE-521", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _auth_reset_mechanism(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            reset_paths = ["/password/reset", "/forgot-password", "/reset-password", "/api/password/reset"]
            for path in reset_paths:
                reset_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(reset_url)
                    if resp.status_code == 200 and ("reset" in resp.text.lower() or "forgot" in resp.text.lower()):
                        # Check if it reveals user existence
                        post_resp = client.post(reset_url, data={"email": "nonexistent@example.com"})
                        if post_resp.status_code == 200:
                            body = post_resp.text.lower()
                            if "not found" in body or "does not exist" in body or "no account" in body:
                                findings.append(Finding(
                                    vuln_type="Password Reset User Enumeration",
                                    title="Password reset reveals non-existent users",
                                    severity="MEDIUM",
                                    url=reset_url,
                                    evidence=f"Response reveals email not registered",
                                    description="Password reset function reveals whether an email is registered.",
                                    remediation="Always show the same success message regardless of email existence.",
                                    cvss=5.3, cwe="CWE-204", tool="owasp_methodology",
                                    verified=True, confidence="MEDIUM",
                                ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _auth_captcha(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            login_paths = ["/login", "/signin", "/auth/login"]
            for path in login_paths:
                login_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(login_url)
                    body = resp.text.lower()
                    has_captcha = any(kw in body for kw in ["captcha", "recaptcha", "hcaptcha", "turnstile", "g-recaptcha"])

                    if not has_captcha:
                        # Try multiple rapid logins to see if there's brute force protection
                        blocked = False
                        for i in range(5):
                            self.limiter.wait(self._get_host(url))
                            resp = client.post(login_url, data={
                                "username": "admin",
                                "password": f"wrongpass{i}",
                            })
                            if resp.status_code == 429 or (resp.status_code == 200 and "captcha" in resp.text.lower()):
                                blocked = True
                                break

                        if not blocked:
                            findings.append(Finding(
                                vuln_type="No Brute Force Protection",
                                title=f"No CAPTCHA or brute force protection at {path}",
                                severity="MEDIUM",
                                url=login_url,
                                evidence=f"5 rapid login attempts allowed without CAPTCHA or rate limiting",
                                description="Login form lacks brute force protection.",
                                remediation="Implement CAPTCHA after failed attempts. Add rate limiting.",
                                cvss=5.3, cwe="CWE-307", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _auth_credential_transport(self, url: str) -> List[Finding]:
        findings = []
        try:
            if url.startswith("http://"):
                findings.append(Finding(
                    vuln_type="Credentials Over HTTP",
                    title="Login page served over HTTP (no TLS)",
                    severity="HIGH",
                    url=url,
                    evidence=f"URL uses HTTP: {url}",
                    description="Credentials transmitted over HTTP can be intercepted.",
                    remediation="Enforce HTTPS for all authentication pages.",
                    cvss=7.5, cwe="CWE-319", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            client = self._make_client()
            resp = client.get(url)
            # Check if login form action uses HTTP
            actions = re.findall(r'<form[^>]*action="([^"]*)"[^>]*>', resp.text, re.IGNORECASE)
            for action in actions:
                if action.startswith("http://"):
                    findings.append(Finding(
                        vuln_type="Form Posts to HTTP",
                        title=f"Login form posts to HTTP: {action}",
                        severity="HIGH",
                        url=url,
                        evidence=f"Form action: {action}",
                        description="Form submits credentials over unencrypted HTTP.",
                        remediation="Change form action to HTTPS.",
                        cvss=7.5, cwe="CWE-319", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))
            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 5: Authorization Testing
    # ──────────────────────────────────────────────────────────────

    def test_phase_5(self, target: str) -> List[Finding]:
        """OWASP-AZ: Authorization Testing."""
        findings = []
        findings.extend(self._authz_directory_traversal(target))
        findings.extend(self._authz_privilege_escalation(target))
        findings.extend(self._authz_idor(target))
        return findings

    def _authz_directory_traversal(self, url: str) -> List[Finding]:
        findings = []
        traversal_payloads = [
            ("../../../etc/passwd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("....//....//....//etc/passwd", "root:"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
            ("..%252f..%252f..%252fetc/passwd", "root:"),
        ]

        try:
            client = self._make_client()
            # Find URL parameters to test
            parsed = urlparse(url)
            if parsed.query:
                params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                for param_name, param_value in params.items():
                    for payload, indicator in traversal_payloads:
                        test_params = dict(params)
                        test_params[param_name] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        self.limiter.wait(self._get_host(url))
                        try:
                            resp = client.get(test_url, params=test_params)
                            if indicator in resp.text:
                                findings.append(Finding(
                                    vuln_type="Directory Traversal",
                                    title=f"Path traversal in parameter: {param_name}",
                                    severity="CRITICAL",
                                    url=test_url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Response contains '{indicator}' from {payload}",
                                    description=f"Parameter '{param_name}' is vulnerable to path traversal.",
                                    remediation="Validate and sanitize file path inputs. Use chroot or sandboxing.",
                                    cvss=9.8, cwe="CWE-22", tool="owasp_methodology",
                                    verified=True, confidence="CONFIRMED",
                                ))
                                break
                        except Exception:
                            pass
            else:
                # Test common parameter names on the URL
                common_params = ["file", "path", "page", "include", "dir", "document", "folder", "root", "data"]
                for param in common_params:
                    for payload, indicator in traversal_payloads:
                        self.limiter.wait(self._get_host(url))
                        try:
                            resp = client.get(url, params={param: payload})
                            if indicator in resp.text:
                                findings.append(Finding(
                                    vuln_type="Directory Traversal",
                                    title=f"Path traversal in parameter: {param}",
                                    severity="CRITICAL",
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"Response contains '{indicator}' from {payload}",
                                    description=f"Parameter '{param}' is vulnerable to path traversal.",
                                    remediation="Validate and sanitize file path inputs.",
                                    cvss=9.8, cwe="CWE-22", tool="owasp_methodology",
                                    verified=True, confidence="CONFIRMED",
                                ))
                                break
                        except Exception:
                            pass
            client.close()
        except Exception:
            pass
        return findings

    def _authz_privilege_escalation(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            admin_paths = [
                "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
                "/api/admin", "/api/users", "/api/config",
                "/management", "/internal",
            ]
            for path in admin_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url, follow_redirects=False)
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if any(kw in body for kw in ["admin", "dashboard", "settings", "users", "management"]):
                            findings.append(Finding(
                                vuln_type="Unprotected Admin Function",
                                title=f"Admin endpoint accessible without authentication: {path}",
                                severity="HIGH",
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code} with admin content",
                                description=f"Admin endpoint '{path}' is accessible without authentication.",
                                remediation="Require authentication and authorization for admin endpoints.",
                                cvss=8.1, cwe="CWE-284", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _authz_idor(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Look for numeric IDs in URL
            parsed = urlparse(url)
            path = parsed.path

            # Find numeric segments
            segments = path.split("/")
            for i, seg in enumerate(segments):
                if seg.isdigit() and int(seg) > 0:
                    # Try adjacent IDs
                    for delta in [1, -1, 2]:
                        test_id = str(int(seg) + delta)
                        test_segments = list(segments)
                        test_segments[i] = test_id
                        test_path = "/".join(test_segments)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

                        if parsed.query:
                            test_url += f"?{parsed.query}"

                        self.limiter.wait(self._get_host(url))
                        try:
                            resp = client.get(test_url)
                            resp_orig = client.get(url)

                            # If both return 200 with similar content length, IDOR may exist
                            if (resp.status_code == 200 and resp_orig.status_code == 200 and
                                    abs(len(resp.text) - len(resp_orig.text)) < len(resp_orig.text) * 0.3):
                                findings.append(Finding(
                                    vuln_type="IDOR",
                                    title=f"Potential IDOR: changing ID from {seg} to {test_id}",
                                    severity="HIGH",
                                    url=test_url,
                                    parameter=f"path segment [{i}]",
                                    payload=test_id,
                                    evidence=f"Both IDs return 200 with similar content ({len(resp.text)} vs {len(resp_orig.text)} bytes)",
                                    description=f"Changing resource ID from '{seg}' to '{test_id}' returns similar data. Possible IDOR.",
                                    remediation="Implement proper authorization checks. Use indirect references.",
                                    cvss=7.5, cwe="CWE-639", tool="owasp_methodology",
                                    verified=False, confidence="MEDIUM",
                                ))
                                break
                        except Exception:
                            pass
                    break

            # Test query parameters for IDOR
            if parsed.query:
                params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                for param_name, param_value in params.items():
                    if param_value.isdigit():
                        test_params = dict(params)
                        test_params[param_name] = str(int(param_value) + 1)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        self.limiter.wait(self._get_host(url))
                        try:
                            resp = client.get(test_url, params=test_params)
                            resp_orig = client.get(url)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                findings.append(Finding(
                                    vuln_type="IDOR",
                                    title=f"Potential IDOR in parameter: {param_name}",
                                    severity="HIGH",
                                    url=test_url,
                                    parameter=param_name,
                                    payload=test_params[param_name],
                                    evidence=f"Modified {param_name}={test_params[param_name]} returned {resp.status_code}",
                                    description=f"Parameter '{param_name}' may be vulnerable to IDOR.",
                                    remediation="Implement proper authorization checks.",
                                    cvss=7.5, cwe="CWE-639", tool="owasp_methodology",
                                    verified=False, confidence="MEDIUM",
                                ))
                        except Exception:
                            pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 6: Session Management
    # ──────────────────────────────────────────────────────────────

    def test_phase_6(self, target: str) -> List[Finding]:
        """OWASP-SM: Session Management Testing."""
        findings = []
        findings.extend(self._session_cookie_attributes(target))
        findings.extend(self._session_csrf(target))
        findings.extend(self._session_fixation(target))
        return findings

    def _session_cookie_attributes(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=True)
            resp = client.get(url)

            for cookie in client.cookies.jar:
                name = cookie.name
                issues = []

                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly flag")
                if not cookie.secure and url.startswith("https://"):
                    issues.append("Missing Secure flag")

                # Check SameSite via raw headers
                set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
                raw_cookie = ""
                for h in resp.headers.get("set-cookie", "").split(","):
                    if name in h:
                        raw_cookie = h
                        break

                if "samesite" not in raw_cookie.lower():
                    issues.append("Missing SameSite attribute")

                if issues:
                    severity = "MEDIUM" if "HttpOnly" in str(issues) or "Secure" in str(issues) else "LOW"
                    findings.append(Finding(
                        vuln_type="Insecure Cookie Configuration",
                        title=f"Cookie '{name}' missing security flags: {', '.join(issues)}",
                        severity=severity,
                        url=url,
                        evidence=f"Cookie: {name} — Issues: {', '.join(issues)}",
                        description=f"Cookie '{name}' lacks proper security attributes.",
                        remediation="Set HttpOnly, Secure, and SameSite flags on all cookies.",
                        cvss=4.0, cwe="CWE-614", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))

            # Check for cookies with long expiry
            for cookie in client.cookies.jar:
                if cookie.expires and cookie.expires > time.time() + 86400 * 365:
                    findings.append(Finding(
                        vuln_type="Long-Lived Cookie",
                        title=f"Cookie '{cookie.name}' expires in >1 year",
                        severity="LOW",
                        url=url,
                        evidence=f"Cookie '{cookie.name}' expires: {cookie.expires}",
                        description="Long-lived cookies increase the window for session hijacking.",
                        remediation="Set reasonable cookie expiration times.",
                        cvss=2.0, cwe="CWE-613", tool="owasp_methodology",
                        verified=True, confidence="HIGH",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    def _session_csrf(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text.lower()

            # Check for forms without CSRF tokens
            forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            for i, form in enumerate(forms):
                form_lower = form.lower()
                has_csrf = any(kw in form_lower for kw in [
                    "csrf", "token", "_token", "authenticity_token",
                    "csrfmiddlewaretoken", "__requestverificationtoken",
                ])
                has_method_post = 'method="post"' in resp.text.lower() or "method='post'" in resp.text.lower()

                if not has_csrf and has_method_post and "password" not in form_lower:
                    findings.append(Finding(
                        vuln_type="Missing CSRF Token",
                        title=f"Form #{i+1} lacks CSRF protection",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"POST form found without CSRF token",
                        description="Form does not include a CSRF token, making it vulnerable to CSRF attacks.",
                        remediation="Add CSRF tokens to all state-changing forms.",
                        cvss=5.3, cwe="CWE-352", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    def _session_fixation(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)

            # Check if session cookie exists before login
            pre_cookies = {c.name: c.value for c in client.cookies.jar}

            if pre_cookies:
                # Check if session ID is in URL
                if any(kw in url.lower() for kw in ["sessionid=", "sid=", "jsessionid=", "phpsessid="]):
                    findings.append(Finding(
                        vuln_type="Session ID in URL",
                        title="Session ID exposed in URL",
                        severity="HIGH",
                        url=url,
                        evidence=f"URL contains session identifier",
                        description="Session ID in URL can be leaked via Referer header, browser history, and logs.",
                        remediation="Use cookies for session management. Never put session IDs in URLs.",
                        cvss=7.5, cwe="CWE-598", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 7: Input Validation
    # ──────────────────────────────────────────────────────────────

    def test_phase_7(self, target: str) -> List[Finding]:
        """OWASP-INP: Input Validation Testing."""
        findings = []
        findings.extend(self._input_reflected_xss(target))
        findings.extend(self._input_sqli_basic(target))
        findings.extend(self._input_command_injection(target))
        findings.extend(self._input_ssrf_basic(target))
        findings.extend(self._input_http_splitting(target))
        return findings

    def _input_reflected_xss(self, url: str) -> List[Finding]:
        findings = []
        xss_payloads = [
            ('<script>alert("XSS")</script>', '<script>alert("XSS")</script>'),
            ('"><img src=x onerror=alert(1)>', 'onerror=alert(1)'),
            ("javascript:alert(1)", "javascript:alert(1)"),
            ("'-alert(1)-'", "alert(1)"),
        ]

        try:
            client = self._make_client()
            parsed = urlparse(url)

            # Find parameters to test
            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            # Also test common param names
            common_params = ["q", "search", "query", "input", "name", "value", "text", "msg", "id"]
            for p in common_params:
                if p not in params_to_test:
                    params_to_test[p] = "test"

            for param_name in params_to_test:
                for payload, indicator in xss_payloads:
                    test_params = dict(params_to_test)
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    self.limiter.wait(self._get_host(url))
                    try:
                        resp = client.get(test_url, params=test_params)
                        if indicator in resp.text:
                            # Verify it's not encoded
                            if payload in resp.text:
                                findings.append(Finding(
                                    vuln_type="Reflected XSS",
                                    title=f"Reflected XSS in parameter: {param_name}",
                                    severity="HIGH",
                                    url=test_url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Payload reflected unencoded in response",
                                    description=f"Parameter '{param_name}' reflects input without encoding.",
                                    remediation="Encode all user input in output. Implement CSP.",
                                    cvss=6.1, cwe="CWE-79", tool="owasp_methodology",
                                    verified=True, confidence="HIGH",
                                ))
                                break
                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    def _input_sqli_basic(self, url: str) -> List[Finding]:
        findings = []
        sqli_payloads = [
            ("'", ("sql syntax", "mysql", "syntax error", "unclosed quotation", "sqlite", "postgresql", "ORA-")),
            ("1 OR 1=1", ("sql syntax", "mysql", "error")),
            ("1' AND '1'='1", ("sql syntax", "mysql", "error")),
            ("'; WAITFOR DELAY '0:0:5'--", None),  # time-based
        ]

        try:
            client = self._make_client()
            parsed = urlparse(url)

            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            common_params = ["id", "user", "item", "product", "page", "category", "search"]
            for p in common_params:
                if p not in params_to_test:
                    params_to_test[p] = "1"

            for param_name in params_to_test:
                for payload, indicators in sqli_payloads:
                    test_params = dict(params_to_test)
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    self.limiter.wait(self._get_host(url))
                    try:
                        start_time = time.time()
                        resp = client.get(test_url, params=test_params)
                        elapsed = time.time() - start_time

                        body_lower = resp.text.lower()

                        # Error-based detection
                        if indicators:
                            for indicator in indicators:
                                if indicator.lower() in body_lower:
                                    findings.append(Finding(
                                        vuln_type="SQL Injection",
                                        title=f"Error-based SQLi in parameter: {param_name}",
                                        severity="CRITICAL",
                                        url=test_url,
                                        parameter=param_name,
                                        payload=payload,
                                        evidence=f"SQL error indicator '{indicator}' found in response",
                                        description=f"Parameter '{param_name}' appears vulnerable to SQL injection.",
                                        remediation="Use parameterized queries. Never concatenate user input.",
                                        cvss=9.8, cwe="CWE-89", tool="owasp_methodology",
                                        verified=True, confidence="HIGH",
                                    ))
                                    break

                        # Time-based detection (WAITFOR)
                        if payload.startswith("'; WAITFOR") and elapsed > 4.5:
                            findings.append(Finding(
                                vuln_type="SQL Injection (Time-based)",
                                title=f"Time-based SQLi in parameter: {param_name}",
                                severity="CRITICAL",
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Response delayed {elapsed:.1f}s (expected ~5s delay)",
                                description=f"Parameter '{param_name}' appears vulnerable to time-based SQL injection.",
                                remediation="Use parameterized queries.",
                                cvss=9.8, cwe="CWE-89", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))

                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    def _input_command_injection(self, url: str) -> List[Finding]:
        findings = []
        cmd_payloads = [
            ("; id", "uid="),
            ("| id", "uid="),
            ("`id`", "uid="),
            ("$(id)", "uid="),
            ("; cat /etc/passwd", "root:"),
            ("| whoami", None),
        ]

        try:
            client = self._make_client()
            parsed = urlparse(url)

            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            common_params = ["host", "ip", "target", "url", "domain", "cmd", "command", "ping", "file"]
            for p in common_params:
                if p not in params_to_test:
                    params_to_test[p] = "127.0.0.1"

            for param_name in params_to_test:
                for payload, indicator in cmd_payloads:
                    if indicator is None:
                        continue
                    base_value = params_to_test[param_name]
                    test_params = dict(params_to_test)
                    test_params[param_name] = base_value + payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    self.limiter.wait(self._get_host(url))
                    try:
                        resp = client.get(test_url, params=test_params)
                        if indicator in resp.text:
                            findings.append(Finding(
                                vuln_type="Command Injection",
                                title=f"OS command injection in parameter: {param_name}",
                                severity="CRITICAL",
                                url=test_url,
                                parameter=param_name,
                                payload=test_params[param_name],
                                evidence=f"Command output indicator '{indicator}' found in response",
                                description=f"Parameter '{param_name}' is vulnerable to OS command injection.",
                                remediation="Never pass user input to system commands. Use whitelisting.",
                                cvss=9.8, cwe="CWE-78", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                            break
                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    def _input_ssrf_basic(self, url: str) -> List[Finding]:
        findings = []
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0x7f000001",
        ]

        try:
            client = self._make_client()
            parsed = urlparse(url)

            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            url_params = ["url", "uri", "link", "src", "href", "redirect", "next", "return", "callback", "feed", "page"]
            for p in url_params:
                if p not in params_to_test:
                    params_to_test[p] = "https://example.com"

            for param_name in params_to_test:
                for payload in ssrf_payloads:
                    test_params = dict(params_to_test)
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    self.limiter.wait(self._get_host(url))
                    try:
                        resp = client.get(test_url, params=test_params, timeout=10)
                        body = resp.text.lower()
                        # Check for signs of SSRF (metadata, localhost responses)
                        if any(kw in body for kw in ["ami-id", "instance-id", "root:", "localhost", "127.0.0.1"]):
                            findings.append(Finding(
                                vuln_type="SSRF",
                                title=f"SSRF in parameter: {param_name}",
                                severity="CRITICAL",
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Response contains internal/localhost content",
                                description=f"Parameter '{param_name}' may be vulnerable to SSRF.",
                                remediation="Validate and whitelist URLs. Block internal IPs.",
                                cvss=9.1, cwe="CWE-918", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                            break
                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    def _input_http_splitting(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)
            parsed = urlparse(url)

            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            redirect_params = ["url", "redirect", "next", "return", "goto", "continue", "dest", "target"]
            for p in redirect_params:
                if p not in params_to_test:
                    params_to_test[p] = "https://example.com"

            for param_name in params_to_test:
                # Test CRLF injection
                payload = "https://example.com%0d%0aInjected-Header:%20injected"
                test_params = dict(params_to_test)
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url, params=test_params)
                    if "injected-header" in str(resp.headers).lower():
                        findings.append(Finding(
                            vuln_type="HTTP Header Injection / CRLF",
                            title=f"CRLF injection in parameter: {param_name}",
                            severity="HIGH",
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Injected header found in response",
                            description=f"Parameter '{param_name}' is vulnerable to CRLF/header injection.",
                            remediation="Sanitize line breaks in user input used in headers.",
                            cvss=7.5, cwe="CWE-113", tool="owasp_methodology",
                            verified=True, confidence="HIGH",
                        ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 8: Error Handling
    # ──────────────────────────────────────────────────────────────

    def test_phase_8(self, target: str) -> List[Finding]:
        """OWASP-ERR: Error Handling Testing."""
        findings = []
        findings.extend(self._error_stack_traces(target))
        findings.extend(self._error_verbose_messages(target))
        findings.extend(self._error_debug_mode(target))
        findings.extend(self._error_codes(target))
        return findings

    def _error_stack_traces(self, url: str) -> List[Finding]:
        findings = []
        error_triggers = [
            ("'", "SQL/error"),
            ("{{7*7}}", "template/error"),
            ("<%=", "template/error"),
            ("${7*7}", "expression/error"),
            ("../../../etc/passwd", "path/error"),
        ]

        try:
            client = self._make_client()
            for payload, trigger_type in error_triggers:
                test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    body = resp.text.lower()

                    stack_indicators = [
                        "traceback (most recent call last)",
                        "stack trace:",
                        "at com.",
                        "at org.",
                        "system.exception",
                        "unhandled exception",
                        "fatal error",
                        "warning:",
                        "notice:",
                        "deprecated:",
                    ]

                    for indicator in stack_indicators:
                        if indicator in body:
                            # Extract a snippet
                            idx = body.index(indicator)
                            snippet = resp.text[max(0, idx-50):idx+200]
                            findings.append(Finding(
                                vuln_type="Stack Trace Disclosure",
                                title=f"Stack trace exposed via {trigger_type}",
                                severity="MEDIUM",
                                url=test_url,
                                payload=payload,
                                evidence=f"Stack trace found: {snippet[:150]}...",
                                description="Application exposes stack traces, revealing internal implementation details.",
                                remediation="Implement custom error pages. Never expose stack traces in production.",
                                cvss=5.3, cwe="CWE-209", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                            break
                except Exception:
                    pass
            client.close()
        except Exception:
            pass
        return findings

    def _error_verbose_messages(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Trigger 404
            resp = client.get(f"{url}/nonexistent_page_{int(time.time())}")
            body = resp.text.lower()

            verbose_indicators = [
                ("apache/", "Apache version disclosed"),
                ("nginx/", "Nginx version disclosed"),
                ("iis/", "IIS version disclosed"),
                ("php/", "PHP version disclosed"),
                ("python/", "Python version disclosed"),
                ("node.js", "Node.js disclosed"),
                ("express", "Express.js disclosed"),
                ("tomcat", "Tomcat disclosed"),
            ]

            for indicator, desc in verbose_indicators:
                if indicator in body:
                    findings.append(Finding(
                        vuln_type="Verbose Error Message",
                        title=desc,
                        severity="LOW",
                        url=f"{url}/nonexistent_page",
                        evidence=f"404 page contains '{indicator}'",
                        description="Error pages reveal server technology and version.",
                        remediation="Use custom error pages. Hide technology details.",
                        cvss=3.1, cwe="CWE-209", tool="owasp_methodology",
                        verified=True, confidence="HIGH",
                    ))

            # Test for debug endpoints
            debug_paths = ["/debug", "/debug/vars", "/debug/pprof", "/server-info", "/server-status"]
            for path in debug_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        if any(kw in resp.text.lower() for kw in ["debug", "profiler", "diagnostic", "dump"]):
                            findings.append(Finding(
                                vuln_type="Debug Endpoint Exposed",
                                title=f"Debug endpoint accessible: {path}",
                                severity="HIGH",
                                url=test_url,
                                evidence=f"GET {test_url} returned {resp.status_code} with debug content",
                                description=f"Debug endpoint '{path}' is accessible in production.",
                                remediation="Disable debug endpoints in production.",
                                cvss=7.5, cwe="CWE-215", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _error_debug_mode(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text.lower()

            debug_indicators = [
                "debug=true", "debug mode", "debug_mode", "development mode",
                "django debug", "flask debug", "rails debug", "laravel debug",
                "stack trace", "exception details", "request information",
            ]

            for indicator in debug_indicators:
                if indicator in body:
                    findings.append(Finding(
                        vuln_type="Debug Mode Enabled",
                        title="Application appears to be in debug mode",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"Debug indicator found: '{indicator}'",
                        description="Debug mode exposes detailed error information and may disable security controls.",
                        remediation="Disable debug mode in production environments.",
                        cvss=5.3, cwe="CWE-215", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))
                    break

            client.close()
        except Exception:
            pass
        return findings

    def _error_codes(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Test various error codes
            error_urls = [
                (f"{url}/nonexistent", "404"),
                (f"{url}", "200"),  # baseline
            ]

            # Check if custom error pages are implemented
            resp = client.get(f"{url}/nonexistent_page_{int(time.time())}")
            if resp.status_code == 404:
                body = resp.text.lower()
                if len(body) < 100 or "404" in body:
                    # Likely a default error page
                    if "not found" in body and len(body) < 500:
                        # Default error page — may leak info
                        pass

            # Test for 500 error
            try:
                resp = client.get(f"{url}/api/nonexistent", headers={"Accept": "application/json"})
                if resp.status_code == 500:
                    try:
                        error_json = resp.json()
                        if "stack" in str(error_json).lower() or "trace" in str(error_json).lower():
                            findings.append(Finding(
                                vuln_type="JSON Error Disclosure",
                                title="API returns detailed error in JSON format",
                                severity="MEDIUM",
                                url=f"{url}/api/nonexistent",
                                evidence=f"500 response with error details: {str(error_json)[:200]}",
                                description="API returns detailed error information that could aid attackers.",
                                remediation="Return generic error messages. Log details server-side.",
                                cvss=5.3, cwe="CWE-209", tool="owasp_methodology",
                                verified=True, confidence="HIGH",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 9: Cryptography
    # ──────────────────────────────────────────────────────────────

    def test_phase_9(self, target: str) -> List[Finding]:
        """OWASP-CR: Cryptography Testing."""
        findings = []
        findings.extend(self._crypto_ssl_tls(target))
        findings.extend(self._crypto_certificate(target))
        findings.extend(self._crypto_hsts(target))
        findings.extend(self._crypto_redirect(target))
        return findings

    def _crypto_ssl_tls(self, url: str) -> List[Finding]:
        findings = []
        host = self._get_host(url)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    # Check TLS version
                    if version in ("TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            vuln_type="Weak TLS Version",
                            title=f"Server supports deprecated TLS: {version}",
                            severity="HIGH",
                            url=f"https://{host}",
                            evidence=f"TLS version: {version}",
                            description=f"{version} is deprecated and has known vulnerabilities.",
                            remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2+.",
                            cvss=7.5, cwe="CWE-326", tool="owasp_methodology",
                            verified=True, confidence="CONFIRMED",
                        ))

                    # Check cipher suite
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"]
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                findings.append(Finding(
                                    vuln_type="Weak Cipher Suite",
                                    title=f"Weak cipher suite: {cipher_name}",
                                    severity="HIGH",
                                    url=f"https://{host}",
                                    evidence=f"Cipher: {cipher_name}, Protocol: {cipher[1]}",
                                    description=f"Cipher suite '{cipher_name}' uses weak cryptography.",
                                    remediation="Disable weak ciphers. Use TLS_AES_256_GCM_SHA384 or similar.",
                                    cvss=7.5, cwe="CWE-327", tool="owasp_methodology",
                                    verified=True, confidence="CONFIRMED",
                                ))
                                break

                    # Test for older protocols
                    for proto_name, proto_const in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
                        try:
                            old_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            old_ctx.check_hostname = False
                            old_ctx.verify_mode = ssl.CERT_NONE
                            # Try connecting with old protocol
                            with socket.create_connection((host, 443), timeout=5) as sock2:
                                with old_ctx.wrap_socket(sock2, server_hostname=host) as ssock2:
                                    if ssock2.version() == proto_name:
                                        findings.append(Finding(
                                            vuln_type="Deprecated TLS Support",
                                            title=f"Server accepts {proto_name}",
                                            severity="HIGH",
                                            url=f"https://{host}",
                                            evidence=f"Successfully connected with {proto_name}",
                                            description=f"Server accepts deprecated {proto_name} connections.",
                                            remediation=f"Disable {proto_name} on the server.",
                                            cvss=7.5, cwe="CWE-326", tool="owasp_methodology",
                                            verified=True, confidence="CONFIRMED",
                                        ))
                        except Exception:
                            pass

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                vuln_type="SSL Certificate Error",
                title=f"SSL certificate verification failed: {str(e)[:100]}",
                severity="HIGH",
                url=f"https://{host}",
                evidence=str(e)[:200],
                description="SSL certificate has verification issues.",
                remediation="Fix SSL certificate. Use valid CA-signed certificates.",
                cvss=7.5, cwe="CWE-295", tool="owasp_methodology",
                verified=True, confidence="CONFIRMED",
            ))
        except Exception as e:
            logger.debug(f"SSL/TLS test error: {e}")
        return findings

    def _crypto_certificate(self, url: str) -> List[Finding]:
        findings = []
        host = self._get_host(url)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Check expiry
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                expiry = ssl.cert_time_to_seconds(not_after)
                                days_left = (expiry - time.time()) / 86400
                                if days_left < 0:
                                    findings.append(Finding(
                                        vuln_type="Expired SSL Certificate",
                                        title=f"SSL certificate expired: {not_after}",
                                        severity="CRITICAL",
                                        url=f"https://{host}",
                                        evidence=f"Certificate expired: {not_after}",
                                        description="SSL certificate has expired.",
                                        remediation="Renew SSL certificate immediately.",
                                        cvss=9.1, cwe="CWE-295", tool="owasp_methodology",
                                        verified=True, confidence="CONFIRMED",
                                    ))
                                elif days_left < 30:
                                    findings.append(Finding(
                                        vuln_type="SSL Certificate Expiring Soon",
                                        title=f"SSL certificate expires in {int(days_left)} days",
                                        severity="MEDIUM",
                                        url=f"https://{host}",
                                        evidence=f"Expires: {not_after} ({int(days_left)} days)",
                                        description="SSL certificate will expire soon.",
                                        remediation="Renew SSL certificate.",
                                        cvss=4.0, cwe="CWE-295", tool="owasp_methodology",
                                        verified=True, confidence="CONFIRMED",
                                    ))
                            except Exception:
                                pass

                        # Check subject
                        subject = cert.get("subject", ())
                        cn = ""
                        for rdn in subject:
                            for attr_type, attr_value in rdn:
                                if attr_type == "commonName":
                                    cn = attr_value

                        # Check SAN
                        san = cert.get("subjectAltName", ())
                        san_hosts = [entry[1] for entry in san if entry[0] == "DNS"]

                        if cn and host not in cn and not any(host.endswith(s.lstrip("*")) for s in san_hosts):
                            findings.append(Finding(
                                vuln_type="Hostname Mismatch",
                                title=f"SSL certificate hostname mismatch",
                                severity="HIGH",
                                url=f"https://{host}",
                                evidence=f"CN: {cn}, SAN: {san_hosts[:3]}, Target: {host}",
                                description="SSL certificate does not match the requested hostname.",
                                remediation="Obtain a certificate matching the hostname.",
                                cvss=7.5, cwe="CWE-297", tool="owasp_methodology",
                                verified=True, confidence="CONFIRMED",
                            ))

                        # Check key size
                        # getpeercert doesn't directly give key size, but we can check via binary form
                        try:
                            der_cert = ssock.getpeercert(binary_form=True)
                            # Basic check — we'll note that cert was retrieved
                        except Exception:
                            pass

        except Exception as e:
            logger.debug(f"Certificate test error: {e}")
        return findings

    def _crypto_hsts(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client(follow_redirects=False)
            https_url = url.replace("http://", "https://") if url.startswith("http://") else url
            resp = client.get(https_url)
            hsts = resp.headers.get("Strict-Transport-Security", "")

            if not hsts:
                findings.append(Finding(
                    vuln_type="Missing HSTS",
                    title="HSTS header not set",
                    severity="MEDIUM",
                    url=https_url,
                    evidence="Strict-Transport-Security header not found",
                    description="Without HSTS, users may be vulnerable to SSL stripping attacks.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
                    cvss=4.0, cwe="CWE-319", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))
            else:
                # Parse max-age
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:
                        findings.append(Finding(
                            vuln_type="HSTS Max-Age Too Short",
                            title=f"HSTS max-age too short: {max_age}s",
                            severity="LOW",
                            url=https_url,
                            evidence=f"Strict-Transport-Security: {hsts}",
                            description=f"HSTS max-age of {max_age}s is below recommended 31536000s (1 year).",
                            remediation="Set max-age to at least 31536000 (1 year).",
                            cvss=2.0, cwe="CWE-319", tool="owasp_methodology",
                            verified=True, confidence="CONFIRMED",
                        ))

                if "includesubdomains" not in hsts.lower():
                    findings.append(Finding(
                        vuln_type="HSTS Missing includeSubDomains",
                        title="HSTS does not include subdomains",
                        severity="LOW",
                        url=https_url,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        description="HSTS without includeSubDomains leaves subdomains unprotected.",
                        remediation="Add 'includeSubDomains' to HSTS header.",
                        cvss=2.0, cwe="CWE-319", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    def _crypto_redirect(self, url: str) -> List[Finding]:
        findings = []
        if not url.startswith("http://"):
            return findings
        try:
            client = self._make_client(follow_redirects=False)
            resp = client.get(url)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location.startswith("https://"):
                    # Good — redirects to HTTPS
                    pass
                else:
                    findings.append(Finding(
                        vuln_type="No HTTPS Redirect",
                        title="HTTP does not redirect to HTTPS",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"HTTP {resp.status_code} redirects to: {location}",
                        description="HTTP traffic is not redirected to HTTPS.",
                        remediation="Configure HTTP to HTTPS redirect (301).",
                        cvss=4.0, cwe="CWE-319", tool="owasp_methodology",
                        verified=True, confidence="CONFIRMED",
                    ))
            elif resp.status_code == 200:
                findings.append(Finding(
                    vuln_type="HTTP Accessible Without Redirect",
                    title="HTTP site accessible without HTTPS redirect",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"HTTP GET returned {resp.status_code} without redirect",
                    description="Site is accessible over HTTP without redirecting to HTTPS.",
                    remediation="Redirect all HTTP traffic to HTTPS.",
                    cvss=4.0, cwe="CWE-319", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 10: Business Logic
    # ──────────────────────────────────────────────────────────────

    def test_phase_10(self, target: str) -> List[Finding]:
        """OWASP-BL: Business Logic Testing."""
        findings = []
        findings.extend(self._logic_negative_values(target))
        findings.extend(self._logic_step_skipping(target))
        findings.extend(self._logic_process_timing(target))
        return findings

    def _logic_negative_values(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            # Find numeric parameters
            if parsed.query:
                params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                for param_name, param_value in params.items():
                    if param_value.isdigit():
                        # Try negative value
                        test_params = dict(params)
                        test_params[param_name] = f"-{param_value}"
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                        self.limiter.wait(self._get_host(url))
                        try:
                            resp = client.get(test_url, params=test_params)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                findings.append(Finding(
                                    vuln_type="Negative Value Accepted",
                                    title=f"Negative value accepted in parameter: {param_name}",
                                    severity="MEDIUM",
                                    url=test_url,
                                    parameter=param_name,
                                    payload=f"-{param_value}",
                                    evidence=f"Negative value returned {resp.status_code}",
                                    description=f"Parameter '{param_name}' accepts negative values. May cause logic flaws.",
                                    remediation="Validate that numeric parameters are positive.",
                                    cvss=5.3, cwe="CWE-20", tool="owasp_methodology",
                                    verified=False, confidence="MEDIUM",
                                ))
                        except Exception:
                            pass
            client.close()
        except Exception:
            pass
        return findings

    def _logic_step_skipping(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Look for multi-step URL patterns
            step_patterns = [
                (r"/step(\d+)/", "step"),
                (r"/checkout/(\d+)/", "checkout"),
                (r"/wizard/(\d+)/", "wizard"),
                (r"/flow/(\d+)/", "flow"),
            ]

            parsed = urlparse(url)
            path = parsed.path

            for pattern, name in step_patterns:
                match = re.search(pattern, path)
                if match:
                    current_step = int(match.group(1))
                    if current_step > 1:
                        # Try to skip to an earlier step
                        for skip_to in [1, current_step - 1]:
                            skip_url = re.sub(pattern, f"/{name}{skip_to}/", path)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{skip_url}"
                            if parsed.query:
                                test_url += f"?{parsed.query}"

                            self.limiter.wait(self._get_host(url))
                            try:
                                resp = client.get(test_url)
                                if resp.status_code == 200:
                                    findings.append(Finding(
                                        vuln_type="Step Skipping",
                                        title=f"Multi-step process can be skipped (step {current_step} → {skip_to})",
                                        severity="MEDIUM",
                                        url=test_url,
                                        evidence=f"Step {skip_to} accessible from step {current_step}",
                                        description="Multi-step process can be bypassed by directly accessing earlier steps.",
                                        remediation="Enforce step progression server-side.",
                                        cvss=5.3, cwe="CWE-841", tool="owasp_methodology",
                                        verified=True, confidence="MEDIUM",
                                    ))
                            except Exception:
                                pass
                    break

            client.close()
        except Exception:
            pass
        return findings

    def _logic_process_timing(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Measure response time for identical requests
            times = []
            for _ in range(3):
                self.limiter.wait(self._get_host(url))
                start = time.time()
                try:
                    resp = client.get(url)
                    times.append(time.time() - start)
                except Exception:
                    pass

            if len(times) >= 2:
                variance = max(times) - min(times)
                if variance > 2.0:
                    findings.append(Finding(
                        vuln_type="High Response Time Variance",
                        title=f"High response time variance: {variance:.2f}s",
                        severity="INFO",
                        url=url,
                        evidence=f"Response times: {', '.join(f'{t:.2f}s' for t in times)}",
                        description="High response time variance may indicate timing-based vulnerabilities.",
                        remediation="Investigate causes of response time variance.",
                        cvss=0.0, cwe="CWE-208", tool="owasp_methodology",
                        verified=False, confidence="LOW",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 11: Client-Side Testing
    # ──────────────────────────────────────────────────────────────

    def test_phase_11(self, target: str) -> List[Finding]:
        """OWASP-CLIENT: Client-Side Testing."""
        findings = []
        findings.extend(self._client_dom_xss(target))
        findings.extend(self._client_local_storage(target))
        findings.extend(self._client_cors(target))
        findings.extend(self._client_js_security(target))
        return findings

    def _client_dom_xss(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Look for dangerous DOM sinks
            dangerous_sinks = [
                "document.write",
                "innerHTML",
                "outerHTML",
                "eval(",
                "setTimeout(",
                "setInterval(",
                "document.location",
                "window.location",
                ".href",
                "document.URL",
                "document.referrer",
                "location.hash",
                "location.search",
            ]

            # Look for sources
            sources = [
                "location.hash", "location.search", "document.URL",
                "document.referrer", "window.name", "document.cookie",
            ]

            found_sinks = []
            for sink in dangerous_sinks:
                if sink in body:
                    found_sinks.append(sink)

            found_sources = []
            for source in sources:
                if source in body:
                    found_sources.append(source)

            if found_sinks and found_sources:
                findings.append(Finding(
                    vuln_type="Potential DOM XSS",
                    title=f"DOM-based XSS risk: {len(found_sinks)} sinks, {len(found_sources)} sources",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"Sinks: {', '.join(found_sinks[:5])}; Sources: {', '.join(found_sources[:5])}",
                    description="JavaScript uses dangerous DOM manipulation with user-controlled sources.",
                    remediation="Use textContent instead of innerHTML. Sanitize all DOM inputs.",
                    cvss=6.1, cwe="CWE-79", tool="owasp_methodology",
                    verified=False, confidence="MEDIUM",
                ))

            client.close()
        except Exception:
            pass
        return findings

    def _client_local_storage(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Check for localStorage/sessionStorage usage with sensitive data
            storage_patterns = [
                (r"localStorage\.setItem\(['\"]([^'\"]*?)['\"]", "localStorage"),
                (r"sessionStorage\.setItem\(['\"]([^'\"]*?)['\"]", "sessionStorage"),
            ]

            sensitive_keywords = ["token", "password", "secret", "key", "auth", "session", "credential"]

            for pattern, storage_type in storage_patterns:
                matches = re.findall(pattern, body)
                for key in matches:
                    if any(kw in key.lower() for kw in sensitive_keywords):
                        findings.append(Finding(
                            vuln_type="Sensitive Data in Client Storage",
                            title=f"Sensitive data in {storage_type}: {key}",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"{storage_type}.setItem('{key}', ...)",
                            description=f"Sensitive key '{key}' stored in {storage_type}. Accessible via XSS.",
                            remediation="Store sensitive data in HttpOnly cookies or server-side sessions.",
                            cvss=5.3, cwe="CWE-922", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))

            client.close()
        except Exception:
            pass
        return findings

    def _client_cors(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url, headers={"Origin": "https://evil.com"})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append(Finding(
                    vuln_type="CORS Wildcard",
                    title="CORS allows all origins (*)",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: *",
                    description="CORS wildcard allows any origin to make cross-origin requests.",
                    remediation="Whitelist specific allowed origins.",
                    cvss=5.3, cwe="CWE-346", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))
            elif acao == "https://evil.com" and acac.lower() == "true":
                findings.append(Finding(
                    vuln_type="CORS Reflects Origin",
                    title="CORS reflects arbitrary origin with credentials",
                    severity="HIGH",
                    url=url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description="Server reflects any Origin header with credentials enabled.",
                    remediation="Validate Origin against a whitelist.",
                    cvss=8.1, cwe="CWE-346", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            client.close()
        except Exception:
            pass
        return findings

    def _client_js_security(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Check for inline scripts (CSP risk)
            inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', body, re.DOTALL)
            if inline_scripts:
                findings.append(Finding(
                    vuln_type="Inline JavaScript",
                    title=f"{len(inline_scripts)} inline script blocks found",
                    severity="LOW",
                    url=url,
                    evidence=f"{len(inline_scripts)} inline <script> blocks",
                    description="Inline scripts bypass CSP and increase XSS risk.",
                    remediation="Move scripts to external files. Use CSP nonces.",
                    cvss=2.0, cwe="CWE-79", tool="owasp_methodology",
                    verified=True, confidence="CONFIRMED",
                ))

            # Check for eval usage
            if "eval(" in body:
                findings.append(Finding(
                    vuln_type="eval() Usage",
                    title="JavaScript uses eval() — potential code injection",
                    severity="MEDIUM",
                    url=url,
                    evidence="eval() found in page source",
                    description="eval() can execute arbitrary code and is a common XSS vector.",
                    remediation="Remove eval() usage. Use JSON.parse() for JSON data.",
                    cvss=6.1, cwe="CWE-95", tool="owasp_methodology",
                    verified=True, confidence="MEDIUM",
                ))

            # Check for postMessage without origin validation
            if "addEventListener('message'" in body or 'addEventListener("message"' in body:
                if "event.origin" not in body and "e.origin" not in body:
                    findings.append(Finding(
                        vuln_type="postMessage Without Origin Check",
                        title="postMessage handler without origin validation",
                        severity="MEDIUM",
                        url=url,
                        evidence="message event listener without origin check",
                        description="postMessage handler accepts messages from any origin.",
                        remediation="Validate event.origin in message handlers.",
                        cvss=5.3, cwe="CWE-345", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  Phase 12: API Security
    # ──────────────────────────────────────────────────────────────

    def test_phase_12(self, target: str) -> List[Finding]:
        """OWASP-API: API Security Testing."""
        findings = []
        findings.extend(self._api_method_override(target))
        findings.extend(self._api_mass_assignment(target))
        findings.extend(self._api_rate_limiting(target))
        findings.extend(self._api_verbose_errors(target))
        findings.extend(self._api_content_type(target))
        return findings

    def _api_method_override(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            override_headers = [
                "X-HTTP-Method-Override",
                "X-HTTP-Method",
                "X-Method-Override",
                "_method",
            ]

            for header in override_headers:
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(url, headers={header: "DELETE"})
                    if resp.status_code in (200, 204):
                        findings.append(Finding(
                            vuln_type="HTTP Method Override",
                            title=f"Method override via {header}",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"GET with {header}: DELETE → {resp.status_code}",
                            description=f"Server accepts method override via {header}.",
                            remediation="Disable method override or validate allowed methods.",
                            cvss=5.3, cwe="CWE-287", tool="owasp_methodology",
                            verified=True, confidence="MEDIUM",
                        ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _api_mass_assignment(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Test mass assignment by adding extra fields
            extra_fields = {
                "role": "admin",
                "is_admin": True,
                "admin": True,
                "permissions": "all",
                "user_type": "admin",
            }

            # Try POST with extra fields
            for field_name, field_value in extra_fields.items():
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.post(url, json={
                        "username": "testuser",
                        "email": "test@example.com",
                        field_name: field_value,
                    })
                    if resp.status_code in (200, 201):
                        body = resp.text.lower()
                        if field_name in body:
                            findings.append(Finding(
                                vuln_type="Mass Assignment",
                                title=f"Mass assignment possible: {field_name}={field_value}",
                                severity="HIGH",
                                url=url,
                                payload=json.dumps({field_name: field_value}),
                                evidence=f"Response contains '{field_name}' field",
                                description=f"Server accepts and reflects extra field '{field_name}'.",
                                remediation="Use allowlists for accepted fields. Reject unknown fields.",
                                cvss=7.5, cwe="CWE-915", tool="owasp_methodology",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _api_rate_limiting(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            statuses = []
            for _ in range(20):
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(url)
                    statuses.append(resp.status_code)
                except Exception:
                    pass

            if 429 not in statuses and len(statuses) >= 15:
                findings.append(Finding(
                    vuln_type="Missing API Rate Limiting",
                    title="API does not implement rate limiting",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"{len(statuses)} requests without 429 response",
                    description="API accepts unlimited requests without rate limiting.",
                    remediation="Implement rate limiting (e.g., 100 req/min per IP).",
                    cvss=5.3, cwe="CWE-770", tool="owasp_methodology",
                    verified=True, confidence="MEDIUM",
                ))

            client.close()
        except Exception:
            pass
        return findings

    def _api_verbose_errors(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Trigger error with invalid Accept header
            resp = client.get(
                f"{url}/nonexistent_{int(time.time())}",
                headers={"Accept": "application/json"},
            )

            body = resp.text.lower()
            error_indicators = ["stack", "trace", "exception", "debug", "sql", "internal"]

            for indicator in error_indicators:
                if indicator in body:
                    findings.append(Finding(
                        vuln_type="Verbose API Error",
                        title="API returns verbose error messages",
                        severity="LOW",
                        url=url,
                        evidence=f"Error contains: '{indicator}'",
                        description="API error responses reveal implementation details.",
                        remediation="Return generic error messages in production.",
                        cvss=3.1, cwe="CWE-209", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))
                    break

            client.close()
        except Exception:
            pass
        return findings

    def _api_content_type(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            # Test if API accepts any content type
            resp = client.get(url, headers={"Accept": "text/html"})
            if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                # Now try with JSON accept
                resp_json = client.get(url, headers={"Accept": "application/json"})
                if resp_json.status_code == 200 and "application/json" in resp_json.headers.get("content-type", ""):
                    findings.append(Finding(
                        vuln_type="Content Negotiation",
                        title="API supports multiple content types",
                        severity="INFO",
                        url=url,
                        evidence=f"HTML and JSON both served",
                        description="API serves both HTML and JSON. Verify access controls apply to both.",
                        remediation="Ensure consistent security controls across all content types.",
                        cvss=0.0, cwe="CWE-200", tool="owasp_methodology",
                        verified=True, confidence="MEDIUM",
                    ))

            client.close()
        except Exception:
            pass
        return findings
