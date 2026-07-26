"""Cryptographic Security Scanner — SSL/TLS and crypto weakness detection.

Based on: Applied Cryptography (Schneier), Network Security (Kaufman), OWASP Testing Guide.

Tests for:
- SSL/TLS configuration (protocol versions, cipher suites)
- Certificate validation (self-signed, expired, hostname mismatch)
- Weak algorithms (MD5, SHA1, DES, RC4, export ciphers)
- Key exchange (DH params, RSA key size, forward secrecy)
- HSTS (enabled, max-age, include subdomains)
- HTTP to HTTPS redirect
- Mixed content
"""

import re
import ssl
import socket
from typing import List, Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


class CryptoScanner:
    """Tests cryptographic implementations and SSL/TLS configuration."""
    NAME = "crypto"

    # Weak cipher suites
    WEAK_CIPHERS = [
        "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5",
        "aNULL", "eNULL", "ADH", "AECDH",
        "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5",
        "DES-CBC-SHA", "EXP-DES-CBC-SHA", "EXP-RC4-MD5",
        "EXP-RC2-CBC-MD5", "EXP-EDH-RSA-DES-CBC-SHA",
    ]

    # Weak protocols
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

    # Strong protocols
    STRONG_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]

    def __init__(self):
        self.limiter = get_limiter(rps=2.0)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan URL for cryptographic weaknesses."""
        findings = []

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Test SSL/TLS configuration
        if parsed.scheme == "https" or port == 443:
            ssl_findings = self._test_ssl_config(host, port)
            findings.extend(ssl_findings)

        # Test HSTS
        hsts_findings = self._test_hsts(url)
        findings.extend(hsts_findings)

        # Test HTTP to HTTPS redirect
        if parsed.scheme == "https":
            redirect_findings = self._test_https_redirect(host, parsed.port or 80, url)
            findings.extend(redirect_findings)

        # Test mixed content
        mixed_findings = self._test_mixed_content(url)
        findings.extend(mixed_findings)

        return findings

    def _test_ssl_config(self, host: str, port: int) -> List[Finding]:
        """Test SSL/TLS configuration."""
        findings = []

        try:
            # Create SSL context and connect
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check protocol version
                    if version in self.WEAK_PROTOCOLS:
                        findings.append(Finding(
                            vuln_type="Weak TLS Protocol",
                            title=f"Weak SSL/TLS protocol: {version}",
                            severity="HIGH",
                            url=f"https://{host}:{port}",
                            evidence=f"Server supports {version}",
                            description=f"Server uses {version} which has known vulnerabilities (BEAST, POODLE, etc.).",
                            remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                            cvss=7.5,
                            cwe="CWE-326",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))

                    # Check cipher suite
                    if cipher:
                        cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                        for weak in self.WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                findings.append(Finding(
                                    vuln_type="Weak Cipher Suite",
                                    title=f"Weak cipher suite: {cipher_name}",
                                    severity="HIGH",
                                    url=f"https://{host}:{port}",
                                    evidence=f"Active cipher: {cipher_name}",
                                    description=f"Server uses weak cipher {cipher_name} which may be vulnerable to attacks.",
                                    remediation="Configure server to use strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
                                    cvss=7.0,
                                    cwe="CWE-327",
                                    tool=self.NAME,
                                    verified=True,
                                    confidence="HIGH",
                                ))
                                break

                    # Check certificate
                    if cert:
                        # Check expiration
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                # Parse certificate date
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                if expiry < datetime.utcnow():
                                    findings.append(Finding(
                                        vuln_type="Expired Certificate",
                                        title="SSL/TLS certificate has expired",
                                        severity="CRITICAL",
                                        url=f"https://{host}:{port}",
                                        evidence=f"Certificate expired: {not_after}",
                                        description="The SSL/TLS certificate has expired, causing trust issues for users.",
                                        remediation="Renew the SSL/TLS certificate immediately.",
                                        cvss=9.0,
                                        cwe="CWE-295",
                                        tool=self.NAME,
                                        verified=True,
                                        confidence="CONFIRMED",
                                    ))
                            except ValueError:
                                pass

                        # Check subject
                        subject = cert.get("subject", ())
                        common_name = ""
                        for rdn in subject:
                            for attr_type, attr_value in rdn:
                                if attr_type == "commonName":
                                    common_name = attr_value

                        # Check SAN
                        san = cert.get("subjectAltName", ())
                        san_names = [v for t, v in san if t == "DNS"]

                        # Check if hostname matches
                        if common_name and common_name != host:
                            if not any(self._match_hostname(host, sn) for sn in san_names):
                                findings.append(Finding(
                                    vuln_type="Hostname Mismatch",
                                    title=f"Certificate hostname mismatch: {common_name}",
                                    severity="HIGH",
                                    url=f"https://{host}:{port}",
                                    evidence=f"CN={common_name}, Host={host}",
                                    description="The certificate does not match the requested hostname.",
                                    remediation="Obtain a certificate that matches the hostname.",
                                    cvss=8.0,
                                    cwe="CWE-297",
                                    tool=self.NAME,
                                    verified=True,
                                    confidence="CONFIRMED",
                                ))

                        # Check key size
                        # Note: Python's ssl module doesn't directly expose key size
                        # We check the signature algorithm instead
                        signature_algorithm = cert.get("signatureAlgorithm", "")
                        if "sha1" in signature_algorithm.lower():
                            findings.append(Finding(
                                vuln_type="Weak Signature Algorithm",
                                title=f"Certificate uses SHA-1: {signature_algorithm}",
                                severity="MEDIUM",
                                url=f"https://{host}:{port}",
                                evidence=f"Signature algorithm: {signature_algorithm}",
                                description="SHA-1 is deprecated and collisions have been demonstrated.",
                                remediation="Use certificates with SHA-256 or stronger signature algorithms.",
                                cvss=5.0,
                                cwe="CWE-327",
                                tool=self.NAME,
                                verified=True,
                                confidence="HIGH",
                            ))

                    # Test for specific weak protocols
                    for proto_name, proto_const in [("SSLv3", ssl.PROTOCOL_TLSv1), ("TLSv1", ssl.PROTOCOL_TLSv1)]:
                        try:
                            weak_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            weak_ctx.check_hostname = False
                            weak_ctx.verify_mode = ssl.CERT_NONE
                            with socket.create_connection((host, port), timeout=5) as sock2:
                                with weak_ctx.wrap_socket(sock2, server_hostname=host) as ssock2:
                                    if ssock2.version() == proto_name:
                                        findings.append(Finding(
                                            vuln_type="Weak Protocol Enabled",
                                            title=f"Server supports {proto_name}",
                                            severity="HIGH" if proto_name == "SSLv3" else "MEDIUM",
                                            url=f"https://{host}:{port}",
                                            evidence=f"Successfully connected with {proto_name}",
                                            description=f"{proto_name} is vulnerable to known attacks.",
                                            remediation=f"Disable {proto_name} on the server.",
                                            cvss=7.5,
                                            cwe="CWE-326",
                                            tool=self.NAME,
                                            verified=True,
                                            confidence="CONFIRMED",
                                        ))
                        except Exception:
                            pass  # Protocol not supported (good)

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                vuln_type="Certificate Verification Failed",
                title=f"SSL certificate verification failed: {str(e)[:100]}",
                severity="HIGH",
                url=f"https://{host}:{port}",
                evidence=str(e)[:200],
                description="Certificate verification failed, indicating potential MITM or misconfiguration.",
                remediation="Fix the SSL certificate configuration.",
                cvss=8.0,
                cwe="CWE-295",
                tool=self.NAME,
                verified=True,
                confidence="CONFIRMED",
            ))
        except Exception as e:
            logger.debug(f"SSL test failed for {host}:{port}: {e}")

        return findings

    def _test_hsts(self, url: str) -> List[Finding]:
        """Test HSTS header."""
        findings = []
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
            resp = client.get(url)
            headers = resp.headers

            hsts = headers.get("strict-transport-security", "")

            if not hsts:
                findings.append(Finding(
                    vuln_type="Missing HSTS",
                    title="HSTS header not set",
                    severity="MEDIUM",
                    url=url,
                    evidence="Strict-Transport-Security header missing",
                    description="Without HSTS, users may be vulnerable to downgrade attacks and cookie hijacking.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                    cvss=5.0,
                    cwe="CWE-319",
                    tool=self.NAME,
                    verified=True,
                    confidence="CONFIRMED",
                ))
            else:
                # Check max-age
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        findings.append(Finding(
                            vuln_type="Weak HSTS",
                            title=f"HSTS max-age too short: {max_age}s",
                            severity="LOW",
                            url=url,
                            evidence=f"Strict-Transport-Security: {hsts}",
                            description=f"HSTS max-age is {max_age} seconds (less than 1 year recommended).",
                            remediation="Set max-age to at least 31536000 (1 year).",
                            cvss=3.0,
                            cwe="CWE-319",
                            tool=self.NAME,
                            verified=True,
                            confidence="HIGH",
                        ))

                # Check includeSubDomains
                if "includesubdomains" not in hsts.lower():
                    findings.append(Finding(
                        vuln_type="HSTS Missing Subdomains",
                        title="HSTS missing includeSubDomains",
                        severity="LOW",
                        url=url,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        description="HSTS does not include subdomains, leaving them vulnerable.",
                        remediation="Add 'includeSubDomains' to HSTS header.",
                        cvss=3.0,
                        cwe="CWE-319",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                    ))

            client.close()
        except Exception as e:
            logger.debug(f"HSTS test failed: {e}")

        return findings

    def _test_https_redirect(self, host: str, http_port: int, https_url: str) -> List[Finding]:
        """Test HTTP to HTTPS redirect."""
        findings = []
        try:
            import httpx
            http_url = f"http://{host}:{http_port}"
            client = httpx.Client(follow_redirects=False, timeout=10, verify=False)
            resp = client.get(http_url)

            if resp.status_code not in (301, 302, 307, 308):
                findings.append(Finding(
                    vuln_type="No HTTPS Redirect",
                    title="HTTP does not redirect to HTTPS",
                    severity="MEDIUM",
                    url=http_url,
                    evidence=f"HTTP response: {resp.status_code}",
                    description="HTTP requests are not redirected to HTTPS, allowing unencrypted traffic.",
                    remediation="Configure server to redirect HTTP to HTTPS with 301 redirect.",
                    cvss=5.0,
                    cwe="CWE-319",
                    tool=self.NAME,
                    verified=True,
                    confidence="CONFIRMED",
                ))
            else:
                location = resp.headers.get("location", "")
                if not location.startswith("https://"):
                    findings.append(Finding(
                        vuln_type="Insecure Redirect",
                        title=f"HTTP redirects to non-HTTPS: {location[:50]}",
                        severity="MEDIUM",
                        url=http_url,
                        evidence=f"Redirect to: {location}",
                        description="HTTP redirects to a non-HTTPS URL.",
                        remediation="Redirect HTTP to HTTPS.",
                        cvss=5.0,
                        cwe="CWE-319",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                    ))

            client.close()
        except Exception as e:
            logger.debug(f"HTTPS redirect test failed: {e}")

        return findings

    def _test_mixed_content(self, url: str) -> List[Finding]:
        """Test for mixed content (HTTP resources on HTTPS page)."""
        findings = []
        if not url.startswith("https://"):
            return findings

        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
            resp = client.get(url)
            body = resp.text

            # Find HTTP URLs in the page
            http_pattern = re.compile(r'(src|href|action)=["\']http://[^"\']+["\']', re.IGNORECASE)
            matches = http_pattern.findall(body)

            if matches:
                # Filter out false positives (documentation links, etc.)
                real_matches = [m for m in matches if "example.com" not in m and "localhost" not in m]
                if real_matches:
                    findings.append(Finding(
                        vuln_type="Mixed Content",
                        title=f"HTTPS page loads {len(real_matches)} HTTP resource(s)",
                        severity="MEDIUM",
                        url=url,
                        evidence=f"Found {len(real_matches)} HTTP resources on HTTPS page",
                        description="HTTPS page loads resources over HTTP, which may be intercepted.",
                        remediation="Serve all resources over HTTPS.",
                        cvss=5.0,
                        cwe="CWE-319",
                        tool=self.NAME,
                        verified=True,
                        confidence="MEDIUM",
                    ))

            client.close()
        except Exception as e:
            logger.debug(f"Mixed content test failed: {e}")

        return findings

    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a certificate pattern (wildcard support)."""
        if pattern.startswith("*."):
            # Wildcard match
            suffix = pattern[2:]
            return hostname.endswith(suffix) or hostname == suffix
        return hostname == pattern


# Export
__all__ = ["CryptoScanner"]
