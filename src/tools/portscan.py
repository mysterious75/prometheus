"""Port Scanner Wrapper — network port scanning.

Falls back to Python socket-based scanning if nmap/naabu are not installed.
"""

import time
import socket
from typing import List, Dict, Any, Optional

from .base import BaseTool, ToolResult
from ..core.logger import logger


class PortScanner(BaseTool):
    """Wrapper around nmap/naabu for port scanning."""

    name = "nmap"
    binary = "nmap"
    description = "Network port scanning and service detection"

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432,
        5900, 6379, 8000, 8080, 8443, 8888, 9090, 9200, 27017,
    ]

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Scan ports on a target."""
        ports = kwargs.get("ports", None)
        top_ports = kwargs.get("top_ports", 100)

        if not self.installed:
            return self._fallback_scan(target, ports=ports)

        cmd = ["nmap", "-sV", "--open", "-oX", "-", target]
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        else:
            cmd.extend([f"--top-ports={top_ports}"])

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        duration = time.time() - start

        findings = self._parse_nmap_xml(result.stdout) if result.returncode == 0 else []

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output."""
        import re
        findings = []
        # Simple regex parsing (avoid XML dependency)
        port_blocks = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?/>'
            r'(?:.*?<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)")?',
            xml_output, re.DOTALL
        )
        for protocol, port, state, service, product, version in port_blocks:
            if state == "open":
                findings.append({
                    "type": "open_port",
                    "port": int(port),
                    "protocol": protocol,
                    "service": service or "unknown",
                    "product": product or "",
                    "version": version or "",
                })
        return findings

    def _fallback_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> ToolResult:
        """Fallback: Python socket-based port scanning."""
        scan_ports = ports or self.COMMON_PORTS
        findings = []
        start = time.time()

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error=f"DNS resolution failed: {e}",
                duration=time.time() - start,
            )

        for port in scan_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Try to grab banner
                    banner = ""
                    try:
                        sock.settimeout(2)
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass

                    service = self._guess_service(port)
                    findings.append({
                        "type": "open_port",
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "banner": banner[:200] if banner else "",
                    })
                sock.close()
            except Exception:
                continue

        duration = time.time() - start
        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )

    @staticmethod
    def _guess_service(port: int) -> str:
        """Guess service name from port number."""
        _map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
            143: "imap", 443: "https", 445: "smb", 993: "imaps",
            995: "pop3s", 1433: "mssql", 1521: "oracle", 3000: "dev",
            3306: "mysql", 3389: "rdp", 5000: "docker", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
            8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
            27017: "mongodb",
        }
        return _map.get(port, "unknown")
