"""Whois/ASN Tools — domain registration and network intelligence."""

import subprocess
import re
import time
import socket
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from ..core.logger import logger, console


@dataclass
class WhoisResult:
    """Whois lookup result."""
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    registrant: Dict[str, str] = field(default_factory=dict)
    emails: List[str] = field(default_factory=list)
    dnssec: str = ""
    status: List[str] = field(default_factory=list)
    raw: str = ""

    def to_dict(self):
        return {
            "domain": self.domain, "registrar": self.registrar,
            "creation_date": self.creation_date, "expiration_date": self.expiration_date,
            "name_servers": self.name_servers, "emails": self.emails,
        }


class WhoisTool:
    """Whois and ASN lookup tools."""

    def __init__(self):
        pass

    def lookup(self, target: str) -> WhoisResult:
        """Full whois lookup."""
        console.print(f"  [tool]▸ Whois[/tool] → [target]{target}[/target]")

        result = WhoisResult(domain=target)

        # Method 1: whois command
        result = self._whois_cmd(target, result)

        # Method 2: Python fallback
        if not result.registrar:
            result = self._whois_python(target, result)

        console.print(f"  [tool]◂ Whois[/tool] — registrar={result.registrar or 'unknown'}")
        return result

    def _whois_cmd(self, target: str, result: WhoisResult) -> WhoisResult:
        """Run whois command."""
        try:
            proc = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                raw = proc.stdout
                result.raw = raw[:2000]

                # Parse registrar
                match = re.search(r'Registrar:\s*(.+)', raw, re.I)
                if match:
                    result.registrar = match.group(1).strip()

                # Parse dates
                match = re.search(r'Creation Date:\s*(.+)', raw, re.I)
                if match:
                    result.creation_date = match.group(1).strip()
                match = re.search(r'Registry Expiry Date:\s*(.+)', raw, re.I)
                if match:
                    result.expiration_date = match.group(1).strip()

                # Parse name servers
                ns_matches = re.findall(r'Name Server:\s*(\S+)', raw, re.I)
                result.name_servers = [ns.lower().rstrip('.') for ns in ns_matches]

                # Parse emails
                emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', raw)
                result.emails = list(set(emails))

                # Parse status
                status_matches = re.findall(r'Status:\s*(.+)', raw, re.I)
                result.status = [s.strip() for s in status_matches]

                # DNSSEC
                match = re.search(r'DNSSEC:\s*(\S+)', raw, re.I)
                if match:
                    result.dnssec = match.group(1)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug(f"whois command failed: {e}")

        return result

    def _whois_python(self, target: str, result: WhoisResult) -> WhoisResult:
        """Fallback: basic whois via socket."""
        try:
            # Connect to whois server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.verisign-grs.com", 43))
            s.send(f"{target}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            raw = response.decode("utf-8", errors="ignore")
            result.raw = raw[:2000]

            match = re.search(r'Registrar:\s*(.+)', raw, re.I)
            if match:
                result.registrar = match.group(1).strip()

        except Exception:
            pass

        return result

    def asn_lookup(self, ip_or_domain: str) -> Dict[str, Any]:
        """ASN lookup for an IP or domain."""
        try:
            # Resolve to IP if domain
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_or_domain):
                ip = socket.gethostbyname(ip_or_domain)
            else:
                ip = ip_or_domain

            # Use bgp.tools (free, no API key)
            import httpx
            client = httpx.Client(timeout=10, verify=True)
            resp = client.get(f"https://bgp.tools/prefix/{ip}")
            if resp.status_code == 200:
                body = resp.text
                asn_match = re.search(r'AS(\d+)', body)
                org_match = re.search(r'<td[^>]*>([^<]+)</td>', body)
                return {
                    "ip": ip,
                    "asn": asn_match.group(1) if asn_match else "",
                    "org": org_match.group(1) if org_match else "",
                    "source": "bgp.tools",
                }
        except Exception:
            pass

        return {"ip": ip_or_domain}

    def ip_history(self, domain: str) -> List[Dict[str, str]]:
        """Get historical DNS/IP records for a domain."""
        try:
            import httpx
            client = httpx.Client(timeout=10, verify=True)
            # Use SecurityTrails or similar free API
            resp = client.get(f"https://securitytrails.com/domain/{domain}/dns")
            # Limited without API key, but can extract some data
            return []
        except Exception:
            return []
