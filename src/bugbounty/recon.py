"""Reconnaissance Pipeline for Bug Bounty."""

import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

from ..utils.logger import logger


class ReconPipeline:
    """Automated reconnaissance pipeline."""

    def __init__(self, target: str, output_dir: str = "./output/bugbounty"):
        self.target = target
        self.output_dir = Path(output_dir) / target
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}

    def subdomain_enum(self) -> str:
        """Phase 1: Subdomain enumeration."""
        logger.info(f"[*] Enumerating subdomains for {self.target}")
        output_file = self.output_dir / "subdomains.txt"

        try:
            # Try subdomain enumeration via DNS
            import socket
            common_subdomains = [
                "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
                "dns", "webmail", "cpanel", "api", "dev", "staging",
                "admin", "test", "beta", "app", "portal", "vpn",
                "cdn", "static", "media", "images", "blog", "shop"
            ]

            found = []
            for sub in common_subdomains:
                try:
                    hostname = f"{sub}.{self.target}"
                    ip = socket.gethostbyname(hostname)
                    found.append(f"{hostname} -> {ip}")
                    logger.info(f"  [+] {hostname} -> {ip}")
                except socket.gaierror:
                    pass

            with open(output_file, "w") as f:
                f.write("\n".join(found) if found else "No subdomains found")

            logger.info(f"[green]Found {len(found)} subdomains[/green]")
            self.results["subdomains"] = found
            return str(output_file)

        except Exception as e:
            logger.error(f"[red]Subdomain enum failed: {e}[/red]")
            return ""

    def port_scan(self, ports: str = "80,443,8080,8443,3000,5000") -> str:
        """Phase 2: Port scanning."""
        logger.info(f"[*] Scanning ports on {self.target}")
        output_file = self.output_dir / "ports.txt"

        try:
            import socket
            open_ports = []

            for port in ports.split(","):
                port = int(port.strip())
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        open_ports.append(port)
                        logger.info(f"  [+] Port {port} is OPEN")
                    sock.close()
                except Exception:
                    pass

            with open(output_file, "w") as f:
                f.write("\n".join(str(p) for p in open_ports) if open_ports else "No open ports found")

            logger.info(f"[green]Found {len(open_ports)} open ports[/green]")
            self.results["ports"] = open_ports
            return str(output_file)

        except Exception as e:
            logger.error(f"[red]Port scan failed: {e}[/red]")
            return ""

    def http_probe(self) -> str:
        """Phase 3: HTTP probing."""
        logger.info(f"[*] Probing HTTP services on {self.target}")
        output_file = self.output_dir / "http_services.txt"]

        try:
            import requests

            services = []
            ports = self.results.get("ports", [80, 443])

            for port in ports:
                for scheme in ["http", "https"]:
                    url = f"{scheme}://{self.target}:{port}"
                    try:
                        response = requests.get(url, timeout=5, verify=False)
                        services.append({
                            "url": url,
                            "status": response.status_code,
                            "title": self._extract_title(response.text),
                            "server": response.headers.get("Server", "Unknown")
                        })
                        logger.info(f"  [+] {url} - Status: {response.status_code}")
                    except requests.exceptions.SSLError:
                        pass
                    except requests.exceptions.ConnectionError:
                        pass

            with open(output_file, "w") as f:
                json.dump(services, f, indent=2)

            logger.info(f"[green]Found {len(services)} HTTP services[/green]")
            self.results["http_services"] = services
            return str(output_file)

        except Exception as e:
            logger.error(f"[red]HTTP probe failed: {e}[/red]")
            return ""

    def _extract_title(self, html: str) -> str:
        """Extract title from HTML."""
        import re
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No title"

    def full_recon(self) -> Dict:
        """Execute full recon pipeline."""
        logger.info(f"[bold blue]Starting full recon for {self.target}[/bold blue]")

        self.subdomain_enum()
        self.port_scan()
        self.http_probe()

        # Save summary
        summary = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "results": self.results
        }

        summary_file = self.output_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"[bold green]Recon complete! Results in {self.output_dir}[/bold green]")
        return summary
