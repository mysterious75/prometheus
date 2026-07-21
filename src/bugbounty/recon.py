"""Reconnaissance Pipeline - Uses real bug bounty tools (Kali Linux)."""

import subprocess
import json
import shutil
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

from ..utils.logger import logger


class ReconPipeline:
    """Automated recon using subfinder, httpx, naabu."""

    def __init__(self, target: str, output_dir: str = "./output/bugbounty"):
        self.target = target
        self.output_dir = Path(output_dir) / target
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.tools = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are installed."""
        tools = {}
        for tool in ["nuclei", "subfinder", "httpx", "naabu", "katana", "gau", "waybackurls", "ffuf"]:
            tools[tool] = shutil.which(tool) is not None
        return tools

    def _run_cmd(self, cmd: List[str], timeout: int = 300) -> str:
        """Run a shell command and return output."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            return ""
        except FileNotFoundError:
            logger.warning(f"Tool not found: {cmd[0]}")
            return ""
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return ""

    def subdomain_enum(self) -> str:
        """Phase 1: Subdomain enumeration using subfinder."""
        logger.info(f"[*] Enumerating subdomains for {self.target}")
        output_file = self.output_dir / "subdomains.txt"

        if self.tools.get("subfinder"):
            # Use real subfinder
            logger.info("  Using subfinder...")
            output = self._run_cmd([
                "subfinder", "-d", self.target, "-silent", "-o", str(output_file)
            ])
            with open(output_file, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            logger.info(f"[green]Subfinder: {len(subdomains)} subdomains found[/green]")
        else:
            # Fallback: DNS brute force
            logger.info("  subfinder not found, using DNS fallback...")
            import socket
            common = [
                "www", "mail", "ftp", "smtp", "api", "dev", "staging",
                "admin", "test", "beta", "app", "cdn", "blog", "shop",
                "portal", "vpn", "webmail", "cpanel", "ns1", "ns2"
            ]
            subdomains = []
            for sub in common:
                try:
                    hostname = f"{sub}.{self.target}"
                    ip = socket.gethostbyname(hostname)
                    subdomains.append(f"{hostname}")
                    logger.info(f"  [+] {hostname} -> {ip}")
                except socket.gaierror:
                    pass
            with open(output_file, "w") as f:
                f.write("\n".join(subdomains))

        self.results["subdomains"] = subdomains
        return str(output_file)

    def port_scan(self) -> str:
        """Phase 2: Port scanning using naabu."""
        logger.info(f"[*] Scanning ports on {self.target}")
        output_file = self.output_dir / "ports.txt"

        if self.tools.get("naabu"):
            # Use real naabu
            logger.info("  Using naabu...")
            self._run_cmd([
                "naabu", "-host", self.target, "-silent",
                "-o", str(output_file)
            ])
            with open(output_file, "r") as f:
                ports = [line.strip() for line in f if line.strip()]
            logger.info(f"[green]Naabu: {len(ports)} open ports found[/green]")
        else:
            # Fallback: socket scan common ports
            logger.info("  naabu not found, using socket fallback...")
            import socket
            common_ports = [80, 443, 8080, 8443, 3000, 5000, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 27017]
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((self.target, port)) == 0:
                        open_ports.append(str(port))
                    sock.close()
                except Exception:
                    pass
            with open(output_file, "w") as f:
                f.write("\n".join(open_ports))
            ports = open_ports

        self.results["ports"] = ports
        return str(output_file)

    def http_probe(self) -> str:
        """Phase 3: HTTP probing using httpx."""
        logger.info(f"[*] Probing HTTP services on {self.target}")
        output_file = self.output_dir / "http_services.json"

        if self.tools.get("httpx") and self.results.get("subdomains"):
            # Use real httpx
            logger.info("  Using httpx...")
            subdomains_file = self.output_dir / "subdomains.txt"
            self._run_cmd([
                "httpx", "-l", str(subdomains_file),
                "-silent", "-json", "-o", str(output_file)
            ])
            services = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        try:
                            services.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        else:
            # Fallback: requests probe
            logger.info("  httpx not found, using requests fallback...")
            import requests
            services = []
            ports = self.results.get("ports", ["80", "443"])
            for port in ports:
                for scheme in ["http", "https"]:
                    url = f"{scheme}://{self.target}:{port}"
                    try:
                        resp = requests.get(url, timeout=5, verify=False)
                        services.append({
                            "url": url,
                            "status_code": resp.status_code,
                            "title": self._extract_title(resp.text),
                            "server": resp.headers.get("Server", "Unknown")
                        })
                        logger.info(f"  [+] {url} -> {resp.status_code}")
                    except Exception:
                        pass
            with open(output_file, "w") as f:
                json.dump(services, f, indent=2)

        logger.info(f"[green]Found {len(services)} HTTP services[/green]")
        self.results["http_services"] = services
        return str(output_file)

    def url_discovery(self) -> str:
        """Phase 4: URL discovery using gau + waybackurls."""
        logger.info(f"[*] Discovering URLs for {self.target}")
        output_file = self.output_dir / "urls.txt"

        urls = set()

        if self.tools.get("gau"):
            logger.info("  Using gau...")
            output = self._run_cmd(["gau", self.target])
            for url in output.split("\n"):
                if url.strip():
                    urls.add(url.strip())

        if self.tools.get("waybackurls"):
            logger.info("  Using waybackurls...")
            output = self._run_cmd(["waybackurls", self.target])
            for url in output.split("\n"):
                if url.strip():
                    urls.add(url.strip())

        with open(output_file, "w") as f:
            f.write("\n".join(sorted(urls)))

        logger.info(f"[green]Found {len(urls)} unique URLs[/green]")
        self.results["urls"] = list(urls)
        return str(output_file)

    def crawl_site(self) -> str:
        """Phase 5: Web crawling using katana."""
        logger.info(f"[*] Crawling {self.target}")
        output_file = self.output_dir / "crawled_urls.txt"

        if self.tools.get("katana"):
            logger.info("  Using katana...")
            self._run_cmd([
                "katana", "-u", f"https://{self.target}",
                "-silent", "-o", str(output_file)
            ])
            with open(output_file) as f:
                urls = [line.strip() for line in f if line.strip()]
        else:
            urls = []
            logger.info("  katana not found, skipping crawl")

        logger.info(f"[green]Crawled {len(urls)} URLs[/green]")
        self.results["crawled_urls"] = urls
        return str(output_file)

    def full_recon(self) -> Dict:
        """Execute full recon pipeline."""
        logger.info(f"[bold blue]Starting full recon for {self.target}[/bold blue]")

        # Available tools summary
        available = [t for t, v in self.tools.items() if v]
        missing = [t for t, v in self.tools.items() if not v]
        logger.info(f"  Tools available: {available}")
        if missing:
            logger.warning(f"  Tools missing: {missing} (will use fallback)")

        # Run phases
        self.subdomain_enum()
        self.port_scan()
        self.http_probe()

        # Advanced phases (if tools available)
        if any([self.tools.get("gau"), self.tools.get("waybackurls")]):
            self.url_discovery()
        if self.tools.get("katana"):
            self.crawl_site()

        # Save summary
        summary = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "tools_used": available,
            "tools_missing": missing,
            "results": {
                "subdomains": len(self.results.get("subdomains", [])),
                "ports": len(self.results.get("ports", [])),
                "http_services": len(self.results.get("http_services", [])),
                "urls": len(self.results.get("urls", [])),
                "crawled_urls": len(self.results.get("crawled_urls", []))
            }
        }

        summary_file = self.output_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"[bold green]Recon complete! Results in {self.output_dir}[/bold green]")
        return summary

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No title"
