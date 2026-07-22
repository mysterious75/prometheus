"""Extended Hacker Tools - All red team/white team tools."""

import subprocess
import shutil
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..utils.logger import logger
from ..platform import detector


@dataclass
class ToolInfo:
    name: str
    category: str
    description: str
    install_cmd: str
    platform: str  # all, linux, windows, macos
    use_case: str


# Complete tool database
ALL_TOOLS = {
    # === RECONNAISSANCE ===
    "nmap": ToolInfo(
        name="nmap", category="recon",
        description="Network scanner - port scan, service detection, OS fingerprint",
        install_cmd="apt install nmap" if detector.info.os.value != "windows" else "choco install nmap",
        platform="all",
        use_case="Port scanning, service enumeration, OS detection"
    ),
    "masscan": ToolInfo(
        name="masscan", category="recon",
        description="Fastest port scanner (10M packets/sec)",
        install_cmd="apt install masscan",
        platform="linux",
        use_case="Ultra-fast port scanning of large networks"
    ),
    "subfinder": ToolInfo(
        name="subfinder", category="recon",
        description="Fast passive subdomain enumeration",
        install_cmd="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        platform="all",
        use_case="Discover all subdomains of a target"
    ),
    "amass": ToolInfo(
        name="amass", category="recon",
        description="In-depth attack surface mapping",
        install_cmd="go install github.com/owasp-amass/amass/v4/...@master",
        platform="all",
        use_case="Comprehensive subdomain discovery"
    ),
    "httpx": ToolInfo(
        name="httpx", category="recon",
        description="Fast HTTP toolkit - probe, scan, fingerprint",
        install_cmd="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        platform="all",
        use_case="HTTP probing, technology detection"
    ),
    "naabu": ToolInfo(
        name="naabu", category="recon",
        description="Fast port scanner written in Go",
        install_cmd="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        platform="all",
        use_case="SYN port scanning"
    ),
    "dnsx": ToolInfo(
        name="dnsx", category="recon",
        description="DNS toolkit with multiple resolver support",
        install_cmd="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        platform="all",
        use_case="DNS enumeration, brute-forcing"
    ),
    "uncover": ToolInfo(
        name="uncover", category="recon",
        description="Discover hosts from multiple search engines",
        install_cmd="go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
        platform="all",
        use_case="Shodan, Censys, FOFA discovery"
    ),
    "katana": ToolInfo(
        name="katana", category="recon",
        description="Next-gen crawling and spidering",
        install_cmd="go install github.com/projectdiscovery/katana/cmd/katana@latest",
        platform="all",
        use_case="Web crawling, URL discovery"
    ),

    # === VULNERABILITY SCANNING ===
    "nuclei": ToolInfo(
        name="nuclei", category="vuln_scan",
        description="Fast vulnerability scanner with templates",
        install_cmd="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        platform="all",
        use_case="CVE scanning, misconfiguration detection"
    ),
    "nikto": ToolInfo(
        name="nikto", category="vuln_scan",
        description="Web server scanner",
        install_cmd="apt install nikto",
        platform="linux",
        use_case="Web server vulnerabilities, dangerous files"
    ),
    "wapiti": ToolInfo(
        name="wapiti", category="vuln_scan",
        description="Web application vulnerability scanner",
        install_cmd="apt install wapiti",
        platform="linux",
        use_case="XSS, SQLi, file inclusion"
    ),
    "wapiti3": ToolInfo(
        name="wapiti3", category="vuln_scan",
        description="Wapiti 3 (Python 3 version)",
        install_cmd="pip install wapiti3",
        platform="all",
        use_case="Web app vulnerability scanning"
    ),

    # === SQL INJECTION ===
    "sqlmap": ToolInfo(
        name="sqlmap", category="sqli",
        description="Automatic SQL injection tool",
        install_cmd="apt install sqlmap",
        platform="linux",
        use_case="SQL injection detection and exploitation"
    ),

    # === DIRECTORY DISCOVERY ===
    "ffuf": ToolInfo(
        name="ffuf", category="dir",
        description="Fast web fuzzer",
        install_cmd="go install github.com/ffuf/ffuf/v2@latest",
        platform="all",
        use_case="Directory/file brute-forcing"
    ),
    "gobuster": ToolInfo(
        name="gobuster", category="dir",
        description="Directory/file brute-forcer",
        install_cmd="apt install gobuster",
        platform="linux",
        use_case="URI/DNS/S3 brute-forcing"
    ),
    "dirsearch": ToolInfo(
        name="dirsearch", category="dir",
        description="Web path scanner",
        install_cmd="pip install dirsearch",
        platform="all",
        use_case="Directory and file brute-forcing"
    ),
    "feroxbuster": ToolInfo(
        name="feroxbuster", category="dir",
        description="Fast, recursive content discovery tool (Rust)",
        install_cmd="cargo install feroxbuster",
        platform="linux",
        use_case="Recursive directory discovery"
    ),

    # === EXPLOITATION ===
    "metasploit": ToolInfo(
        name="msfconsole", category="exploit",
        description="Metasploit Framework - exploitation platform",
        install_cmd="apt install metasploit-framework",
        platform="linux",
        use_case="Exploit development and execution"
    ),
    "searchsploit": ToolInfo(
        name="searchsploit", category="exploit",
        description="Exploit-DB search tool",
        install_cmd="apt install exploitdb",
        platform="linux",
        use_case="Search 40k+ public exploits"
    ),

    # === WIRELESS ===
    "aircrack-ng": ToolInfo(
        name="aircrack-ng", category="wireless",
        description="WiFi security auditing tools",
        install_cmd="apt install aircrack-ng",
        platform="linux",
        use_case="WiFi cracking, packet capture"
    ),
    "wifite": ToolInfo(
        name="wifite", category="wireless",
        description="Automated wireless attack tool",
        install_cmd="apt install wifite",
        platform="linux",
        use_case="Automated WiFi attacks"
    ),

    # === PASSWORD ATTACKS ===
    "hashcat": ToolInfo(
        name="hashcat", category="password",
        description="Advanced password recovery utility",
        install_cmd="apt install hashcat",
        platform="linux",
        use_case="GPU password cracking"
    ),
    "john": ToolInfo(
        name="john", category="password",
        description="John the Ripper password cracker",
        install_cmd="apt install john",
        platform="linux",
        use_case="Password hash cracking"
    ),
    "hydra": ToolInfo(
        name="hydra", category="password",
        description="Network login cracker",
        install_cmd="apt install hydra",
        platform="linux",
        use_case="Brute-force login attacks"
    ),

    # === WEB ===
    "whatweb": ToolInfo(
        name="whatweb", category="web",
        description="Web technology fingerprinter",
        install_cmd="apt install whatweb",
        platform="linux",
        use_case="Identify web technologies"
    ),
    "wpscan": ToolInfo(
        name="wpscan", category="web",
        description="WordPress security scanner",
        install_cmd="gem install wpscan",
        platform="linux",
        use_case="WordPress vulnerability scanning"
    ),
    "droopescan": ToolInfo(
        name="droopescan", category="web",
        description="CMS scanner (Drupal, SilverStripe, Joomla)",
        install_cmd="pip install droopescan",
        platform="all",
        use_case="CMS vulnerability scanning"
    ),
    "gau": ToolInfo(
        name="gau", category="web",
        description="Get All URLs from AlienVault OTX, Wayback, Common Crawl",
        install_cmd="go install github.com/lc/gau/v2/cmd/gau@latest",
        platform="all",
        use_case="URL harvesting"
    ),
    "waybackurls": ToolInfo(
        name="waybackurls", category="web",
        description="Fetch URLs from Wayback Machine",
        install_cmd="go install github.com/tomnomnom/waybackurls@latest",
        platform="all",
        use_case="Historical URL discovery"
    ),

    # === SOCIAL ENGINEERING ===
    "set": ToolInfo(
        name="setoolkit", category="social",
        description="Social Engineering Toolkit",
        install_cmd="apt install set",
        platform="linux",
        use_case="Phishing, credential harvesting"
    ),

    # === POST EXPLOITATION ===
    "linpeas": ToolInfo(
        name="linpeas", category="post_exploit",
        description="Linux Privilege Escalation Awesome Script",
        install_cmd="curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh",
        platform="linux",
        use_case="Find privilege escalation vectors"
    ),
    "winpeas": ToolInfo(
        name="winpeas", category="post_exploit",
        description="Windows Privilege Escalation Awesome Script",
        install_cmd="https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat",
        platform="windows",
        use_case="Find Windows privesc vectors"
    ),

    # === PROXY / INTERCEPT ===
    "burpsuite": ToolInfo(
        name="burpsuite", category="proxy",
        description="Web vulnerability scanner and proxy",
        install_cmd="apt install burpsuite",
        platform="linux",
        use_case="HTTP proxy, intercept, scan"
    ),
    "mitmproxy": ToolInfo(
        name="mitmproxy", category="proxy",
        description="Interactive HTTPS proxy",
        install_cmd="apt install mitmproxy",
        platform="linux",
        use_case="Traffic interception and modification"
    ),

    # === FOOTPRINTING ===
    "theHarvester": ToolInfo(
        name="theHarvester", category="footprint",
        description="Email, subdomain, IP harvester",
        install_cmd="apt install theharvester",
        platform="linux",
        use_case="OSINT email and domain gathering"
    ),
    "recon-ng": ToolInfo(
        name="recon-ng", category="footprint",
        description="Full-featured web reconnaissance framework",
        install_cmd="apt install recon-ng",
        platform="linux",
        use_case="Modular OSINT framework"
    ),
}


class HackerTools:
    """Extended hacker tool manager."""

    def __init__(self):
        self.tools = ALL_TOOLS
        self.installed_cache: Dict[str, bool] = {}

    def is_installed(self, tool_name: str) -> bool:
        """Check if tool is installed."""
        if tool_name in self.installed_cache:
            return self.installed_cache[tool_name]

        # Check common names
        names_to_check = [tool_name]
        if tool_name == "john":
            names_to_check.append("john-the-ripper")
        if tool_name == "set":
            names_to_check.append("setoolkit")

        for name in names_to_check:
            if shutil.which(name):
                self.installed_cache[tool_name] = True
                return True

        self.installed_cache[tool_name] = False
        return False

    def get_category(self, category: str) -> List[ToolInfo]:
        """Get all tools in a category."""
        return [t for t in self.tools.values() if t.category == category]

    def get_missing(self) -> List[ToolInfo]:
        """Get all missing tools."""
        return [t for t in self.tools.values() if not self.is_installed(t.name)]

    def get_installed(self) -> List[ToolInfo]:
        """Get all installed tools."""
        return [t for t in self.tools.values() if self.is_installed(t.name)]

    def get_categories(self) -> Dict[str, int]:
        """Get tool count per category."""
        cats = {}
        for tool in self.tools.values():
            cats[tool.category] = cats.get(tool.category, 0) + 1
        return cats

    def print_status(self):
        """Print complete tool status."""
        categories = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)

        print(f"\n  Hacker Tools Database ({len(self.tools)} tools)")
        print(f"  {'=' * 55}")

        for cat, tools in sorted(categories.items()):
            print(f"\n  [{cat.upper()}]")
            for tool in tools:
                installed = self.is_installed(tool.name)
                icon = "[OK]" if installed else "[--]"
                plat = f" ({tool.platform})" if tool.platform != "all" else ""
                print(f"    {icon} {tool.name:18s} {tool.description[:40]}{plat}")

        installed_count = len(self.get_installed())
        print(f"\n  {'=' * 55}")
        print(f"  Installed: {installed_count}/{len(self.tools)}")
        print(f"  Missing: {len(self.tools) - installed_count}")

    def get_install_script(self) -> str:
        """Generate install script for all missing tools."""
        missing = self.get_missing()
        lines = ["#!/bin/bash", "# Auto-generated install script", ""]

        for tool in missing:
            if tool.platform in ("all", "linux"):
                lines.append(f"# {tool.name}: {tool.description}")
                lines.append(tool.install_cmd)
                lines.append("")

        return "\n".join(lines)
