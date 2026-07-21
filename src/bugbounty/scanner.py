"""Vulnerability Scanner - Uses Nuclei for real scanning."""

import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..utils.logger import logger


class VulnerabilityScanner:
    """Vulnerability scanner using Nuclei + custom checks."""

    def __init__(self, target: str, output_dir: str = "./output/bugbounty"):
        self.target = target
        self.output_dir = Path(output_dir) / target
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Dict] = []
        self.nuclei_available = shutil.which("nuclei") is not None

    def _run_cmd(self, cmd: List[str], timeout: int = 600) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return ""

    def nuclei_scan(self, severity: str = "critical,high,medium") -> List[Dict]:
        """Run Nuclei vulnerability scanner."""
        if not self.nuclei_available:
            logger.warning("[!] Nuclei not installed. Skipping nuclei scan.")
            return []

        logger.info(f"[*] Running Nuclei scan on {self.target}")
        output_file = self.output_dir / "nuclei_results.json"

        # Run nuclei
        cmd = [
            "nuclei",
            "-u", f"https://{self.target}",
            "-severity", severity,
            "-json",
            "-o", str(output_file),
            "-silent"
        ]

        logger.info(f"  Command: {' '.join(cmd)}")
        self._run_cmd(cmd, timeout=600)

        # Parse results
        findings = []
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    try:
                        item = json.loads(line)
                        finding = {
                            "type": item.get("info", {}).get("name", "Unknown"),
                            "severity": item.get("info", {}).get("severity", "unknown").title(),
                            "url": item.get("matched-at", item.get("host", "")),
                            "description": item.get("info", {}).get("description", ""),
                            "recommendation": item.get("info", {}).get("remediation", ""),
                            "template_id": item.get("template-id", ""),
                            "cwe": item.get("info", {}).get("classification", {}).get("cwe", []),
                            "source": "nuclei"
                        }
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass

        logger.info(f"[green]Nuclei: {len(findings)} vulnerabilities found[/green]")
        self.findings.extend(findings)
        return findings

    def check_security_headers(self, url: str) -> List[Dict]:
        """Check for missing security headers."""
        logger.info(f"[*] Checking security headers for {url}")

        try:
            import requests
            response = requests.get(url, timeout=10, verify=False)

            security_headers = {
                "Strict-Transport-Security": "HSTS not set",
                "X-Content-Type-Options": "Content-Type sniffing not prevented",
                "X-Frame-Options": "Clickjacking protection missing",
                "X-XSS-Protection": "XSS filter not enabled",
                "Content-Security-Policy": "CSP not set",
                "Referrer-Policy": "Referrer policy not set",
                "Permissions-Policy": "Permissions policy not set"
            }

            findings = []
            for header, description in security_headers.items():
                if header.lower() not in [h.lower() for h in response.headers.keys()]:
                    finding = {
                        "type": "Missing Security Header",
                        "severity": "Medium",
                        "url": url,
                        "header": header,
                        "description": description,
                        "recommendation": f"Add {header} header",
                        "source": "header_check"
                    }
                    findings.append(finding)
                    logger.warning(f"  [!] Missing: {header}")

            self.findings.extend(findings)
            return findings

        except Exception as e:
            logger.error(f"[red]Header check failed: {e}[/red]")
            return []

    def check_information_disclosure(self, url: str) -> List[Dict]:
        """Check for information disclosure."""
        logger.info(f"[*] Checking information disclosure for {url}")

        try:
            import requests
            findings = []

            response = requests.get(url, timeout=10, verify=False)
            server = response.headers.get("Server", "")
            if server and any(v in server.lower() for v in ["apache", "nginx", "iis", "php"]):
                finding = {
                    "type": "Server Header Disclosure",
                    "severity": "Low",
                    "url": url,
                    "description": f"Server header reveals: {server}",
                    "recommendation": "Remove or obscure Server header",
                    "source": "info_disclosure"
                }
                findings.append(finding)

            sensitive_paths = [
                "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
                "/wp-admin", "/phpmyadmin", "/.htaccess", "/server-status",
                "/.DS_Store", "/backup", "/config", "/debug"
            ]

            for path in sensitive_paths:
                try:
                    resp = requests.get(f"{url}{path}", timeout=5, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        finding = {
                            "type": "Sensitive Path Accessible",
                            "severity": "Medium",
                            "url": f"{url}{path}",
                            "status_code": resp.status_code,
                            "description": f"Sensitive path accessible: {path}",
                            "recommendation": f"Restrict access to {path}",
                            "source": "info_disclosure"
                        }
                        findings.append(finding)
                        logger.warning(f"  [!] Accessible: {path}")
                except Exception:
                    pass

            self.findings.extend(findings)
            return findings

        except Exception as e:
            logger.error(f"[red]Info disclosure check failed: {e}[/red]")
            return []

    def run_all_checks(self, url: str) -> List[Dict]:
        """Run all vulnerability checks."""
        logger.info(f"[bold blue]Running all checks on {url}[/bold blue]")

        # Nuclei scan (real vulnerabilities)
        self.nuclei_scan()

        # Header checks
        self.check_security_headers(url)

        # Info disclosure
        self.check_information_disclosure(url)

        # Save findings
        findings_file = self.output_dir / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(self.findings, f, indent=2)

        logger.info(f"[green]Found {len(self.findings)} total issues[/green]")
        return self.findings

    def generate_summary(self) -> Dict:
        """Generate a summary of findings."""
        summary = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.get("severity", "").lower() == "critical"]),
            "high": len([f for f in self.findings if f.get("severity", "").lower() == "high"]),
            "medium": len([f for f in self.findings if f.get("severity", "").lower() == "medium"]),
            "low": len([f for f in self.findings if f.get("severity", "").lower() == "low"]),
            "nuclei_findings": len([f for f in self.findings if f.get("source") == "nuclei"]),
            "findings": self.findings
        }

        summary_file = self.output_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        return summary
