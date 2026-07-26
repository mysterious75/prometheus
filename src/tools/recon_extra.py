"""Additional Recon Tools — theHarvester, Photon, Wappalyzer, etc.

Wraps common recon tools with Python fallbacks.
"""

import subprocess
import re
import time
import socket
from typing import List, Dict, Any
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


class ReconTools:
    """Collection of reconnaissance tools."""

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def theharvester(self, domain: str, source: str = "all") -> Dict[str, Any]:
        """Run theHarvester for email and subdomain discovery."""
        import shutil
        if not shutil.which("theHarvester"):
            return self._theharvester_fallback(domain)

        console.print(f"  [tool]▸ theHarvester[/tool] → [target]{domain}[/target]")
        try:
            cmd = ["theHarvester", "-d", domain, "-b", source, "-l", "200"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                emails = re.findall(r'[\w.-]+@[\w.-]+\.' + re.escape(domain), proc.stdout)
                hosts = re.findall(r'[\w.-]+\.' + re.escape(domain), proc.stdout)
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', proc.stdout)
                return {
                    "domain": domain, "emails": list(set(emails)),
                    "hosts": list(set(hosts)), "ips": list(set(ips)),
                }
        except Exception as e:
            logger.debug(f"theHarvester failed: {e}")

        return {"domain": domain}

    def _theharvester_fallback(self, domain: str) -> Dict[str, Any]:
        """Fallback: basic email and host discovery."""
        emails = set()
        hosts = set()

        try:
            import httpx
            client = httpx.Client(timeout=10, verify=ssl_verify())

            # Check website for emails
            resp = client.get(f"https://{domain}")
            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.' + re.escape(domain), resp.text)
            emails.update(found_emails)

            # Check robots.txt
            try:
                resp2 = client.get(f"https://{domain}/robots.txt")
                found_emails2 = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.' + re.escape(domain), resp2.text)
                emails.update(found_emails2)
            except Exception:
                pass

        except Exception:
            pass

        return {"domain": domain, "emails": list(emails), "hosts": list(hosts)}

    def photon_crawl(self, target: str) -> Dict[str, Any]:
        """Run Photon crawler for OSINT."""
        import shutil
        if not shutil.which("photon"):
            return self._photon_fallback(target)

        console.print(f"  [tool]▸ Photon[/tool] → [target]{target}[/target]")
        try:
            cmd = ["photon", "-u", target, "-l", "3", "--stdout"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                urls = re.findall(r'https?://[^\s<>"]+', proc.stdout)
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', proc.stdout)
                return {"target": target, "urls": list(set(urls))[:50], "emails": list(set(emails))}
        except Exception:
            pass

        return {"target": target}

    def _photon_fallback(self, target: str) -> Dict[str, Any]:
        """Fallback: basic crawling."""
        try:
            import httpx
            client = httpx.Client(follow_redirects=True, timeout=10, verify=ssl_verify())
            if not target.startswith("http"):
                target = f"https://{target}"
            resp = client.get(target)
            urls = re.findall(r'href="(https?://[^"]+)"', resp.text)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
            return {"target": target, "urls": list(set(urls))[:30], "emails": list(set(emails))}
        except Exception:
            return {"target": target}

    def wappalyzer_detect(self, url: str) -> Dict[str, Any]:
        """Run Wappalyzer CLI for technology detection."""
        import shutil
        if shutil.which("wappalyzer"):
            try:
                cmd = ["wappalyzer", url, "--json"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode == 0:
                    return json.loads(proc.stdout)
            except Exception:
                pass

        return {"url": url, "note": "wappalyzer not installed, using fingerprint module"}

    def amass_enum(self, domain: str) -> List[str]:
        """Run Amass for subdomain enumeration."""
        import shutil
        if not shutil.which("amass"):
            return []

        console.print(f"  [tool]▸ Amass[/tool] → [target]{domain}[/target]")
        try:
            cmd = ["amass", "enum", "-passive", "-d", domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                subdomains = [line.strip() for line in proc.stdout.strip().split("\n") if line.strip()]
                console.print(f"  [tool]◂ Amass[/tool] — {len(subdomains)} subdomains")
                return subdomains
        except Exception:
            pass

        return []

    def ffuf_fuzz(self, url: str, wordlist: str = "") -> List[Dict[str, Any]]:
        """Run ffuf for directory/path fuzzing."""
        import shutil
        if not shutil.which("ffuf"):
            return []

        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"

        console.print(f"  [tool]▸ ffuf[/tool] → [target]{url}[/target]")
        findings = []
        try:
            cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,301,302,403", "-o", "/dev/stdout", "-of", "json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                try:
                    data = json.loads(proc.stdout)
                    for result in data.get("results", []):
                        findings.append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "word": result.get("input", {}).get("FUZZ", ""),
                        })
                except json.JSONDecodeError:
                    pass

            console.print(f"  [tool]◂ ffuf[/tool] — {len(findings)} paths found")
        except Exception:
            pass

        return findings

    def nikto_scan(self, target: str) -> List[Dict[str, Any]]:
        """Run Nikto web server scanner."""
        import shutil
        if not shutil.which("nikto"):
            return []

        console.print(f"  [tool]▸ Nikto[/tool] → [target]{target}[/target]")
        findings = []
        try:
            cmd = ["nikto", "-h", target, "-Format", "json", "-output", "/dev/stdout"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode == 0:
                try:
                    data = json.loads(proc.stdout)
                    for vuln in data.get("vulnerabilities", []):
                        findings.append({
                            "id": vuln.get("id", ""),
                            "osvdb": vuln.get("OSVDB", ""),
                            "method": vuln.get("method", ""),
                            "url": vuln.get("url", ""),
                            "message": vuln.get("msg", ""),
                        })
                except json.JSONDecodeError:
                    pass

            console.print(f"  [tool]◂ Nikto[/tool] — {len(findings)} findings")
        except Exception:
            pass

        return findings

    def ssl_scan(self, target: str) -> Dict[str, Any]:
        """SSL/TLS certificate analysis."""
        console.print(f"  [tool]▸ SSL Scan[/tool] → [target]{target}[/target]")

        result = {"target": target, "certificates": [], "issues": []}

        try:
            import ssl
            import socket

            hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            port = 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Certificate info
                    result["certificates"].append({
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "version": cert.get("version", ""),
                    })

                    # Check for issues
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        from datetime import datetime
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            if expiry < datetime.now():
                                result["issues"].append("Certificate EXPIRED")
                            elif (expiry - datetime.now()).days < 30:
                                result["issues"].append(f"Certificate expires in {(expiry - datetime.now()).days} days")
                        except Exception:
                            pass

                    # Check SAN
                    san = cert.get("subjectAltName", [])
                    result["san"] = [s[1] for s in san if s[0] == "DNS"]

        except ssl.SSLCertVerificationError as e:
            result["issues"].append(f"SSL verification failed: {e}")
        except Exception as e:
            result["issues"].append(f"SSL check failed: {e}")

        console.print(f"  [tool]◂ SSL[/tool] — {len(result['issues'])} issues")
        return result


import json
from ..core.transport import ssl_verify
