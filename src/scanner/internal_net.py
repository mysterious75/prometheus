"""Internal Network Scanner — SMB, LDAP, Kerberos, AD attack paths.

For internal network pentesting when you have network access.
"""

import subprocess
import socket
import re
import time
from typing import List, Dict, Any
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter
from ..scanner.findings import Finding


class InternalNetworkScanner:
    """Internal network security testing."""

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_smb(self, target: str) -> List[Finding]:
        """Scan for SMB vulnerabilities."""
        findings = []
        console.print(f"  [tool]▸ SMB Scan[/tool] → [target]{target}[/target]")

        # Check SMB signing
        findings.extend(self._check_smb_signing(target))

        # Check null sessions
        findings.extend(self._check_null_session(target))

        # Check SMBv1
        findings.extend(self._check_smbv1(target))

        console.print(f"  [tool]◂ SMB[/tool] — {len(findings)} findings")
        return findings

    def _check_smb_signing(self, target: str) -> List[Finding]:
        """Check if SMB signing is required."""
        findings = []
        try:
            import shutil
            if shutil.which("nmap"):
                cmd = ["nmap", "-p", "445", "--script", "smb2-security-mode", target]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if "message signing enabled but not required" in proc.stdout.lower():
                    findings.append(Finding(
                        vuln_type="SMB Signing Not Required",
                        title="SMB signing is enabled but not required",
                        severity="MEDIUM",
                        url=target,
                        evidence="Message signing enabled but not required",
                        description="SMB signing not required allows man-in-the-middle attacks.",
                        remediation="Require SMB signing on all hosts via Group Policy.",
                        cvss=5.3,
                        cwe="CWE-319",
                        tool="smb",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass
        return findings

    def _check_null_session(self, target: str) -> List[Finding]:
        """Check for null session access."""
        findings = []
        try:
            import shutil
            if shutil.which("enum4linux"):
                cmd = ["enum4linux", "-a", target]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if "null session" in proc.stdout.lower() or "allowed" in proc.stdout.lower():
                    findings.append(Finding(
                        vuln_type="SMB Null Session",
                        title="Null session access allowed on SMB",
                        severity="HIGH",
                        url=target,
                        evidence="Null session enumeration successful",
                        description="Null session allows unauthenticated enumeration of users, shares, and policies.",
                        remediation="Disable null session access. Restrict anonymous enumeration.",
                        cvss=7.5,
                        cwe="CWE-287",
                        tool="smb",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass
        return findings

    def _check_smbv1(self, target: str) -> List[Finding]:
        """Check for SMBv1 (EternalBlue risk)."""
        findings = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if sock.connect_ex((target, 445)) == 0:
                # Try to negotiate SMBv1
                smb_negotiate = bytes.fromhex(
                    "00000085ff534d4272000000001853c00000000000000000000000000000fffe00000000"
                    "006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e"
                    "30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e"
                    "325830303200024c414e4d414e322e3100024e54204c4d20302e313200"
                )
                sock.send(smb_negotiate)
                resp = sock.recv(1024)
                if resp and len(resp) > 0:
                    findings.append(Finding(
                        vuln_type="SMBv1 Enabled",
                        title="SMBv1 protocol is enabled (EternalBlue risk)",
                        severity="HIGH",
                        url=target,
                        port=445,
                        evidence="SMBv1 negotiation accepted",
                        description="SMBv1 is vulnerable to EternalBlue (MS17-010) and other attacks.",
                        remediation="Disable SMBv1 on all systems. Use SMBv2 or SMBv3.",
                        cvss=8.1,
                        cwe="CWE-327",
                        tool="smb",
                        verified=True,
                        confidence="MEDIUM",
                    ))
            sock.close()
        except Exception:
            pass
        return findings

    def scan_ldap(self, target: str) -> List[Finding]:
        """Scan for LDAP vulnerabilities."""
        findings = []
        console.print(f"  [tool]▸ LDAP Scan[/tool] → [target]{target}[/target]")

        # Check for anonymous LDAP bind
        try:
            import shutil
            if shutil.which("nmap"):
                cmd = ["nmap", "-p", "389", "--script", "ldap-search", target]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if "anonymous" in proc.stdout.lower():
                    findings.append(Finding(
                        vuln_type="Anonymous LDAP Bind",
                        title="Anonymous LDAP bind allowed",
                        severity="MEDIUM",
                        url=target,
                        port=389,
                        evidence="Anonymous LDAP bind successful",
                        description="Anonymous LDAP allows enumeration of directory objects.",
                        remediation="Require authentication for LDAP binds.",
                        cvss=5.3,
                        cwe="CWE-287",
                        tool="ldap",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass

        console.print(f"  [tool]◂ LDAP[/tool] — {len(findings)} findings")
        return findings

    def scan_kerberos(self, target: str) -> List[Finding]:
        """Scan for Kerberos vulnerabilities (Kerberoasting, AS-REP Roasting)."""
        findings = []
        console.print(f"  [tool]▸ Kerberos Scan[/tool] → [target]{target}[/target]")

        # Check for Kerberoastable accounts
        try:
            import shutil
            if shutil.which("impacket-GetUserSPNs"):
                cmd = ["impacket-GetUserSPNs", f"domain/user:pass@{target}", "-request"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if "$krb5tgs$" in proc.stdout:
                    findings.append(Finding(
                        vuln_type="Kerberoastable Accounts",
                        title="Kerberoastable service accounts found",
                        severity="HIGH",
                        url=target,
                        evidence="Kerberoast hash extracted",
                        description="Service accounts with SPNs can be Kerberoasted to extract password hashes.",
                        remediation="Use managed service accounts. Set strong passwords (25+ chars).",
                        cvss=7.5,
                        cwe="CWE-262",
                        tool="kerberos",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass

        # Check for AS-REP Roastable accounts
        try:
            if shutil.which("impacket-GetNPUsers"):
                cmd = ["impacket-GetNPUsers", f"domain/user:pass@{target}", "-request"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if "$krb5asrep$" in proc.stdout:
                    findings.append(Finding(
                        vuln_type="AS-REP Roastable Accounts",
                        title="AS-REP Roastable accounts found",
                        severity="HIGH",
                        url=target,
                        evidence="AS-REP hash extracted",
                        description="Accounts without pre-authentication can be roasted offline.",
                        remediation="Enable Kerberos pre-authentication for all accounts.",
                        cvss=7.5,
                        cwe="CWE-262",
                        tool="kerberos",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass

        console.print(f"  [tool]◂ Kerberos[/tool] — {len(findings)} findings")
        return findings

    def scan_network_shares(self, target: str) -> List[Finding]:
        """Scan for exposed network shares."""
        findings = []
        console.print(f"  [tool]▸ Network Shares[/tool] → [target]{target}[/target]")

        try:
            import shutil
            if shutil.which("smbclient"):
                cmd = ["smbclient", "-L", f"//{target}", "-N"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                shares = re.findall(r'(\S+)\s+Disk', proc.stdout)
                if shares:
                    findings.append(Finding(
                        vuln_type="Exposed Network Shares",
                        title=f"Accessible shares found: {', '.join(shares)}",
                        severity="MEDIUM",
                        url=target,
                        evidence=f"Shares: {', '.join(shares)}",
                        description="Network shares are accessible without authentication.",
                        remediation="Restrict share access. Remove unnecessary shares.",
                        cvss=5.3,
                        cwe="CWE-284",
                        tool="smb",
                        verified=True,
                        confidence="HIGH",
                    ))
        except Exception:
            pass

        console.print(f"  [tool]◂ Shares[/tool] — {len(findings)} findings")
        return findings

    def full_internal_scan(self, target: str) -> List[Finding]:
        """Run all internal network scans."""
        findings = []
        findings.extend(self.scan_smb(target))
        findings.extend(self.scan_ldap(target))
        findings.extend(self.scan_kerberos(target))
        findings.extend(self.scan_network_shares(target))
        return findings
