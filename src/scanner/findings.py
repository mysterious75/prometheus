"""Finding model — standardized vulnerability representation.

Every finding must have evidence. No evidence = not a finding.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class Finding:
    """A verified security finding. Evidence is mandatory."""
    id: int = 0
    vuln_type: str = ""
    title: str = ""
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""  # MUST have evidence — proof it's real
    description: str = ""
    remediation: str = ""
    cvss: float = 0.0
    cwe: str = ""
    tool: str = ""
    verified: bool = False  # True only if confirmed
    confidence: str = "LOW"  # LOW, MEDIUM, HIGH, CONFIRMED
    request: str = ""  # full HTTP request for reproduction
    response_snippet: str = ""  # relevant part of response
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "description": self.description,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "tool": self.tool,
            "verified": self.verified,
            "confidence": self.confidence,
            "request": self.request[:500],
            "timestamp": self.timestamp,
        }

    def poc_command(self) -> str:
        """Generate a curl PoC command."""
        if self.method == "GET":
            return f'curl -k "{self.url}"'
        elif self.method == "POST":
            return f'curl -k -X POST "{self.url}" -d "{self.payload}"'
        return f'curl -k "{self.url}"'


@dataclass
class ScanResult:
    """Aggregated scan result."""
    target: str
    findings: List[Finding] = field(default_factory=list)
    crawl: Optional[Any] = None
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def add(self, finding: Finding):
        """Add a finding with auto-incrementing ID."""
        finding.id = len(self.findings) + 1
        self.findings.append(finding)

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def medium(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "MEDIUM"]

    @property
    def low(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "LOW"]

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total": len(self.findings),
            "critical": len(self.critical),
            "high": len(self.high),
            "medium": len(self.medium),
            "low": len(self.low),
            "duration": f"{self.duration:.1f}s",
        }
