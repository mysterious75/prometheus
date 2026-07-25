"""IDOR Scanner — Insecure Direct Object Reference detection.

Tests for unauthorized access to other users' resources by manipulating IDs.
"""

import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .findings import Finding
from ..core.ratelimit import get_limiter


class IDORScanner:
    """IDOR vulnerability scanner."""

    NAME = "idor"

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        """Test for IDOR by manipulating numeric IDs."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        parsed = urlparse(url)
        test_params = params or {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not test_params:
            return []

        client = httpx.Client(follow_redirects=True, timeout=10, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})

        # Get original response
        try:
            self.limiter.wait(parsed.netloc)
            original = client.get(url)
            original_body = original.text
            original_len = len(original_body)
        except Exception:
            return []

        # Find numeric ID parameters
        for param_name, param_value in test_params.items():
            if not param_value.isdigit():
                continue

            original_id = int(param_value)

            # Test with different IDs
            test_ids = [original_id + 1, original_id - 1, original_id + 100, 1, 2]

            for test_id in test_ids:
                if test_id == original_id or test_id < 0:
                    continue

                test_params_copy = dict(test_params)
                test_params_copy[param_name] = str(test_id)
                test_url = urlunparse(parsed._replace(query=urlencode(test_params_copy)))

                self.limiter.wait(parsed.netloc)
                try:
                    resp = client.get(test_url)

                    # Different ID returns similar content (not 403/404)
                    if (resp.status_code == 200 and
                        abs(len(resp.text) - original_len) < original_len * 0.3 and
                        len(resp.text) > 100):

                        # Check it's not the same user's data
                        if self._different_data(original_body, resp.text):
                            findings.append(Finding(
                                vuln_type="Insecure Direct Object Reference (IDOR)",
                                title=f"IDOR in parameter '{param_name}' — access to user ID {test_id}",
                                severity="HIGH",
                                url=url,
                                parameter=param_name,
                                method="GET",
                                payload=f"{param_name}={test_id}",
                                evidence=f"Accessed user {test_id}'s data (original: user {original_id})",
                                description=f"Changing {param_name} from {original_id} to {test_id} returns different user's data.",
                                remediation="Implement authorization checks. Use session-based object ownership validation.",
                                cvss=7.5,
                                cwe="CWE-639",
                                tool=self.NAME,
                                verified=True,
                                confidence="MEDIUM",
                            ))
                            break

                except Exception:
                    continue

        return findings

    def _different_data(self, body1: str, body2: str) -> bool:
        """Check if two responses contain different data."""
        # Extract potential names, emails, IDs from both
        emails1 = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body1))
        emails2 = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body2))

        if emails1 and emails2 and emails1 != emails2:
            return True

        # Check for different numeric values (account numbers, etc.)
        nums1 = set(re.findall(r'\b\d{4,}\b', body1[:1000]))
        nums2 = set(re.findall(r'\b\d{4,}\b', body2[:1000]))

        if nums1 and nums2 and nums1 != nums2:
            return True

        return False
