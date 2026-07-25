"""Cloud Security Tools — S3, Azure Blob, GCP bucket discovery.

Finds exposed cloud storage, misconfigurations, and data leaks.
"""

import re
import time
import json
from typing import List, Dict, Any
from dataclasses import dataclass, field

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


@dataclass
class CloudFinding:
    """A cloud security finding."""
    service: str  # s3, azure, gcp
    bucket: str
    url: str
    public: bool
    listing_enabled: bool = False
    files: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"

    def to_dict(self):
        return {
            "service": self.service,
            "bucket": self.bucket,
            "url": self.url,
            "public": self.public,
            "listing_enabled": self.listing_enabled,
            "files_count": len(self.files),
        }


class CloudScanner:
    """Cloud storage security scanner."""

    # Common bucket name patterns
    BUCKET_PATTERNS = [
        "{name}", "{name}-backup", "{name}-bak", "{name}-dev", "{name}-staging",
        "{name}-prod", "{name}-production", "{name}-test", "{name}-data",
        "{name}-assets", "{name}-media", "{name}-images", "{name}-uploads",
        "{name}-logs", "{name}-archive", "{name}-old", "{name}-new",
        "{name}-static", "{name}-cdn", "{name}-content", "{name}-files",
        "{name}-db", "{name}-dump", "{name}-export", "{name}-config",
        "{name}-private", "{name}-public", "{name}-internal", "{name}-external",
        "{name}.com", "{name}-app", "{name}-api", "{name}-web",
        "{name}-storage", "{name}-store", "{name}-vault",
    ]

    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)

    def scan_all(self, name: str) -> List[CloudFinding]:
        """Scan all cloud providers for exposed buckets."""
        findings = []
        console.print(f"  [tool]▸ Cloud Scanner[/tool] → [target]{name}[/target]")

        findings.extend(self.scan_s3(name))
        findings.extend(self.scan_azure(name))
        findings.extend(self.scan_gcp(name))

        console.print(f"  [tool]◂ Cloud[/tool] — {len(findings)} findings")
        return findings

    def scan_s3(self, name: str) -> List[CloudFinding]:
        """Scan for exposed AWS S3 buckets."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=8, verify=False)

        # Generate bucket names
        base_names = [name, name.replace(".", "-"), name.replace(".", "")]
        bucket_names = set()
        for base in base_names:
            for pattern in self.BUCKET_PATTERNS:
                bucket_names.add(pattern.format(name=base))

        for bucket in bucket_names:
            self.limiter.wait("s3.amazonaws.com")
            try:
                url = f"https://{bucket}.s3.amazonaws.com/"
                resp = client.get(url)

                if resp.status_code == 200:
                    listing_enabled = "<ListBucketResult" in resp.text
                    files = []
                    if listing_enabled:
                        files = re.findall(r'<Key>([^<]+)</Key>', resp.text)

                    findings.append(CloudFinding(
                        service="AWS S3",
                        bucket=bucket,
                        url=url,
                        public=True,
                        listing_enabled=listing_enabled,
                        files=files[:20],
                        severity="HIGH" if listing_enabled else "MEDIUM",
                    ))
                    console.print(f"    [success]+ S3 bucket found: {bucket} (listing={'ON' if listing_enabled else 'OFF'})[/success]")

                elif resp.status_code == 403:
                    # Bucket exists but private
                    findings.append(CloudFinding(
                        service="AWS S3",
                        bucket=bucket,
                        url=url,
                        public=False,
                        severity="INFO",
                    ))

            except Exception:
                continue

        return findings

    def scan_azure(self, name: str) -> List[CloudFinding]:
        """Scan for exposed Azure Blob Storage."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=8, verify=False)

        base_names = [name, name.replace(".", "-"), name.replace(".", "")]
        container_names = set()
        for base in base_names:
            for pattern in self.BUCKET_PATTERNS:
                container_names.add(pattern.format(name=base))

        for container in container_names:
            self.limiter.wait("blob.core.windows.net")
            try:
                url = f"https://{container}.blob.core.windows.net/?comp=list"
                resp = client.get(url)

                if resp.status_code == 200 and "EnumerationResults" in resp.text:
                    files = re.findall(r'<Name>([^<]+)</Name>', resp.text)
                    findings.append(CloudFinding(
                        service="Azure Blob",
                        bucket=container,
                        url=url,
                        public=True,
                        listing_enabled=True,
                        files=files[:20],
                        severity="HIGH",
                    ))
                    console.print(f"    [success]+ Azure blob found: {container}[/success]")

            except Exception:
                continue

        return findings

    def scan_gcp(self, name: str) -> List[CloudFinding]:
        """Scan for exposed GCP Cloud Storage buckets."""
        try:
            import httpx
        except ImportError:
            return []

        findings = []
        client = httpx.Client(follow_redirects=True, timeout=8, verify=False)

        base_names = [name, name.replace(".", "-"), name.replace(".", "")]
        bucket_names = set()
        for base in base_names:
            for pattern in self.BUCKET_PATTERNS:
                bucket_names.add(pattern.format(name=base))

        for bucket in bucket_names:
            self.limiter.wait("storage.googleapis.com")
            try:
                url = f"https://storage.googleapis.com/{bucket}"
                resp = client.get(url)

                if resp.status_code == 200:
                    files = re.findall(r'<Key>([^<]+)</Key>', resp.text)
                    findings.append(CloudFinding(
                        service="GCP Cloud Storage",
                        bucket=bucket,
                        url=url,
                        public=True,
                        listing_enabled=bool(files),
                        files=files[:20],
                        severity="HIGH" if files else "MEDIUM",
                    ))
                    console.print(f"    [success]+ GCP bucket found: {bucket}[/success]")

            except Exception:
                continue

        return findings

    def check_s3_permissions(self, bucket: str) -> Dict[str, Any]:
        """Check S3 bucket permissions."""
        try:
            import httpx
            client = httpx.Client(timeout=8, verify=False)

            # Check ACL
            acl_url = f"https://{bucket}.s3.amazonaws.com/?acl"
            resp = client.get(acl_url)

            # Check policy
            policy_url = f"https://{bucket}.s3.amazonaws.com/?policy"
            resp2 = client.get(policy_url)

            return {
                "bucket": bucket,
                "acl_accessible": resp.status_code == 200,
                "policy_accessible": resp2.status_code == 200,
                "acl_data": resp.text[:500] if resp.status_code == 200 else "",
            }
        except Exception:
            return {"bucket": bucket, "error": "check failed"}
