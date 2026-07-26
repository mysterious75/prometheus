"""Dependency Confusion Scanner — detects supply chain vulnerabilities.

Detects:
- Internal package names leaked in JS/HTML
- npm/PyPI package name confusion potential
- Exposed package configuration files
"""

from __future__ import annotations

import json
import re
from typing import List, Dict, Set
from urllib.parse import urlparse

from .findings import Finding
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# Patterns for internal package names
INTERNAL_PACKAGE_PATTERNS = [
    # npm scoped packages (often internal)
    re.compile(r'@([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)'),
    # Private registry URLs
    re.compile(r'https?://(?:registry|npm|packages?)\.[a-zA-Z0-9.-]+\.internal'),
    re.compile(r'https?://(?:registry|npm|packages?)\.(?:local|corp|intra|private)'),
    # Artifactory/Nexus URLs
    re.compile(r'https?://(?:artifactory|nexus|jfrog)\.[a-zA-Z0-9.-]+'),
    # Private PyPI
    re.compile(r'https?://pypi\.[a-zA-Z0-9.-]+\.internal'),
    # Gemfury/private gem sources
    re.compile(r'https?://gems?\.[a-zA-Z0-9.-]+\.internal'),
]

# Sensitive config file paths
CONFIG_PATHS = [
    "/.npmrc",
    "/.yarnrc",
    "/.yarnrc.yml",
    "/.pypirc",
    "/Gemfile",
    "/Gemfile.lock",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/poetry.lock",
    "/go.sum",
    "/Cargo.lock",
    "/composer.json",
    "/composer.lock",
    "/pom.xml",
    "/build.gradle",
    "/settings.gradle",
    "/.gemrc",
    "/bower.json",
    "/lerna.json",
    "/nx.json",
    "/rush.json",
]


class DependencyConfusionScanner:
    """Detects dependency confusion / supply chain vulnerabilities."""

    NAME = "dependency_confusion"

    def __init__(self, rps: float = 5.0, timeout: float = 10.0):
        self.limiter = get_limiter(rps)
        self.timeout = timeout

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scan for dependency confusion vulnerabilities."""
        import httpx

        findings: List[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        base = f"{parsed.scheme}://{parsed.netloc}"

        client = httpx.Client(
            verify=True, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            found_packages: Set[str] = set()
            found_registries: Set[str] = set()

            # Step 1: Fetch config files and extract package info
            for path in CONFIG_PATHS:
                test_url = base + path
                self.limiter.wait(host)
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        body = resp.text
                        findings.extend(self._analyze_config(path, body, test_url))

                        # Extract internal package names
                        packages, registries = self._extract_packages(body)
                        found_packages.update(packages)
                        found_registries.update(registries)
                except Exception:
                    pass

            # Step 2: Scan main page for package references
            self.limiter.wait(host)
            try:
                resp = client.get(url)
                packages, registries = self._extract_packages(resp.text)
                found_packages.update(packages)
                found_registries.update(registries)
            except Exception:
                pass

            # Step 3: Scan JS files for package references
            self.limiter.wait(host)
            try:
                resp = client.get(url)
                js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
                for js_url in js_urls[:5]:
                    full_url = js_url if js_url.startswith("http") else base + js_url
                    self.limiter.wait(host)
                    try:
                        js_resp = client.get(full_url)
                        if js_resp.status_code == 200:
                            packages, registries = self._extract_packages(js_resp.text)
                            found_packages.update(packages)
                            found_registries.update(registries)
                    except Exception:
                        pass
            except Exception:
                pass

            # Step 4: Report findings
            if found_packages:
                findings.append(Finding(
                    vuln_type="Dependency Confusion",
                    title=f"Internal package names exposed: {len(found_packages)} found",
                    severity="HIGH",
                    url=url,
                    evidence=f"Packages: {', '.join(list(found_packages)[:20])}",
                    description=f"Found {len(found_packages)} internal/private package names. These could be targets for dependency confusion attacks.",
                    remediation="Use scoped packages with --registry flag. Pin dependency versions. Use lock files.",
                    cvss=7.5, cwe="CWE-1395",
                    tool=self.NAME, verified=False, confidence="MEDIUM",
                ))

            if found_registries:
                findings.append(Finding(
                    vuln_type="Dependency Confusion",
                    title=f"Private registries exposed: {len(found_registries)} found",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"Registries: {', '.join(list(found_registries)[:10])}",
                    description=f"Found {len(found_registries)} private registry URLs. Reveals internal infrastructure.",
                    remediation="Use environment variables for registry URLs. Don't commit .npmrc files.",
                    cvss=5.3, cwe="CWE-200",
                    tool=self.NAME, verified=True, confidence="HIGH",
                ))

        finally:
            client.close()

        logger.info(f"Dependency confusion scan: {len(findings)} findings")
        return findings

    def _analyze_config(self, path: str, body: str, url: str) -> List[Finding]:
        """Analyze a config file for dependency confusion risks."""
        findings = []

        # .npmrc with private registry
        if path == "/.npmrc":
            if "registry=" in body:
                registry_match = re.search(r'registry=(https?://\S+)', body)
                if registry_match:
                    registry = registry_match.group(1)
                    if any(kw in registry for kw in [".internal", ".local", ".corp", "artifactory", "nexus"]):
                        findings.append(Finding(
                            vuln_type="Dependency Confusion",
                            title=f"Private npm registry in .npmrc",
                            severity="CRITICAL",
                            url=url,
                            evidence=f"Registry: {registry}",
                            description=f".npmrc exposes private registry: {registry}. Package names can be harvested for dependency confusion.",
                            remediation="Remove .npmrc from public access. Use environment variables for auth tokens.",
                            cvss=9.1, cwe="CWE-1395",
                            tool=self.NAME, verified=True, confidence="CONFIRMED",
                        ))

            if "_authToken" in body or "_auth" in body:
                findings.append(Finding(
                    vuln_type="Dependency Confusion",
                    title="npm auth token exposed in .npmrc",
                    severity="CRITICAL",
                    url=url,
                    evidence="Auth token found in .npmrc",
                    description=".npmrc contains authentication tokens for private registry.",
                    remediation="Rotate tokens immediately. Use environment variables.",
                    cvss=9.1, cwe="CWE-798",
                    tool=self.NAME, verified=True, confidence="CONFIRMED",
                ))

        # package.json with private packages
        if path == "/package.json":
            try:
                pkg = json.loads(body)
                for section in ["dependencies", "devDependencies", "peerDependencies"]:
                    deps = pkg.get(section, {})
                    for name, version in deps.items():
                        if name.startswith("@") and "/" in name:
                            scope = name.split("/")[0][1:]  # Remove @
                            # Check if it looks like a private scope
                            if scope not in [
                                "types", "babel", "angular", "vue", "react", "next",
                                "nuxt", "eslint", "prettier", "jest", "mocha", "chai",
                                "aws-sdk", "azure", "google-cloud", "firebase",
                            ]:
                                findings.append(Finding(
                                    vuln_type="Dependency Confusion",
                                    title=f"Scoped package in package.json: {name}",
                                    severity="MEDIUM",
                                    url=url,
                                    payload=f"{name}: {version}",
                                    evidence=f"Scoped package '{name}' found in {section}",
                                    description=f"Scoped package '{name}' may be internal. Potential dependency confusion target.",
                                    remediation="Use --registry flag for scoped packages. Verify scope configuration.",
                                    cvss=6.5, cwe="CWE-1395",
                                    tool=self.NAME, verified=True, confidence="LOW",
                                ))
            except (json.JSONDecodeError, KeyError):
                pass

        # .pypirc with private index
        if path == "/.pypirc":
            if "repository" in body:
                repo_match = re.search(r'repository\s*=\s*(https?://\S+)', body)
                if repo_match:
                    findings.append(Finding(
                        vuln_type="Dependency Confusion",
                        title="Private PyPI repository exposed in .pypirc",
                        severity="HIGH",
                        url=url,
                        evidence=f"Repository: {repo_match.group(1)}",
                        description=".pypirc exposes private PyPI repository URL.",
                        remediation="Remove .pypirc from public access.",
                        cvss=7.5, cwe="CWE-200",
                        tool=self.NAME, verified=True, confidence="HIGH",
                    ))

        return findings

    def _extract_packages(self, content: str) -> tuple:
        """Extract package names and registry URLs from content."""
        packages = set()
        registries = set()

        # Find scoped packages
        for match in re.finditer(r'@([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)', content):
            scope = match.group(1)
            name = match.group(2)
            full = f"@{scope}/{name}"
            # Filter common public scopes
            public_scopes = [
                "types", "babel", "angular", "vue", "react", "next",
                "nuxt", "eslint", "prettier", "jest", "mocha",
                "aws-sdk", "azure", "google-cloud", "firebase",
                "testing-library", "commitlint", "changesets",
            ]
            if scope.lower() not in public_scopes:
                packages.add(full)

        # Find private registry URLs
        for pattern in INTERNAL_PACKAGE_PATTERNS:
            for match in pattern.finditer(content):
                registries.add(match.group(0)[:100])

        return packages, registries


__all__ = ["DependencyConfusionScanner"]
