"""Prometheus API Client — Python SDK for the Prometheus Security API.

Usage:
    from src.api.client import PrometheusClient

    client = PrometheusClient(api_key="pk_...")
    scan_id = client.scan("https://example.com")
    result = client.wait_for_scan(scan_id)
    findings = client.get_findings(scan_id=scan_id)
"""

import time
from typing import Optional, Dict, Any, List
from pathlib import Path

import httpx


class PrometheusAPIError(Exception):
    """API error with status code and detail."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API Error {status_code}: {detail}")


class PrometheusClient:
    """Python client for the Prometheus Security API.

    Provides a clean interface for starting scans, polling status,
    retrieving findings, and generating reports.

    Example:
        client = PrometheusClient(base_url="http://localhost:8000", api_key="pk_...")

        # Start a scan
        scan_id = client.scan("https://example.com", scan_type="full")

        # Wait for completion (polls automatically)
        result = client.wait_for_scan(scan_id, timeout=300)

        # Get findings
        findings = client.get_findings(scan_id=scan_id, severity="HIGH")

        # Get report
        report = client.get_report(scan_id, format="markdown")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """Initialize the client.

        Args:
            base_url: Base URL of the Prometheus API server.
            api_key: API key for authentication.
            timeout: Default request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
        )

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """Make an HTTP request and handle errors."""
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.ConnectError:
            raise PrometheusAPIError(0, f"Cannot connect to {self.base_url}. Is the API server running?")
        except httpx.TimeoutException:
            raise PrometheusAPIError(0, f"Request timed out after {self.timeout}s")

        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise PrometheusAPIError(response.status_code, detail)

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        return response.text

    # ──────────────────────────────────────────
    # Scan Operations
    # ──────────────────────────────────────────

    def scan(
        self,
        target: str,
        scan_type: str = "full",
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Start a new security scan.

        Args:
            target: Target URL or domain to scan.
            scan_type: Scan type — full, quick, owasp, business, session, crypto, api.
            options: Additional scan options.

        Returns:
            scan_id for tracking the scan.
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "options": options or {},
        }
        result = self._request("POST", "/scan", json=data)
        return result["scan_id"]

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status and metadata.

        Args:
            scan_id: The scan ID returned by scan().

        Returns:
            Dict with scan_id, target, status, progress, findings_count, etc.
        """
        return self._request("GET", f"/scan/{scan_id}")

    def list_scans(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all scans.

        Args:
            status: Optional filter — pending, running, completed, failed.

        Returns:
            List of scan status dicts.
        """
        params = {}
        if status:
            params["status"] = status
        result = self._request("GET", "/scans", params=params)
        return result.get("scans", [])

    def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """Cancel or delete a scan.

        Args:
            scan_id: The scan ID to cancel.

        Returns:
            Confirmation message.
        """
        return self._request("DELETE", f"/scan/{scan_id}")

    # ──────────────────────────────────────────
    # Findings
    # ──────────────────────────────────────────

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get findings with optional filters.

        Args:
            scan_id: Filter by scan ID.
            severity: Filter by severity — CRITICAL, HIGH, MEDIUM, LOW, INFO.
            vuln_type: Filter by vulnerability type (partial match).

        Returns:
            List of finding dicts.
        """
        params = {}
        if scan_id:
            params["scan_id"] = scan_id
        if severity:
            params["severity"] = severity
        if vuln_type:
            params["vuln_type"] = vuln_type
        return self._request("GET", "/findings", params=params)

    # ──────────────────────────────────────────
    # Reports
    # ──────────────────────────────────────────

    def get_report(self, scan_id: str, format: str = "markdown") -> str:
        """Get scan report.

        Args:
            scan_id: The scan ID.
            format: Report format — "markdown" or "json".

        Returns:
            Report content as string (markdown) or dict (json).
        """
        result = self._request("GET", f"/report/{scan_id}", params={"format": format})
        return result

    # ──────────────────────────────────────────
    # Targets
    # ──────────────────────────────────────────

    def authorize_target(self, target: str) -> Dict[str, Any]:
        """Authorize a target for scanning.

        Args:
            target: Target URL or domain.

        Returns:
            Confirmation message.
        """
        return self._request("POST", "/authorize", json={"target": target})

    def list_targets(self) -> List[str]:
        """List authorized targets.

        Returns:
            List of authorized target strings.
        """
        result = self._request("GET", "/targets")
        return result.get("targets", [])

    # ──────────────────────────────────────────
    # System
    # ──────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Get system status.

        Returns:
            System status dict.
        """
        return self._request("GET", "/status")

    def tools(self) -> List[Dict[str, Any]]:
        """List available tools.

        Returns:
            List of tool info dicts.
        """
        return self._request("GET", "/tools")

    def health(self) -> Dict[str, Any]:
        """Health check (no auth required).

        Returns:
            Health status dict.
        """
        # Health doesn't need auth, use a separate request
        try:
            response = httpx.get(f"{self.base_url}/health", timeout=5.0)
            return response.json()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    # ──────────────────────────────────────────
    # Convenience Methods
    # ──────────────────────────────────────────

    def wait_for_scan(
        self,
        scan_id: str,
        timeout: int = 300,
        poll_interval: float = 2.0,
        on_progress: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Wait for a scan to complete, polling at intervals.

        Args:
            scan_id: The scan ID to wait for.
            timeout: Maximum wait time in seconds.
            poll_interval: Seconds between status checks.
            on_progress: Optional callback(progress: int, status: str) for updates.

        Returns:
            Final scan status dict.

        Raises:
            TimeoutError: If scan doesn't complete within timeout.
            PrometheusAPIError: If scan fails.
        """
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed > timeout:
                raise TimeoutError(f"Scan {scan_id} did not complete within {timeout}s")

            scan = self.get_scan(scan_id)
            status = scan["status"]
            progress = scan["progress"]

            if on_progress:
                on_progress(progress, status)

            if status == "completed":
                return scan
            elif status == "failed":
                error = scan.get("error", "Unknown error")
                raise PrometheusAPIError(500, f"Scan failed: {error}")

            time.sleep(poll_interval)

    def scan_and_report(
        self,
        target: str,
        scan_type: str = "full",
        report_format: str = "markdown",
        timeout: int = 300,
        on_progress: Optional[Any] = None,
    ) -> tuple:
        """Convenience: start scan, wait, return (scan_result, report).

        Args:
            target: Target to scan.
            scan_type: Scan type.
            report_format: Report format.
            timeout: Max wait time.
            on_progress: Progress callback.

        Returns:
            Tuple of (scan_status_dict, report_content).
        """
        scan_id = self.scan(target, scan_type=scan_type)
        result = self.wait_for_scan(scan_id, timeout=timeout, on_progress=on_progress)
        report = self.get_report(scan_id, format=report_format)
        return result, report

    def close(self):
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        return f"PrometheusClient(base_url='{self.base_url}', authenticated={self.api_key is not None})"
