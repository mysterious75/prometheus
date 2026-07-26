"""Prometheus REST API — FastAPI-based security scanning API.

Provides RESTful endpoints for managing scans, viewing findings,
and generating reports programmatically.
"""

import uuid
import time
import json
import secrets
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.config import load_config, ScanProfile
from src.core.auth import TargetAuthorization
from src.core.logger import console, logger

# ──────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────


class ScanRequest(BaseModel):
    """Request model for starting a new scan."""
    target: str = Field(..., description="Target URL or domain to scan")
    scan_type: str = Field(
        default="full",
        description="Scan type: full, quick, owasp, business, session, crypto, api"
    )
    options: Dict[str, Any] = Field(default_factory=dict, description="Additional scan options")


class ScanStatus(BaseModel):
    """Scan status response model."""
    scan_id: str
    target: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    findings_count: int
    started_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None


class FindingResponse(BaseModel):
    """Individual finding response model."""
    id: int
    vuln_type: str
    title: str
    severity: str
    url: str
    evidence: str
    remediation: str
    cvss: float
    cwe: str
    confidence: str = "LOW"
    parameter: str = ""
    method: str = "GET"
    payload: str = ""


class ScanListResponse(BaseModel):
    """Response for listing scans."""
    scans: List[ScanStatus]
    total: int


class AuthorizeRequest(BaseModel):
    """Request model for authorizing a target."""
    target: str


class SystemStatus(BaseModel):
    """System status response."""
    version: str
    uptime: str
    active_scans: int
    total_scans: int
    total_findings: int
    tools_available: int


class ToolInfo(BaseModel):
    """Tool availability info."""
    name: str
    installed: bool
    binary: str


class APIKeyInfo(BaseModel):
    """API key information."""
    key: str
    created_at: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: str


# ──────────────────────────────────────────────
# In-memory scan store
# ──────────────────────────────────────────────


class ScanStore:
    """Thread-safe in-memory scan storage with optional file persistence."""

    def __init__(self, persist_dir: Optional[Path] = None):
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._persist_dir = persist_dir
        if persist_dir:
            persist_dir.mkdir(parents=True, exist_ok=True)

    def create_scan(self, scan_id: str, target: str, scan_type: str, options: dict) -> Dict[str, Any]:
        """Create a new scan entry."""
        scan = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "options": options,
            "status": "pending",
            "progress": 0,
            "findings_count": 0,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "error": None,
        }
        self._scans[scan_id] = scan
        self._findings[scan_id] = []
        self._persist(scan_id)
        return scan

    def update_scan(self, scan_id: str, **kwargs) -> Dict[str, Any]:
        """Update scan fields."""
        if scan_id not in self._scans:
            raise KeyError(f"Scan {scan_id} not found")
        self._scans[scan_id].update(kwargs)
        self._persist(scan_id)
        return self._scans[scan_id]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan by ID."""
        return self._scans.get(scan_id)

    def list_scans(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all scans, optionally filtered by status."""
        scans = list(self._scans.values())
        if status:
            scans = [s for s in scans if s["status"] == status]
        return sorted(scans, key=lambda s: s["started_at"], reverse=True)

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings."""
        if scan_id not in self._scans:
            return False
        del self._scans[scan_id]
        self._findings.pop(scan_id, None)
        if self._persist_dir:
            p = self._persist_dir / f"{scan_id}.json"
            p.unlink(missing_ok=True)
        return True

    def add_findings(self, scan_id: str, findings: List[Dict[str, Any]]):
        """Add findings to a scan."""
        if scan_id not in self._findings:
            self._findings[scan_id] = []
        self._findings[scan_id].extend(findings)
        self._scans[scan_id]["findings_count"] = len(self._findings[scan_id])
        self._persist(scan_id)

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get findings with optional filters."""
        if scan_id:
            findings = list(self._findings.get(scan_id, []))
        else:
            findings = []
            for fl in self._findings.values():
                findings.extend(fl)

        if severity:
            findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]
        if vuln_type:
            findings = [f for f in findings if vuln_type.lower() in f.get("vuln_type", "").lower()]

        return findings

    def _persist(self, scan_id: str):
        """Persist scan data to disk if configured."""
        if not self._persist_dir:
            return
        try:
            data = {
                "scan": self._scans.get(scan_id),
                "findings": self._findings.get(scan_id, []),
            }
            p = self._persist_dir / f"{scan_id}.json"
            p.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.error(f"Failed to persist scan {scan_id}: {e}")


# ──────────────────────────────────────────────
# API Key Management
# ──────────────────────────────────────────────


class APIKeyManager:
    """Simple API key authentication manager."""

    def __init__(self, keys_file: Optional[Path] = None):
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._keys_file = keys_file
        self._load()

    def _load(self):
        """Load API keys from file."""
        if self._keys_file and self._keys_file.exists():
            try:
                self._keys = json.loads(self._keys_file.read_text())
            except (json.JSONDecodeError, KeyError):
                self._keys = {}

    def _save(self):
        """Save API keys to file."""
        if self._keys_file:
            self._keys_file.parent.mkdir(parents=True, exist_ok=True)
            self._keys_file.write_text(json.dumps(self._keys, indent=2))

    def create_key(self) -> str:
        """Create a new API key."""
        key = f"pk_{secrets.token_urlsafe(32)}"
        self._keys[key] = {
            "created_at": datetime.now().isoformat(),
            "requests": 0,
        }
        self._save()
        return key

    def validate(self, key: str) -> bool:
        """Validate an API key."""
        if key in self._keys:
            self._keys[key]["requests"] = self._keys[key].get("requests", 0) + 1
            return True
        return False

    def list_keys(self) -> List[str]:
        """List all API keys."""
        return list(self._keys.keys())

    def revoke_key(self, key: str) -> bool:
        """Revoke an API key."""
        if key in self._keys:
            del self._keys[key]
            self._save()
            return True
        return False


# ──────────────────────────────────────────────
# Rate Limiter (per API key)
# ──────────────────────────────────────────────


class APIRateLimiter:
    """Simple in-memory rate limiter per API key."""

    def __init__(self, requests_per_minute: int = 60):
        self.rpm = requests_per_minute
        self._counts: Dict[str, List[float]] = {}

    def check(self, key: str) -> bool:
        """Check if request is within rate limit. Returns True if allowed."""
        now = time.time()
        if key not in self._counts:
            self._counts[key] = []

        # Clean old entries (older than 60s)
        self._counts[key] = [t for t in self._counts[key] if now - t < 60]

        if len(self._counts[key]) >= self.rpm:
            return False

        self._counts[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        """Get remaining requests for a key."""
        now = time.time()
        if key not in self._counts:
            return self.rpm
        recent = [t for t in self._counts[key] if now - t < 60]
        return max(0, self.rpm - len(recent))


# ──────────────────────────────────────────────
# Application Factory
# ──────────────────────────────────────────────

# Startup timestamp
_startup_time = datetime.now()

# Default data directory
_data_dir = Path(__file__).parent.parent.parent / "data" / "api"


def create_app(
    api_keys_file: Optional[Path] = None,
    persist_dir: Optional[Path] = None,
    require_auth: bool = True,
    requests_per_minute: int = 60,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        api_keys_file: Path to API keys JSON file.
        persist_dir: Directory for persisting scan results.
        require_auth: Whether to require API key authentication.
        requests_per_minute: Rate limit per API key per minute.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="Prometheus Security API",
        description="REST API for the Prometheus AI Security Researcher platform.",
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Shared state
    store = ScanStore(persist_dir=persist_dir or _data_dir / "scans")
    key_mgr = APIKeyManager(keys_file=api_keys_file or _data_dir / "api_keys.json")
    rate_limiter = APIRateLimiter(requests_per_minute=requests_per_minute)
    auth_mgr = TargetAuthorization()

    # Ensure at least one API key exists
    if not key_mgr.list_keys():
        default_key = key_mgr.create_key()
        logger.info(f"Created default API key: {default_key}")

    security = HTTPBearer(auto_error=False)

    async def get_api_key(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Optional[str]:
        """Extract and validate API key from Authorization header."""
        if not require_auth:
            return "anonymous"

        if credentials is None:
            raise HTTPException(status_code=401, detail="Missing Authorization header. Use: Bearer <api_key>")

        key = credentials.credentials
        if not key_mgr.validate(key):
            raise HTTPException(status_code=401, detail="Invalid API key.")

        if not rate_limiter.check(key):
            remaining = rate_limiter.remaining(key)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. {remaining} requests remaining.",
            )

        return key

    # ──────────────────────────────────────────
    # Health & Status
    # ──────────────────────────────────────────

    @app.get("/health", response_model=HealthResponse, tags=["System"])
    async def health_check():
        """Health check endpoint (no auth required)."""
        return HealthResponse(
            status="healthy",
            version="3.0.0",
            timestamp=datetime.now().isoformat(),
        )

    @app.get("/status", response_model=SystemStatus, tags=["System"])
    async def system_status(api_key: str = Depends(get_api_key)):
        """Get system status including active scans and tool availability."""
        from src.tools.registry import registry

        active = len(store.list_scans(status="running")) + len(store.list_scans(status="pending"))
        total = len(store.list_scans())
        all_findings = store.get_findings()
        tools = registry.status()

        uptime_delta = datetime.now() - _startup_time
        hours, remainder = divmod(int(uptime_delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        return SystemStatus(
            version="3.0.0",
            uptime=f"{hours}h {minutes}m {seconds}s",
            active_scans=active,
            total_scans=total,
            total_findings=len(all_findings),
            tools_available=tools.count("✓") if isinstance(tools, str) else 0,
        )

    @app.get("/tools", response_model=List[ToolInfo], tags=["System"])
    async def list_tools(api_key: str = Depends(get_api_key)):
        """List all security tools and their availability."""
        import shutil as sh
        from src.core.config import config

        tools = []
        config.check_tools()
        for name, cfg in config.tools.items():
            tools.append(ToolInfo(
                name=cfg.name,
                installed=cfg.installed,
                binary=cfg.binary,
            ))
        return tools

    # ──────────────────────────────────────────
    # Scan Management
    # ──────────────────────────────────────────

    async def _run_scan_background(scan_id: str, target: str, scan_type: str, options: dict):
        """Execute scan in background thread."""
        try:
            store.update_scan(scan_id, status="running", progress=5)

            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"

            store.update_scan(scan_id, progress=10)

            if scan_type == "quick":
                # Quick scan: headers + CORS + secrets only
                from src.scanner.headers import HeadersScanner
                from src.scanner.cors import CORSScanner
                from src.scanner.secrets import SecretsScanner

                scanners = [HeadersScanner(), CORSScanner(), SecretsScanner()]
                findings_list = []
                for i, scanner in enumerate(scanners):
                    try:
                        fs = scanner.scan_url(target)
                        findings_list.extend(fs)
                    except Exception:
                        pass
                    progress = 10 + int((i + 1) / len(scanners) * 85)
                    store.update_scan(scan_id, progress=progress)

            elif scan_type == "stealth":
                from src.scanner.runner import ScanRunner
                runner = ScanRunner(rps=2.0)
                result = runner.scan(target, full=True)
                findings_list = result.findings
                store.update_scan(scan_id, progress=90)

            elif scan_type in ("owasp", "business", "session", "crypto", "api"):
                # Specialized scan types
                findings_list = await _run_specialized_scan(scan_type, target)
                store.update_scan(scan_id, progress=90)

            else:
                # Full scan
                from src.scanner.runner import ScanRunner
                runner = ScanRunner(rps=float(options.get("rps", 10.0)))
                result = runner.scan(target, full=True)
                findings_list = result.findings
                store.update_scan(scan_id, progress=90)

            # Convert findings to dicts
            findings_dicts = [f.to_dict() for f in findings_list]
            store.add_findings(scan_id, findings_dicts)
            store.update_scan(
                scan_id,
                status="completed",
                progress=100,
                completed_at=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            store.update_scan(
                scan_id,
                status="failed",
                error=str(e),
                completed_at=datetime.now().isoformat(),
            )

    async def _run_specialized_scan(scan_type: str, target: str) -> list:
        """Run a specialized scanner by type."""
        import asyncio

        def _run():
            if scan_type == "owasp":
                from src.scanner.owasp_methodology import OWASPMethodologyScanner
                scanner = OWASPMethodologyScanner()
                result = scanner.scan(target)
                return result.findings if hasattr(result, 'findings') else []
            elif scan_type == "business":
                from src.scanner.business_logic import BusinessLogicScanner
                scanner = BusinessLogicScanner()
                return scanner.scan_url(target)
            elif scan_type == "session":
                from src.scanner.session_manager import SessionManagerScanner
                scanner = SessionManagerScanner()
                return scanner.scan_url(target)
            elif scan_type == "crypto":
                from src.scanner.crypto_scanner import CryptoScanner
                scanner = CryptoScanner()
                return scanner.scan_url(target)
            elif scan_type == "api":
                from src.scanner.api_security import APISecurityScanner
                scanner = APISecurityScanner()
                return scanner.scan_url(target)
            return []

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    @app.post("/scan", response_model=ScanStatus, tags=["Scans"])
    async def start_scan(
        request: ScanRequest,
        background_tasks: BackgroundTasks,
        api_key: str = Depends(get_api_key),
    ):
        """Start a new security scan.

        Supported scan types: full, quick, owasp, business, session, crypto, api.
        Returns immediately with a scan_id for tracking progress.
        """
        valid_types = {"full", "quick", "owasp", "business", "session", "crypto", "api", "stealth"}
        if request.scan_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scan_type '{request.scan_type}'. Valid: {', '.join(sorted(valid_types))}",
            )

        scan_id = str(uuid.uuid4())[:12]
        scan = store.create_scan(scan_id, request.target, request.scan_type, request.options)

        background_tasks.add_task(
            _run_scan_background,
            scan_id,
            request.target,
            request.scan_type,
            request.options,
        )

        return ScanStatus(**scan)

    @app.get("/scan/{scan_id}", response_model=ScanStatus, tags=["Scans"])
    async def get_scan(scan_id: str, api_key: str = Depends(get_api_key)):
        """Get scan status and progress by scan ID."""
        scan = store.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
        return ScanStatus(**scan)

    @app.get("/scans", response_model=ScanListResponse, tags=["Scans"])
    async def list_scans(
        status: Optional[str] = Query(None, description="Filter by status: pending, running, completed, failed"),
        api_key: str = Depends(get_api_key),
    ):
        """List all scans with optional status filter."""
        scans = store.list_scans(status=status)
        return ScanListResponse(
            scans=[ScanStatus(**s) for s in scans],
            total=len(scans),
        )

    @app.delete("/scan/{scan_id}", tags=["Scans"])
    async def cancel_scan(scan_id: str, api_key: str = Depends(get_api_key)):
        """Cancel or delete a scan."""
        scan = store.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

        if scan["status"] in ("pending", "running"):
            store.update_scan(scan_id, status="failed", error="Cancelled by user",
                              completed_at=datetime.now().isoformat())
            return {"message": f"Scan '{scan_id}' cancelled.", "scan_id": scan_id}
        else:
            store.delete_scan(scan_id)
            return {"message": f"Scan '{scan_id}' deleted.", "scan_id": scan_id}

    # ──────────────────────────────────────────
    # Findings
    # ──────────────────────────────────────────

    @app.get("/findings", response_model=List[FindingResponse], tags=["Findings"])
    async def get_findings(
        scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
        severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
        vuln_type: Optional[str] = Query(None, description="Filter by vulnerability type (partial match)"),
        api_key: str = Depends(get_api_key),
    ):
        """Get all findings with optional filters."""
        findings = store.get_findings(scan_id=scan_id, severity=severity, vuln_type=vuln_type)
        return [
            FindingResponse(
                id=f.get("id", 0),
                vuln_type=f.get("vuln_type", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "INFO"),
                url=f.get("url", ""),
                evidence=f.get("evidence", "")[:500],
                remediation=f.get("remediation", ""),
                cvss=f.get("cvss", 0.0),
                cwe=f.get("cwe", ""),
                confidence=f.get("confidence", "LOW"),
                parameter=f.get("parameter", ""),
                method=f.get("method", "GET"),
                payload=f.get("payload", ""),
            )
            for f in findings
        ]

    # ──────────────────────────────────────────
    # Reports
    # ──────────────────────────────────────────

    @app.get("/report/{scan_id}", tags=["Reports"])
    async def get_report(
        scan_id: str,
        format: str = Query("markdown", description="Report format: markdown or json"),
        api_key: str = Depends(get_api_key),
    ):
        """Get scan report in markdown or JSON format."""
        scan = store.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

        if scan["status"] not in ("completed", "failed"):
            raise HTTPException(status_code=400, detail=f"Scan is '{scan['status']}'. Wait for completion.")

        findings = store.get_findings(scan_id=scan_id)

        if format == "json":
            return {
                "scan_id": scan_id,
                "target": scan["target"],
                "scan_type": scan["scan_type"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
                "findings_count": len(findings),
                "findings": findings,
            }

        # Markdown report
        lines = [
            f"# 🔒 Security Assessment Report",
            f"",
            f"**Target:** {scan['target']}",
            f"**Scan ID:** {scan_id}",
            f"**Type:** {scan['scan_type']}",
            f"**Status:** {scan['status']}",
            f"**Started:** {scan['started_at']}",
            f"**Completed:** {scan.get('completed_at', 'N/A')}",
            f"",
        ]

        if not findings:
            lines.append("✅ **No vulnerabilities found.**")
            return PlainTextResponse("\n".join(lines), media_type="text/markdown")

        # Severity counts
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
                lines.append(f"| {icon} {sev} | {count} |")
        lines.append(f"| **Total** | **{len(findings)}** |")
        lines.append("")

        # Findings detail
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if not sev_findings:
                continue
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
            lines.append(f"## {icon} {sev} Findings")
            lines.append("")
            for f in sev_findings:
                lines.append(f"### {f.get('title', 'Unknown')}")
                lines.append(f"")
                lines.append(f"- **Type:** {f.get('vuln_type', '')}")
                lines.append(f"- **URL:** `{f.get('url', '')}`")
                if f.get("parameter"):
                    lines.append(f"- **Parameter:** `{f['parameter']}`")
                lines.append(f"- **CVSS:** {f.get('cvss', 0)}")
                if f.get("cwe"):
                    lines.append(f"- **CWE:** {f['cwe']}")
                lines.append(f"- **Confidence:** {f.get('confidence', 'LOW')}")
                if f.get("evidence"):
                    lines.append(f"")
                    lines.append(f"**Evidence:**")
                    lines.append(f"```")
                    lines.append(f"{f['evidence'][:500]}")
                    lines.append(f"```")
                if f.get("remediation"):
                    lines.append(f"")
                    lines.append(f"**Remediation:** {f['remediation']}")
                lines.append(f"")
                lines.append(f"---")
                lines.append("")

        return PlainTextResponse("\n".join(lines), media_type="text/markdown")

    # ──────────────────────────────────────────
    # Authorization
    # ──────────────────────────────────────────

    @app.post("/authorize", tags=["Targets"])
    async def authorize_target(
        request: AuthorizeRequest,
        api_key: str = Depends(get_api_key),
    ):
        """Authorize a target for scanning."""
        result = auth_mgr.authorize(request.target)
        return {"message": result, "target": request.target}

    @app.get("/targets", tags=["Targets"])
    async def list_targets(api_key: str = Depends(get_api_key)):
        """List all authorized targets."""
        targets = sorted(auth_mgr.authorized)
        return {"targets": targets, "count": len(targets)}

    # ──────────────────────────────────────────
    # API Key Management
    # ──────────────────────────────────────────

    @app.post("/keys", response_model=APIKeyInfo, tags=["API Keys"])
    async def create_api_key(api_key: str = Depends(get_api_key)):
        """Create a new API key."""
        new_key = key_mgr.create_key()
        return APIKeyInfo(key=new_key, created_at=datetime.now().isoformat())

    @app.get("/keys", tags=["API Keys"])
    async def list_api_keys(api_key: str = Depends(get_api_key)):
        """List all API keys (masked)."""
        keys = key_mgr.list_keys()
        return {
            "keys": [
                {"key": k[:8] + "..." + k[-4:], "full_key": k}
                for k in keys
            ],
            "count": len(keys),
        }

    @app.delete("/keys/{key}", tags=["API Keys"])
    async def revoke_api_key(key: str, api_key: str = Depends(get_api_key)):
        """Revoke an API key."""
        if key_mgr.revoke_key(key):
            return {"message": f"Key revoked."}
        raise HTTPException(status_code=404, detail="Key not found.")

    return app


# ──────────────────────────────────────────────
# Standalone entry point
# ──────────────────────────────────────────────

def main():
    """Run the API server standalone."""
    import argparse

    parser = argparse.ArgumentParser(description="Prometheus Security API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--no-auth", action="store_true", help="Disable API key authentication")
    parser.add_argument("--rpm", type=int, default=60, help="Rate limit: requests per minute per key")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    app = create_app(require_auth=not args.no_auth, requests_per_minute=args.rpm)

    console.print(f"\n[bold cyan]Prometheus Security API[/bold cyan]")
    console.print(f"  Host: {args.host}:{args.port}")
    console.print(f"  Auth: {'disabled' if args.no_auth else 'enabled'}")
    console.print(f"  Rate limit: {args.rpm} req/min/key")
    console.print(f"  Docs: http://{args.host}:{args.port}/docs")
    console.print()

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)


# Module-level app for importability
try:
    app = create_app()
except Exception:
    app = None

if __name__ == "__main__":
    main()
