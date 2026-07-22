"""HTTP Proxy Interceptor - Burp Suite replacement. Intercept, modify, replay."""

import asyncio
import json
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

import httpx
from ..utils.logger import logger


@dataclass
class InterceptedRequest:
    """A captured HTTP request."""
    id: int
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timestamp: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0
    modified: bool = False
    notes: str = ""


class ProxyInterceptor:
    """HTTP proxy that intercepts, modifies, and replays requests."""

    def __init__(self):
        self.intercepted: List[InterceptedRequest] = self._load_history()
        self.intercept_rules: List[Dict] = []
        self.auto_modify: bool = False
        self.request_counter = len(self.intercepted)
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=15,
            verify=False
        )

    def _load_history(self) -> List[InterceptedRequest]:
        return []

    def intercept(self, method: str, url: str, headers: Optional[Dict] = None,
                  body: str = "", notes: str = "") -> InterceptedRequest:
        """Capture a request (doesn't send yet)."""
        self.request_counter += 1

        if not headers:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }

        req = InterceptedRequest(
            id=self.request_counter,
            method=method.upper(),
            url=url,
            headers=headers,
            body=body,
            timestamp=datetime.now().isoformat(),
            notes=notes
        )

        # Apply intercept rules
        for rule in self.intercept_rules:
            if self._matches_rule(req, rule):
                req = self._apply_rule(req, rule)

        self.intercepted.append(req)
        logger.info(f"[cyan]Intercepted: {method} {url}[/cyan]")
        return req

    def modify(self, request_id: int, **kwargs) -> InterceptedRequest:
        """Modify an intercepted request."""
        req = self._get_request(request_id)
        if not req:
            raise ValueError(f"Request {request_id} not found")

        if "method" in kwargs:
            req.method = kwargs["method"]
        if "url" in kwargs:
            req.url = kwargs["url"]
        if "headers" in kwargs:
            req.headers.update(kwargs["headers"])
        if "body" in kwargs:
            req.body = kwargs["body"]
        if "notes" in kwargs:
            req.notes = kwargs["notes"]

        req.modified = True
        return req

    def send(self, request_id: int) -> InterceptedRequest:
        """Send the intercepted request."""
        req = self._get_request(request_id)
        if not req:
            raise ValueError(f"Request {request_id} not found")

        start = time.time()
        try:
            response = self.client.request(
                method=req.method,
                url=req.url,
                headers=req.headers,
                content=req.body if req.body else None
            )
            elapsed = (time.time() - start) * 1000

            req.response_status = response.status_code
            req.response_headers = dict(response.headers)
            req.response_body = response.text[:5000]
            req.response_time_ms = elapsed

            logger.info(f"[green]Response: {response.status_code} ({elapsed:.0f}ms)[/green]")
        except Exception as e:
            req.response_status = 0
            req.response_body = str(e)
            req.response_time_ms = (time.time() - start) * 1000
            logger.error(f"[red]Request failed: {e}[/red]")

        return req

    def replay(self, request_id: int, modifications: Optional[Dict] = None) -> InterceptedRequest:
        """Replay a request with optional modifications."""
        req = self._get_request(request_id)
        if not req:
            raise ValueError(f"Request {request_id} not found")

        # Create a copy with modifications
        new_req = self.intercept(
            method=req.method,
            url=req.url,
            headers=dict(req.headers),
            body=req.body,
            notes=f"Replay of #{request_id}"
        )

        if modifications:
            self.modify(new_req.id, **modifications)

        return self.send(new_req.id)

    def add_rule(self, name: str, match_url: str = "", match_header: str = "",
                 action: str = "add_header", value: str = ""):
        """Add an intercept rule (auto-modify requests)."""
        self.intercept_rules.append({
            "name": name,
            "match_url": match_url,
            "match_header": match_header,
            "action": action,
            "value": value
        })

    def _matches_rule(self, req: InterceptedRequest, rule: Dict) -> bool:
        if rule["match_url"] and rule["match_url"] not in req.url:
            return False
        if rule["match_header"] and rule["match_header"] not in str(req.headers):
            return False
        return True

    def _apply_rule(self, req: InterceptedRequest, rule: Dict) -> InterceptedRequest:
        action = rule["action"]
        value = rule["value"]
        if action == "add_header":
            key, val = value.split(":", 1) if ":" in value else (value, "")
            req.headers[key.strip()] = val.strip()
        elif action == "remove_header":
            req.headers.pop(value, None)
        elif action == "replace_body":
            req.body = value
        return req

    def get_request(self, request_id: int) -> Optional[Dict]:
        """Get request details."""
        req = self._get_request(request_id)
        if not req:
            return None
        return {
            "id": req.id,
            "method": req.method,
            "url": req.url,
            "headers": req.headers,
            "body": req.body,
            "timestamp": req.timestamp,
            "response_status": req.response_status,
            "response_body": req.response_body[:2000],
            "response_time_ms": req.response_time_ms,
            "modified": req.modified,
            "notes": req.notes,
        }

    def _get_request(self, request_id: int) -> Optional[InterceptedRequest]:
        for req in self.intercepted:
            if req.id == request_id:
                return req
        return None

    def search(self, keyword: str) -> List[Dict]:
        """Search intercepted requests."""
        results = []
        for req in self.intercepted:
            if keyword.lower() in req.url.lower() or keyword.lower() in req.body.lower():
                results.append({
                    "id": req.id,
                    "method": req.method,
                    "url": req.url,
                    "status": req.response_status,
                    "notes": req.notes,
                })
        return results

    def export_har(self) -> str:
        """Export all requests as HAR format."""
        har = {
            "log": {
                "version": "1.2",
                "entries": []
            }
        }
        for req in self.intercepted:
            har["log"]["entries"].append({
                "startedDateTime": req.timestamp,
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                    "postData": {"text": req.body} if req.body else None,
                },
                "response": {
                    "status": req.response_status,
                    "headers": [{"name": k, "value": v} for k, v in req.response_headers.items()],
                    "content": {"text": req.response_body[:2000]},
                },
                "time": req.response_time_ms,
            })
        return json.dumps(har, indent=2)

    def get_stats(self) -> Dict:
        return {
            "total_intercepted": len(self.intercepted),
            "modified": sum(1 for r in self.intercepted if r.modified),
            "rules": len(self.intercept_rules),
            "avg_response_ms": (
                sum(r.response_time_ms for r in self.intercepted) / len(self.intercepted)
                if self.intercepted else 0
            )
        }
