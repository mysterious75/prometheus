"""API Discovery — Auto-discover API endpoints from OpenAPI/Swagger specs.

Inspired by Brutecat's Google hacking approach:
"Discovery documents are essentially Google's equivalent of Swagger docs —
machine-readable API specifications that list all available endpoints,
parameters, and methods."

This module:
1. Discovers OpenAPI/Swagger specs at common paths
2. Parses specs to extract all endpoints
3. Groups endpoints by category (read, write, admin)
4. Generates test requests for each endpoint
"""

import re
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.logger import logger, console
from ..core.ratelimit import get_limiter


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    summary: str = ""
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    request_body: Optional[Dict] = None
    responses: Dict[str, Any] = field(default_factory=dict)
    security: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    operation_id: str = ""
    
    @property
    def category(self) -> str:
        """Categorize endpoint by method and path."""
        if self.method in ("DELETE",):
            return "destructive"
        if self.method in ("POST", "PUT", "PATCH"):
            return "write"
        if any(kw in self.path.lower() for kw in ["admin", "manage", "config", "settings"]):
            return "admin"
        if any(kw in self.path.lower() for kw in ["auth", "login", "token", "oauth"]):
            return "auth"
        return "read"
    
    @property
    def risk_level(self) -> str:
        """Assess risk level of endpoint."""
        if self.category == "admin":
            return "HIGH"
        if self.category == "auth":
            return "HIGH"
        if self.category == "destructive":
            return "HIGH"
        if self.category == "write":
            return "MEDIUM"
        # Check for sensitive paths
        sensitive = ["user", "password", "secret", "key", "token", "payment", "billing"]
        if any(s in self.path.lower() for s in sensitive):
            return "MEDIUM"
        return "LOW"


@dataclass
class APISpec:
    """Parsed API specification."""
    title: str = ""
    version: str = ""
    base_url: str = ""
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: Dict[str, Any] = field(default_factory=dict)
    servers: List[str] = field(default_factory=list)
    raw_spec: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_endpoints(self) -> int:
        return len(self.endpoints)
    
    @property
    def by_category(self) -> Dict[str, List[APIEndpoint]]:
        cats = {}
        for ep in self.endpoints:
            cats.setdefault(ep.category, []).append(ep)
        return cats
    
    @property
    def high_risk_endpoints(self) -> List[APIEndpoint]:
        return [ep for ep in self.endpoints if ep.risk_level == "HIGH"]


class APIDiscovery:
    """Auto-discovers and parses API specifications.
    
    Common OpenAPI/Swagger paths:
    - /swagger.json
    - /swagger/v1/swagger.json
    - /api-docs
    - /openapi.json
    - /openapi/v1.json
    - /v1/api-docs
    - /v2/api-docs
    - /api/swagger.json
    - /api/openapi.json
    - /.well-known/openapi.json
    - /graphql (introspection)
    """
    
    # Common paths where API specs are found
    SPEC_PATHS = [
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger/v2/swagger.json",
        "/api-docs",
        "/api-docs/v1",
        "/api-docs/v2",
        "/openapi.json",
        "/openapi/v1.json",
        "/openapi/v2.json",
        "/openapi/v3.json",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/v1/swagger.json",
        "/api/v2/swagger.json",
        "/api/v1/openapi.json",
        "/api/v2/openapi.json",
        "/api/spec",
        "/api/specification",
        "/api/docs",
        "/docs/swagger.json",
        "/docs/openapi.json",
        "/swagger-ui/swagger.json",
        "/swagger-resources",
        "/api/swagger-resources",
        "/.well-known/openapi.json",
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
    ]
    
    def __init__(self, rps: float = 5.0):
        self.limiter = get_limiter(rps)
    
    def discover(self, base_url: str) -> APISpec:
        """Discover API endpoints from a target.
        
        1. Try common spec paths
        2. Parse discovered specs
        3. Extract all endpoints
        4. Categorize and assess risk
        """
        import httpx
        
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip("/")
        
        console.print(f"\n[bold cyan]API Discovery: {base_url}[/bold cyan]")
        
        spec = APISpec()
        client = httpx.Client(
            follow_redirects=True,
            timeout=10,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        
        # Try each spec path
        for path in self.SPEC_PATHS:
            url = f"{base_url}{path}"
            self.limiter.wait(urlparse(base_url).hostname)
            
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    
                    # Try to parse as JSON
                    if "json" in content_type or resp.text.strip().startswith("{"):
                        try:
                            data = resp.json()
                            parsed = self._parse_spec(data, base_url)
                            if parsed and parsed.endpoints:
                                console.print(f"  [green]✓ Found API spec at {path}[/green]")
                                console.print(f"    Endpoints: {len(parsed.endpoints)}")
                                spec = parsed
                                spec.base_url = base_url
                                client.close()
                                return spec
                        except (json.JSONDecodeError, KeyError):
                            pass
                    
                    # Try GraphQL introspection
                    if "graphql" in path.lower():
                        gql_result = self._graphql_introspection(client, url)
                        if gql_result:
                            spec = gql_result
                            spec.base_url = base_url
                            client.close()
                            return spec
                            
            except Exception:
                continue
        
        # If no spec found, try to discover from HTML/JS
        console.print("  [dim]No API spec found, analyzing HTML/JS...[/dim]")
        spec = self._discover_from_html(client, base_url)
        spec.base_url = base_url
        
        client.close()
        return spec
    
    def _parse_spec(self, data: Dict, base_url: str) -> Optional[APISpec]:
        """Parse OpenAPI/Swagger specification."""
        spec = APISpec(raw_spec=data)
        
        # OpenAPI 3.x
        if "openapi" in data:
            spec.title = data.get("info", {}).get("title", "")
            spec.version = data.get("info", {}).get("version", "")
            spec.servers = [s.get("url", "") for s in data.get("servers", [])]
            spec.security_schemes = data.get("components", {}).get("securitySchemes", {})
            
            for path, methods in data.get("paths", {}).items():
                for method, details in methods.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                        ep = APIEndpoint(
                            path=path,
                            method=method.upper(),
                            summary=details.get("summary", ""),
                            description=details.get("description", ""),
                            parameters=details.get("parameters", []),
                            request_body=details.get("requestBody"),
                            responses=details.get("responses", {}),
                            security=details.get("security", []),
                            tags=details.get("tags", []),
                            operation_id=details.get("operationId", ""),
                        )
                        spec.endpoints.append(ep)
        
        # Swagger 2.x
        elif "swagger" in data:
            spec.title = data.get("info", {}).get("title", "")
            spec.version = data.get("info", {}).get("version", "")
            host = data.get("host", "")
            base_path = data.get("basePath", "")
            schemes = data.get("schemes", ["https"])
            if host:
                spec.servers = [f"{schemes[0]}://{host}{base_path}"]
            
            for path, methods in data.get("paths", {}).items():
                for method, details in methods.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        ep = APIEndpoint(
                            path=path,
                            method=method.upper(),
                            summary=details.get("summary", ""),
                            description=details.get("description", ""),
                            parameters=details.get("parameters", []),
                            responses=details.get("responses", {}),
                            tags=details.get("tags", []),
                            operation_id=details.get("operationId", ""),
                        )
                        spec.endpoints.append(ep)
        
        return spec if spec.endpoints else None
    
    def _graphql_introspection(self, client, url: str) -> Optional[APISpec]:
        """Run GraphQL introspection query."""
        introspection_query = {
            "query": """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                        }
                    }
                }
            }
            """
        }
        
        try:
            resp = client.post(url, json=introspection_query)
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    schema = data["data"]["__schema"]
                    spec = APISpec(title="GraphQL API", version="1.0")
                    
                    # Extract query fields
                    query_type = schema.get("queryType", {}).get("name", "Query")
                    mutation_type = schema.get("mutationType", {}).get("name", "Mutation")
                    
                    for t in schema.get("types", []):
                        if t["name"] == query_type:
                            for f in t.get("fields", []):
                                spec.endpoints.append(APIEndpoint(
                                    path=f"/graphql",
                                    method="POST",
                                    summary=f"Query: {f['name']}",
                                    tags=["graphql", "query"],
                                    operation_id=f["name"],
                                ))
                        elif t["name"] == mutation_type:
                            for f in t.get("fields", []):
                                spec.endpoints.append(APIEndpoint(
                                    path=f"/graphql",
                                    method="POST",
                                    summary=f"Mutation: {f['name']}",
                                    tags=["graphql", "mutation"],
                                    operation_id=f["name"],
                                ))
                    
                    console.print(f"  [green]✓ GraphQL introspection: {len(spec.endpoints)} operations[/green]")
                    return spec
        except Exception as e:
            logger.debug(f"GraphQL introspection failed: {e}")
        
        return None
    
    def _discover_from_html(self, client, base_url: str) -> APISpec:
        """Discover API endpoints from HTML page and JavaScript files."""
        spec = APISpec()
        
        try:
            resp = client.get(base_url)
            body = resp.text
            
            # Find API-like URLs in HTML
            api_patterns = [
                r'["\']/(api/[^"\']+)["\']',
                r'["\']/(v[123]/[^"\']+)["\']',
                r'["\']/(graphql[^"\']*)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.\w+\(["\']([^"\']+)["\']',
                r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            ]
            
            found_paths = set()
            for pattern in api_patterns:
                matches = re.findall(pattern, body)
                for match in matches:
                    if match.startswith("/") and not match.startswith("//"):
                        found_paths.add(match)
            
            # Check for JavaScript files and extract endpoints
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
            for js_url in js_urls[:5]:  # Limit to 5 JS files
                if not js_url.startswith("http"):
                    js_url = f"{base_url}{js_url}"
                try:
                    js_resp = client.get(js_url)
                    if js_resp.status_code == 200:
                        js_paths = self._extract_from_js(js_resp.text)
                        found_paths.update(js_paths)
                except Exception:
                    continue
            
            # Convert found paths to endpoints
            for path in found_paths:
                ep = APIEndpoint(
                    path=path,
                    method="GET",
                    summary=f"Discovered from HTML/JS",
                    tags=["discovered"],
                )
                spec.endpoints.append(ep)
            
            if spec.endpoints:
                console.print(f"  [green]✓ Discovered {len(spec.endpoints)} endpoints from HTML/JS[/green]")
            
        except Exception as e:
            logger.debug(f"HTML discovery failed: {e}")
        
        return spec
    
    def _extract_from_js(self, js_content: str) -> set:
        """Extract API endpoints from JavaScript code."""
        paths = set()
        
        patterns = [
            r'["\']/(api/[^"\']+)["\']',
            r'["\']/(v[123]/[^"\']+)["\']',
            r'["\']/(graphql[^"\']*)["\']',
            r'["\'](/[a-z][a-z0-9_-]+/[a-z][a-z0-9_-/]+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith("/") and len(match) > 3 and not match.startswith("//"):
                    paths.add(match)
        
        return paths
    
    def generate_test_requests(self, spec: APISpec) -> List[Dict]:
        """Generate test requests for discovered endpoints."""
        tests = []
        
        for ep in spec.endpoints:
            test = {
                "path": ep.path,
                "method": ep.method,
                "category": ep.category,
                "risk": ep.risk_level,
                "summary": ep.summary,
            }
            
            # Generate sample parameters
            if ep.parameters:
                test["params"] = {}
                for param in ep.parameters:
                    if isinstance(param, dict):
                        name = param.get("name", "")
                        param_type = param.get("schema", {}).get("type", "string")
                        if param_type == "integer":
                            test["params"][name] = 1
                        elif param_type == "boolean":
                            test["params"][name] = True
                        else:
                            test["params"][name] = "test"
            
            # Generate sample body for POST/PUT/PATCH
            if ep.request_body and ep.method in ("POST", "PUT", "PATCH"):
                content = ep.request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema = json_content.get("schema", {})
                if schema:
                    test["body"] = self._generate_sample_body(schema)
            
            tests.append(test)
        
        return tests
    
    def _generate_sample_body(self, schema: Dict) -> Dict:
        """Generate sample request body from schema."""
        body = {}
        
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        for name, prop in properties.items():
            prop_type = prop.get("type", "string")
            
            if prop_type == "string":
                if "enum" in prop:
                    body[name] = prop["enum"][0]
                elif "format" in prop:
                    if prop["format"] == "email":
                        body[name] = "test@example.com"
                    elif prop["format"] == "date":
                        body[name] = "2026-01-01"
                    elif prop["format"] == "uri":
                        body[name] = "https://example.com"
                    else:
                        body[name] = "test"
                else:
                    body[name] = "test"
            elif prop_type == "integer":
                body[name] = 1
            elif prop_type == "number":
                body[name] = 1.0
            elif prop_type == "boolean":
                body[name] = True
            elif prop_type == "array":
                body[name] = []
            elif prop_type == "object":
                body[name] = self._generate_sample_body(prop)
        
        return body


# Export
__all__ = ["APIDiscovery", "APISpec", "APIEndpoint"]
