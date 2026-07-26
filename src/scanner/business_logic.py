"""Business Logic Scanner — tests for logic flaws and workflow abuse.

Covers:
- Negative quantity / price manipulation
- Step skipping in multi-step processes
- Force browsing / parameter tampering
- Race conditions
- Trust boundary violations
- Input length abuse
- File upload bypass
- API abuse (mass assignment, parameter pollution)
"""

import re
import time
import json
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

import httpx

from ..core.logger import logger, console, log_tool_start, log_tool_result
from ..core.ratelimit import get_limiter
from .findings import Finding


class BusinessLogicScanner:
    """Tests for business logic vulnerabilities."""

    NAME = "business_logic"

    def __init__(self, rps: float = 10.0):
        self.limiter = get_limiter(rps)
        self.rps = rps

    def _make_client(self, **kwargs) -> httpx.Client:
        defaults = {"timeout": 15, "verify": False, "follow_redirects": True,
                     "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}}
        defaults.update(kwargs)
        return httpx.Client(**defaults)

    def _get_host(self, url: str) -> str:
        return urlparse(url).hostname or url

    def scan_url(self, url: str, **kwargs) -> List[Finding]:
        """Scanner interface — runs all business logic tests."""
        findings = []
        console.print(f"  [tool]▸ Business Logic[/tool] → [target]{url}[/target]")
        findings.extend(self.test_negative_quantity(url))
        findings.extend(self.test_price_manipulation(url))
        findings.extend(self.test_step_skipping(url))
        findings.extend(self.test_force_browsing(url))
        findings.extend(self.test_parameter_tampering(url))
        findings.extend(self.test_race_conditions(url))
        findings.extend(self.test_trust_boundary(url))
        findings.extend(self.test_input_length(url))
        findings.extend(self.test_file_upload_bypass(url))
        findings.extend(self.test_api_abuse(url))
        console.print(f"  [tool]◂ Business Logic[/tool] — {len(findings)} findings")
        return findings

    # ──────────────────────────────────────────────────────────────
    #  1. Negative Quantity
    # ──────────────────────────────────────────────────────────────

    def test_negative_quantity(self, url: str) -> List[Finding]:
        """Test if application accepts negative quantities."""
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            # Find numeric parameters that might represent quantities
            quantity_params = ["quantity", "qty", "amount", "count", "num", "number", "total"]

            # Check existing query parameters
            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            # Also try common quantity param names
            for p in quantity_params:
                if p not in params_to_test:
                    params_to_test[p] = "1"

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name in list(params_to_test.keys()):
                if param_name.lower() in quantity_params or params_to_test[param_name].lstrip('-').isdigit():
                    # Try negative value via GET
                    test_params = dict(params_to_test)
                    test_params[param_name] = "-1"
                    self.limiter.wait(self._get_host(url))
                    try:
                        resp_get = client.get(base_url, params=test_params)
                        if resp_get.status_code == 200 and "error" not in resp_get.text.lower()[:500]:
                            findings.append(Finding(
                                vuln_type="Negative Quantity Accepted (GET)",
                                title=f"Negative quantity accepted in GET parameter: {param_name}",
                                severity="MEDIUM",
                                url=base_url,
                                parameter=param_name,
                                method="GET",
                                payload=f"{param_name}=-1",
                                evidence=f"GET {param_name}=-1 returned {resp_get.status_code} without error",
                                description=f"Parameter '{param_name}' accepts negative values. This could allow credit/refund abuse.",
                                remediation="Validate that quantity parameters are positive integers server-side.",
                                cvss=5.3, cwe="CWE-20", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

                    # Try negative value via POST
                    self.limiter.wait(self._get_host(url))
                    try:
                        post_data = dict(test_params)
                        resp_post = client.post(base_url, data=post_data)
                        if resp_post.status_code in (200, 201, 302) and "error" not in resp_post.text.lower()[:500]:
                            findings.append(Finding(
                                vuln_type="Negative Quantity Accepted (POST)",
                                title=f"Negative quantity accepted in POST parameter: {param_name}",
                                severity="HIGH",
                                url=base_url,
                                parameter=param_name,
                                method="POST",
                                payload=json.dumps({param_name: -1}),
                                evidence=f"POST {param_name}=-1 returned {resp_post.status_code}",
                                description=f"POST parameter '{param_name}' accepts negative values. Potential financial abuse.",
                                remediation="Validate quantities are positive on the server side.",
                                cvss=6.5, cwe="CWE-20", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

            # Try JSON body with negative values
            self.limiter.wait(self._get_host(url))
            try:
                resp_json = client.post(base_url, json={"quantity": -1, "amount": -100, "price": -50})
                if resp_json.status_code in (200, 201, 302):
                    body_lower = resp_json.text.lower()
                    if "error" not in body_lower and "invalid" not in body_lower:
                        findings.append(Finding(
                            vuln_type="Negative Values in JSON Body",
                            title="API accepts negative values in JSON body",
                            severity="HIGH",
                            url=base_url,
                            method="POST",
                            payload='{"quantity": -1, "amount": -100}',
                            evidence=f"JSON POST with negative values returned {resp_json.status_code}",
                            description="API accepts negative numeric values in JSON body.",
                            remediation="Validate all numeric inputs are within expected ranges.",
                            cvss=6.5, cwe="CWE-20", tool="business_logic",
                            verified=True, confidence="MEDIUM",
                        ))
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  2. Price Manipulation
    # ──────────────────────────────────────────────────────────────

    def test_price_manipulation(self, url: str) -> List[Finding]:
        """Test if user can manipulate price in requests."""
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            price_params = ["price", "cost", "amount", "total", "subtotal", "discount", "rate", "fee"]
            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Check if price-like parameters exist in URL
            for param_name, param_value in params_to_test.items():
                if param_name.lower() in price_params:
                    # Try modifying the value
                    try:
                        original_val = float(param_value)
                        modified_val = original_val * 0.01  # 1% of original

                        test_params = dict(params_to_test)
                        test_params[param_name] = str(modified_val)

                        self.limiter.wait(self._get_host(url))
                        resp = client.get(base_url, params=test_params)
                        if resp.status_code in (200, 302) and "error" not in resp.text.lower()[:500]:
                            findings.append(Finding(
                                vuln_type="Price Manipulation",
                                title=f"Price parameter '{param_name}' can be modified",
                                severity="CRITICAL",
                                url=base_url,
                                parameter=param_name,
                                method="GET",
                                payload=f"{param_name}={modified_val}",
                                evidence=f"Changed {param_name} from {param_value} to {modified_val}",
                                description=f"Price parameter '{param_name}' is modifiable by the user.",
                                remediation="Calculate prices server-side. Never trust client-sent prices.",
                                cvss=9.1, cwe="CWE-472", tool="business_logic",
                                verified=True, confidence="HIGH",
                            ))
                    except (ValueError, TypeError):
                        pass

            # Test via JSON body
            for param_name in price_params:
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.post(base_url, json={
                        "product_id": 1,
                        param_name: 0.01,
                        "quantity": 1,
                    })
                    if resp.status_code in (200, 201, 302):
                        body = resp.text.lower()
                        if param_name in body and "error" not in body[:500]:
                            findings.append(Finding(
                                vuln_type="Price Manipulation via JSON",
                                title=f"Price field '{param_name}' accepted in JSON body",
                                severity="CRITICAL",
                                url=base_url,
                                method="POST",
                                payload=json.dumps({param_name: 0.01}),
                                evidence=f"POST with {param_name}=0.01 returned {resp.status_code}",
                                description=f"Server accepts client-provided '{param_name}' field.",
                                remediation="Calculate prices server-side from product catalog.",
                                cvss=9.1, cwe="CWE-472", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass

            # Check for hidden price fields in HTML forms
            self.limiter.wait(self._get_host(url))
            try:
                resp = client.get(url)
                # Look for hidden fields with price-like values
                hidden_fields = re.findall(
                    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
                    resp.text, re.IGNORECASE
                )
                for name, value in hidden_fields:
                    if any(kw in name.lower() for kw in price_params):
                        try:
                            float(value)  # Verify it's numeric
                            findings.append(Finding(
                                vuln_type="Hidden Price Field",
                                title=f"Hidden price field in form: {name}={value}",
                                severity="HIGH",
                                url=url,
                                parameter=name,
                                payload=f"{name}={value}",
                                evidence=f'<input type="hidden" name="{name}" value="{value}">',
                                description=f"Hidden field '{name}' contains a price value that can be modified.",
                                remediation="Remove price from hidden fields. Calculate server-side.",
                                cvss=8.1, cwe="CWE-472", tool="business_logic",
                                verified=True, confidence="HIGH",
                            ))
                        except ValueError:
                            pass
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  3. Step Skipping
    # ──────────────────────────────────────────────────────────────

    def test_step_skipping(self, url: str) -> List[Finding]:
        """Test if multi-step processes can be skipped."""
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)
            path = parsed.path

            # Pattern: /checkout/step/2, /wizard/3, /flow?step=3
            step_path_patterns = [
                (r"(/(?:checkout|wizard|flow|process|step|order)/)(\d+)", "path"),
                (r"(step)=(\d+)", "query"),
            ]

            for pattern, location in step_path_patterns:
                match = re.search(pattern, path if location == "path" else parsed.query or "")
                if match:
                    prefix = match.group(1)
                    current_step = int(match.group(2))

                    if current_step > 1:
                        # Try jumping to step 1 (bypass)
                        for skip_to in [1, current_step - 1]:
                            if location == "path":
                                skip_path = re.sub(pattern, f"{prefix}{skip_to}", path)
                                skip_url = f"{parsed.scheme}://{parsed.netloc}{skip_path}"
                            else:
                                skip_query = re.sub(pattern, f"step={skip_to}", parsed.query)
                                skip_url = f"{parsed.scheme}://{parsed.netloc}{path}?{skip_query}"

                            self.limiter.wait(self._get_host(url))
                            try:
                                resp = client.get(skip_url)
                                if resp.status_code == 200:
                                    # Check if it's the actual step content (not a redirect back)
                                    if len(resp.text) > 200:
                                        findings.append(Finding(
                                            vuln_type="Step Skipping",
                                            title=f"Multi-step bypass: step {current_step} → {skip_to}",
                                            severity="MEDIUM",
                                            url=skip_url,
                                            evidence=f"Step {skip_to} returned {resp.status_code} with content",
                                            description="User can skip steps in a multi-step process.",
                                            remediation="Enforce step order server-side. Track progress in session.",
                                            cvss=5.3, cwe="CWE-841", tool="business_logic",
                                            verified=True, confidence="MEDIUM",
                                        ))
                            except Exception:
                                pass
                    break

            # Test common multi-step endpoints
            multi_step_paths = [
                "/checkout", "/checkout/step/2", "/checkout/step/3",
                "/order/confirm", "/order/review", "/order/complete",
                "/apply/step2", "/apply/step3", "/register/complete",
            ]
            for path in multi_step_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url, follow_redirects=False)
                    if resp.status_code == 200:
                        # Check if the page has form action pointing to next step
                        next_step_match = re.search(r'action=["\']([^"\']*step\d+[^"\']*)["\']', resp.text, re.IGNORECASE)
                        if next_step_match:
                            # Try to access the final step directly
                            final_url = urljoin(test_url, "/order/complete")
                            resp_final = client.get(final_url, follow_redirects=False)
                            if resp_final.status_code == 200 and "complete" in resp_final.text.lower():
                                findings.append(Finding(
                                    vuln_type="Step Skipping — Final Step Accessible",
                                    title=f"Can skip to final step from: {path}",
                                    severity="HIGH",
                                    url=final_url,
                                    evidence=f"Final step returned {resp_final.status_code}",
                                    description="User can directly access the final step, bypassing validation steps.",
                                    remediation="Track user progress. Validate all steps are completed.",
                                    cvss=7.5, cwe="CWE-841", tool="business_logic",
                                    verified=True, confidence="MEDIUM",
                                ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  4. Force Browsing
    # ──────────────────────────────────────────────────────────────

    def test_force_browsing(self, url: str) -> List[Finding]:
        """Test if admin/privileged pages are accessible directly."""
        findings = []
        sensitive_paths = [
            ("/admin", "Admin dashboard"),
            ("/admin/dashboard", "Admin dashboard"),
            ("/admin/users", "User management"),
            ("/admin/settings", "System settings"),
            ("/admin/config", "Configuration"),
            ("/admin/logs", "Access logs"),
            ("/management", "Management console"),
            ("/internal", "Internal tools"),
            ("/api/admin", "Admin API"),
            ("/api/v1/admin", "Admin API v1"),
            ("/console", "System console"),
            ("/monitoring", "Monitoring dashboard"),
            ("/actuator", "Spring Actuator"),
            ("/actuator/env", "Environment variables"),
            ("/actuator/beans", "Spring beans"),
            ("/debug", "Debug interface"),
            ("/debug/vars", "Debug variables"),
            ("/status", "Server status"),
            ("/metrics", "Metrics endpoint"),
        ]

        try:
            client = self._make_client(follow_redirects=False)
            for path, description in sensitive_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 200:
                        body_lower = resp.text.lower()
                        # Verify it's not a login page redirect or generic page
                        if any(kw in body_lower for kw in ["admin", "dashboard", "management", "settings", "users", "config", "monitoring"]):
                            if "login" not in body_lower[:500] and "sign in" not in body_lower[:500]:
                                findings.append(Finding(
                                    vuln_type="Force Browsing",
                                    title=f"Unauthenticated access: {description} ({path})",
                                    severity="HIGH",
                                    url=test_url,
                                    evidence=f"GET {test_url} returned {resp.status_code} with {description.lower()} content",
                                    description=f"{description} at '{path}' is accessible without authentication.",
                                    remediation="Implement proper authentication and authorization checks.",
                                    cvss=8.1, cwe="CWE-284", tool="business_logic",
                                    verified=True, confidence="HIGH",
                                ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  5. Parameter Tampering
    # ──────────────────────────────────────────────────────────────

    def test_parameter_tampering(self, url: str) -> List[Finding]:
        """Test if hidden/readonly parameters can be tampered with."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Find hidden form fields
            hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*>'
            hidden_fields = re.findall(hidden_pattern, body, re.IGNORECASE)

            sensitive_hidden = []
            for field in hidden_fields:
                name_match = re.search(r'name=["\']([^"\']*)["\']', field, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', field, re.IGNORECASE)
                if name_match and value_match:
                    name = name_match.group(1)
                    value = value_match.group(1)
                    # Check for sensitive hidden fields
                    if any(kw in name.lower() for kw in [
                        "role", "admin", "price", "discount", "type", "level",
                        "permission", "access", "credit", "balance", "total",
                        "is_admin", "user_type", "account_type", "privilege",
                    ]):
                        sensitive_hidden.append((name, value))

            for name, value in sensitive_hidden:
                # Try escalating the value
                tamper_values = []
                if value.lower() in ("0", "false", "no", "user", "normal"):
                    tamper_values = ["1", "true", "yes", "admin", "administrator", "superadmin"]
                elif value.isdigit():
                    tamper_values = [str(int(value) + 100), "99999", "0", "-1"]
                else:
                    tamper_values = [f"{value}_admin", "admin", "true", "1"]

                for tamper_val in tamper_values:
                    self.limiter.wait(self._get_host(url))
                    try:
                        # Find the form action
                        form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.IGNORECASE)
                        form_action = urljoin(url, form_match.group(1)) if form_match else url

                        resp = client.post(form_action, data={name: tamper_val})
                        if resp.status_code in (200, 201, 302):
                            findings.append(Finding(
                                vuln_type="Hidden Parameter Tampering",
                                title=f"Hidden field '{name}' can be tampered: {value} → {tamper_val}",
                                severity="HIGH",
                                url=form_action,
                                parameter=name,
                                method="POST",
                                payload=f"{name}={tamper_val}",
                                evidence=f"Modified hidden field '{name}' from '{value}' to '{tamper_val}', got {resp.status_code}",
                                description=f"Hidden field '{name}' is modifiable. Original: '{value}', tampered: '{tamper_val}'.",
                                remediation="Don't trust client-side parameters. Validate all values server-side.",
                                cvss=7.5, cwe="CWE-472", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                            break
                    except Exception:
                        pass

            # Check for readonly fields that can be modified
            readonly_pattern = r'<input[^>]*readonly[^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']'
            readonly_fields = re.findall(readonly_pattern, body, re.IGNORECASE)

            for name, value in readonly_fields:
                if any(kw in name.lower() for kw in ["price", "amount", "total", "discount", "balance"]):
                    findings.append(Finding(
                        vuln_type="Readonly Field Tampering Risk",
                        title=f"Readonly field contains sensitive data: {name}={value}",
                        severity="MEDIUM",
                        url=url,
                        parameter=name,
                        payload=f"{name}={value}",
                        evidence=f'<input readonly name="{name}" value="{value}">',
                        description=f"Readonly field '{name}' contains a value that can be modified via browser devtools.",
                        remediation="Validate all values server-side. Readonly is a client-side control only.",
                        cvss=6.5, cwe="CWE-472", tool="business_logic",
                        verified=True, confidence="HIGH",
                    ))

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  6. Race Conditions
    # ──────────────────────────────────────────────────────────────

    def test_race_conditions(self, url: str) -> List[Finding]:
        """Test for race condition vulnerabilities."""
        findings = []
        try:
            client = self._make_client()

            # Test if the same action can be performed concurrently
            # Look for action endpoints
            action_paths = [
                "/api/transfer", "/api/withdraw", "/api/redeem",
                "/api/coupon", "/api/vote", "/api/like",
                "/transfer", "/withdraw", "/redeem",
            ]

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in action_paths:
                test_url = urljoin(url, path)
                self.limiter.wait(self._get_host(url))
                try:
                    # Send the same request multiple times rapidly
                    import concurrent.futures
                    results = []

                    def make_request():
                        try:
                            c = self._make_client()
                            resp = c.post(test_url, json={"action": "test", "amount": 1})
                            result = (resp.status_code, resp.text[:200])
                            c.close()
                            return result
                        except Exception as e:
                            return (0, str(e))

                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        futures = [executor.submit(make_request) for _ in range(5)]
                        results = [f.result() for f in concurrent.futures.as_completed(futures)]

                    # Check if multiple requests succeeded
                    success_count = sum(1 for status, _ in results if status in (200, 201))
                    if success_count > 1:
                        findings.append(Finding(
                            vuln_type="Race Condition",
                            title=f"Potential race condition at {path}",
                            severity="HIGH",
                            url=test_url,
                            evidence=f"{success_count}/5 concurrent requests succeeded",
                            description="Multiple concurrent requests to the same action endpoint succeed. Possible race condition.",
                            remediation="Implement idempotency keys. Use database-level locking.",
                            cvss=7.5, cwe="CWE-362", tool="business_logic",
                            verified=False, confidence="MEDIUM",
                        ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  7. Trust Boundary
    # ──────────────────────────────────────────────────────────────

    def test_trust_boundary(self, url: str) -> List[Finding]:
        """Test if user can cross trust boundaries."""
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            # Test IDOR-like patterns (cross-user access)
            path = parsed.path
            segments = path.split("/")

            # Look for user/account ID in path
            id_patterns = [r"user", r"account", r"profile", r"member", r"customer"]
            for i, seg in enumerate(segments):
                if any(p in seg.lower() for p in id_patterns):
                    # Check if next segment is an ID
                    if i + 1 < len(segments) and segments[i + 1]:
                        original_id = segments[i + 1]
                        # Try adjacent IDs
                        for delta in [1, -1, 2]:
                            try:
                                new_id = str(int(original_id) + delta)
                                new_segments = list(segments)
                                new_segments[i + 1] = new_id
                                new_path = "/".join(new_segments)
                                test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                                if parsed.query:
                                    test_url += f"?{parsed.query}"

                                self.limiter.wait(self._get_host(url))
                                resp = client.get(test_url)
                                if resp.status_code == 200 and len(resp.text) > 200:
                                    findings.append(Finding(
                                        vuln_type="Trust Boundary Violation",
                                        title=f"Cross-user access: changed {original_id} → {new_id}",
                                        severity="HIGH",
                                        url=test_url,
                                        evidence=f"Accessing user {new_id} returned {resp.status_code} with data",
                                        description=f"User can access other users' data by changing ID from '{original_id}' to '{new_id}'.",
                                        remediation="Implement proper authorization. Map resources to authenticated user.",
                                        cvss=7.5, cwe="CWE-639", tool="business_logic",
                                        verified=False, confidence="MEDIUM",
                                    ))
                                    break
                            except ValueError:
                                pass
                    break

            # Test privilege escalation via role parameter
            if parsed.query:
                params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                for param_name, param_value in params.items():
                    if "role" in param_name.lower() or "type" in param_name.lower():
                        for escalated_value in ["admin", "administrator", "superuser", "root"]:
                            test_params = dict(params)
                            test_params[param_name] = escalated_value
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                            self.limiter.wait(self._get_host(url))
                            try:
                                resp = client.get(test_url, params=test_params)
                                if resp.status_code == 200 and "admin" in resp.text.lower():
                                    findings.append(Finding(
                                        vuln_type="Privilege Escalation",
                                        title=f"Role escalation: {param_name}={escalated_value}",
                                        severity="CRITICAL",
                                        url=test_url,
                                        parameter=param_name,
                                        payload=f"{param_name}={escalated_value}",
                                        evidence=f"Set {param_name}={escalated_value}, got {resp.status_code} with admin content",
                                        description=f"User can escalate privileges by setting {param_name} to '{escalated_value}'.",
                                        remediation="Never accept role/privilege from client. Determine server-side.",
                                        cvss=9.8, cwe="CWE-269", tool="business_logic",
                                        verified=True, confidence="MEDIUM",
                                    ))
                                    break
                            except Exception:
                                pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  8. Input Length
    # ──────────────────────────────────────────────────────────────

    def test_input_length(self, url: str) -> List[Finding]:
        """Test if application handles excessive input lengths."""
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            # Test with extremely long input
            long_string = "A" * 10000

            params_to_test = {}
            if parsed.query:
                params_to_test = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

            common_params = ["name", "comment", "message", "description", "text", "input", "search", "query"]
            for p in common_params:
                if p not in params_to_test:
                    params_to_test[p] = "test"

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name in params_to_test:
                test_params = dict(params_to_test)
                test_params[param_name] = long_string

                self.limiter.wait(self._get_host(url))
                try:
                    resp = client.get(base_url, params=test_params)
                    if resp.status_code == 200:
                        findings.append(Finding(
                            vuln_type="Excessive Input Length Accepted",
                            title=f"10,000+ char input accepted in: {param_name}",
                            severity="LOW",
                            url=base_url,
                            parameter=param_name,
                            payload=f"{param_name}={'A' * 10000}...",
                            evidence=f"10,000 character input accepted (HTTP {resp.status_code})",
                            description=f"Parameter '{param_name}' accepts extremely long input. May cause DoS or buffer issues.",
                            remediation="Enforce maximum input length on server side.",
                            cvss=3.1, cwe="CWE-119", tool="business_logic",
                            verified=True, confidence="MEDIUM",
                        ))
                except Exception:
                    pass

            # Test POST with large body
            self.limiter.wait(self._get_host(url))
            try:
                large_payload = {"data": "X" * 100000}
                resp = client.post(base_url, json=large_payload, timeout=30)
                if resp.status_code in (200, 201):
                    findings.append(Finding(
                        vuln_type="Large POST Body Accepted",
                        title="API accepts 100KB+ POST body without limit",
                        severity="LOW",
                        url=base_url,
                        method="POST",
                        evidence=f"100KB POST body accepted (HTTP {resp.status_code})",
                        description="API accepts very large request bodies. Potential for DoS.",
                        remediation="Set maximum request body size.",
                        cvss=3.1, cwe="CWE-119", tool="business_logic",
                        verified=True, confidence="MEDIUM",
                    ))
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  9. File Upload Bypass
    # ──────────────────────────────────────────────────────────────

    def test_file_upload_bypass(self, url: str) -> List[Finding]:
        """Test for file upload bypass techniques."""
        findings = []
        try:
            client = self._make_client()
            resp = client.get(url)
            body = resp.text

            # Look for file upload forms
            upload_forms = re.findall(
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*action=["\']([^"\']*)["\'][^>]*>',
                body, re.IGNORECASE
            )

            if not upload_forms:
                # Check for file input fields
                file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', body, re.IGNORECASE)
                if file_inputs:
                    upload_forms = [url]  # Form posts to same URL

            for form_action in upload_forms:
                upload_url = urljoin(url, form_action)

                # Bypass techniques to test
                bypass_tests = [
                    # Double extension
                    ("test.php.jpg", "application/octet-stream", b"<?php echo 'test'; ?>", "Double extension"),
                    # Content-Type mismatch
                    ("test.jpg", "image/jpeg", b"<?php echo 'test'; ?>", "Content-Type mismatch"),
                    # Null byte
                    ("test.php\x00.jpg", "application/octet-stream", b"<?php echo 'test'; ?>", "Null byte injection"),
                    # SVG with script
                    ("test.svg", "image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "SVG XSS"),
                    # HTML file
                    ("test.html", "text/html", b'<script>alert("XSS")</script>', "HTML upload"),
                    # .htaccess
                    (".htaccess", "application/octet-stream", b"AddType application/x-httpd-php .jpg", ".htaccess upload"),
                ]

                for filename, content_type, content, technique in bypass_tests:
                    self.limiter.wait(self._get_host(url))
                    try:
                        # Find the file input name
                        file_input_match = re.search(
                            r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']*)["\']',
                            body, re.IGNORECASE
                        )
                        file_field = file_input_match.group(1) if file_input_match else "file"

                        resp = client.post(
                            upload_url,
                            files={file_field: (filename, content, content_type)},
                            follow_redirects=False,
                        )

                        if resp.status_code in (200, 201, 302):
                            body_lower = resp.text.lower()
                            # Check if upload was accepted
                            if "error" not in body_lower[:500] and "invalid" not in body_lower[:500] and "denied" not in body_lower[:500]:
                                findings.append(Finding(
                                    vuln_type="File Upload Bypass",
                                    title=f"File upload bypass: {technique}",
                                    severity="HIGH" if technique in ("Double extension", "Null byte injection", ".htaccess upload") else "MEDIUM",
                                    url=upload_url,
                                    payload=f"filename={filename}, content-type={content_type}",
                                    evidence=f"Upload of '{filename}' returned {resp.status_code} without error",
                                    description=f"File upload accepts '{technique}' bypass technique.",
                                    remediation="Validate file content (magic bytes), not just extension. Use allowlists.",
                                    cvss=7.5, cwe="CWE-434", tool="business_logic",
                                    verified=True, confidence="MEDIUM",
                                ))
                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    # ──────────────────────────────────────────────────────────────
    #  10. API Abuse
    # ──────────────────────────────────────────────────────────────

    def test_api_abuse(self, url: str) -> List[Finding]:
        """Test for API abuse: mass assignment, parameter pollution, batch ops."""
        findings = []

        # Mass assignment
        findings.extend(self._api_mass_assignment(url))
        # HTTP parameter pollution
        findings.extend(self._api_parameter_pollution(url))
        # Batch operations
        findings.extend(self._api_batch_operations(url))

        return findings

    def _api_mass_assignment(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()

            # Try adding admin/privileged fields
            extra_fields = [
                {"role": "admin"},
                {"is_admin": True},
                {"admin": True},
                {"permissions": "all"},
                {"user_type": "admin"},
                {"access_level": 999},
                {"verified": True},
                {"active": True},
            ]

            for extra in extra_fields:
                self.limiter.wait(self._get_host(url))
                try:
                    # Try as JSON
                    resp = client.post(url, json={
                        "username": "testuser",
                        "email": "test@example.com",
                        **extra,
                    })
                    if resp.status_code in (200, 201):
                        body = resp.text.lower()
                        field_name = list(extra.keys())[0]
                        if field_name in body or str(list(extra.values())[0]).lower() in body:
                            findings.append(Finding(
                                vuln_type="Mass Assignment",
                                title=f"Mass assignment: {field_name} field accepted",
                                severity="HIGH",
                                url=url,
                                method="POST",
                                payload=json.dumps(extra),
                                evidence=f"Response contains '{field_name}' field",
                                description=f"Server accepts and reflects extra field '{field_name}'.",
                                remediation="Use allowlists for accepted fields.",
                                cvss=7.5, cwe="CWE-915", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                except Exception:
                    pass

            client.close()
        except Exception:
            pass
        return findings

    def _api_parameter_pollution(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()
            parsed = urlparse(url)

            if parsed.query:
                params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                for param_name, param_value in params.items():
                    # Try sending duplicate parameter
                    dup_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}={param_value}&{param_name}=admin"
                    self.limiter.wait(self._get_host(url))
                    try:
                        resp = client.get(dup_url)
                        if resp.status_code == 200 and "admin" in resp.text.lower():
                            findings.append(Finding(
                                vuln_type="HTTP Parameter Pollution",
                                title=f"Parameter pollution: {param_name} (duplicate values)",
                                severity="MEDIUM",
                                url=dup_url,
                                parameter=param_name,
                                payload=f"{param_name}={param_value}&{param_name}=admin",
                                evidence=f"Duplicate parameter '{param_name}' with 'admin' returned {resp.status_code}",
                                description=f"Server processes duplicate '{param_name}' parameter. May cause confusion.",
                                remediation="Reject duplicate parameters. Use first or last value consistently.",
                                cvss=5.3, cwe="CWE-20", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass

            client.close()
        except Exception:
            pass
        return findings

    def _api_batch_operations(self, url: str) -> List[Finding]:
        findings = []
        try:
            client = self._make_client()

            # Try array body
            self.limiter.wait(self._get_host(url))
            try:
                batch_payload = [
                    {"action": "test", "id": 1},
                    {"action": "test", "id": 2},
                    {"action": "test", "id": 3},
                ]
                resp = client.post(url, json=batch_payload)
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 1:
                            findings.append(Finding(
                                vuln_type="Batch API Operations",
                                title="API accepts batch operations (array body)",
                                severity="LOW",
                                url=url,
                                method="POST",
                                evidence=f"Batch of {len(batch_payload)} operations accepted, returned {len(data)} results",
                                description="API accepts batch operations. May bypass rate limiting.",
                                remediation="Limit batch size. Apply rate limits per-operation.",
                                cvss=3.1, cwe="CWE-770", tool="business_logic",
                                verified=True, confidence="MEDIUM",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

            client.close()
        except Exception:
            pass
        return findings
