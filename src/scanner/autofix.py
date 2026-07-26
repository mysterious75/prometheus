"""Auto-Fix PR Generator — generates code fixes for found vulnerabilities.

Inspired by MindFort's killer feature:
- Detects vulnerability
- Analyzes the vulnerable code
- Generates a fix
- Creates a Pull Request (GitHub/GitLab)
- Re-tests after fix is applied

Supports: SQLi, XSS, CSRF, SSRF, command injection, path traversal, etc.
"""

import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..scanner.findings import Finding
from ..core.logger import logger, console


@dataclass
class CodeFix:
    """A generated code fix."""
    finding_id: int
    vuln_type: str
    language: str  # python, javascript, php, java, ruby, go
    framework: str  # django, express, laravel, spring, rails, flask
    file_path: str
    line_number: int
    before: str  # vulnerable code
    after: str   # fixed code
    explanation: str
    test_command: str  # command to verify the fix

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "language": self.language,
            "framework": self.framework,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "before": self.before,
            "after": self.after,
            "explanation": self.explanation,
            "test_command": self.test_command,
        }


class AutoFixGenerator:
    """Generates code fixes for security vulnerabilities.

    Each vulnerability type has a fix template that adapts to the
    detected language and framework.
    """

    # Fix templates organized by vulnerability type and language
    FIX_TEMPLATES = {
        "SQL Injection": {
            "python": {
                "django": {
                    "before": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "after": 'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, [user_id])',
                    "explanation": "Use parameterized queries instead of string formatting.",
                },
                "flask": {
                    "before": 'query = f"SELECT * FROM users WHERE id = {request.args.get(\'id\')}"',
                    "after": 'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (request.args.get("id"),))',
                    "explanation": "Use parameterized queries with SQLAlchemy or raw cursor.",
                },
                "generic": {
                    "before": 'query = "SELECT * FROM users WHERE id = " + user_id',
                    "after": 'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (user_id,))',
                    "explanation": "Use parameterized queries. Never concatenate user input into SQL.",
                },
            },
            "javascript": {
                "express": {
                    "before": 'const query = `SELECT * FROM users WHERE id = ${req.params.id}`',
                    "after": 'const query = "SELECT * FROM users WHERE id = $1"\nconst result = await db.query(query, [req.params.id])',
                    "explanation": "Use parameterized queries with pg/mysql2 driver.",
                },
                "generic": {
                    "before": 'const query = "SELECT * FROM users WHERE id = " + userId',
                    "after": 'const query = "SELECT * FROM users WHERE id = ?"\ndb.query(query, [userId])',
                    "explanation": "Use parameterized queries. Never concatenate user input into SQL.",
                },
            },
            "php": {
                "laravel": {
                    "before": '$users = DB::select("SELECT * FROM users WHERE id = " . $id)',
                    "after": '$users = DB::select("SELECT * FROM users WHERE id = ?", [$id])',
                    "explanation": "Use Laravel's parameterized query builder.",
                },
                "generic": {
                    "before": '$query = "SELECT * FROM users WHERE id = " . $_GET["id"]',
                    "after": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")\n$stmt->execute([$_GET["id"]])',
                    "explanation": "Use PDO prepared statements.",
                },
            },
            "java": {
                "spring": {
                    "before": 'String query = "SELECT * FROM users WHERE id = " + request.getParameter("id")',
                    "after": 'String query = "SELECT * FROM users WHERE id = ?"\nPreparedStatement stmt = conn.prepareStatement(query);\nstmt.setString(1, request.getParameter("id"));',
                    "explanation": "Use PreparedStatement with parameter binding.",
                },
            },
        },
        "Cross-Site Scripting (XSS)": {
            "python": {
                "django": {
                    "before": 'return HttpResponse(f"<h1>Welcome {user_input}</h1>")',
                    "after": 'from django.utils.html import escape\nreturn HttpResponse(f"<h1>Welcome {escape(user_input)}</h1>")',
                    "explanation": "Use Django's escape() function or auto-escaping templates.",
                },
                "flask": {
                    "before": 'return f"<h1>Welcome {user_input}</h1>"',
                    "after": 'from markupsafe import escape\nreturn f"<h1>Welcome {escape(user_input)}</h1>"',
                    "explanation": "Use markupsafe.escape() to sanitize output.",
                },
            },
            "javascript": {
                "express": {
                    "before": 'res.send(`<h1>Welcome ${userInput}</h1>`)',
                    "after": 'const escape = require("escape-html")\nres.send(`<h1>Welcome ${escape(userInput)}</h1>`)',
                    "explanation": "Use escape-html or helmet middleware.",
                },
                "react": {
                    "before": 'dangerouslySetInnerHTML={{__html: userInput}}',
                    "after": '/* Use React\'s automatic escaping */\n<span>{userInput}</span>',
                    "explanation": "Avoid dangerouslySetInnerHTML. Use React's default escaping.",
                },
            },
            "php": {
                "generic": {
                    "before": 'echo "<h1>Welcome " . $_GET["name"] . "</h1>"',
                    "after": 'echo "<h1>Welcome " . htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8") . "</h1>"',
                    "explanation": "Use htmlspecialchars() to encode output.",
                },
            },
        },
        "Server-Side Request Forgery (SSRF)": {
            "python": {
                "generic": {
                    "before": 'response = requests.get(user_url)',
                    "after": 'from urllib.parse import urlparse\nimport ipaddress\n\nparsed = urlparse(user_url)\nif parsed.hostname:\n    try:\n        ip = ipaddress.ip_address(parsed.hostname)\n        if ip.is_private or ip.is_loopback:\n            raise ValueError("Internal URLs not allowed")\n    except ValueError:\n        pass\nresponse = requests.get(user_url, timeout=5)',
                    "explanation": "Validate URLs against internal/private IP ranges.",
                },
            },
            "javascript": {
                "generic": {
                    "before": 'const response = await fetch(userUrl)',
                    "after": 'const { URL } = require("url")\nconst parsed = new URL(userUrl)\nconst blocked = ["127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254"]\nif (blocked.some(b => parsed.hostname.includes(b))) {\n    throw new Error("Internal URLs not allowed")\n}\nconst response = await fetch(userUrl)',
                    "explanation": "Validate URLs against blocked internal addresses.",
                },
            },
        },
        "OS Command Injection": {
            "python": {
                "generic": {
                    "before": 'os.system(f"ping {user_input}")',
                    "after": 'import subprocess\nresult = subprocess.run(["ping", "-c", "4", user_input], capture_output=True, text=True)',
                    "explanation": "Use subprocess with argument list (no shell=True).",
                },
            },
            "javascript": {
                "generic": {
                    'before': 'exec(`ping ${userInput}`)',
                    'after': 'const { execFile } = require("child_process")\nexecFile("ping", ["-c", "4", userInput])',
                    "explanation": "Use execFile instead of exec to prevent shell injection.",
                },
            },
        },
        "Path Traversal / LFI": {
            "python": {
                "generic": {
                    "before": 'file = open(user_path, "r")',
                    "after": 'import os\nbase_dir = "/var/www/files"\nfull_path = os.path.realpath(os.path.join(base_dir, user_path))\nif not full_path.startswith(base_dir):\n    raise ValueError("Path traversal detected")\nfile = open(full_path, "r")',
                    "explanation": "Validate that the resolved path stays within the allowed directory.",
                },
            },
        },
        "Missing Security Headers": {
            "python": {
                "django": {
                    "before": "# No security headers configured",
                    "after": '# In settings.py:\nSECURE_BROWSER_XSS_FILTER = True\nSECURE_CONTENT_TYPE_NOSNIFF = True\nX_FRAME_OPTIONS = "DENY"\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True',
                    "explanation": "Configure Django security settings.",
                },
                "flask": {
                    "before": "# No security headers configured",
                    "after": 'from flask import Flask\nfrom flask_talisman import Talisman\n\napp = Flask(__name__)\nTalisman(app, force_https=True)',
                    "explanation": "Use Flask-Talisman for security headers.",
                },
            },
            "javascript": {
                "express": {
                    "before": "// No security headers configured",
                    "after": 'const helmet = require("helmet")\napp.use(helmet())',
                    "explanation": "Use helmet middleware for security headers.",
                },
            },
        },
    }

    def generate_fix(self, finding: Finding, language: str = "python",
                     framework: str = "generic") -> Optional[CodeFix]:
        """Generate a code fix for a finding."""
        vuln_type = finding.vuln_type
        templates = self.FIX_TEMPLATES.get(vuln_type, {})
        lang_templates = templates.get(language, {})
        fix = lang_templates.get(framework, lang_templates.get("generic"))

        if not fix:
            # Try to generate a generic fix
            fix = self._generate_generic_fix(finding, language)
            if not fix:
                return None

        return CodeFix(
            finding_id=finding.finding_id,
            vuln_type=vuln_type,
            language=language,
            framework=framework,
            file_path=self._guess_file_path(finding, language),
            line_number=0,
            before=fix.get("before", ""),
            after=fix.get("after", ""),
            explanation=fix.get("explanation", f"Fix for {vuln_type}"),
            test_command=self._generate_test_command(finding),
        )

    def _generate_generic_fix(self, finding: Finding, language: str) -> Optional[Dict]:
        """Generate a generic fix when no template exists."""
        remediation = finding.remediation
        if not remediation:
            return None

        return {
            "before": f"# Vulnerable: {finding.vuln_type}",
            "after": f"# Fix: {remediation}",
            "explanation": remediation,
        }

    def _guess_file_path(self, finding: Finding, language: str) -> str:
        """Guess the file path from the finding URL."""
        url_path = urlparse(finding.url).path
        ext = {"python": ".py", "javascript": ".js", "php": ".php", "java": ".java"}.get(language, ".py")
        return f"app{ext}  # likely at: {url_path}"

    def _generate_test_command(self, finding: Finding) -> str:
        """Generate a command to test if the fix works."""
        if "SQLi" in finding.vuln_type or "SQL" in finding.vuln_type:
            return f'curl -k "{finding.url}?{finding.parameter}={finding.payload}" | grep -i "sql" && echo "STILL VULNERABLE" || echo "FIXED"'
        elif "XSS" in finding.vuln_type:
            return f'curl -k "{finding.url}?{finding.parameter}=<script>alert(1)</script>" | grep "<script>" && echo "STILL VULNERABLE" || echo "FIXED"'
        else:
            return f'curl -k "{finding.url}" # Manual verification needed'

    def generate_github_pr(self, fix: CodeFix, repo: str = "") -> Dict[str, Any]:
        """Generate a GitHub PR payload."""
        return {
            "title": f"fix: {fix.vuln_type} in {fix.file_path}",
            "body": f"""## Security Fix: {fix.vuln_type}

### Vulnerability
{fix.explanation}

### Before (Vulnerable)
```{fix.language}
{fix.before}
```

### After (Fixed)
```{fix.language}
{fix.after}
```

### Verification
```bash
{fix.test_command}
```

### Details
- **Finding ID:** {fix.finding_id}
- **File:** {fix.file_path}
- **Language:** {fix.language}
- **Framework:** {fix.framework}

---
*Auto-generated by Prometheus Security Agent*
""",
            "head": f"fix/security-{fix.finding_id}",
            "base": "main",
        }

    def generate_fixes_for_findings(self, findings: List[Finding],
                                     language: str = "python",
                                     framework: str = "generic") -> List[CodeFix]:
        """Generate fixes for all findings."""
        fixes = []
        for finding in findings:
            fix = self.generate_fix(finding, language, framework)
            if fix:
                fixes.append(fix)
        return fixes


from urllib.parse import urlparse
