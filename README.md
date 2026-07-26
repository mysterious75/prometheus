<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:16213e&height=220&section=header&text=Prometheus&fontSize=80&fontColor=e94560&fontAlignY=35&desc=Automated%20Security%20Testing%20Platform&descSize=18&descAlignY=55&animation=fadeIn" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/mysterious75/prometheus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-00d4aa?style=for-the-badge&logo=none" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-322_passing-00d4aa?style=for-the-badge&logo=none" alt="Tests">
  <img src="https://img.shields.io/badge/scanners-41-e94560?style=for-the-badge&logo=none" alt="Scanners">
  <img src="https://img.shields.io/badge/payloads-777-ff6b35?style=for-the-badge&logo=none" alt="Payloads">
  <img src="https://img.shields.io/badge/API-REST-6c5ce7?style=for-the-badge&logo=fastapi&logoColor=white" alt="API">
</p>

<p align="center">
  <b>Find real vulnerabilities. Validate with proof-of-concept. Generate executive reports.</b>
</p>

<p align="center">
  <a href="#-installation">Installation</a> &bull;
  <a href="#-features">Features</a> &bull;
  <a href="#-commands">Commands</a> &bull;
  <a href="#-api">API</a> &bull;
  <a href="#-architecture">Architecture</a> &bull;
  <a href="#-pricing">Pricing</a>
</p>

---

## Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
>
> Users must obtain proper authorization before testing any target. Unauthorized access to computer systems is illegal in most jurisdictions. The authors are not responsible for any misuse of this tool. All scanning requires explicit target authorization (`authorize <target>`).
>
> See [SECURITY.md](SECURITY.md) for full security policy.

---

## What Is Prometheus?

Prometheus is an **open-source automated security testing platform** that autonomously discovers and validates vulnerabilities in web applications, APIs, networks, and cloud infrastructure.

<table>
<tr>
<td width="50%">

**Why Prometheus?**

- **41 vulnerability scanners** with adversarial validation
- **5-stage pipeline** (Recon, Hunt, Validate, Trace, Report)
- **777 core payloads** with WAF bypass variants (10,000+ at runtime)
- **300+ real security advisories** (from GitHub Advisory Database + NVD)
- **Skill/plugin system** with on-demand loading
- **API auto-discovery** (OpenAPI/Swagger/GraphQL)
- **403/401 bypass testing** (39 + 24 enhanced techniques)
- **Anti-bot detection** (11 WAF systems, 5 CAPTCHAs)
- **Deep JS analysis** (10 categories, noise filtering)
- **154 sensitive file paths** probed automatically
- **ORM injection detection** (Django, SQLAlchemy, MongoDB)
- **Mass assignment testing** (50 privilege escalation payloads)
- **Subdomain takeover** (37 cloud service fingerprints)
- **WordPress scanner** (version, plugins, xmlrpc, user enum)
- **Attack surface change detection**
- **Works offline** — no API keys needed
- **REST API** for automation & CI/CD

</td>
<td width="50%">

**Supported Platforms**

| Platform | Status |
|----------|--------|
| Linux (Ubuntu/Debian) | Fully supported |
| Linux (Fedora/RHEL) | Fully supported |
| Linux (Arch) | Fully supported |
| macOS (Intel + Apple Silicon) | Fully supported |
| Windows 10/11 | Supported (PowerShell) |
| Docker | Supported |
| WSL2 | Fully supported |

</td>
</tr>
</table>

---

## Installation

### Linux (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m src.entry
```

### Linux (Fedora / RHEL)

```bash
sudo dnf install -y python3 python3-pip git
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m src.entry
```

### Linux (Arch)

```bash
sudo pacman -S python python-pip git
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m src.entry
```

### macOS

```bash
brew install python3 git
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m src.entry
```

### Windows (PowerShell)

```powershell
git clone https://github.com/mysterious75/prometheus.git
cd prometheus
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m src.entry
```

### Windows (WSL2 — Recommended)

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m src.entry
```

### Docker

```bash
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
docker build -t prometheus .
docker run -it prometheus
```

### One-Command Install (Linux/macOS)

```bash
git clone https://github.com/mysterious75/prometheus.git && cd prometheus && bash install.sh
```

### pip Install

```bash
git clone https://github.com/mysterious75/prometheus.git && cd prometheus
pip install -e .
prometheus
```

---

## First Scan

```bash
prometheus                          # Start interactive CLI
authorize example.com               # Authorize target
scan example.com                    # Full autonomous scan
```

### Quick Commands

```bash
prometheus scan example.com          # Full autonomous scan
prometheus owasp https://target.com  # OWASP methodology
prometheus crypto target.com         # SSL/TLS analysis
prometheus quick target.com          # Fast scan
prometheus stealth target.com        # Stealthy scan
```

### REST API

```bash
python -m src.api.app               # Start API server
# Docs at http://localhost:8000/docs
```

### Python Library

```python
from src.main import Prometheus
p = Prometheus()
result = p.assess("example.com")
```

---

## Features

### 55 Vulnerability Scanners

<table>
<tr>
<td>

**Injection (9)**
- SQL Injection (198 patterns, 8 DBMS)
- XSS (context-aware, DOM, stored, WAF bypass)
- Command Injection (Linux + Windows)
- SSTI (Jinja2, Twig, Freemarker, Velocity, ERB, Pug)
- XXE (file read, SSRF, blind)
- HTTP Smuggling (CL.TE / TE.CL / TE.TE)
- CRLF Injection (response splitting, header injection)
- ORM Injection (Django, SQLAlchemy, MongoDB, GraphQL)
- CSV Injection (formula injection in exports)

</td>
<td>

**Access & Logic (10)**
- IDOR / BOLA (multi-session)
- Advanced IDOR (UUID, encoded, JWT, GraphQL)
- IDOR JWT & GraphQL (claim manipulation, object-level auth)
- Auth Bypass (default creds, admin panels)
- Path Traversal (30+ encoding bypasses)
- Open Redirect (28 bypass techniques)
- CORS Misconfiguration
- Race Conditions
- Mass Assignment (50 privilege payloads, nested/array/dot-notation)
- HTTP Method Override (headers, query params, method cycling)

</td>
<td>

**Configuration (8)**
- Exposed Secrets (25 regex patterns)
- Security Headers (10 critical headers)
- SSL/TLS/Crypto (weak ciphers, cert validation)
- Business Logic (price manipulation, step skipping)
- Session Management (cookie flags, CSRF, JWT)
- OWASP Methodology (12 phases)
- File Disclosure (154 sensitive paths, secret detection)
- Dependency Confusion (private packages, registry exposure)

</td>
</tr>
<tr>
<td>

**Bypass & Detection (5)**
- 403/401 Bypass (39 techniques)
- Enhanced 403 Bypass (UA rotation, mid-path, nginx headers, method cycling)
- Anti-Bot Detection (11 WAFs, 5 CAPTCHAs)
- Fingerprinting Detection (Canvas, WebGL, Audio)
- JS Analysis (endpoints, secrets, cloud URLs)

</td>
<td>

**Platform-Specific (4)**
- WordPress (version, plugins, xmlrpc, user enum)
- Subdomain Takeover (37 cloud service fingerprints)
- CSS Injection (data exfil, UI redress, style injection)
- Google Dorking (72 dorks in 6 categories)

</td>
<td>

**API, AI & Reporting (5)**
- API Security (REST, GraphQL, JWT, OAuth)
- API Auto-Discovery (OpenAPI/Swagger/GraphQL)
- Payload engine with context-aware generation
- PayloadsAllTheThings Import (markdown/text/URL)
- Executive Report (risk matrix, compliance mapping)

</td>
</tr>
</table>

### 403/401 Bypass Scanner (63 Techniques Total)

Inspired by [NoMore403](https://github.com/devploit/nomore403):

```
Path Mutations (20)          Header Overrides (5)         IP Spoofing (10)
├─ //admin (double slash)    ├─ X-HTTP-Method-Override    ├─ X-Forwarded-For: 127.0.0.1
├─ /admin/ (trailing slash)  ├─ X-Method-Override         ├─ X-Real-IP: 127.0.0.1
├─ /admin/. (dot suffix)     ├─ X-HTTP-Method             ├─ X-Client-IP: 127.0.0.1
├─ /./admin (dot prefix)     ├─ X-Original-Method         ├─ X-Remote-Addr: 127.0.0.1
├─ /admin%20 (space)         └─ X-Rewrite-Method          └─ X-Host: localhost
├─ /admin%09 (tab)
├─ /admin%00 (null byte)
├─ /%2f/admin (encoded slash)
├─ /admin..;/ (semicolon)
├─ /admin.json (extension)
├─ /ADMIN (uppercase)
└─ ... (20 total)

Enhanced Bypass (24 more)    Protocol Bypass (4)
├─ User-Agent Rotation (12)  ├─ Content-Length: 0
│  ├─ Googlebot              ├─ Transfer-Encoding: chunked
│  ├─ Bingbot                ├─ Content-Type: application/json
│  ├─ curl                   └─ Content-Type: application/xml
│  └─ ... (12 total)
├─ Mid-Path Mutations (6)    Auto Method Cycling
├─ Nginx Headers (4)         ├─ PUT, PATCH, DELETE
│  ├─ X-Original-URL         ├─ OPTIONS, TRACE, HEAD
│  └─ X-Rewrite-URL          └─ Combined UA + Method
```

### Anti-Bot Detection (16 Systems)

```
WAF Detection (11)           CAPTCHA Detection (5)
├─ Cloudflare                ├─ reCAPTCHA
├─ Akamai                    ├─ hCaptcha
├─ DataDome                  ├─ FunCaptcha
├─ PerimeterX                ├─ GeeTest
├─ Shape Security            └─ Cloudflare Turnstile
├─ AWS WAF
├─ Imperva                   Fingerprinting (6)
├─ Kasada                    ├─ Canvas
├─ Sucuri                    ├─ WebGL
├─ Wordfence                 ├─ Audio
└─ ModSecurity               ├─ Font, WebRTC, Navigator
```

### Deep JS Analysis (10 Categories)

Inspired by [JSAnalyzer](https://github.com/jenish-sojitra/JSAnalyzer):

```
API Endpoints      /api/v1/users, /graphql, /rest/data
Cloud URLs         S3://, *.blob.core.windows.net, storage.googleapis.com
OAuth URLs         /oauth2/token, /auth/login, /callback
Secrets            AWS keys, GitHub tokens, Stripe keys, JWT, API keys
Sensitive Files    .sql, .csv, .bak, .env, .pem, .key
Emails             developer@company.com
Internal URLs      http://localhost, http://10.*, http://192.168.*
Comments           Developer comments with sensitive info
Credentials        password=, secret=, token=, apikey=
DOM XSS            document.location, innerHTML, eval()
```

### Sensitive File Disclosure (154 Paths)

```
Environment (15)       Version Control (6)    Backups (15)
├─ /.env               ├─ /.git/config        ├─ /backup.zip
├─ /.env.local         ├─ /.git/HEAD          ├─ /backup.sql
├─ /.env.production    ├─ /.svn/entries       ├─ /dump.sql
├─ /.env.staging       └─ /.hg/dirstate       └─ /db.sqlite3

Server/Admin (16)      Cloud (6)              CI/CD (9)
├─ /actuator/env       ├─ /.aws/credentials   ├─ /.github/workflows
├─ /server-status      ├─ /service-account    ├─ /.gitlab-ci.yml
├─ /phpinfo.php        └─ /.azure/credentials ├─ /Jenkinsfile
└─ /manager/html                               └─ /buildspec.yml

SSH/Keys (7)           Package (14)           WordPress (5)
├─ /id_rsa             ├─ /package.json       ├─ /wp-config.php.bak
├─ /.ssh/config        ├─ /composer.json      ├─ /xmlrpc.php
└─ /.npmrc             └─ /requirements.txt   └─ /wp-json/wp/v2/users

API/Debug (12)         Well-Known (6)         Misc (20+)
├─ /swagger.json       ├─ /.well-known/       ├─ /.DS_Store
├─ /graphql            │  security.txt        ├─ /robots.txt
├─ /metrics            └─ /.well-known/       └─ /crossdomain.xml
└─ /debug/pprof           openid-configuration
```

### ORM Injection Detection

Inspired by [real-world Django ORM exploits](https://blog.p1.gs/writeup/2025/07/06/Hacking-a-crypto-game/):

```
Django ORM Filters       NoSQL Injection        Error-Based Detection
├─ __contains            ├─ $gt / $ne           ├─ FieldError (Django)
├─ __startswith          ├─ $regex              ├─ Cannot resolve keyword
├─ __endswith            ├─ $where              ├─ ProgrammingError
├─ __gt / __gte / __lt   └─ MongoDB bypass      ├─ SequelizeDatabaseError
├─ __in                                            └─ PrismaClientKnownRequestError
├─ is_superuser / is_staff
└─ field traversal (user__is_admin)
```

### Mass Assignment (50 Privilege Payloads)

Inspired by [LostSec's mass assignment guide](https://infosecwriteups.com/uncovering-invisible-privileges-the-ultimate-guide-to-mass-assignment-in-registration-flows-9ecd5ff40512):

```
Direct Flags          Nested JSON           Array Bypass          Dot Notation
├─ role: "admin"      ├─ user.role          ├─ roles: ["admin"]   ├─ user.role
├─ is_admin: true     ├─ user.is_admin      ├─ permissions:       ├─ user.is_admin
├─ is_superuser: true ├─ account.type         ["admin"]           └─ account.type
├─ verified: true     └─ metadata.role      └─ groups:
├─ plan: "premium"                            ["administrators"]
└─ access_level: 999
```

### Subdomain Takeover (37 Services)

```
Cloud Storage     PaaS/Hosting      CDNs/Proxy     SaaS Platforms
├─ AWS S3         ├─ Heroku         ├─ Fastly      ├─ Shopify
├─ Azure Blob     ├─ Netlify        ├─ Cloudflare  ├─ Zendesk
├─ Azure Web App  ├─ Vercel         └─ Akamai      ├─ Tumblr
├─ GCP Storage    ├─ GitHub Pages                   ├─ WordPress.com
└─ Azure Traffic  ├─ Pantheon                       ├─ SurveyMonkey
   Manager        ├─ Webflow                        ├─ Intercom
                  └─ Kajabi                         └─ ... (37 total)
```

### Adversarial Validation

Three-stage validation eliminates false positives:

```
Finding → Hunter (confirm) → Skeptic (disprove) → Referee (verdict)
                                                        │
                                    ┌───────────────────┼───────────────────┐
                                    │                   │                   │
                               CONFIRMED     LIKELY_FALSE_POS      FALSE_POSITIVE
                                    │                   │                   │
                                 KEEP              KEEP (low)            DROP
```

### Payload Engine

2,035 Core Payloads
├── SQLi: 607  ├── XSS: 342  ├── SSRF: 238
├── CMDi: 197  ├── SSTI: 163 ├── Others: 488

Dynamic Variant Generation (7 types)
├── URL encoding    ├── Double URL encoding
├── HTML entity     ├── Unicode
├── Case variation  ├── Comment injection
└── Whitespace substitution

External Import
├── PayloadsAllTheThings (markdown/text/URL)
├── Deduplication engine
└── Auto vuln-type mapping
```

### Context-Aware Payload Engine

Rule-based payload generation that adapts based on target fingerprinting:

```
Technology Detection          Vulnerability Context        Payload Adaptation
├─ PHP / Python / Java       ├─ Parameter name analysis   ├─ DBMS-specific SQLi
├─ Node / Ruby / .NET        ├─ Response content analysis  ├─ Framework-specific SSTI
├─ WordPress / Django        ├─ Header fingerprinting      ├─ Context-aware XSS
└─ Flask / Spring / Rails    └─ Error message analysis     └─ OS-specific CMDi
```

### 5-Stage Pipeline

```
Stage 1  RECON      Fast model       Subdomains, ports, HTTP, crawl, API discovery
Stage 2  HUNT       Primary model    Run all 41 vulnerability scanners
Stage 3  VALIDATE   Reasoning model  Adversarial review (Hunter-Skeptic-Referee)
Stage 4  TRACE      Primary model    Prove attacker input reaches vulnerable sink
Stage 5  REPORT     Fast model       Executive report with confirmed findings only
```

### Skill/Plugin System

8 YAML skill files with structured methodology, payloads, and detection patterns:

```
sqli.yml  xss.yml  ssrf.yml  idor.yml  auth_bypass.yml  api_security.yml  cloud_security.yml  session_mgmt.yml
```

---

## Commands

<table>
<tr>
<td>

**Assessment**
| Command | Description |
|---------|-------------|
| `scan <target>` | Full autonomous assessment |
| `recon <target>` | Reconnaissance only |
| `osint <target>` | OSINT (username/domain) |
| `quick <target>` | Fast scan (top vulns) |
| `stealth <target>` | Slow, stealthy scan |

</td>
<td>

**OWASP / Book-Based**
| Command | Description |
|---------|-------------|
| `owasp <target>` | OWASP Testing Guide v4 |
| `business <target>` | Business logic testing |
| `session <target>` | Session management |
| `crypto <target>` | SSL/TLS analysis |
| `api <target>` | API security |
| `report <target>` | Executive report |

</td>
<td>

**System**
| Command | Description |
|---------|-------------|
| `authorize <target>` | Authorize target |
| `revoke <target>` | Revoke authorization |
| `targets` | List authorized |
| `kb [query]` | Knowledge base |
| `history` | Previous scans |
| `pricing` | Pricing plans |
| `bounty` | Bug bounty programs |
| `status` | System status |
| `tools` | Tool availability |

</td>
</tr>
</table>

---

## API

FastAPI-based REST API for automation:

```bash
python -m src.api.app
# Docs at http://localhost:8000/docs
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Start a new scan |
| `GET` | `/scan/{id}` | Get scan status and results |
| `GET` | `/scans` | List all scans |
| `GET` | `/findings` | Get findings (filter by severity, type) |
| `GET` | `/report/{id}` | Get report (markdown or JSON) |
| `POST` | `/authorize` | Authorize a target |
| `GET` | `/targets` | List authorized targets |
| `GET` | `/status` | System status |
| `GET` | `/tools` | Tool availability |

---

## Architecture

```
src/
├── core/                      Foundation
│   ├── config.py              Configuration
│   ├── auth.py                Authorization-first security
│   ├── scope.py               Scope enforcement
│   ├── state.py               Scan state persistence (resume)
│   └── resources.py           System resource monitoring
│
├── agent/                     AI Agent brain
│   ├── orchestrator.py        Multi-agent orchestrator
│   ├── pipeline.py            5-stage pipeline
│   ├── recon_agent.py         Reconnaissance specialist
│   ├── scan_agent.py          Vulnerability scanning specialist
│   ├── exploit_agent.py       Exploit validation specialist
│   └── report_agent.py        Report generation specialist
│
├── scanner/                   Vulnerability detection (41 scanners)
│   ├── sqli.py                SQL Injection (198 patterns, 8 DBMS)
│   ├── xss.py                 XSS (context-aware, DOM, stored)
│   ├── ssrf.py                SSRF (23 cloud, 32 internal targets)
│   ├── cmdi.py                Command Injection (Linux + Windows)
│   ├── ssti.py                SSTI (6 template engines)
│   ├── xxe.py                 XXE (file read, SSRF, blind)
│   ├── traversal.py           Path Traversal (30+ bypasses)
│   ├── redirect.py            Open Redirect (28 techniques)
│   ├── cors.py                CORS Misconfiguration
│   ├── smuggling.py           HTTP Smuggling
│   ├── race.py                Race Conditions
│   ├── idor.py                IDOR / BOLA
│   ├── idor_advanced.py       Advanced IDOR (UUID, encoded)
│   ├── idor_jwt_graphql.py    IDOR JWT & GraphQL ← NEW
│   ├── auth.py                Auth Bypass
│   ├── secrets.py             Exposed Secrets (25 patterns)
│   ├── headers.py             Security Headers
│   ├── crypto_scanner.py      SSL/TLS/Crypto
│   ├── business_logic.py      Business Logic
│   ├── session_manager.py     Session Management
│   ├── owasp_methodology.py   OWASP Testing Guide v4
│   ├── api_security.py        API Security
│   ├── api_discovery.py       API Auto-Discovery
│   ├── bypass_403.py          403/401 Bypass (39 techniques)
│   ├── bypass_enhanced.py     Enhanced 403 Bypass ← NEW
│   ├── antibot.py             Anti-Bot Detection (16 systems)
│   ├── js_analyzer.py         Deep JS Analysis (10 categories)
│   ├── file_disclosure.py     Sensitive File Disclosure ← NEW
│   ├── orm_injection.py       ORM Injection Detection ← NEW
│   ├── mass_assignment.py     Mass Assignment Testing ← NEW
│   ├── http_method_override.py HTTP Method Override ← NEW
│   ├── crlf.py                CRLF Injection ← NEW
│   ├── csv_injection.py       CSV Injection ← NEW
│   ├── css_injection.py       CSS Injection ← NEW
│   ├── subdomain_takeover.py  Subdomain Takeover ← NEW
│   ├── wordpress.py           WordPress Scanner ← NEW
│   ├── google_dorking.py      Google Dorking ← NEW
│   ├── dependency_confusion.py Dependency Confusion ← NEW
│   ├── context_analyzer.py    Context-Aware Payload Generator ← NEW
│   ├── payload_engine.py      777 core payloads + variants
│   ├── payload_importer.py    PayloadsAllTheThings importer
│   ├── adversarial.py         Adversarial validation
│   ├── surface_tracker.py     Attack surface change detection
│   ├── internal_net.py        Internal network scanning
│   ├── evidence.py            Evidence collection
│   └── executive_report.py    Executive report generator
│
├── skills/                    Skill/plugin system (8 YAML files)
├── tools/                     External tool wrappers (6 tools)
├── brain/                     LLM router (14 providers)
├── knowledge/                 Knowledge base (300+ real advisories)
├── api/                       REST API (FastAPI)
├── market/                    Market features
├── cli/                       Interactive CLI
├── main.py                    Orchestrator (with LLM)
└── offline.py                 Orchestrator (without LLM)
```

---

## Tool Fallbacks

| Tool | Binary Mode | Fallback Mode | Fallback Size |
|------|-------------|---------------|---------------|
| Nuclei | 12,000+ YAML templates | HTTP path checks | 177 paths |
| Subfinder | 40+ passive sources | crt.sh + DNS brute force | 246 prefixes |
| httpx | HTTP probing | Python httpx | Full |
| SQLMap | SQLi exploitation | Basic SQLi payloads | 128 payloads |
| Sherlock | 400+ platforms | HTTP-based checking | 123 platforms |
| Nmap | Port scanning + service detection | Python socket | 320 ports |

---

## Supported LLM Providers

| Provider | Role | Free Tier |
|----------|------|-----------|
| DeepSeek | Primary | Cheap, long context |
| Gemini (1-3 keys) | Fast | 150K tokens/day each |
| OpenRouter | Fallback | Free models available |
| OpenAI | Backup | Paid |
| Anthropic | Backup | Paid |
| Qwen, Kimi, GLM | Backup | Free tier |

---

## Pricing

| Tier | USD | INR | Features |
|------|-----|-----|----------|
| **Free** | $0 | Rs.0 | 5 URLs/month, 5 scanners, CLI |
| **Pro** | $19/mo | Rs.1,499/mo | Unlimited URLs, all 41 scanners, API |
| **Team** | $99/mo | Rs.7,499/mo | + 5 members, continuous scanning, CI/CD |
| **Enterprise** | $299/mo | Rs.22,499/mo | + SSO, on-prem, custom playbooks, SLA |

---

## Testing

```bash
python -m pytest tests/ -v
```

**322 passing**

---

## Security

- **Authorization required** — Only scan authorized targets
- **Scope enforcement** — Hard block on out-of-scope targets
- **Rate limiting** — Configurable requests per second (default: 10)
- **Resource monitoring** — Auto-throttle if system overloaded
- **No shell injection** — Commands use argument lists, never `shell=True`
- **API keys stay local** — `.env` is gitignored
- **State persistence** — Scan progress saved to disk, resumable

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

| Project | Contribution | License |
|---------|--------------|---------|
| [ProjectDiscovery](https://github.com/projectdiscovery) | Nuclei, Subfinder, httpx | MIT |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | Skill system architecture | MIT |
| [codexstar69/bug-hunter](https://github.com/codexstar69/bug-hunter) | Adversarial validation pattern | MIT |
| [ZephrFish/harness-kit](https://github.com/ZephrFish/harness-kit) | 5-stage pipeline design | Public |
| [The-XSS-Rat/subScraper](https://github.com/The-XSS-Rat/subScraper) | Stateful scanning design | Public |
| [DevCop95/bugbounty-lab101](https://github.com/DevCop95/bugbounty-lab101) | Scope enforcement | MIT |
| [devploit/nomore403](https://github.com/devploit/nomore403) | 403/401 bypass techniques | MIT |
| [jenish-sojitra/JSAnalyzer](https://github.com/jenish-sojitra/JSAnalyzer) | JS analysis patterns | MIT |
| [0xSojalSec/sqlmap-ai](https://github.com/0xSojalSec/sqlmap-ai) | Adaptive SQLi testing | MIT |
| [scrapfly/Antibot-Detector](https://github.com/scrapfly/Antibot-Detector) | Anti-bot detection | MIT |
| [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload database | MIT |
| [KingOfBugbounty/KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips) | Recon methodology | MIT |
| [nahamsec](https://github.com/nahamsec) | Bug bounty tooling | Various |
| [Brutecat](https://brutecat.com/articles/hacking-google-with-ai/) | API discovery technique | Blog |
| [Joseph Thacker](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html) | Hackbot methodology | Blog |
| [Niels Provos](https://www.provos.org/p/finding-zero-days-with-any-model/) | Orchestration > model | Blog |
| Security research community | 300+ advisories (GHSA + NVD) | Various |

---

<p align="center">
  <b>Built for authorized security testing. Use responsibly.</b>
</p>

<p align="center">
  <a href="https://github.com/mysterious75/prometheus/issues">Report Bug</a> &bull;
  <a href="https://github.com/mysterious75/prometheus/issues">Request Feature</a>
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:16213e&height=120&section=footer&animation=fadeIn" width="100%"/>
</p>
