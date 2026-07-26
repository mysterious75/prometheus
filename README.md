<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:16213e&height=220&section=header&text=Prometheus&fontSize=80&fontColor=e94560&fontAlignY=35&desc=AI-Powered%20Security%20Testing%20Platform&descSize=18&descAlignY=55&animation=fadeIn" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/mysterious75/prometheus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-00d4aa?style=for-the-badge&logo=none" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-252_passing-00d4aa?style=for-the-badge&logo=none" alt="Tests">
  <img src="https://img.shields.io/badge/scanners-27-e94560?style=for-the-badge&logo=none" alt="Scanners">
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

Prometheus is an **open-source, AI-powered security testing platform** that autonomously discovers and validates vulnerabilities in web applications, APIs, networks, and cloud infrastructure.

<table>
<tr>
<td width="50%">

**Why Prometheus?**

- **27 vulnerability scanners** with adversarial validation
- **5-stage pipeline** (Recon, Hunt, Validate, Trace, Report)
- **777 core payloads** + 2,861 WAF bypass variants
- **1,242+ report knowledge base**
- **Skill/plugin system** with on-demand loading
- **API auto-discovery** (OpenAPI/Swagger/GraphQL)
- **403/401 bypass testing** (39 techniques)
- **Anti-bot detection** (11 WAF systems, 5 CAPTCHAs)
- **Deep JS analysis** (endpoints, secrets, cloud URLs)
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

### 27 Vulnerability Scanners

<table>
<tr>
<td>

**Injection (6)**
- SQL Injection (198 patterns, 8 DBMS)
- XSS (context-aware, DOM, stored, WAF bypass)
- Command Injection (Linux + Windows)
- SSTI (Jinja2, Twig, Freemarker, Velocity, ERB, Pug)
- XXE (file read, SSRF, blind)
- HTTP Smuggling (CL.TE / TE.CL / TE.TE)

</td>
<td>

**Access & Logic (7)**
- IDOR / BOLA (multi-session)
- Advanced IDOR (UUID, encoded, JWT, GraphQL)
- Auth Bypass (default creds, admin panels)
- Path Traversal (30+ encoding bypasses)
- Open Redirect (28 bypass techniques)
- CORS Misconfiguration
- Race Conditions

</td>
<td>

**Configuration (6)**
- Exposed Secrets (25 regex patterns)
- Security Headers (10 critical headers)
- SSL/TLS/Crypto (weak ciphers, cert validation)
- Business Logic (price manipulation, step skipping)
- Session Management (cookie flags, CSRF, JWT)
- OWASP Methodology (12 phases)

</td>
</tr>
<tr>
<td>

**Bypass & Detection (4)**
- 403/401 Bypass (39 techniques)
- Anti-Bot Detection (11 WAFs, 5 CAPTCHAs)
- Fingerprinting Detection (Canvas, WebGL, Audio)
- JS Analysis (endpoints, secrets, cloud URLs)

</td>
<td>

**API & Infrastructure (2)**
- API Security (REST, GraphQL, JWT, OAuth)
- API Auto-Discovery (OpenAPI/Swagger/GraphQL)

</td>
<td>

**Reporting (2)**
- Executive Report (risk matrix, compliance mapping)
- Attack Surface Change Detection

</td>
</tr>
</table>

### 403/401 Bypass Scanner (39 Techniques)

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

```
777 Core Payloads
├── SQLi: 235  ├── XSS: 194  ├── SSRF: 73
├── CMDi: 78   ├── SSTI: 43  ├── Others: 154

Dynamic Variant Generation (7 types)
├── URL encoding    ├── Double URL encoding
├── HTML entity     ├── Unicode
├── Case variation  ├── Comment injection
└── Whitespace substitution

Result: 2,861+ effective payloads with WAF bypass
```

### 5-Stage Pipeline

```
Stage 1  RECON      Fast model       Subdomains, ports, HTTP, crawl, API discovery
Stage 2  HUNT       Primary model    Run all 27 vulnerability scanners
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
├── scanner/                   Vulnerability detection (27 scanners)
│   ├── sqli.py                SQL Injection (198 patterns, 8 DBMS)
│   ├── xss.py                 XSS (context-aware, DOM, stored)
│   ├── ssrf.py                SSRF (23 cloud, 32 internal targets)
│   ├── bypass_403.py          403/401 bypass (39 techniques)
│   ├── antibot.py             Anti-bot detection (16 systems)
│   ├── idor_advanced.py       Advanced IDOR (UUID, encoded, JWT)
│   ├── js_analyzer.py         Deep JS analysis (10 categories)
│   ├── surface_tracker.py     Attack surface change detection
│   ├── adversarial.py         Adversarial validation
│   ├── payload_engine.py      777 core payloads + variants
│   ├── payload_importer.py    PayloadsAllTheThings importer
│   ├── api_discovery.py       OpenAPI/Swagger/GraphQL discovery
│   ├── owasp_methodology.py   OWASP Testing Guide v4
│   ├── business_logic.py      Business logic testing
│   ├── session_manager.py     Session management
│   ├── crypto_scanner.py      SSL/TLS/crypto
│   ├── api_security.py        API security
│   └── executive_report.py    Executive report generator
│
├── skills/                    Skill/plugin system (8 YAML files)
├── tools/                     External tool wrappers (6 tools)
├── brain/                     LLM router (14 providers)
├── knowledge/                 Knowledge base (1,242+ reports)
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
| **Pro** | $19/mo | Rs.1,499/mo | Unlimited URLs, all 27 scanners, API |
| **Team** | $99/mo | Rs.7,499/mo | + 5 members, continuous scanning, CI/CD |
| **Enterprise** | $299/mo | Rs.22,499/mo | + SSO, on-prem, custom playbooks, SLA |

---

## Testing

```bash
python -m pytest tests/ -v
```

**252 passing, 100% pass rate**

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
| [Brutecat](https://brutecat.com/articles/hacking-google-with-ai/) | API discovery technique | Blog |
| [Joseph Thacker](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html) | Hackbot methodology | Blog |
| [Niels Provos](https://www.provos.org/p/finding-zero-days-with-any-model/) | Orchestration > model | Blog |
| Security research community | 1,242+ bug bounty reports | Various |

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
