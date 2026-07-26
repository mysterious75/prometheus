<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:16213e&height=220&section=header&text=Prometheus&fontSize=80&fontColor=e94560&fontAlignY=35&desc=AI-Powered%20Security%20Testing%20Platform&descSize=18&descAlignY=55&animation=fadeIn" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/mysterious75/prometheus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-00d4aa?style=for-the-badge&logo=none" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-251_passing-00d4aa?style=for-the-badge&logo=none" alt="Tests">
  <img src="https://img.shields.io/badge/scanners-21-e94560?style=for-the-badge&logo=none" alt="Scanners">
  <img src="https://img.shields.io/badge/payloads-777-ff6b35?style=for-the-badge&logo=none" alt="Payloads">
  <img src="https://img.shields.io/badge/API-REST-6c5ce7?style=for-the-badge&logo=fastapi&logoColor=white" alt="API">
</p>

<p align="center">
  <b>Find real vulnerabilities. Validate with proof-of-concept. Generate executive reports.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-features">Features</a> &bull;
  <a href="#-architecture">Architecture</a> &bull;
  <a href="#-commands">Commands</a> &bull;
  <a href="#-api">API</a> &bull;
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

- **21 vulnerability scanners** with adversarial validation
- **5-stage pipeline** (Recon, Hunt, Validate, Trace, Report)
- **777 core payloads** + 2,861 WAF bypass variants
- **1,242+ report knowledge base**
- **Skill/plugin system** with on-demand loading
- **API auto-discovery** (OpenAPI/Swagger/GraphQL)
- **Works offline** — no API keys needed
- **REST API** for automation & CI/CD
- **Scope enforcement** — hard block out-of-scope

</td>
<td width="50%">

**Inspired By**

| Project | What We Learned |
|---------|-----------------|
| [Bug Hunter](https://github.com/codexstar69/bug-hunter) | Adversarial validation |
| [Claude-Red](https://github.com/SnailSploit/Claude-Red) | Skill system |
| [Harness Kit](https://github.com/ZephrFish/harness-kit) | 5-stage pipeline |
| [subScraper](https://github.com/The-XSS-Rat/subScraper) | State persistence |
| [IronCurtain](https://www.provos.org/p/finding-zero-days-with-any-model/) | Orchestration > model |
| [Brutecat](https://brutecat.com/articles/hacking-google-with-ai/) | API discovery |

</td>
</tr>
</table>

---

## Quick Start

### One-Command Install

```bash
git clone https://github.com/mysterious75/prometheus.git && cd prometheus && bash install.sh
```

The installer automatically:
- Checks Python 3.10+ (installs if missing)
- Creates virtual environment
- Installs Python dependencies
- Installs external tools (nuclei, subfinder, httpx, nmap, sqlmap, sherlock) if available
- Creates global `prometheus` command
- Works from any directory after install

### First Scan

```bash
prometheus
authorize example.com
scan example.com
```

### Or Use Directly

```bash
prometheus scan example.com          # Full autonomous scan
prometheus owasp https://target.com  # OWASP methodology
prometheus crypto target.com         # SSL/TLS analysis
prometheus quick target.com          # Fast scan
```

### Or Use the REST API

```bash
python -m src.api.app
# Docs at http://localhost:8000/docs
```

### Or Use as Python Library

```python
from src.main import Prometheus
p = Prometheus()
result = p.assess("example.com")
```

---

## Features

### 21 Vulnerability Scanners

<table>
<tr>
<td>

**Injection**
- SQL Injection (198 patterns, 8 DBMS)
- XSS (context-aware, DOM, stored, WAF bypass)
- Command Injection (Linux + Windows)
- SSTI (Jinja2, Twig, Freemarker, Velocity, ERB, Pug)
- XXE (file read, SSRF, blind)
- HTTP Smuggling (CL.TE / TE.CL / TE.TE)

</td>
<td>

**Access & Logic**
- IDOR / BOLA (multi-session)
- Auth Bypass (default creds, admin panels)
- Path Traversal (30+ encoding bypasses)
- Open Redirect (28 bypass techniques)
- CORS Misconfiguration
- Race Conditions

</td>
<td>

**Configuration**
- Exposed Secrets (25 regex patterns)
- Security Headers (10 critical headers)
- SSL/TLS/Crypto (weak ciphers, cert validation)
- Business Logic (price manipulation, step skipping)
- Session Management (cookie flags, CSRF, JWT)
- OWASP Methodology (12 phases)

</td>
</tr>
</table>

### Adversarial Validation

Three-stage validation eliminates false positives (inspired by [Bug Hunter](https://github.com/codexstar69/bug-hunter)):

```
Finding ──> Hunter (confirm) ──> Skeptic (disprove) ──> Referee (verdict)
                                                              │
                                          ┌───────────────────┼───────────────────┐
                                          │                   │                   │
                                     CONFIRMED     LIKELY_FALSE_POS      FALSE_POSITIVE
                                          │                   │                   │
                                       KEEP              KEEP (low)            DROP
```

### Payload Engine

```
┌─────────────────────────────────────────────────────┐
│  777 Core Payloads                                    │
│  ├── SQLi: 235  ├── XSS: 194  ├── SSRF: 73          │
│  ├── CMDi: 78   ├── SSTI: 43  ├── Others: 154       │
│                                                       │
│  Dynamic Variant Generation                           │
│  ├── URL encoding    ├── Double URL encoding          │
│  ├── HTML entity     ├── Unicode                      │
│  ├── Case variation  ├── Comment injection            │
│  └── Whitespace substitution                          │
│                                                       │
│  Result: 2,861+ effective payloads with WAF bypass   │
│                                                       │
│  Learning System: Caches successful payloads          │
│  Context-Aware: DBMS, WAF, framework detection       │
└─────────────────────────────────────────────────────┘
```

### 5-Stage Pipeline

```
Stage 1  RECON      Fast model       Subdomains, ports, HTTP, crawl, API discovery
Stage 2  HUNT       Primary model    Run all 21 vulnerability scanners
Stage 3  VALIDATE   Reasoning model  Adversarial review (Hunter-Skeptic-Referee)
Stage 4  TRACE      Primary model    Prove attacker input reaches vulnerable sink
Stage 5  REPORT     Fast model       Executive report with confirmed findings only
```

### Skill/Plugin System

8 YAML skill files with structured methodology, payloads, detection patterns, and remediation:

```
src/skills/
├── sqli.yml            SQL injection methodology
├── xss.yml             XSS methodology
├── ssrf.yml            SSRF methodology
├── idor.yml            IDOR methodology
├── auth_bypass.yml     Authentication bypass
├── api_security.yml    API security testing
├── cloud_security.yml  Cloud misconfiguration
└── session_mgmt.yml    Session management
```

Skills auto-load on-demand based on target characteristics.

### API Auto-Disc

Automatically discovers and parses API specifications:

```
OpenAPI 3.x specs    ──>  Endpoint extraction
Swagger 2.x specs    ──>  Parameter analysis
GraphQL introspection ──>  Operation discovery
HTML/JS parsing      ──>  Hidden endpoint finding
Risk assessment      ──>  Categorize (read/write/admin/auth)
```

32 common spec paths checked automatically.

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
├── scanner/                   Vulnerability detection (21 scanners)
│   ├── sqli.py                SQL Injection (198 patterns, 8 DBMS)
│   ├── xss.py                 XSS (context-aware, DOM, stored)
│   ├── ssrf.py                SSRF (23 cloud, 32 internal targets)
│   ├── adversarial.py         Adversarial validation
│   ├── payload_engine.py      777 core payloads + variants
│   ├── api_discovery.py       OpenAPI/Swagger/GraphQL discovery
│   ├── owasp_methodology.py   OWASP Testing Guide v4
│   ├── business_logic.py      Business logic testing
│   ├── session_manager.py     Session management
│   ├── crypto_scanner.py      SSL/TLS/crypto
│   ├── api_security.py        API security
│   └── executive_report.py    Executive report generator
│
├── skills/                    Skill/plugin system
│   ├── loader.py              On-demand skill loading
│   └── *.yml                  8 skill files
│
├── tools/                     External tool wrappers
│   ├── nuclei.py              Nuclei (177 fallback paths)
│   ├── sqlmap.py              SQLMap (128 fallback payloads)
│   ├── subfinder.py           Subfinder (246 fallback prefixes)
│   ├── httpx.py               httpx (HTTP probing)
│   ├── portscan.py            Nmap (320 fallback ports)
│   └── sherlock.py            Sherlock (123 fallback platforms)
│
├── brain/                     LLM router (14 providers)
│   ├── llm.py                 Provider integrations
│   ├── router.py              Smart routing + fallback
│   └── critic.py              Multi-model consensus
│
├── knowledge/                 Knowledge base (1,242+ reports)
│   └── index.py               NetworkX graph-based search
│
├── api/                       REST API
│   ├── app.py                 FastAPI application
│   └── client.py              Python client
│
├── market/                    Market features
│   └── india.py               Professional reports, pricing
│
├── cli/
│   └── interface.py           Interactive CLI
│
├── main.py                    Orchestrator (with LLM)
└── offline.py                 Orchestrator (without LLM)
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

FastAPI-based REST API for automation and CI/CD integration:

```bash
python -m src.api.app
# Interactive docs at http://localhost:8000/docs
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

### Python Client

```python
from src.api.client import PrometheusClient

client = PrometheusClient(base_url="http://localhost:8000", api_key="your-key")
scan_id = client.scan("example.com")
result = client.wait_for_scan(scan_id)
findings = client.get_findings(scan_id, severity="HIGH")
report = client.get_report(scan_id, format="markdown")
```

---

## Tool Fallbacks

Every tool works without external binaries (Python fallback mode):

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
| **Pro** | $19/mo | Rs.1,499/mo | Unlimited URLs, all 21 scanners, API, OWASP methodology |
| **Team** | $99/mo | Rs.7,499/mo | + 5 members, continuous scanning, CI/CD, compliance |
| **Enterprise** | $299/mo | Rs.22,499/mo | + SSO, on-prem, custom playbooks, SLA |

---

## Testing

```bash
python -m pytest tests/ -v          # Run all tests
python -m pytest tests/ --tb=short  # Quick smoke test
```

**251 passing, 99.6% pass rate**

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

| Project | Contribution |
|---------|--------------|
| [ProjectDiscovery](https://github.com/projectdiscovery) | Nuclei, Subfinder, httpx (MIT) |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | Skill system architecture (MIT) |
| [codexstar69/bug-hunter](https://github.com/codexstar69/bug-hunter) | Adversarial validation pattern (MIT) |
| [ZephrFish/harness-kit](https://github.com/ZephrFish/harness-kit) | 5-stage pipeline design |
| [The-XSS-Rat/subScraper](https://github.com/The-XSS-Rat/subScraper) | Stateful scanning design |
| [DevCop95/bugbounty-lab101](https://github.com/DevCop95/bugbounty-lab101) | Scope enforcement (MIT) |
| [rawfilejson/awesome-osint-arsenal](https://github.com/rawfilejson/awesome-osint-arsenal) | Tool inventory (MIT) |
| [Brutecat](https://brutecat.com/articles/hacking-google-with-ai/) | API discovery technique |
| [Joseph Thacker](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html) | Hackbot methodology |
| [Niels Provos](https://www.provos.org/p/finding-zero-days-with-any-model/) | Orchestration > model philosophy |
| Security research community | 1,242+ bug bounty reports |

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
