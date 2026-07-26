<div align="center">

# Prometheus

### AI-Powered Autonomous Security Testing Platform

![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Tests](https://img.shields.io/badge/tests-251%20passing-brightgreen?style=flat-square)

**Find real vulnerabilities. Validate with proof-of-concept. Generate executive reports.**

</div>

---

## Disclaimer

This tool is for authorized security testing and educational purposes only. Users must obtain proper authorization before testing any target. Unauthorized access to computer systems is illegal in most jurisdictions. See [SECURITY.md](SECURITY.md) for full security policy.

---

## What Is Prometheus?

Prometheus is an open-source, AI-powered security testing platform that autonomously discovers and validates vulnerabilities in web applications, APIs, networks, and cloud infrastructure.

**Key differentiators:**
- 21 vulnerability scanners with adversarial validation (Hunter-Skeptic-Referee eliminates false positives)
- 5-stage pipeline (Recon, Hunt, Validate, Trace, Report)
- 777 core payloads with dynamic variant generation (2,861+ with WAF bypass)
- 1,242+ report knowledge base
- Skill/plugin system with on-demand loading
- API auto-discovery (OpenAPI/Swagger/GraphQL)
- Works offline (no API keys needed)
- REST API for automation
- Scope enforcement (hard block on out-of-scope targets)

---

## Quick Start

### One-Command Install

```bash
git clone https://github.com/mysterious75/prometheus.git
cd prometheus
bash install.sh
```

The installer automatically:
- Checks Python 3.10+ (installs if missing)
- Creates virtual environment
- Installs Python dependencies
- Installs external tools (nuclei, subfinder, httpx, nmap, sqlmap, sherlock) if available
- Creates global `prometheus` command
- Works from any directory after install

### Manual Install

```bash
git clone https://github.com/mysterious75/prometheus.git
cd prometheus
pip install -r requirements.txt
cp .env.example .env
# Edit .env — add at least one API key (optional, works without keys too)
python -m src.entry
```

### First Scan

```bash
prometheus                          # Interactive CLI
authorize example.com               # Authorize target
scan example.com                    # Full autonomous scan
```

### Or Use Directly

```bash
prometheus scan example.com
prometheus owasp https://target.com
prometheus crypto target.com
```

### Or Use the REST API

```bash
python -m src.api.app               # Start API server
# Open http://localhost:8000/docs for interactive API documentation
```

### Or Use as Python Library

```python
from src.main import Prometheus
p = Prometheus()
result = p.assess("example.com")
print(result["findings"])
```

---

## Commands

### Assessment
| Command | Description |
|---------|-------------|
| `scan <target>` | Full autonomous security assessment |
| `recon <target>` | Reconnaissance only (subdomains, ports, HTTP) |
| `osint <target>` | OSINT (username search or domain intel) |
| `quick <target>` | Fast scan (top vulnerabilities only) |
| `stealth <target>` | Slow, stealthy scan (1 req/sec) |

### OWASP / Book-Based Scanners
| Command | Description |
|---------|-------------|
| `owasp <target>` | Full OWASP Testing Guide v4 scan (12 phases) |
| `business <target>` | Business logic vulnerability testing |
| `session <target>` | Session management security testing |
| `crypto <target>` | SSL/TLS and cryptographic weakness testing |
| `api <target>` | API security testing (REST/GraphQL/JWT) |
| `report <target>` | Generate executive security report |

### Authorization
| Command | Description |
|---------|-------------|
| `authorize <target>` | Authorize a target for scanning |
| `revoke <target>` | Revoke target authorization |
| `targets` | List authorized targets |

### Knowledge & History
| Command | Description |
|---------|-------------|
| `kb [query]` | Search knowledge base (1,242+ reports) |
| `playbook <vuln_type>` | Get attack playbook |
| `history` | Show previous scan results |

### System
| Command | Description |
|---------|-------------|
| `status` | System status |
| `tools` | Tool availability |
| `pricing` | Pricing plans |
| `bounty` | Bug bounty programs |
| `help` | Show all commands |
| `quit` | Exit |

---

## REST API

Prometheus includes a FastAPI-based REST API for automation:

```bash
python -m src.api.app
# Docs at http://localhost:8000/docs
```

### Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Start a new scan |
| GET | `/scan/{id}` | Get scan status and results |
| GET | `/scans` | List all scans |
| GET | `/findings` | Get findings (filter by severity, type) |
| GET | `/report/{id}` | Get report (markdown or JSON) |
| POST | `/authorize` | Authorize a target |
| GET | `/targets` | List authorized targets |
| GET | `/status` | System status |
| GET | `/tools` | Tool availability |

### Python Client
```python
from src.api.client import PrometheusClient

client = PrometheusClient(base_url="http://localhost:8000", api_key="your-key")
scan_id = client.scan("example.com")
result = client.wait_for_scan(scan_id)
findings = client.get_findings(scan_id)
```

---

## Architecture

```
src/
├── core/                      Foundation
│   ├── config.py              Configuration
│   ├── auth.py                Authorization-first security
│   ├── ratelimit.py           Rate limiter
│   ├── scope.py               Scope enforcement
│   ├── state.py               Scan state persistence (resume)
│   └── resources.py           System resource monitoring
│
├── agent/                     AI Agent brain
│   ├── orchestrator.py        Multi-agent orchestrator
│   ├── pipeline.py            5-stage pipeline (recon/hunt/validate/trace/report)
│   ├── recon_agent.py         Reconnaissance specialist
│   ├── scan_agent.py          Vulnerability scanning specialist
│   ├── exploit_agent.py       Exploit validation specialist
│   ├── report_agent.py        Report generation specialist
│   ├── planner.py             LLM-powered attack planning
│   └── learning.py            Self-learning engine
│
├── scanner/                   Vulnerability detection (21 scanners)
│   ├── sqli.py                SQL Injection (198 error patterns, 8 DBMS)
│   ├── xss.py                 XSS (context-aware, DOM, stored, WAF bypass)
│   ├── ssrf.py                SSRF (23 cloud targets, 32 internal, 19 protocols)
│   ├── owasp_methodology.py   OWASP Testing Guide v4 (12 phases)
│   ├── business_logic.py      Business logic testing
│   ├── session_manager.py     Session management testing
│   ├── crypto_scanner.py      SSL/TLS/crypto testing
│   ├── api_security.py        API security (REST/GraphQL/JWT)
│   ├── api_discovery.py       OpenAPI/Swagger/GraphQL auto-discovery
│   ├── adversarial.py         Adversarial validation (Hunter-Skeptic-Referee)
│   ├── payload_engine.py      777 core payloads + dynamic variants
│   ├── executive_report.py    Executive report generator
│   ├── crawler.py             Web crawler (JS parsing, API discovery)
│   └── ... (13 more scanners)
│
├── skills/                    Skill/plugin system
│   ├── loader.py              On-demand skill loading
│   ├── sqli.yml               SQLi methodology
│   ├── xss.yml                XSS methodology
│   ├── ssrf.yml               SSRF methodology
│   └── ... (5 more skills)
│
├── tools/                     External tool wrappers
│   ├── nuclei.py              Nuclei (177 fallback paths)
│   ├── sqlmap.py              SQLMap (128 fallback payloads)
│   ├── subfinder.py           Subfinder (246 fallback prefixes)
│   ├── httpx.py               httpx (HTTP probing)
│   ├── portscan.py            Nmap (320 fallback ports)
│   ├── sherlock.py            Sherlock (123 fallback platforms)
│   └── registry.py            Central tool hub
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
│   └── india.py               Professional reports, pricing, bug bounty
│
├── cli/
│   └── interface.py           Interactive CLI
│
├── main.py                    Orchestrator (with LLM)
└── offline.py                 Orchestrator (without LLM)
```

---

## Tool Fallbacks

Every tool has a Python fallback that works without external binaries:

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

| Tier | Price (USD) | Price (INR) | Features |
|------|-------------|-------------|----------|
| **Free** | $0 | Rs.0 | 5 URLs/month, 5 scanners, CLI, community support |
| **Pro** | $19/mo | Rs.1,499/mo | Unlimited URLs, all 21 scanners, OWASP methodology, API access, executive reports |
| **Team** | $99/mo | Rs.7,499/mo | Everything in Pro + 5 members, continuous scanning, auto-fix PRs, CI/CD, compliance reports |
| **Enterprise** | $299/mo | Rs.22,499/mo | Everything in Team + unlimited members, SSO, on-prem, custom playbooks, SLA |

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific tests
python -m pytest tests/test_scanner_real.py -v
python -m pytest tests/test_tools.py -v
python -m pytest tests/test_knowledge.py -v

# Quick smoke test
python -m pytest tests/ --tb=short -q
```

**Results:** 251 passing, 1 failed (99.6% pass rate)

---

## Security

- **Authorization required**: Only scan authorized targets (`authorize <target>`)
- **Scope enforcement**: Hard block on out-of-scope targets
- **Rate limiting**: Configurable requests per second (default: 10)
- **Resource monitoring**: Auto-throttle if system overloaded
- **No shell injection**: Commands use argument lists, never `shell=True`
- **API keys stay local**: `.env` is gitignored
- **State persistence**: Scan progress saved to disk, resumable

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

- [ProjectDiscovery](https://github.com/projectdiscovery) — Nuclei, Subfinder, httpx
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) — Skill system inspiration
- [codexstar69/bug-hunter](https://github.com/codexstar69/bug-hunter) — Adversarial validation pattern
- [ZephrFish/harness-kit](https://github.com/ZephrFish/harness-kit) — 5-stage pipeline architecture
- [The-XSS-Rat/subScraper](https://github.com/The-XSS-Rat/subScraper) — Stateful scanning design
- [DevCop95/bugbounty-lab101](https://github.com/DevCop95/bugbounty-lab101) — Scope enforcement
- [rawfilejson/awesome-osint-arsenal](https://github.com/rawfilejson/awesome-osint-arsenal) — Tool inventory
- Security research community — 1,242+ bug bounty reports

---

<div align="center">

**Built for authorized security testing. Use responsibly.**

[Report Bug](https://github.com/mysterious75/prometheus/issues) • [Request Feature](https://github.com/mysterious75/prometheus/issues)

</div>
