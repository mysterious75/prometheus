<div align="center">

# 🛡️ Prometheus

### AI-Powered Autonomous Security Testing Platform

[![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)]()
[![Tests](https://img.shields.io/badge/tests-185%20passing-brightgreen?style=flat-square)]()
[![Stars](https://img.shields.io/github/stars/mysterious75/prometheus?style=flat-square)]()

**Find real vulnerabilities. Generate proof-of-concepts. Auto-fix code.**

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Tools](#tools) • [Commands](#commands) • [Pricing](#pricing)

</div>

---

## What Is Prometheus?

Prometheus is an **open-source, AI-powered security testing platform** that autonomously discovers and validates vulnerabilities in web applications, APIs, networks, and cloud infrastructure.

Unlike traditional scanners that produce false positives, Prometheus **validates every finding with real proof-of-concept evidence**.

### Key Differentiators

- **15 vulnerability scanners** with zero false positives (every finding has evidence)
- **AI-powered attack planning** — the agent decides what to test and in what order
- **Multi-session BOLA/IDOR testing** — creates resources as User A, accesses as User B
- **GraphQL/REST API security** — introspection, batching, depth limits, JWT analysis
- **Auto-fix PR generation** — generates code fixes and creates Pull Requests
- **Self-learning engine** — remembers WAF bypasses and framework attack patterns
- **1242+ report knowledge base** — real-world attack patterns for smarter testing
- **Works offline** — no API keys needed for basic scanning

---

## Features

### Vulnerability Scanners (15)

| Scanner | Detection Method | Verified |
|---------|-----------------|----------|
| SQL Injection | Error-based, Time-based, Boolean-based | ✅ |
| Cross-Site Scripting (XSS) | Context-aware (HTML/JS/Attribute) | ✅ |
| Server-Side Request Forgery (SSRF) | Internal network, Cloud metadata | ✅ |
| OS Command Injection | Time-based, Output-based | ✅ |
| IDOR / BOLA | Multi-session cross-user testing | ✅ |
| Server-Side Template Injection | Expression evaluation detection | ✅ |
| XML External Entity (XXE) | File content extraction | ✅ |
| HTTP Request Smuggling | CL.TE / TE.CL detection | ✅ |
| Path Traversal / LFI | Multiple encoding bypasses | ✅ |
| Open Redirect | Redirect parameter manipulation | ✅ |
| CORS Misconfiguration | Origin reflection testing | ✅ |
| Exposed Secrets | 20+ regex patterns (AWS, GitHub, JWT, etc.) | ✅ |
| Missing Security Headers | 6 critical headers checked | ✅ |
| Race Condition | Concurrent request analysis | ✅ |
| Authentication Bypass | Admin panel + API access testing | ✅ |

### API Security

- **GraphQL**: Introspection exposure, query batching, depth limits, sensitive field detection
- **REST API**: CORS, rate limiting, method override, verbose errors
- **JWT**: None algorithm, algorithm confusion, expiry bypass, sensitive data in payload
- **OAuth**: Flow testing, redirect URI validation

### Reconnaissance & OSINT

- **Subdomain Discovery**: crt.sh, DNS brute force, ffuf, permutations, reverse DNS (smart deduplication — no duplicate work across tools)
- **DNS Intelligence**: Full record enumeration, zone transfer attempts, DNSSEC validation
- **Web Fingerprinting**: 50+ technologies, 10+ WAFs, CMS detection, JS framework detection
- **Cloud Security**: AWS S3, Azure Blob, GCP bucket discovery
- **Internet Intelligence**: Shodan, Whois, ASN lookup, SSL/TLS analysis
- **Subdomain Takeover**: 15 vulnerable services (GitHub Pages, Heroku, S3, etc.)
- **Dorking**: Google, GitHub, Shodan, Bing (100+ dorks generated automatically)
- **Exploit Database**: SearchSploit + NVD CVE integration

### AI Agent

- **Attack Planner**: LLM-powered decision making for next steps
- **Tool Orchestrator**: 5 playbooks (web_app, domain_recon, ip_scan, username_osint, exploit_search)
- **Exploit Chainer**: Finds multi-step attack paths
- **Self-Learning**: Remembers WAF bypasses, framework patterns, successful techniques
- **Stateful Tracker**: Maintains context across all attack steps

### Reporting

- **Markdown Reports**: Professional format with severity breakdown, PoC commands, remediation
- **JSON Reports**: Machine-readable for automation
- **HackerOne Reports**: Auto-generated vulnerability reports ready for submission
- **CVE Templates**: Structured data for CVE submission

---

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/mysterious75/prometheus.git
cd prometheus

# Install dependencies
pip install -r requirements.txt

# Optional: Install external tools for enhanced scanning
# (Prometheus works without these — fallback mode is built in)
sudo apt install nmap whois dnsutils
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Add at least one LLM API key (for AI-guided scanning)
# Without API keys, Prometheus runs in offline mode (still fully functional)
echo "DEEPSEEK_API_KEY=your_key_here" >> .env
# OR
echo "GEMINI_API_KEY_1=your_key_here" >> .env
# OR
echo "OPENROUTER_API_KEY=your_key_here" >> .env
```

### First Scan

```bash
# Start Prometheus
python -m src.entry

# Inside the CLI:
authorize example.com
scan example.com
```

### Offline Mode (No API Keys)

```bash
# Prometheus works fully offline — no LLM calls for scanning
python -m src.entry

authorize example.com
scan example.com
# Uses predefined attack sequences, all 15 scanners, full reporting
```

---

## Architecture

```
prometheus/
├── src/
│   ├── core/                    # Foundation
│   │   ├── config.py            # Centralized configuration
│   │   ├── logger.py            # Rich console output
│   │   ├── auth.py              # Authorization-first security
│   │   ├── ratelimit.py         # Token bucket rate limiter
│   │   └── pricing.py           # Pricing model
│   │
│   ├── tools/                   # External tool wrappers (15+)
│   │   ├── base.py              # Abstract BaseTool interface
│   │   ├── nuclei.py            # Nuclei + HTTP fallback
│   │   ├── subfinder.py         # Subfinder + crt.sh fallback
│   │   ├── httpx.py             # httpx + Python fallback
│   │   ├── sqlmap.py            # SQLMap + basic SQLi fallback
│   │   ├── sherlock.py          # Sherlock (400+ platforms)
│   │   ├── portscan.py          # Nmap + socket fallback
│   │   ├── dns.py               # DNS tools (dig, zone transfer)
│   │   ├── fingerprint.py       # Tech/WAF/CMS/JS detection
│   │   ├── cloud.py             # S3/Azure/GCP bucket scanning
│   │   ├── shodan.py            # Shodan + InternetDB
│   │   ├── whois.py             # Whois + ASN lookup
│   │   ├── takeover.py          # Subdomain takeover (15 services)
│   │   ├── exploits.py          # SearchSploit + NVD
│   │   ├── recon_extra.py       # theHarvester, ffuf, Nikto, SSL
│   │   ├── dorking.py           # Google/GitHub/Shodan/Bing dorking
│   │   └── registry.py          # Central tool hub
│   │
│   ├── scanner/                 # Vulnerability detection (15 scanners)
│   │   ├── crawler.py           # Web crawler + parameter discovery
│   │   ├── findings.py          # Finding + ScanResult models
│   │   ├── sqli.py              # SQL Injection (3 techniques)
│   │   ├── xss.py               # XSS (context-aware)
│   │   ├── ssrf.py              # SSRF (cloud metadata)
│   │   ├── cmdi.py              # Command Injection
│   │   ├── idor.py              # IDOR
│   │   ├── ssti.py              # Template Injection
│   │   ├── xxe.py               # XML External Entity
│   │   ├── smuggling.py         # HTTP Smuggling
│   │   ├── traversal.py         # Path Traversal
│   │   ├── redirect.py          # Open Redirect
│   │   ├── cors.py              # CORS Misconfiguration
│   │   ├── secrets.py           # Exposed secrets/keys
│   │   ├── headers.py           # Security headers
│   │   ├── race.py              # Race conditions
│   │   ├── auth.py              # Auth bypass
│   │   ├── auth_engine.py       # Multi-session BOLA/IDOR
│   │   ├── api_security.py      # GraphQL/REST/JWT/OAuth
│   │   ├── internal_net.py      # SMB/LDAP/Kerberos
│   │   ├── autofix.py           # Auto-fix PR generation
│   │   ├── continuous.py        # Continuous scanning
│   │   ├── evidence.py          # PoC + HackerOne reports
│   │   ├── runner.py            # Scan orchestrator
│   │   └── report.py            # Report generator
│   │
│   ├── agent/                   # AI Agent brain
│   │   ├── planner.py           # LLM-powered attack planning
│   │   ├── executor.py          # Tool execution
│   │   ├── memory.py            # Working memory
│   │   ├── chain.py             # Exploit chaining
│   │   ├── assets.py            # Smart asset deduplication
│   │   ├── attack_tracker.py    # Stateful attack tracking
│   │   ├── orchestrator.py      # AI tool orchestrator
│   │   ├── subdomain_discovery.py  # Smart subdomain discovery
│   │   └── learning.py          # Self-learning engine
│   │
│   ├── knowledge/               # 1242+ report knowledge base
│   │   └── index.py             # Search + playbooks
│   │
│   ├── brain/                   # LLM router (14 providers)
│   │   ├── llm.py               # Provider integrations
│   │   ├── router.py            # Smart routing + fallback
│   │   └── critic.py            # Multi-model consensus
│   │
│   ├── cli/
│   │   └── interface.py         # Interactive CLI
│   │
│   ├── main.py                  # Orchestrator (with LLM)
│   └── offline.py               # Orchestrator (without LLM)
│
├── tests/                       # 185 tests
├── learn-from-others/           # Knowledge base (1242 reports)
├── config/                      # Configuration files
└── requirements.txt             # Python dependencies
```

---

## Tools

### Built-in Security Tools

Every tool has a **Python fallback** — works even without external binaries installed.

| Tool | Purpose | Fallback |
|------|---------|----------|
| **Nuclei** | Template-based vulnerability scanning (12,000+ templates) | HTTP path checks |
| **Subfinder** | Passive subdomain enumeration (40+ sources) | crt.sh + DNS brute force |
| **httpx** | HTTP service probing | Python httpx |
| **SQLMap** | SQL injection detection | Basic SQLi payloads |
| **Sherlock** | Username search (400+ platforms) | HTTP-based checking |
| **Nmap** | Port scanning + NSE scripts | Python socket |
| **dig/nslookup** | DNS record enumeration | Python socket |
| **WhatWeb** | Technology fingerprinting | Header + HTML analysis |
| **Shodan** | Internet intelligence | InternetDB (free) |
| **ffuf** | Directory/path fuzzing | — |
| **SearchSploit** | Exploit database search | Web search |
| **Nikto** | Web server scanning | — |
| **theHarvester** | Email + subdomain OSINT | HTTP regex |

### AI Tool Orchestrator

The AI automatically selects the right tools based on target type:

```
URL detected     → web_app playbook (21 steps)
Domain detected  → domain_recon playbook (8 steps)
IP detected      → ip_scan playbook (4 steps)
Username detected → username_osint playbook (1 step)
```

---

## Commands

### Assessment

| Command | Description |
|---------|-------------|
| `scan <target>` | Full autonomous security assessment |
| `recon <target>` | Reconnaissance only (subdomains, ports, HTTP) |
| `osint <target>` | OSINT (username search or domain intel) |

### Authorization

| Command | Description |
|---------|-------------|
| `authorize <target>` | Authorize a target for scanning |
| `revoke <target>` | Revoke target authorization |
| `targets` | List authorized targets |

### Knowledge Base

| Command | Description |
|---------|-------------|
| `kb [query]` | Search knowledge base (1242+ reports) |
| `playbook <vuln_type>` | Get attack playbook for a vulnerability type |

### System

| Command | Description |
|---------|-------------|
| `status` | System status (providers, tools, knowledge base) |
| `tools` | Tool availability status |
| `help` | Show all commands |
| `quit` | Exit |

### General

Any other input is treated as a conversation with the AI assistant.

---

## Supported LLM Providers

| Provider | Role | Free Tier |
|----------|------|-----------|
| DeepSeek | Primary | Cheap, long context |
| Gemini (1-3 keys) | Consciousness | 150K tokens/day each |
| OpenRouter | Fallback | Free models available |
| OpenAI | Backup | Paid |
| Anthropic | Backup | Paid |
| Qwen, Kimi, GLM | Backup | Free tier |

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Community** | Free | 10 URLs, 5 scanners, CLI, community support |
| **Pro** | $19/mo | Unlimited URLs, all scanners, API, JWT/GraphQL |
| **Team** | $99/mo | Continuous scanning, auto-fix PRs, BOLA, internal network |
| **Enterprise** | $299/mo | SSO, compliance reports, on-prem, unlimited team |

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test suite
python -m pytest tests/test_v3.py -v
python -m pytest tests/test_scanner.py -v
python -m pytest tests/test_smart_tools.py -v

# Quick smoke test
python -m pytest tests/ --tb=short
```

---

## Security

- **Authorization required**: Only scan authorized targets
- **Rate limiting**: Configurable requests per second (default: 10)
- **No shell injection**: Commands use argument lists, never `shell=True`
- **API keys stay local**: `.env` is gitignored
- **Verified findings only**: Every vulnerability has proof-of-concept evidence

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

- [ProjectDiscovery](https://github.com/projectdiscovery) — Nuclei, Subfinder, httpx, Katana
- [Alias Robotics](https://github.com/aliasrobotics/CAI) — CAI framework inspiration
- [UseStrix](https://github.com/usestrix/strix) — Strix architecture inspiration
- [vxcontrol](https://github.com/vxcontrol/pentagi) — PentAGI agent design
- Security research community — 1242+ bug bounty reports

---

<div align="center">

**Built for authorized security testing. Use responsibly.**

[Report Bug](https://github.com/mysterious75/prometheus/issues) • [Request Feature](https://github.com/mysterious75/prometheus/issues)

</div>
