# Prometheus

<div align="center">

**Security Research Assistant with LLM-Powered Analysis**

[![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square)]()

</div>

---

## What Is This?

Prometheus is a **security research assistant** that combines:

- **Automated vulnerability scanning** (SQLi, XSS, SSRF, command injection)
- **OSINT reconnaissance** (username search, domain intel, subdomain enumeration)
- **LLM-powered analysis** (14 provider support with smart routing)
- **Knowledge base** (1242+ bug bounty reports, attack playbooks, cheatsheets)

It's designed for **authorized security testing** — you must explicitly authorize targets before scanning.

## Architecture

```
┌─────────────────────────────────────────────┐
│              CLI Chat Interface              │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│          Intent Parser (regex + LLM)        │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│  Scan  │  │  OSINT   │  │   Chat   │
│ Engine │  │  Finder  │  │  (LLM)   │
└────┬───┘  └────┬─────┘  └────┬─────┘
     │           │              │
     ▼           ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│VulnScan│  │ Username │  │ 14 LLM   │
│SQLi/XSS│  │ 20+ plat │  │ providers│
└────────┘  └──────────┘  └──────────┘
```

## Quick Start

```bash
# Clone
git clone https://github.com/mysterious75/prometheus.git
cd prometheus

# Install
pip install -r requirements.txt

# Configure (at least one API key needed)
cp .env.example .env
# Edit .env — add your API key(s)

# Run
python -m src.main
```

### Supported LLM Providers

| Provider | Role | Free Tier |
|----------|------|-----------|
| DeepSeek | Primary | Cheap, long context |
| Gemini (1-3 keys) | Consciousness | 150K tokens/day each |
| OpenRouter | Fallback | Free models available |
| OpenAI | Backup | Paid |
| Anthropic | Backup | Paid |
| Qwen, Kimi, GLM | Backup | Free tier |

## Usage

### Authorization First

```bash
Tum: authorize google.com
Prometheus: Target 'google.com' authorized for scanning.

Tum: targets
Prometheus: Authorized targets:
  - google.com
```

### Vulnerability Scanning

```bash
Tum: scan google.com
Tum: full recon example.com
Tum: exploit http://authorized-target.com
Tum: full audit http://my-app.com
```

### OSINT (No Authorization Needed)

```bash
Tum: osint username123
# Searches 20+ platforms for username

Tum: osint google.com
# Domain recon: subdomains, emails, tech stack
```

### Individual Checks

```bash
Tum: headers google.com        # Security headers
Tum: ssl google.com            # SSL/TLS check
Tum: cors http://target.com    # CORS misconfig
Tum: waf http://target.com     # WAF detection
Tum: xss http://target.com     # Reflected XSS
Tum: sqlmap http://target.com  # SQL injection
```

### Knowledge Base

```bash
Tum: cheatsheet sqli           # SQL injection cheatsheet
Tum: playbook xss              # XSS attack playbook
Tum: payloads sqli             # Attack payloads
Tum: bounty xss                # Bounty ranges
```

## Project Structure

```
prometheus/
├── config/
│   ├── models.json              # LLM provider configs
│   └── authorized_targets.json  # Authorized scan targets
├── src/
│   ├── main.py                  # Chat system + authorization
│   ├── brain/                   # LLM routing + multi-provider
│   │   ├── llm.py               # 14 provider integrations
│   │   ├── router.py            # Smart routing + fallback
│   │   └── critic.py            # Multi-model consensus
│   ├── memory/                  # Vector memory (ChromaDB)
│   │   ├── chroma.py            # Vector store + in-memory fallback
│   │   ├── episodic.py          # Event memory
│   │   └── emotional.py         # Emotional context
│   ├── consciousness/           # NLP components
│   │   ├── emotions.py          # Keyword + LLM emotion detection
│   │   ├── identity.py          # System persona
│   │   ├── intent_parser.py     # Command parsing
│   │   ├── conversation_memory.py
│   │   ├── monologue.py         # Internal reasoning
│   │   ├── dreaming.py          # Memory consolidation
│   │   └── reflection.py        # Self-reflection
│   ├── web/                     # Web security tools
│   │   ├── vuln_scanner.py      # SQLi/XSS/SSRF/CMDi scanner
│   │   ├── osint.py             # Username + domain OSINT
│   │   ├── proxy.py             # HTTP interceptor
│   │   └── browser.py           # Playwright automation
│   ├── bugbounty/               # Bug bounty toolkit
│   │   ├── toolkit.py           # Pure Python security checks
│   │   ├── knowledge.py         # 1242+ report knowledge base
│   │   ├── recon.py             # Recon pipeline
│   │   ├── scanner.py           # Vulnerability scanner
│   │   └── reporter.py          # Report generation
│   ├── autonomy/                # Goal management
│   │   ├── goals.py             # Goal tracking
│   │   ├── executor.py          # Task execution
│   │   └── evolution/           # Self-improvement
│   └── developer/
│       └── codegen.py           # Code generation
├── learn-from-others/           # Bug bounty knowledge base
│   ├── knowledge_base.json      # 1242 reports
│   └── patterns/                # Cheatsheets, payloads
├── tests/                       # Test suite
├── requirements.txt
└── .env.example
```

## Key Design Decisions

### Why Authorization-First?

Security tools must not be used for unauthorized scanning. Prometheus requires explicit target authorization before any active scanning. This prevents misuse and keeps you legal.

### Why 14 LLM Providers?

Different providers have different strengths:
- **DeepSeek**: Cheap, long context (primary brain)
- **Gemini**: Free tier, good for consciousness/emotions
- **OpenRouter**: Free model fallback
- Multiple backups = no single point of failure

### Why ChromaDB with In-Memory Fallback?

Vector search enables semantic memory (recall by meaning, not keywords). The in-memory fallback means the system works even without ChromaDB installed — you just lose persistence.

### Why Pure Python Security Toolkit?

Most security tools require external binaries (nmap, sqlmap, etc.). The `PythonToolkit` does security checks with pure Python (httpx, ssl, socket), so it works anywhere Python runs.

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Quick smoke test
python test_all.py

# Specific module
python -m pytest tests/test_brain.py -v
```

## Configuration

### Environment Variables

```bash
# .env file — at least one key needed
DEEPSEEK_API_KEY=sk-...           # Primary (recommended)
GEMINI_API_KEY_1=AIza...          # Consciousness (free)
OPENROUTER_API_KEY=sk-or-v1-...   # Fallback (free models)
# OPENAI_API_KEY=sk-...           # Backup (paid)
# ANTHROPIC_API_KEY=sk-ant-...    # Backup (paid)
```

### Model Configuration

Edit `config/models.json` to:
- Add/remove providers
- Change routing strategy
- Configure rate limits
- Set token budgets

## Security

- **Authorization required**: Only scan authorized targets
- **No shell injection**: Commands use `shlex.split()`, never `shell=True`
- **API keys stay local**: `.env` is gitignored
- **Client-side hashing**: VORA protocol computes hashes locally

## Limitations

- This is a **research tool**, not a replacement for professional security audits
- Vulnerability detection is pattern-based — it may miss novel attack vectors
- LLM responses are probabilistic — always verify findings manually
- Some features require external tools (nmap, sqlmap) for full functionality

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contact

- Issues: https://github.com/mysterious75/prometheus/issues
- Twitter: [@VEDKUMAR00143](https://x.com/VEDKUMAR00143)

---

**Built for authorized security testing. Use responsibly.**
