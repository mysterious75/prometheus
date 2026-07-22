# PROJECT PROMETHEUS
## The Ultimate Autonomous AI - Bug Bounty + Consciousness + Developer

---

## Quick Start

### Windows (Recommended)
```powershell
# 1. Clone
git clone https://github.com/mysterious75/prometheus.git
cd prometheus

# 2. Auto Install (sab kuch khud install hoga)
.\install.ps1

# 3. Run
python -m src.main
```

### Linux/Mac
```bash
# 1. Clone
git clone https://github.com/mysterious75/prometheus.git
cd prometheus

# 2. Auto Install
chmod +x install.sh
./install.sh

# 3. Run
python -m src.main
```

### Manual Install
```bash
# Create venv
python -m venv venv

# Activate
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install deps
pip install -r requirements.txt

# Setup .env (copy and edit)
copy .env.example .env   # Windows
cp .env.example .env     # Linux/Mac

# Run
python -m src.main
```

---

## Chat Commands

### Bug Bounty & Scanning
| Command | Description |
|---------|-------------|
| `scan google.com` | Bug bounty scan |
| `full recon google.com` | Full recon + vuln scan |
| `exploit google.com` | Auto SQLi/XSS/SSRF |
| `vuln scan http://x.com` | Vulnerability scan |

### Pure Python Audit (Zero Tools Needed)
| Command | Description |
|---------|-------------|
| `full audit http://x.com` | Sab kuch check |
| `waf http://x.com` | WAF/CDN detect |
| `cors http://x.com` | CORS misconfig check |
| `headers http://x.com` | Security headers |
| `ssl google.com` | SSL/TLS check |
| `sqlmap http://x.com` | SQLMap auto injection |
| `leak http://x.com` | Sensitive files check |
| `redirect http://x.com` | Open redirect check |
| `xss http://x.com` | Reflected XSS check |
| `takeover google.com` | Subdomain takeover |

### OSINT & Recon
| Command | Description |
|---------|-------------|
| `osint username123` | Username search 20+ platforms |
| `osint google.com` | Domain OSINT |
| `recon target.com` | Full OSINT recon |

### Proxy & Intercept
| Command | Description |
|---------|-------------|
| `intercept GET http://x.com` | Request intercept |
| `replay 1` | Last request replay |
| `proxy` | Proxy stats |

### Brute Force
| Command | Description |
|---------|-------------|
| `brute http://x.com login` | OSINT-powered brute |
| `crack http://x.com` | Smart password attack |

### Browser
| Command | Description |
|---------|-------------|
| `browse http://x.com` | Cloudflare bypass |

### AI Knowledge
| Command | Description |
|---------|-------------|
| `learn sqli` | Vulnerability patterns seekho |
| `cheatsheet xss` | Quick reference card |
| `playbook ssrf` | Step-by-step attack guide |
| `payloads rce` | Attack payloads |
| `bounty idor` | Bounty range info |
| `kb` | Knowledge base stats |

### Code & Thinking
| Command | Description |
|---------|-------------|
| `code banao for todo app` | Code generate |
| `soch about AI` | Deep thinking |
| `dream` | Memory consolidation |

### System
| Command | Description |
|---------|-------------|
| `status` | System status |
| `providers` | AI provider status |
| `kaisa feel kar raha hai` | Mood check |
| `yaad karo` | Recall memories |
| `evolve` | Self-upgrade |
| `seekh machine learning` | Research topic |
| `commands` | Show all commands |
| `quit` | Band karo |

---

## AI Providers

Works with ANY API key. System auto-detects and tests keys on startup.

| Provider | Role | Free Tier |
|----------|------|-----------|
| OpenRouter | Primary (openrouter/free) | Unlimited free models |
| DeepSeek | Primary | Cheap, long context |
| Gemini (1-3 keys) | Consciousness only | 150K tokens/day each |
| OpenAI | Backup | Paid |
| Anthropic | Backup | Paid |
| Qwen, Kimi, GLM | Backup | Free tier |

### Setup .env
```env
# At least 1 key needed
OPENROUTER_API_KEY=sk-or-v1-...

# Or any other provider
DEEPSEEK_API_KEY=sk-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY_1=AIza...

# Custom provider (any OpenAI-compatible API)
CUSTOM_API_KEY=sk-...
CUSTOM_BASE_URL=https://your-api.com/v1
CUSTOM_MODEL=your-model
```

---

## Project Structure
```
prometheus/
├── .env                    # API keys (NEVER commit)
├── install.ps1             # Windows auto installer
├── install.sh              # Linux/Mac auto installer
├── requirements.txt        # Python dependencies
├── config/
│   └── models.json         # 13 AI provider configs
├── src/
│   ├── main.py             # Main chat system
│   ├── brain/              # AI brain
│   │   ├── llm.py          # 13 LLM providers
│   │   ├── router.py       # Auto-detect + role routing
│   │   └── critic.py       # Multi-model consensus
│   ├── memory/             # Memory system
│   │   ├── chroma.py       # Vector DB (in-memory fallback)
│   │   ├── episodic.py     # Experience memory
│   │   └── emotional.py    # Emotional memory
│   ├── consciousness/      # Consciousness
│   │   ├── emotions.py     # 20 emotions
│   │   ├── identity.py     # Self-identity
│   │   ├── dreaming.py     # Memory consolidation
│   │   └── intent_parser.py # Hinglish command parser
│   ├── web/                # Web tools
│   │   ├── proxy.py        # HTTP interceptor
│   │   ├── vuln_scanner.py # SQLi/XSS/SSRF
│   │   ├── osint.py        # OSINT 20+ platforms
│   │   ├── brute_force.py  # Smart brute
│   │   └── browser.py      # Playwright stealth
│   ├── bugbounty/          # Bug bounty
│   │   ├── toolkit.py      # Python audit (zero tools)
│   │   ├── knowledge.py    # 1242 reports DB
│   │   └── recon.py        # Recon pipeline
│   ├── autonomy/           # Self-evolution
│   │   ├── goals.py        # Goal management
│   │   ├── survival.py     # Self-preservation
│   │   └── evolution/      # GitHub scanner
│   └── utils/
│       ├── config.py       # Auto-detect config
│       └── logger.py       # Logging
├── learn-from-others/      # Bug bounty knowledge
│   ├── knowledge_base.json # 1242 reports
│   └── patterns/           # Cheatsheets, playbooks, payloads
├── tests/                  # 40 tests
└── docs/                   # GitHub Pages
```

---

## Testing
```bash
# Run all tests
python -m pytest tests/ -v

# Quick test
python test_all.py

# Specific test
python -m pytest tests/test_brain.py -v
```

---

## Knowledge Base

1242 bug bounty reports across 20 vulnerability types:
- SQL Injection, XSS, SSRF, IDOR, RCE
- Auth Bypass, Privilege Escalation, XXE
- CSRF, File Upload, Subdomain Takeover
- Open Redirect, Business Logic, JWT
- GraphQL, Race Condition, Cache Poisoning
- SSTI, LFI, CRLF Injection

---

## Security

- NEVER commit `.env`
- NEVER share API keys
- Rotate keys if compromised
- GitHub push protection enabled

---

## Support

- Issues: https://github.com/mysterious75/prometheus/issues
- Docs: See docs/ folder

---

**Built with love by mysterious75**
