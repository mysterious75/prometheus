# ============================================
# PROJECT PROMETHEUS
# The Ultimate Autonomous AI
# ============================================
# Consciousness + JARVIS + Ultron + FRIDAY + Bug Bounty + Developer
# ============================================

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/mysterious75/prometheus.git
cd prometheus

# 2. Create Python virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Configure environment variables
copy .env.example .env
# Edit .env with your API keys

# 6. Run the system
python -m src.main
```

## 📁 Project Structure

```
prometheus/
├── .env                    # Environment variables (NEVER commit)
├── .gitignore              # Git ignore rules
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── plan.md                 # Detailed implementation plan
├── venv/                   # Python virtual environment
├── src/                    # Source code
│   ├── __init__.py
│   ├── main.py             # Main entry point
│   ├── brain/              # AI Brain (LLM integration)
│   │   ├── __init__.py
│   │   ├── llm.py          # LLM providers (Gemini, OpenRouter)
│   │   └── router.py       # Model routing & fallback
│   ├── memory/             # Memory system
│   │   ├── __init__.py
│   │   ├── chroma.py       # ChromaDB vector memory
│   │   ├── episodic.py     # Episodic memory (experiences)
│   │   └── emotional.py    # Emotional memory
│   ├── voice/              # Voice system
│   │   ├── __init__.py
│   │   ├── stt.py          # Speech-to-text (Whisper)
│   │   └── tts.py          # Text-to-speech (Kokoro)
│   ├── bugbounty/          # Bug bounty automation
│   │   ├── __init__.py
│   │   ├── recon.py        # Reconnaissance pipeline
│   │   ├── scanner.py      # Vulnerability scanning
│   │   └── reporter.py     # Report generation
│   ├── developer/          # Developer tools
│   │   ├── __init__.py
│   │   ├── codegen.py      # Code generation
│   │   └── devops.py       # DevOps automation
│   ├── autonomy/           # Autonomous behavior
│   │   ├── __init__.py
│   │   ├── goals.py        # Goal management
│   │   ├── executor.py     # Task execution
│   │   └── survival.py     # Self-preservation
│   ├── consciousness/      # Consciousness simulation
│   │   ├── __init__.py
│   │   ├── reflection.py   # Self-reflection engine
│   │   ├── emotions.py     # Emotional intelligence
│   │   ├── identity.py     # Identity formation
│   │   └── dreaming.py     # Memory consolidation
│   ├── workflow/           # Workflow automation
│   │   ├── __init__.py
│   │   └── scheduler.py    # Task scheduling
│   └── utils/              # Utilities
│       ├── __init__.py
│       ├── logger.py       # Logging
│       └── config.py       # Configuration loader
├── config/                 # Configuration files
│   └── models.json         # Model configurations
├── scripts/                # Utility scripts
│   ├── setup.sh            # Setup script
│   └── run.sh              # Run script
├── tests/                  # Test files
│   ├── __init__.py
│   ├── test_brain.py       # Brain tests
│   ├── test_memory.py      # Memory tests
│   └── test_voice.py       # Voice tests
├── docs/                   # Documentation
│   └── ARCHITECTURE.md     # Architecture details
└── logs/                   # Application logs
```

## 🧠 System Architecture

```
Layer 8: CONSCIOUSNESS (The Soul)
├── Self-reflection engine
├── Internal monologue
├── Emotional tracking
└── Dreaming/consolidation

Layer 7: IDENTITY (JARVIS + FRIDAY)
├── Voice personality
├── User relationship
├── Proactive behavior
└── Memory of interactions

Layer 6: AUTONOMY (Ultron)
├── Goal creation
├── Strategic planning
├── Self-improvement
└── Self-preservation

Layer 5: DEVELOPER
├── Frontend (React/Next.js)
├── Backend (Python/Go)
├── DevOps (Docker/K8s)
└── AI/ML (LangChain)

Layer 4: BUG BOUNTY
├── Recon (subfinder, httpx)
├── Scanning (Nuclei, ZAP)
├── AI Analysis
└── Report generation

Layer 3: WORKFLOW (n8n)
├── Automated pipelines
├── Scheduled tasks
└── Notifications

Layer 2: DATA (Supabase)
├── User memory
├── Vector search
└── Knowledge base

Layer 1: BRAIN (AI Models)
├── Gemini 2.0 Flash (1M tokens/day)
├── OpenRouter free models
├── Whisper (voice)
└── BGE-M3 (embeddings)
```

## 🔑 API Keys

### Required (Free Tiers)

| Provider | Free Tier | Get Key |
|----------|-----------|---------|
| Google Gemini | 1M tokens/day | https://ai.google.dev |
| OpenRouter | Free models available | https://openrouter.ai |
| GitHub | Personal access token | https://github.com/settings/tokens |

### Optional (For Enhanced Features)

| Provider | Purpose | Get Key |
|----------|---------|---------|
| Supabase | Database & Auth | https://supabase.com |
| Groq | Fast LLM inference | https://console.groq.com |
| Cerebras | 1M tokens/day | https://cerebras.ai |

## 📝 Commands

### Development

```bash
# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Run the main application
python -m src.main

# Run tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_brain.py -v

# Lint code
python -m flake8 src/

# Format code
python -m black src/
```

### Bug Bounty

```bash
# Run recon pipeline
python -m src.bugbounty.recon --target example.com

# Run vulnerability scan
python -m src.bugbounty.scanner --target https://example.com

# Generate report
python -m src.bugbounty.reporter --input results.json
```

### Memory

```bash
# Store a memory
python -m src.memory.episodic --store "Important event"

# Search memories
python -m src.memory.episodic --search "query"

# Run dreaming (consolidation)
python -m src.consciousness.dreaming --dream
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html

# Run specific test file
python -m pytest tests/test_brain.py -v

# Run specific test
python -m pytest tests/test_brain.py::test_llm_connection -v
```

## 📦 Dependencies

### Core (Always Required)
- `google-generativeai` - Gemini API
- `openai` - OpenRouter API
- `chromadb` - Vector database
- `python-dotenv` - Environment variables
- `pydantic` - Data validation

### Voice (Optional)
- `openai-whisper` - Speech-to-text
- `kokoro` - Text-to-speech

### Bug Bounty (Optional)
- `requests` - HTTP requests
- `beautifulsoup4` - HTML parsing

### Development (Optional)
- `fastapi` - Web framework
- `uvicorn` - ASGI server

## 🔒 Security

1. **NEVER** commit `.env` file
2. **NEVER** share API keys publicly
3. **ALWAYS** use virtual environment
4. **ALWAYS** rotate keys if compromised
5. **ALWAYS** use least privilege principle

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

MIT License - See LICENSE file for details

## 🆘 Support

- Issues: https://github.com/mysterious75/prometheus/issues
- Docs: See docs/ folder

---

**Built with ❤️ by mysterious75**
