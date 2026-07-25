# BASE.md — Research, Analysis & Roadmap

> Comprehensive analysis of the security testing landscape, competitor research, tool inventory, and improvement roadmap for Prometheus.

---

## Table of Contents

1. [Market Analysis](#market-analysis)
2. [Competitor Breakdown](#competitor-breakdown)
3. [Tool Inventory](#tool-inventory)
4. [Feature Comparison](#feature-comparison)
5. [Improvement Roadmap](#improvement-roadmap)
6. [Architecture Decisions](#architecture-decisions)
7. [Sources](#sources)

---

## Market Analysis

### Market Categories

The AI security testing market in 2026 is divided into three tiers:

**Tier 1: Enterprise ($100K+ deals)**
- Pentera ($250M funding, ~$100K avg deal)
- Horizon3.ai / NodeZero ($18.6K/yr median)
- Armadin ($190M funding, Mandiant founder)

**Tier 2: AI-Native ($199-$4K per test)**
- XBOW ($4K/test, HackerOne verified)
- RunSybil ($40M funding, OpenAI's first security hire)
- MindFort ($199/mo, auto-fix PRs, YC-backed)
- Intruder ($4K/test, code-level validation)

**Tier 3: Budget/Specialized ($0-$99/mo)**
- BugBunny.ai ($49/mo, 89+ CVEs, HackerOne #1)
- Escape (API/GraphQL specialist, YC-backed)
- CodeAnt AI (free scan, SAST + DAST)

### Market Gap

**No free, open-source, full-featured AI security testing platform exists.**

- CAI is a framework, not a tool
- Strix is a paid platform
- PentAGI has complex setup
- PentestGPT requires human-in-the-loop

Prometheus fills this gap.

---

## Competitor Breakdown

### XBOW
- **Type**: Black-box autonomous pentesting
- **Price**: ~$4,000/test
- **Strengths**: HackerOne verified, autonomous agents, exploit chaining
- **Weaknesses**: Expensive, no auto-fix, no white-box testing, closed source
- **Funding**: Unknown
- **Key Feature**: Verified PoC generation

### RunSybil
- **Type**: AI-native black-box testing
- **Price**: Custom enterprise
- **Strengths**: Founded by OpenAI's first security hire, continuous testing
- **Weaknesses**: Expensive, no auto-fix, no source code access
- **Funding**: $40M (Khosla Ventures)
- **Key Feature**: Autonomous continuous pentesting

### MindFort
- **Type**: Hybrid white/black-box AI security engineer
- **Price**: From $199/month
- **Strengths**: Auto-fix PRs, continuous testing, code analysis, triage in Slack
- **Weaknesses**: Newer platform, less established
- **Funding**: YC-backed
- **Key Feature**: Auto-generates Pull Requests with code fixes

### BugBunny.ai
- **Type**: Black-box automated auditing
- **Price**: From $49/month
- **Strengths**: 89+ public CVEs, HackerOne #1 Business, transparent pricing, verified PoCs
- **Weaknesses**: Less autonomous than XBOW, no white-box
- **Funding**: Unknown
- **Key Feature**: Public CVE proof + transparent pricing

### Horizon3.ai (NodeZero)
- **Type**: Autonomous network pentesting
- **Price**: $18.6K/yr median (per asset)
- **Strengths**: Internal + external + AD + cloud + phishing, unlimited tests
- **Weaknesses**: Network-focused (not web app), expensive, no public pricing
- **Funding**: Significant
- **Key Feature**: Full network attack path validation

### Pentera
- **Type**: Automated security validation
- **Price**: ~$100K avg deal
- **Strengths**: Most commercially proven ($100M+ ARR), on-prem + cloud + AD
- **Weaknesses**: Legacy platform, no white-box, no auto-fix, expensive
- **Funding**: $250M
- **Key Feature**: Enterprise-scale security validation

### Escape
- **Type**: API-native DAST
- **Price**: Commercial
- **Strengths**: GraphQL specialist, BOLA/IDOR detection, 140+ tests, CI/CD integration
- **Weaknesses**: API-focused only, not general web app testing
- **Funding**: YC-backed
- **Key Feature**: Business Logic Security Testing (BLST) for APIs

### Armadin
- **Type**: AI + human red teaming
- **Price**: Custom enterprise
- **Strengths**: Mandiant founder, human-in-the-loop, $190M funding
- **Weaknesses**: Not fully autonomous (humans required)
- **Funding**: $190M
- **Key Feature**: Multi-phase attack campaigns with human review

---

## Tool Inventory

### Reconnaissance & OSINT

| Tool | Stars | Purpose | GitHub |
|------|-------|---------|--------|
| Nuclei | 29,300+ | Template-based vulnerability scanner | projectdiscovery/nuclei |
| Subfinder | 10,500+ | Passive subdomain enumeration | projectdiscovery/subfinder |
| httpx | 7,800+ | HTTP probing and analysis | projectdiscovery/httpx |
| Katana | 12,500+ | Web crawling | projectdiscovery/katana |
| Naabu | 5,000+ | Port scanning | projectdiscovery/naabu |
| Sherlock | 62,000+ | Username search (400+ platforms) | sherlock-project/sherlock |
| Maigret | 14,000+ | Username OSINT (500+ sites) | soxoj/maigret |
| theHarvester | 11,000+ | Email/subdomain harvesting | laramies/theHarvester |
| Amass | 12,500+ | Attack surface mapping | owasp-amass/amass |
| SpiderFoot | 13,500+ | OSINT automation (200+ modules) | smicallef/spiderfoot |
| Shodan | 3,500+ | Internet intelligence | achillean/shodan-python |
| Recon-ng | 6,500+ | Web reconnaissance framework | lanmaster53/recon-ng |

### Vulnerability Scanners

| Tool | Stars | Purpose | GitHub |
|------|-------|---------|--------|
| SQLMap | 33,000+ | SQL injection exploitation | sqlmapproject/sqlmap |
| XSStrike | 22,000+ | Advanced XSS detection | s0md3v/XSStrike |
| OWASP ZAP | 13,000+ | Full web app scanner | zaproxy/zaproxy |
| Nikto | 9,000+ | Web server scanner | sullo/nikto |
| Dalfox | 4,000+ | Fast XSS scanner | hahwul/dalfox |
| Commix | 4,500+ | Command injection | commixproject/commix |
| Arjun | 4,500+ | HTTP parameter discovery | s0md3v/Arjun |
| FFUF | 13,500+ | Web fuzzer | ffuf/ffuf |
| Gobuster | 10,000+ | Directory busting | OJ/gobuster |
| TruffleHog | 18,000+ | Secret detection in git | trufflesecurity/trufflehog |

### AI-Powered Pentest Tools

| Tool | Stars | Purpose | GitHub |
|------|-------|---------|--------|
| CAI | 6,700+ | Cybersecurity AI framework | aliasrobotics/CAI |
| Strix | 19,000+ | AI pentesting with auto-fix | usestrix/strix |
| PentestGPT | 11,000+ | LLM-automated pentesting | GreyDGL/PentestGPT |
| PentAGI | 900+ | Fully autonomous AI agents | vxcontrol/pentagi |
| HexStrike AI | 5,900+ | MCP server with 150+ tools | 0x4m4/hexstrike-ai |
| Nebula | 843+ | AI pentest assistant | berylliumsec/nebula |

### Network & Infrastructure

| Tool | Stars | Purpose | GitHub |
|------|-------|---------|--------|
| Nmap | 10,500+ | Network discovery | nmap/nmap |
| Masscan | 24,000+ | Fast port scanner | robertdavidgraham/masscan |
| RustScan | 15,000+ | Modern port scanner | RustScan/RustScan |
| BloodHound | 3,500+ | AD attack paths | BloodHoundAD/BloodHound |
| Bettercap | 17,000+ | Network attack/monitoring | bettercap/bettercap |

### Full Frameworks

| Tool | Stars | Purpose | GitHub |
|------|-------|---------|--------|
| reconFTW | 10,000+ | Automated recon pipeline | six2dez/reconftw |
| Sn1per | 8,500+ | Automated pentest framework | 1N3/Sn1per |
| Osmedeus | 7,500+ | Offensive security workflow | j3ssie/osmedeus |

### Curated Lists

| List | Stars | Focus |
|------|-------|-------|
| awesome-bugbounty-tools | 6,000+ | Bug bounty tools |
| awesome-ai-security-tools | 2,000+ | AI security tools |
| awesome-osint | 18,000+ | OSINT resources |

---

## Feature Comparison

### Prometheus vs Competitors

| Feature | XBOW | RunSybil | MindFort | BugBunny | Prometheus |
|---------|------|----------|----------|----------|------------|
| **Open Source** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Free Tier** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **15 Vuln Scanners** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Multi-session BOLA** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **GraphQL/API** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **JWT Analysis** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Auto-fix PRs** | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Self-Learning** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Continuous Scanning** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Internal Network** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Cloud Bucket Scan** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Dorking (4 engines)** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Knowledge Base** | ❌ | ❌ | ❌ | ❌ | ✅ (1242 reports) |
| **HackerOne Reports** | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Offline Mode** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Price** | $4K/test | Enterprise | $199/mo | $49/mo | $0-$299/mo |

---

## Improvement Roadmap

### Phase 1: Core Enhancements (Current)
- [x] Multi-session BOLA/IDOR testing
- [x] GraphQL/REST API security
- [x] JWT analysis (none algo, confusion, expiry)
- [x] Auto-fix PR generation
- [x] Internal network scanning (SMB, LDAP, Kerberos)
- [x] Continuous scanning engine
- [x] Evidence engine + HackerOne reports
- [x] Self-learning engine
- [x] Smart subdomain deduplication
- [x] Dorking engine (Google, GitHub, Shodan, Bing)
- [x] Pricing model (USD)

### Phase 2: Advanced Features
- [ ] Docker sandbox for safe exploit execution
- [ ] Web dashboard (React/Next.js)
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] SARIF output for GitHub Security tab
- [ ] OAuth 2.0 flow testing
- [ ] gRPC security testing
- [ ] WebSocket testing
- [ ] API schema validation (OpenAPI/Swagger)

### Phase 3: Intelligence
- [ ] RAG-based attack recommendation (vector search)
- [ ] Community knowledge base contributions
- [ ] Real-time CVE → attack pattern mapping
- [ ] Automated CVE submission workflow
- [ ] Bug bounty platform integration (HackerOne, Bugcrowd)

### Phase 4: Enterprise
- [ ] SSO/SAML integration
- [ ] Compliance reports (OWASP Top 10, SOC 2, PCI-DSS)
- [ ] Team management with role-based access
- [ ] On-premise deployment option
- [ ] Custom playbook creation
- [ ] API for automation

### Phase 5: Network & Cloud
- [ ] Active Directory attack paths (BloodHound-style)
- [ ] Cloud IAM misconfiguration detection (AWS/Azure/GCP)
- [ ] Kubernetes security testing
- [ ] Container vulnerability scanning
- [ ] Infrastructure-as-Code security

---

## Architecture Decisions

### Why Wrap Tools Instead of Building?

External tools like Nuclei (29K stars), SQLMap (33K stars), and Sherlock (62K stars) are battle-tested by millions of users. Building alternatives from scratch would take years and produce inferior results. Prometheus wraps these tools and adds AI intelligence on top.

### Why Fallback Mode?

Not everyone has Go installed or can compile binaries. Every tool wrapper has a Python fallback that provides basic functionality. This ensures Prometheus works anywhere Python runs.

### Why Authorization-First?

Security tools must not be used for unauthorized scanning. Prometheus requires explicit target authorization before any active scanning. This prevents misuse and keeps users legal.

### Why Keyword-Based Emotion Detection?

The old system made LLM API calls for every emotion detection (slow, expensive, unreliable). The new system uses keyword matching (fast, free, offline). LLM-based detection is available as an optional fallback.

### Why Smart Deduplication?

When 10 tools each discover subdomains, naive approaches re-scan the same subdomains 10 times. The SmartAssetManager ensures each tool only scans NEW, undiscovered assets — maximizing coverage with zero redundancy.

---

## Sources

### Research Papers
- CAI: An Open, Bug Bounty-Ready Cybersecurity AI (arXiv:2504.06017)
- PentestGPT: Evaluating and Harnessing LLMs for Pentesting (USENIX Security 2024)
- Comparing AI Agents to Cybersecurity Professionals (arXiv:2512.09882)

### Competitor Analysis
- MindFort Blog: "4 Best XBOW Alternatives in 2026"
- BugBunny.ai: "XBOW Alternative for AI Pentesting"
- Escape.tech: "Best Agentic Pentesting Tools in 2026"
- Ostorlab: "8 Open-Source AI Pentest Tools for Security Teams in 2026"
- CodeAnt AI: "NodeZero Pricing 2026"
- Penligent: "The 2026 Ultimate Guide to AI Penetration Testing"

### Tool Repositories
- github.com/projectdiscovery (Nuclei, Subfinder, httpx, Katana, Naabu)
- github.com/aliasrobotics/CAI
- github.com/usestrix/strix
- github.com/vxcontrol/pentagi
- github.com/GreyDGL/PentestGPT
- github.com/six2dez/reconftw
- github.com/vavkamil/awesome-bugbounty-tools
- github.com/scadastrangelove/awesome-ai-security-tools

### News
- Fortune: "RunSybil raises $40M" (March 2026)
- SiliconAngle: "RunSybil raises $40M to automate offensive security"
- BankInfoSecurity: "Armadin launches with $190M"

---

*Last updated: 2026-07-26*
*Generated by Prometheus Research Module*
