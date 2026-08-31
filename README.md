# Userhunt CLI

Autonomous AI-powered OSINT toolkit with deep hunt engine. Hunt across 35+ tools in parallel, powered by enterprise-grade AI pivoting.

🎯 **Deep Hunt Engine** • 🤖 **AI-Powered Pivots** • ⚡ **35+ Tools** • 📊 **Live Dashboard**

## ⚡ Quick Start

```bash
# Install
pip install -e .

# Interactive mode (recommended)
userhunt

# Fast: scan a username
userhunt --hunt quick -u targetuser

# Full: all tools in parallel
userhunt --hunt full -u user1 -u user2 -e target@email.com

# Deep: complete analysis with AI pivots
userhunt --hunt deep -u user1
```

## 🌟 Features

### 🔍 Reconnaissance
- **Username enumeration** across 500+ sites (Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName, 40+ direct probes)
- **Email reconnaissance** (Holehe, Gravatar, emailrep, MX lookup, Blackbird, h8mail, email2phonenumber)
- **Domain intelligence** (WHOIS, RDAP, DNS all record types, crt.sh, Wayback, ip-api, Sublist3r, FinalRecon, waymore, theHarvester)
- **Phone OSINT** (phonenumbers library, ignorant, phoneinfoga)
- **Name permutations** (username generation, Gravatar validation, Wikipedia, HackerNews)
- **URL reconnaissance** (Photon spider, Wayback availability)

### 🤖 AI & Automation
- **Autonomous pivot engine** — AI extracts new identifiers from results and automatically queues them
- **Free AI providers** — Groq, Gemini, Cerebras, OpenRouter (no credit card required)
- **Paid options** — OpenAI, custom OpenAI-compatible endpoints
- **Live confidence scoring** — HIGH/MEDIUM/LOW ratings with consistency checks
- **AI profile building** — analyzes patterns, extracts profile images

### 🎨 User Experience
- **Rich interactive CLI** — beautiful tables, live progress, color-coded output
- **Live web dashboard** — http://0.0.0.0:8000 streams results in real-time
- **Playwright browser integration** — JS-rendered page analysis, SpiderFoot automation
- **JSON + PDF reports** — shareable findings with embedded profile images
- **Evidence collection** — automatically visits high-confidence hits, extracts display names, bios, avatars

### ⚙️ Configuration
- **Deep hunt (default)** — all tools, unlimited rounds, AI pivoting, full evidence collection
- **Full hunt** — core tools + optional email/domain deep scanners
- **Quick hunt** — Sherlock, Maigret, WhatsMyName, direct probes only
- **Hunt modes** — customize via config or CLI flags

## 📂 Workspace Structure

```
userhunt_workspace/
├── tools/          # 30+ cloned OSINT repositories
├── output/         # JSON reports, PDFs, case exports
├── data/           # case.json (persistent state), temp files
└── config.json     # AI settings, hunt preferences
```

**Disk enforcement**: Warns at <2GB free, stops installation at <500MB.

## 🔐 AI Setup (Optional)

**FREE providers** (no credit card):
- **Groq Free** — 30 RPM, 1000/day, fastest. Get key: https://console.groq.com
- **Gemini Free** — 1500/day, 10 RPM. Get key: https://ai.google.dev
- **Cerebras Free** — 5 RPM, 1M tokens/day. Get key: https://cloud.cerebras.ai
- **OpenRouter Free** — 20 RPM, 50/day (1000 after $10 credit). Get key: https://openrouter.ai

**Setup in CLI**: Select option `[12] AI settings` and choose a provider.

**Via environment**:
```bash
export AI_API_KEY="your-key"
export AI_BASE_URL="https://api.groq.com/openai/v1"
export AI_MODEL="llama-3.3-70b-versatile"
export AI_PROVIDER="groq_free"
userhunt
```

## 🚀 Hunt Modes Explained

| Mode | Tools | Speed | Best For |
|------|-------|-------|----------|
| **Quick** | 6 core tools | Fast (1-2 min) | Initial reconnaissance |
| **Full** | 15+ tools | Medium (5-10 min) | Comprehensive scan |
| **Deep** | 35+ tools + AI | Thorough (15+ min) | Complete investigation |

All modes run **NO TIMEOUT** — tools run to completion for 100% accuracy.

## 🎯 Hunt Features

### Live Dashboard
- Real-time tool status (PENDING → RUNNING → OK/FAIL)
- Hit counter by tool
- Execution time per tool
- Streaming tool logs
- Dashboard persists during/after hunt

### Autonomous Pivoting
After each round, AI extracts:
- New email addresses (regex + pattern matching)
- Additional usernames (handles, path usernames)
- Discord invites & snowflakes
- Phone numbers
- Domain names & subdomains
- Bitcoin addresses
- Automatically queues for next round!

### Evidence Collection
HIGH/MEDIUM confidence hits get visited:
- Extract display name, bio, profile picture
- Download avatar for PDF embedding
- Capture JavaScript-rendered content (via Playwright)
- NO timeout on cached/visited pages

### Confidence Scoring
Each hit scored on:
- Platform (HIGH platforms: Twitter, GitHub, Discord, etc.)
- Data freshness (recent > old)
- Hit type (direct profile > indirect reference)

## 🛠️ Development

### Testing
```bash
pip install -e ".[dev]"
pytest
```

### Code Quality
```bash
ruff check userhunt/
mypy userhunt/
black --check userhunt/
```

## 📋 Default Config

**No caps — unlimited accuracy:**
- `max_hits: 0` — unlimited hits per hunt
- `max_pivot_log: 0` — unlimited pivots extracted
- `tool_timeout: 0` — no timeout (runs to completion)
- `link_visit_cap: 0` — unlimited evidence collection
- `max_rounds: 8` — runs up to 8 rounds of pivoting

All configurable via `userhunt_workspace/config.json`.

## 🐛 Troubleshooting

**Port 8000 already in use?**
```bash
# Kill existing processes
lsof -ti:8000 | xargs kill -9

# Or disable dashboard
userhunt --no-dashboard
```

**Tools not installing?**
```bash
# Deep clean (removes cloned tools, keep output)
userhunt clean

# Deep clean everything
userhunt clean --deep
```

**AI not working?**
```bash
# Re-configure AI
userhunt
# Then select option [12] AI settings
```

## 📄 License

MIT License. See LICENSE for details.

---

**Built for penetration testers, security researchers, and OSINT professionals.**
