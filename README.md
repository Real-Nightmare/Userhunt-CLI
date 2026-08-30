# Userhunt CLI

Autonomous AI-powered OSINT toolkit with deep hunt engine.

## Installation

```bash
pip install -e .
userhunt
```

Or run directly:
```bash
python -m userhunt
```

## Quick Start (Non-Interactive)

```bash
# Deep scan a username — runs ALL tools automatically
userhunt --deep -u targetuser

# Scan multiple identifiers
userhunt --deep -u user1 -u user2 -e target@email.com -n "John Smith"

# Interactive mode (default: deep scan is the default action)
userhunt
```

## Default Behavior

**Deep scan is always the default.** When you add identifiers via the interactive menu, Userhunt CLI automatically offers to start the deep hunt across all tools. The menu default is `[6] RUN FULL DEEP HUNT` — just press Enter to launch.

## Features

- **Username enumeration** across 500+ sites (Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName, direct API probes)
- **Email reconnaissance** (Holehe, Gravatar, emailrep, MX lookup, Blackbird, h8mail, email2phonenumber)
- **Domain intelligence** (WHOIS, RDAP, DNS, crt.sh, Wayback, ip-api, Sublist3r, FinalRecon, waymore, theHarvester)
- **Phone intelligence** (phonenumbers, ignorant, phoneinfoga)
- **Name → username permutations** (Gravatar email validation, Wikipedia, HackerNews)
- **URL reconnaissance** (Photon, Wayback availability)
- **Autonomous AI pivot engine** (remote LLM — Groq, OpenAI, Gemini, OpenRouter, custom)
- **Playwright browser integration** (SpiderFoot web UI, JS-rendered pages, no timeout on local tool UIs)
- **Evidence collection** with profile image extraction and embedding in PDF
- **Confidence scoring** with HIGH/MEDIUM/LOW ratings and consistency checks
- **JSON and PDF reports** with embedded profile images

## AI Settings

Configure via menu option [12] or environment variables:
- `AI_API_KEY` or `OPENAI_API_KEY`
- `AI_BASE_URL`
- `AI_MODEL`

Presets: Groq (free), OpenAI, Gemini, OpenRouter, Custom.

## Storage

Workspace: `./userhunt_workspace/`
- `tools/` — cloned OSINT tools
- `output/` — JSON and PDF reports
- `data/` — case state and temp files

Disk enforcement: warns at <2GB free, aborts install at <500MB.

## Browser Integration

Userhunt CLI includes Playwright-based browser integration for:
- **SpiderFoot** web UI interaction (no timeout on local tool UIs)
- **JS-rendered pages** that need JavaScript execution
- **Evidence collection** from JavaScript-heavy profile pages

Local tool web UIs (127.0.0.1, localhost) are NEVER timed out — they hold session state and evidence.

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```
