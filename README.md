# USERHUNT CLI

Autonomous AI-powered OSINT toolkit with deep hunt engine.

## Installation

```bash
pip install -e .
userhunt
```

## Features

- Username enumeration across 500+ sites (Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName)
- Email reconnaissance (Holehe, Gravatar, emailrep, MX lookup)
- Domain intelligence (WHOIS, DNS, crt.sh, Wayback, Sublist3r)
- Phone intelligence (phonenumbers, ignorant)
- Autonomous AI pivot engine (remote LLM)
- Evidence collection and confidence scoring
- JSON and PDF reports

## AI Settings

Configure via menu option [12] or environment variables:
- `AI_API_KEY` or `OPENAI_API_KEY`
- `AI_BASE_URL`
- `AI_MODEL`

Presets: Groq, OpenAI, Gemini, OpenRouter, Custom.

## Storage

Workspace: `./username_hunt_workspace/`
- `tools/` — cloned OSINT tools
- `output/` — JSON and PDF reports
- `data/` — case state and temp files
