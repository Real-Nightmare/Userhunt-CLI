"""
AI Engine — Remote LLM integration for autonomous pivot analysis.
OpenAI-compatible chat completions API. NEVER uses Ollama.
Built-in free providers: Groq, Gemini, Cerebras, OpenRouter.
No limits — full accuracy.
"""
import json
import re
import time
from typing import Any, Dict, List, Optional

import requests

from userhunt.config import Config, AIConfig, AIProvider, BUILTIN_PROVIDERS


class AIResponse:
    """Response from AI engine."""

    def __init__(self, content: str = "", model: str = "", calls_made: int = 0, error: Optional[str] = None):
        self.content = content
        self.model = model
        self.calls_made = calls_made
        self.error = error


class AIEngine:
    """
    Remote LLM integration via OpenAI-compatible chat completions API.
    Supports Groq, OpenAI, Gemini, OpenRouter, Cerebras, and custom providers.
    No call limits — full accuracy.
    """

    def __init__(self, config: Config):
        self.config = config
        self.ai: AIConfig = config.ai
        self._available: bool = True
        self._logged_unavailable: bool = False

    def reset_round(self) -> None:
        """Reset call counter for a new round."""
        self.ai.calls_made = 0

    def _log_once(self, msg: str) -> None:
        if not self._logged_unavailable:
            print(f"[AI] {msg}")
            self._logged_unavailable = True

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.ai.api_key:
            headers["Authorization"] = f"Bearer {self.ai.api_key}"
        # OpenRouter specific headers
        if "openrouter.ai" in self.ai.base_url:
            headers["HTTP-Referer"] = "https://userhunt-cli.local"
            headers["X-Title"] = "Userhunt CLI"
        return headers

    def _call(
        self,
        messages: List[Dict[str, str]],
        max_chars: Optional[int] = None,
    ) -> AIResponse:
        """Make a chat completion request with retry logic. No call limits."""
        if not self._available or not self.ai.api_key:
            if not self._logged_unavailable:
                self._log_once("AI engine unavailable. Running deterministic-only.")
            return AIResponse(content="[]", model=self.ai.model, calls_made=0, error="unavailable")

        # No call limit check — unlimited calls

        # Truncate messages only if max_chars is set (0 = no truncation)
        limit = max_chars or 0
        truncated = []
        for m in messages:
            content = m.get("content", "")
            if limit > 0 and len(content) > limit:
                content = content[:limit] + "...[truncated]"
            truncated.append({**m, "content": content})

        payload: Dict[str, Any] = {
            "model": self.ai.model,
            "messages": truncated,
            "temperature": self.ai.temperature,
            "max_tokens": self.ai.max_tokens,
        }

        # Try json_object format for compatible models
        model_lower = self.ai.model.lower()
        if any(k in model_lower for k in ("gemini", "gpt", "llama")):
            payload["response_format"] = {"type": "json_object"}

        last_error = None
        for attempt in range(2):
            try:
                resp = requests.post(
                    f"{self.ai.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                    timeout=self.ai.timeout,
                )

                # Retry on 429 or 5xx
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt == 0:
                        time.sleep(self.ai.retry_delay)
                        continue
                    return AIResponse(
                        content="[]", model=self.ai.model,
                        calls_made=self.ai.calls_made,
                        error=f"HTTP {resp.status_code}",
                    )

                # Retry without response_format on 400
                if resp.status_code == 400 and "response_format" in payload:
                    payload.pop("response_format", None)
                    resp = requests.post(
                        f"{self.ai.base_url}/chat/completions",
                        headers=self._headers(),
                        json=payload,
                        timeout=self.ai.timeout,
                    )

                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                self.ai.calls_made += 1
                return AIResponse(
                    content=content,
                    model=data.get("model", self.ai.model),
                    calls_made=self.ai.calls_made,
                )

            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response else 0
                if (status == 429 or status >= 500) and attempt == 0:
                    time.sleep(self.ai.retry_delay)
                    continue
                last_error = str(e)
            except Exception as e:
                if attempt == 0:
                    time.sleep(self.ai.retry_delay)
                    continue
                last_error = str(e)

        return AIResponse(
            content="[]", model=self.ai.model,
            calls_made=self.ai.calls_made, error=last_error,
        )

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Leniently extract JSON from AI response text."""
        text = re.sub(r'```(?:json)?\n?', '', text)
        match = re.search(r'(\[.*\]|\{.*\})', text, re.DOTALL)
        if not match:
            return []
        try:
            return json.loads(match.group(1))
        except Exception:
            return []

    def review_round(self, case: Any, round_num: int) -> None:
        """AI review of scan results for the current round. No call limits."""
        if not self._available or not self.ai.api_key:
            return

        hits_summary = []
        for h in case.hits[-200:]:
            hits_summary.append({
                "platform": h.get("platform", ""),
                "url": h.get("url", ""),
                "confidence": h.get("confidence", "MEDIUM"),
                "display_name": h.get("display_name", ""),
                "bio": (h.get("bio") or "")[:200],
                "emails": h.get("emails_found", [])[:5],
                "socials": h.get("other_socials", [])[:10],
            })

        evidence_summary = []
        for p in case.profile_evidence[-100:]:
            evidence_summary.append({
                "platform": p.get("platform", ""),
                "display_name": p.get("display_name", ""),
                "bio": (p.get("bio") or "")[:200],
                "emails": p.get("emails", [])[:5],
                "socials": p.get("other_socials", [])[:10],
            })

        payload = {
            "hits": hits_summary[:50],
            "evidence": evidence_summary[:30],
            "known_usernames": case.usernames[:20],
            "known_emails": case.emails[:20],
            "known_names": case.names[:10],
        }

        text = json.dumps(payload, ensure_ascii=False)
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an OSINT pivot analyst. Return ONLY a JSON array of objects "
                    '{"action":"queue_username|queue_email|queue_phone|queue_domain|'
                    'verify_real|verify_false|note","value":"...","reason":"..."}. '
                    "Use ONLY values present in the data. Flag inconsistent display names, "
                    "dead accounts, and parked pages as verify_false. Empty array if nothing."
                ),
            },
            {"role": "user", "content": text},
        ]

        # No char limit — send full data
        resp = self._call(messages)
        if resp.error:
            return

        verdicts = self._extract_json(resp.content)
        if not isinstance(verdicts, list):
            return

        for v in verdicts:
            if not isinstance(v, dict):
                continue
            case.ai_verdicts.append({
                "round": round_num,
                "target": v.get("value", ""),
                "verdict": v.get("action", "note"),
                "reason": v.get("reason", ""),
                "model": resp.model,
            })

    def build_profile(self, case: Any) -> Optional[str]:
        """Build AI-powered profile summary from case data. No limits."""
        if not self._available or not self.ai.api_key:
            return None

        summary = {
            "usernames": case.usernames[:30],
            "emails": case.emails[:30],
            "names": case.names[:20],
            "hits": [
                {
                    "platform": h.get("platform", ""),
                    "url": h.get("url", ""),
                    "confidence": h.get("confidence", ""),
                    "display_name": h.get("display_name", ""),
                    "bio": (h.get("bio") or "")[:300],
                    "has_image": bool(h.get("avatar_url") or h.get("images")),
                }
                for h in case.hits[:100]
            ],
            "pivot_chain": case.pivot_log.as_list()[-50:] if hasattr(case.pivot_log, "as_list") else [],
        }

        text = json.dumps(summary, ensure_ascii=False)
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an OSINT analyst. Produce a concise profile summary. "
                    "Label findings as CONFIRMED or UNVERVED. Never invent facts. "
                    "Flag false positives. Summarize pivot chains. "
                    "If profile images were found, note which platforms have profile pictures. "
                    "Plain text."
                ),
            },
            {"role": "user", "content": text},
        ]

        # No char limit — send full data
        resp = self._call(messages)
        if resp.error or not resp.content:
            return None
        return resp.content.strip()
