"""
AI Engine — Remote LLM integration for autonomous pivot analysis.
OpenAI-compatible chat completions API.
"""
import json
import time
import re
import os
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

import requests

from userhunt.config import Config, AIConfig


@dataclass
class AIResponse:
    content: str
    model: str
    calls_made: int
    error: Optional[str] = None


class AIEngine:
    def __init__(self, config: Config):
        self.config = config
        self.ai: AIConfig = config.ai
        self._available: bool = True
        self._logged_unavailable: bool = False

    def _log_once(self, msg: str) -> None:
        if not self._logged_unavailable:
            print(f"[AI] {msg}")
            self._logged_unavailable = True

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.ai.api_key}",
            "Content-Type": "application/json",
        }

    def _call(self, messages: List[Dict[str, str]], max_chars: Optional[int] = None) -> AIResponse:
        if not self._available or not self.ai.api_key:
            if not self._logged_unavailable:
                self._log_once("AI engine unavailable. Running deterministic-only.")
            return AIResponse(content="[]", model=self.ai.model, calls_made=0, error="unavailable")
        if self.ai.calls_made >= self.ai.max_calls_per_round:
            return AIResponse(content="[]", model=self.ai.model, calls_made=self.ai.calls_made, error="cap")
        truncated = []
        for m in messages:
            content = m.get("content", "")
            if max_chars and len(content) > max_chars:
                content = content[:max_chars] + "...[truncated]"
            truncated.append({**m, "content": content})
        payload = {
            "model": self.ai.model,
            "messages": truncated,
            "temperature": self.ai.temperature,
            "max_tokens": self.ai.max_tokens,
        }
        if "gemini" in self.ai.model.lower() or "gpt" in self.ai.model.lower():
            payload["response_format"] = {"type": "json_object"}
        for attempt in range(2):
            try:
                resp = requests.post(
                    f"{self.ai.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                    timeout=self.ai.timeout,
                )
                if resp.status_code == 429 or resp.status_code >= 500:
                    time.sleep(self.ai.retry_delay)
                    continue
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
                return AIResponse(content=content, model=data.get("model", self.ai.model), calls_made=self.ai.calls_made)
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response else 0
                if status == 429 or (status >= 500 and attempt == 0):
                    time.sleep(self.ai.retry_delay)
                    continue
                return AIResponse(content="[]", model=self.ai.model, calls_made=self.ai.calls_made, error=str(e))
            except Exception as e:
                if attempt == 0:
                    time.sleep(self.ai.retry_delay)
                    continue
                return AIResponse(content="[]", model=self.ai.model, calls_made=self.ai.calls_made, error=str(e))
        return AIResponse(content="[]", model=self.ai.model, calls_made=self.ai.calls_made, error="max_retries")

    def _extract_json(self, text: str) -> Any:
        text = re.sub(r'```(?:json)?\n?', '', text)
        match = re.search(r'(\[.*\]|\{.*\})', text, re.DOTALL)
        if not match:
            return []
        try:
            return json.loads(match.group(1))
        except Exception:
            return []

    def review_round(self, case: Any, round_num: int) -> None:
        if not self._available or not self.ai.api_key:
            return
        hits_summary = []
        for h in case.hits[-200:]:
            hits_summary.append({
                "platform": h.get("platform", ""),
                "url": h.get("url", ""),
                "confidence": h.get("confidence", "MEDIUM"),
                "display_name": h.get("display_name", ""),
                "bio": (h.get("bio", "") or "")[:200],
                "emails": h.get("emails_found", [])[:5],
                "socials": h.get("other_socials", [])[:10],
            })
        evidence_summary = []
        for p in case.profile_evidence[-100:]:
            evidence_summary.append({
                "platform": p.get("platform", ""),
                "display_name": p.get("display_name", ""),
                "bio": (p.get("bio", "") or "")[:200],
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
        if len(text) > self.ai.max_input_chars:
            text = text[:self.ai.max_input_chars]
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an OSINT pivot analyst. Return ONLY a JSON array of objects "
                    'with keys: action (queue_username|queue_email|queue_phone|queue_domain|verify_real|verify_false|note), '
                    'value, reason. Use ONLY values present in the data. Flag inconsistent display names, '
                    'dead accounts, parked pages as verify_false. Empty array if nothing.'
                ),
            },
            {"role": "user", "content": text},
        ]
        resp = self._call(messages, max_chars=self.ai.max_input_chars)
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
                    "bio": (h.get("bio", "") or "")[:300],
                }
                for h in case.hits[:100]
            ],
            "pivot_chain": [p for p in list(case.pivot_log)[-50:]],
        }
        text = json.dumps(summary, ensure_ascii=False)
        if len(text) > self.ai.max_final_input_chars:
            text = text[:self.ai.max_final_input_chars]
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an OSINT analyst. Produce a concise profile summary. "
                    "Label findings as CONFIRMED or UNVERIFIED. Never invent facts. "
                    "Flag false positives. Summarize pivot chains. Plain text."
                ),
            },
            {"role": "user", "content": text},
        ]
        resp = self._call(messages, max_chars=self.ai.max_final_input_chars)
        if resp.error or not resp.content:
            return None
        return resp.content.strip()
