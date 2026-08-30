"""
Pivot engine — extracts new identifiers from scan output and AI verdicts.
"""
import json
import re
from typing import List, Dict, Any
from collections import deque

from userhunt.config import Config


class PivotEngine:
    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    URL_RE = re.compile(r'https?://[^\s<>"\']+')
    HANDLE_RE = re.compile(r'@([a-zA-Z0-9_]{3,30})')
    DISCORD_INVITE_RE = re.compile(r'discord\.gg/([A-Za-z0-9_-]+)')
    SNOWFLAKE_RE = re.compile(r'\b(\d{17,20})\b')
    ROBLOX_RE = re.compile(r'\b(\d{3,16})\b')
    BTC_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    PHONE_RE = re.compile(r'\+?\d[\d\s\-\(\)]{7,15}\d')
    DOMAIN_RE = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\b')

    def __init__(self, config: Config):
        self.config = config
        self.pivot_log: deque = deque(maxlen=config.hunt.max_pivot_log)

    def extract_pivots(self, case: Any, round_num: int) -> List[Dict[str, Any]]:
        pivots = []
        for hit in case.hits[-200:]:
            text = json.dumps(hit, ensure_ascii=False)
            pivots.extend(self._extract_from_text(text, f"hit:{hit.get('platform','?')}"))
        for evidence in case.profile_evidence[-100:]:
            text = json.dumps(evidence, ensure_ascii=False)
            pivots.extend(self._extract_from_text(text, f"evidence:{evidence.get('platform','?')}"))
        seen = set()
        deduped = []
        for p in pivots:
            key = (p.get("action", ""), p.get("value", "").lower())
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped[: config.hunt.max_pivot_log]

    def _extract_from_text(self, text: str, source: str) -> List[Dict[str, Any]]:
        pivots = []
        for match in self.EMAIL_RE.finditer(text):
            val = match.group(0)
            pivots.append({"round": 0, "source": source, "found": val, "action": "queue_email", "reason": "regex pivot", "by": "regex"})
        for match in self.URL_RE.finditer(text):
            val = match.group(0)
            pivots.append({"round": 0, "source": source, "found": val, "action": "note", "reason": "url found", "by": "regex"})
        for match in self.DISCORD_INVITE_RE.finditer(text):
            val = match.group(0)
            pivots.append({"round": 0, "source": source, "found": val, "action": "note", "reason": "discord invite", "by": "regex"})
        for match in self.SNOWFLAKE_RE.finditer(text):
            val = match.group(1)
            pivots.append({"round": 0, "source": source, "found": val, "action": "note", "reason": "discord snowflake", "by": "regex"})
        for match in self.ROBLOX_RE.finditer(text):
            val = match.group(1)
            pivots.append({"round": 0, "source": source, "found": val, "action": "note", "reason": "roblox id", "by": "regex"})
        for match in self.BTC_RE.finditer(text):
            val = match.group(0)
            pivots.append({"round": 0, "source": source, "found": val, "action": "note", "reason": "btc address", "by": "regex"})
        for match in self.PHONE_RE.finditer(text):
            val = match.group(0)
            pivots.append({"round": 0, "source": source, "found": val, "action": "queue_phone", "reason": "regex pivot", "by": "regex"})
        for match in self.DOMAIN_RE.finditer(text):
            val = match.group(1)
            if "." in val and len(val) > 4:
                pivots.append({"round": 0, "source": source, "found": val, "action": "queue_domain", "reason": "regex pivot", "by": "regex"})
        for match in self.HANDLE_RE.finditer(text):
            val = match.group(1)
            if len(val) >= 3:
                pivots.append({"round": 0, "source": source, "found": val, "action": "queue_username", "reason": "handle pivot", "by": "regex"})
        return pivots
