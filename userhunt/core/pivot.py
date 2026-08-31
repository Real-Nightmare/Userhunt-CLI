"""
Pivot engine — extracts new identifiers from scan output and AI verdicts.
Uses centralized extractors from utils.extractors.
"""
import json
from typing import Any, Dict, List
from collections import deque

from userhunt.config import Config
from userhunt.utils.extractors import (
    extract_emails, extract_urls, extract_handles, extract_usernames_from_paths,
    extract_discord_invites, extract_discord_snowflakes, extract_roblox_ids,
    extract_btc_addresses, extract_phones, extract_domains,
)


class PivotEngine:
    """Extract new identifiers from scan output and AI verdicts."""

    def __init__(self, config: Config):
        self.config = config

    def extract_pivots(self, case: Any, round_num: int) -> List[Dict[str, Any]]:
        """Extract pivot identifiers from hits, evidence, and AI verdicts."""
        pivots: List[Dict[str, Any]] = []

        # From scan hits
        for hit in case.hits[-200:]:
            text = json.dumps(hit, ensure_ascii=False)
            source = f"hit:{hit.get('platform', '?')}"
            pivots.extend(self._extract_from_text(text, source, round_num))

        # From profile evidence
        for evidence in case.profile_evidence[-100:]:
            text = json.dumps(evidence, ensure_ascii=False)
            source = f"evidence:{evidence.get('platform', '?')}"
            pivots.extend(self._extract_from_text(text, source, round_num))

        # From AI verdicts
        for verdict in case.ai_verdicts[-100:]:
            action = verdict.get("verdict", "")
            value = verdict.get("target", "")
            if not value:
                continue
            if action.startswith("queue_"):
                pivot_type = action.replace("queue_", "")
                pivots.append({
                    "round": round_num,
                    "source": "ai",
                    "found": value,
                    "action": action,
                    "reason": verdict.get("reason", "AI pivot"),
                    "by": "ai",
                })

        # Deduplicate — BUG FIX: use "found" not "value"
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for p in pivots:
            key = (p.get("action", ""), p.get("found", "").lower())
            if key not in seen:
                seen.add(key)
                deduped.append(p)

        return deduped[: self.config.hunt.max_pivot_log]

    def _extract_from_text(
        self, text: str, source: str, round_num: int
    ) -> List[Dict[str, Any]]:
        """Extract all identifier types from a text chunk."""
        pivots: List[Dict[str, Any]] = []

        for val in extract_emails(text):
            pivots.append(self._make_pivot(round_num, source, val, "queue_email", "regex pivot"))
        for val in extract_handles(text):
            pivots.append(self._make_pivot(round_num, source, val, "queue_username", "handle pivot"))
        for val in extract_usernames_from_paths(text):
            pivots.append(self._make_pivot(round_num, source, val, "queue_username", "path pivot"))
        for val in extract_discord_invites(text):
            pivots.append(self._make_pivot(round_num, source, val, "note", "discord invite"))
        for val in extract_discord_snowflakes(text):
            pivots.append(self._make_pivot(round_num, source, val, "note", "discord snowflake"))
        for val in extract_roblox_ids(text):
            pivots.append(self._make_pivot(round_num, source, val, "note", "roblox id"))
        for val in extract_btc_addresses(text):
            pivots.append(self._make_pivot(round_num, source, val, "note", "btc address"))
        for val in extract_phones(text):
            pivots.append(self._make_pivot(round_num, source, val, "queue_phone", "regex pivot"))
        for val in extract_domains(text):
            pivots.append(self._make_pivot(round_num, source, val, "queue_domain", "regex pivot"))
        for val in extract_urls(text):
            pivots.append(self._make_pivot(round_num, source, val, "note", "url found"))

        return pivots

    @staticmethod
    def _make_pivot(
        round_num: int, source: str, value: str, action: str, reason: str
    ) -> Dict[str, Any]:
        return {
            "round": round_num,
            "source": source,
            "found": value,
            "action": action,
            "reason": reason,
            "by": "regex",
        }

    def apply_pivots_to_case(
        self, case: Any, pivots: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Apply verified pivots to case queues. Returns list of applied pivots."""
        applied: List[Dict[str, Any]] = []
        for pivot in pivots:
            action = pivot.get("action", "")
            value = pivot.get("found", "")  # BUG FIX: use "found" not "value"
            if not value:
                continue

            if action == "queue_username":
                if case.add_username(value):
                    applied.append(pivot)
            elif action == "queue_email":
                if case.add_email(value):
                    applied.append(pivot)
            elif action == "queue_phone":
                if value not in case.done_phones and case.can_add_username():
                    case.done_phones.add(value)
                    applied.append(pivot)
            elif action == "queue_domain":
                if value not in case.done_domains and case.can_add_username():
                    case.done_domains.add(value)
                    applied.append(pivot)

        return applied
