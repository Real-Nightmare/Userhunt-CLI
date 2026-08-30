"""
Case management — holds all investigation state for a hunt session.
"""
import json
from pathlib import Path
from typing import Any, Dict, Set

from userhunt.utils.storage import RingBuffer


class Case:
    """Persistent case state for an investigation."""

    def __init__(self, max_hits: int = 999999, max_pivot_log: int = 999999, max_notes: int = 999999):
        self.usernames: list[str] = []
        self.emails: list[str] = []
        self.names: list[str] = []
        self.clues: list[str] = []
        self.hits: list[Dict[str, Any]] = []
        self.pivot_log = RingBuffer(maxlen=max_pivot_log)
        self.notes = RingBuffer(maxlen=max_notes)
        self.profile_evidence: list[Dict[str, Any]] = []
        self.ai_verdicts: list[Dict[str, Any]] = []
        self.ai_profile: str = ""
        self.round: int = 0
        self.done_usernames: Set[str] = set()
        self.done_emails: Set[str] = set()
        self.done_domains: Set[str] = set()
        self.done_phones: Set[str] = set()
        self.done_names: Set[str] = set()
        self.done_urls: Set[str] = set()
        self._max_hits = max_hits
        self._per_round_usernames: int = 0
        self._per_round_emails: int = 0

    # ── No caps — full accuracy ─────────────────────────────────────

    def reset_round_caps(self) -> None:
        pass  # No caps

    def can_add_username(self, cap: int = 999999) -> bool:
        return True

    def can_add_email(self, cap: int = 999999) -> bool:
        return True

    def add_username(self, val: str) -> bool:
        if val in self.usernames:
            return False
        self.usernames.append(val)
        return True

    def add_email(self, val: str) -> bool:
        if val in self.emails:
            return False
        self.emails.append(val)
        return True

    def can_add_hit(self) -> bool:
        return True

    def add_hit(self, hit: Dict[str, Any]) -> bool:
        self.hits.append(hit)
        return True

    # ── Serialization ───────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "usernames": self.usernames,
            "emails": self.emails,
            "names": self.names,
            "clues": self.clues,
            "hits": self.hits,
            "pivot_log": self.pivot_log.as_list(),
            "notes": self.notes.as_list(),
            "profile_evidence": self.profile_evidence,
            "ai_verdicts": self.ai_verdicts,
            "ai_profile": self.ai_profile,
            "round": self.round,
        }

    def save(self, path: Path) -> None:
        """Atomically save case state to JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        tmp.replace(path)

    def load(self, path: Path) -> None:
        """Load case state from JSON if it exists."""
        if not path.exists():
            return
        with open(path, "r") as f:
            data = json.load(f)
        self.usernames = data.get("usernames", [])
        self.emails = data.get("emails", [])
        self.names = data.get("names", [])
        self.clues = data.get("clues", [])
        self.hits = data.get("hits", [])
        self.profile_evidence = data.get("profile_evidence", [])
        self.ai_verdicts = data.get("ai_verdicts", [])
        self.ai_profile = data.get("ai_profile", "")
        self.round = data.get("round", 0)
        for item in data.get("pivot_log", []):
            self.pivot_log.append(item)
        for item in data.get("notes", []):
            self.notes.append(item)

    def is_empty(self) -> bool:
        return not (self.usernames or self.emails or self.names or self.clues)

    def clear(self) -> None:
        """Reset all case data."""
        self.usernames.clear()
        self.emails.clear()
        self.names.clear()
        self.clues.clear()
        self.hits.clear()
        self.pivot_log.clear()
        self.notes.clear()
        self.profile_evidence.clear()
        self.ai_verdicts.clear()
        self.ai_profile = ""
        self.round = 0
        self.done_usernames.clear()
        self.done_emails.clear()
        self.done_domains.clear()
        self.done_phones.clear()
        self.done_names.clear()
        self.done_urls.clear()

    def summary(self) -> Dict[str, int]:
        return {
            "usernames": len(self.usernames),
            "emails": len(self.emails),
            "names": len(self.names),
            "clues": len(self.clues),
            "hits": len(self.hits),
            "pivot_log": len(self.pivot_log),
            "notes": len(self.notes),
        }
