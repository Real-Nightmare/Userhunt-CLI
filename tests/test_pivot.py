"""
Tests for PivotEngine — extraction, dedup, routing, applying to case.
"""
import pytest
from unittest.mock import MagicMock

from userhunt.core.pivot import PivotEngine
from userhunt.config import Config


class TestPivotEngine:
    def setup_method(self):
        self.config = Config()
        self.engine = PivotEngine(self.config)

    def test_extract_emails(self):
        text = "Found email: alice@test.com and bob@example.org"
        pivots = self.engine._extract_from_text(text, "test", 1)
        actions = [p["action"] for p in pivots]
        assert "queue_email" in actions
        emails = [p["found"] for p in pivots if p["action"] == "queue_email"]
        assert "alice@test.com" in emails

    def test_extract_handles(self):
        text = "Found @alice_dev on platform"
        pivots = self.engine._extract_from_text(text, "test", 1)
        actions = [p["action"] for p in pivots]
        assert "queue_username" in actions

    def test_extract_phones(self):
        text = "Phone: +1-555-123-4567"
        pivots = self.engine._extract_from_text(text, "test", 1)
        actions = [p["action"] for p in pivots]
        assert "queue_phone" in actions

    def test_extract_discord_invites(self):
        text = "Join discord.gg/abc123"
        pivots = self.engine._extract_from_text(text, "test", 1)
        reasons = [p["reason"] for p in pivots]
        assert "discord invite" in reasons

    def test_extract_domains(self):
        text = "Found subdomain: api.example.com"
        pivots = self.engine._extract_from_text(text, "test", 1)
        domains = [p["found"] for p in pivots if p["action"] == "queue_domain"]
        assert len(domains) >= 1

    def test_source_tagging(self):
        text = "user@test.com"
        pivots = self.engine._extract_from_text(text, "scanner:github", 1)
        assert all(p["source"] == "scanner:github" for p in pivots)

    def test_round_number(self):
        text = "user@test.com"
        pivots = self.engine._extract_from_text(text, "test", 5)
        assert all(p["round"] == 5 for p in pivots)

    def test_deduplication(self):
        # Same action+value should be deduplicated
        pivots = []
        pivots.extend(self.engine._extract_from_text("alice@test.com", "src1", 1))
        pivots.extend(self.engine._extract_from_text("alice@test.com", "src2", 1))
        seen = set()
        unique = []
        for p in pivots:
            key = (p["action"], p["found"].lower())
            if key not in seen:
                seen.add(key)
                unique.append(p)
        # Should have only one queue_email for alice@test.com
        email_pivots = [p for p in unique if p["action"] == "queue_email" and p["found"] == "alice@test.com"]
        assert len(email_pivots) == 1

    def test_make_pivot(self):
        p = PivotEngine._make_pivot(1, "src", "val", "queue_email", "reason")
        assert p["round"] == 1
        assert p["source"] == "src"
        assert p["found"] == "val"
        assert p["action"] == "queue_email"
        assert p["reason"] == "reason"
        assert p["by"] == "regex"

    def test_apply_pivots_to_case(self):
        case = MagicMock()
        case.add_username.return_value = True
        case.add_email.return_value = True
        case.can_add_username.return_value = True
        case.done_phones = set()
        case.done_domains = set()

        pivots = [
            {"action": "queue_username", "value": "newuser"},
            {"action": "queue_email", "value": "new@test.com"},
        ]
        applied = self.engine.apply_pivots_to_case(case, pivots)
        assert len(applied) == 2
        case.add_username.assert_called_once_with("newuser")
        case.add_email.assert_called_once_with("new@test.com")

    def test_apply_pivots_dedup(self):
        case = MagicMock()
        case.add_username.return_value = False  # already exists
        case.add_email.return_value = True
        case.can_add_username.return_value = True
        case.done_phones = set()
        case.done_domains = set()

        pivots = [
            {"action": "queue_username", "value": "existing"},
            {"action": "queue_email", "value": "new@test.com"},
        ]
        applied = self.engine.apply_pivots_to_case(case, pivots)
        # Only email should be applied
        assert len(applied) == 1
        assert applied[0]["action"] == "queue_email"

    def test_empty_text(self):
        pivots = self.engine._extract_from_text("", "test", 1)
        assert pivots == []
