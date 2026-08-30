"""
Tests for Case class.
"""
import json
from pathlib import Path

import pytest

from userhunt.case import Case


class TestCase:
    def test_init(self):
        c = Case()
        assert c.usernames == []
        assert c.emails == []
        assert c.hits == []
        assert c.round == 0
        assert c.is_empty() is True

    def test_add_username(self):
        c = Case()
        assert c.add_username("testuser") is True
        assert "testuser" in c.usernames
        assert c.add_username("testuser") is False  # dedupe

    def test_add_email(self):
        c = Case()
        assert c.add_email("test@example.com") is True
        assert "test@example.com" in c.emails
        assert c.add_email("test@example.com") is False  # dedupe

    def test_round_caps_unlimited(self):
        """No caps — can add unlimited identifiers."""
        c = Case()
        c.reset_round_caps()
        for i in range(100):
            assert c.add_username(f"user{i}") is True
        assert c.add_username("user0") is False  # dedupe only
        assert len(c.usernames) == 100

    def test_email_round_caps_unlimited(self):
        """No caps — can add unlimited emails."""
        c = Case()
        c.reset_round_caps()
        for i in range(100):
            assert c.add_email(f"u{i}@example.com") is True
        assert c.add_email("u0@example.com") is False  # dedupe only
        assert len(c.emails) == 100

    def test_hit_caps_unlimited(self):
        """No caps — can add unlimited hits."""
        c = Case()
        for i in range(100):
            assert c.add_hit({"platform": f"p{i}"}) is True
        assert len(c.hits) == 100

    def test_is_empty(self):
        c = Case()
        assert c.is_empty() is True
        c.usernames.append("test")
        assert c.is_empty() is False

    def test_to_dict(self):
        c = Case()
        c.usernames.append("alice")
        c.emails.append("alice@example.com")
        d = c.to_dict()
        assert d["usernames"] == ["alice"]
        assert d["emails"] == ["alice@example.com"]
        assert "hits" in d
        assert "pivot_log" in d

    def test_save_load_roundtrip(self, tmp_path: Path):
        c1 = Case()
        c1.usernames = ["alice", "bob"]
        c1.emails = ["alice@test.com"]
        c1.names = ["Alice Smith"]
        c1.clues = ["12345"]
        c1.hits = [{"platform": "github", "url": "https://github.com/alice"}]
        c1.ai_profile = "Test profile"
        c1.round = 3

        path = tmp_path / "case.json"
        c1.save(path)
        assert path.exists()

        c2 = Case()
        c2.load(path)
        assert c2.usernames == ["alice", "bob"]
        assert c2.emails == ["alice@test.com"]
        assert c2.names == ["Alice Smith"]
        assert c2.clues == ["12345"]
        assert len(c2.hits) == 1
        assert c2.ai_profile == "Test profile"
        assert c2.round == 3

    def test_load_nonexistent(self):
        c = Case()
        c.load(Path("/nonexistent/case.json"))
        assert c.usernames == []

    def test_clear(self):
        c = Case()
        c.usernames = ["alice"]
        c.emails = ["alice@test.com"]
        c.hits = [{"platform": "test"}]
        c.round = 5
        c.clear()
        assert c.usernames == []
        assert c.emails == []
        assert c.hits == []
        assert c.round == 0

    def test_summary(self):
        c = Case()
        c.usernames = ["a", "b"]
        c.emails = ["x@y.com"]
        s = c.summary()
        assert s["usernames"] == 2
        assert s["emails"] == 1
        assert s["hits"] == 0

    def test_pivot_log_ring_buffer(self):
        c = Case(max_pivot_log=5)
        for i in range(10):
            c.pivot_log.append({"round": i})
        assert len(c.pivot_log) == 5
        # Should contain the last 5
        items = c.pivot_log.as_list()
        assert items[0]["round"] == 5
        assert items[-1]["round"] == 9

    def test_done_sets(self):
        c = Case()
        c.done_usernames.add("alice")
        c.done_emails.add("a@b.com")
        c.done_domains.add("example.com")
        assert "alice" in c.done_usernames
        assert len(c.done_usernames) == 1
