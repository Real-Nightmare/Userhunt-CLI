"""
Tests for CLI functions — input parsing, clue routing, heuristic profile.
"""
import pytest
from io import StringIO
from unittest.mock import patch

from userhunt.cli import _heuristic_profile
from userhunt.utils.extractors import route_clues


class TestParseMultiLine:
    def test_route_clues_integration(self):
        """Test that route_clues works correctly with mixed clue types."""
        clues = [
            "alice@example.com",
            "https://github.com/alice",
            "discord.gg/abc123",
            "John Smith",
            "alice_dev",
            "example.com",
        ]
        result = route_clues(clues)
        assert "alice@example.com" in result["emails"]
        assert "https://github.com/alice" in result["urls"]
        assert len(result["discord_invites"]) == 1
        assert "John Smith" in result["names"]
        assert "alice_dev" in result["usernames"]
        assert "example.com" in result["domains"]


class TestHeuristicProfile:
    def test_empty_case(self):
        from unittest.mock import MagicMock
        case = MagicMock()
        case.usernames = []
        case.emails = []
        case.names = []
        case.hits = []

        profile = _heuristic_profile(case)
        assert "Heuristic" in profile

    def test_with_hits(self):
        from unittest.mock import MagicMock
        case = MagicMock()
        case.usernames = ["alice", "bob"]
        case.emails = ["alice@test.com"]
        case.names = ["Alice Smith"]
        case.hits = [
            {"platform": "github", "url": "https://github.com/alice", "confidence": "HIGH",
             "avatar_url": "https://example.com/avatar.jpg", "images": []},
            {"platform": "reddit", "url": "https://reddit.com/u/alice", "confidence": "MEDIUM",
             "avatar_url": "", "images": []},
        ]

        profile = _heuristic_profile(case)
        assert "alice" in profile
        assert "alice@test.com" in profile
        assert "github" in profile
        assert "📷" in profile  # image indicator


class TestRouteClues:
    def test_comma_separated_bulk(self):
        clues = ["alice,bob,charlie"]
        result = route_clues(clues)
        total = sum(len(v) for v in result.values())
        assert total >= 0  # At least doesn't crash

    def test_roblox_id_not_phone(self):
        """15-digit number should be Roblox ID, not phone."""
        clues = ["123456789012345"]
        result = route_clues(clues)
        assert len(result["phones"]) == 0

    def test_multi_word_is_name(self):
        clues = ["First Last Name"]
        result = route_clues(clues)
        assert "First Last Name" in result["names"]

    def test_single_word_is_username(self):
        clues = ["alice123"]
        result = route_clues(clues)
        assert "alice123" in result["usernames"]

    def test_btc_address(self):
        clues = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
        result = route_clues(clues)
        total = sum(len(v) for v in result.values())
        assert total >= 0  # Doesn't crash

    def test_phone_with_dashes(self):
        clues = ["+1-555-123-4567"]
        result = route_clues(clues)
        assert len(result["phones"]) == 1

    def test_phone_international(self):
        clues = ["+44 20 7946 0958"]
        result = route_clues(clues)
        assert len(result["phones"]) == 1
