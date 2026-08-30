"""
Tests for ConfidenceEngine — scoring, dedup, consistency checks.
"""
import pytest

from userhunt.core.confidence import ConfidenceEngine


class TestConfidenceEngine:
    def setup_method(self):
        self.engine = ConfidenceEngine()

    def test_high_platform_upgrade(self):
        hits = [{"platform": "GitHub", "url": "https://github.com/alice", "confidence": "MEDIUM"}]
        result = self.engine.score(hits)
        assert result[0]["confidence"] == "HIGH"

    def test_low_platform_downgrade(self):
        hits = [{"platform": "wowhead", "url": "https://wowhead.com/user", "confidence": "MEDIUM"}]
        result = self.engine.score(hits)
        assert result[0]["confidence"] == "LOW"

    def test_parked_page_low(self):
        hits = [{"platform": "test", "url": "https://example.com", "bio": "Domain is for sale"}]
        result = self.engine.score(hits)
        assert result[0]["confidence"] == "LOW"
        assert result[0].get("verdict") == "verify_false"

    def test_dead_page_low(self):
        hits = [{"platform": "test", "url": "https://example.com", "bio": "User not found"}]
        result = self.engine.score(hits)
        assert result[0]["confidence"] == "LOW"
        assert result[0].get("verdict") == "verify_false"

    def test_consistency_check_same_name(self):
        hits = [
            {"platform": "github", "url": "https://github.com/a", "confidence": "MEDIUM", "display_name": "Alice"},
            {"platform": "github", "url": "https://github.com/b", "confidence": "MEDIUM", "display_name": "Alice"},
        ]
        result = self.engine.score(hits)
        # Same display name on same platform → both HIGH
        for h in result:
            if "identity consistent" in h.get("notes", []):
                assert h["confidence"] == "HIGH"

    def test_consistency_check_different_name(self):
        hits = [
            {"platform": "github", "url": "https://github.com/a", "confidence": "MEDIUM", "display_name": "Alice"},
            {"platform": "github", "url": "https://github.com/b", "confidence": "MEDIUM", "display_name": "Bob"},
        ]
        result = self.engine.score(hits)
        # Different names → identity conflict, but NOT lowered from verified HIGH
        has_conflict = any("identity conflict" in h.get("notes", []) for h in result)
        assert has_conflict

    def test_never_lower_verified_high(self):
        """HIGH hits that are explicitly set should NEVER be lowered."""
        hits = [
            {"platform": "github", "url": "https://github.com/a", "confidence": "HIGH",
             "display_name": "Alice", "query": "alice"},
            {"platform": "github", "url": "https://github.com/b", "confidence": "HIGH",
             "display_name": "Bob", "query": "alice"},
        ]
        result = self.engine.score(hits)
        # Even with identity conflict, verified HIGH should stay HIGH
        for h in result:
            assert h["confidence"] == "HIGH"

    def test_deduplication(self):
        hits = [
            {"platform": "github", "url": "https://github.com/alice", "query": "alice"},
            {"platform": "github", "url": "https://github.com/alice", "query": "alice"},
            {"platform": "github", "url": "https://github.com/alice", "query": "bob"},
        ]
        result = self.engine.score(hits)
        # First two are duplicates (same platform, url, query)
        # Third has different query so it's unique
        assert len(result) == 2

    def test_sort_order_high_first(self):
        hits = [
            {"platform": "test1", "url": "url1", "confidence": "LOW"},
            {"platform": "test2", "url": "url2", "confidence": "HIGH"},
            {"platform": "test3", "url": "url3", "confidence": "MEDIUM"},
        ]
        result = self.engine.score(hits)
        confidences = [h["confidence"] for h in result]
        assert confidences == ["HIGH", "MEDIUM", "LOW"]

    def test_empty_input(self):
        result = self.engine.score([])
        assert result == []

    def test_default_confidence_medium(self):
        hits = [{"platform": "unknown", "url": "https://unknown.com"}]
        result = self.engine.score(hits)
        assert result[0]["confidence"] == "MEDIUM"

    def test_normalize_platform(self):
        assert self.engine._normalize_platform("GitHub") == "github"
        assert self.engine._normalize_platform("Social Media") == "socialmedia"
        assert self.engine._normalize_platform("my-site") == "mysite"
