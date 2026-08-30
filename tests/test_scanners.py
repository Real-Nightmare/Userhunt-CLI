"""
Tests for scanners — manager delegation, base scanner, registry.
"""
import pytest
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

from userhunt.scanners.base import BaseScanner
from userhunt.scanners.manager import ScanManager
from userhunt.scanners.username import UsernameScanner
from userhunt.scanners.email import EmailScanner
from userhunt.scanners.phone import PhoneScanner
from userhunt.scanners.domain import DomainScanner
from userhunt.scanners.name import NameScanner
from userhunt.scanners.url import URLScanner
from userhunt.config import Config


class TestBaseScanner:
    def test_make_hit(self):
        config = Config()
        scanner = UsernameScanner(config)
        hit = scanner._make_hit("GitHub", "https://github.com/test", confidence="HIGH")
        assert hit["platform"] == "GitHub"
        assert hit["url"] == "https://github.com/test"
        assert hit["confidence"] == "HIGH"
        assert hit["scanner"] == "username_scanner"

    def test_make_hit_defaults(self):
        config = Config()
        scanner = EmailScanner(config)
        hit = scanner._make_hit("test", "url")
        assert hit["confidence"] == "MEDIUM"


class TestUsernameScanner:
    def test_confidence_high(self):
        config = Config()
        scanner = UsernameScanner(config)
        assert scanner._confidence("github") == "HIGH"
        assert scanner._confidence("GitHub") == "HIGH"
        assert scanner._confidence("reddit") == "HIGH"

    def test_confidence_medium(self):
        config = Config()
        scanner = UsernameScanner(config)
        assert scanner._confidence("someobscuresite") == "MEDIUM"

    def test_wmn_sites_empty(self):
        config = Config()
        config.hunt.workspace = Path("/nonexistent")
        scanner = UsernameScanner(config)
        sites = scanner._load_wmn()
        assert sites == []


class TestEmailScanner:
    def test_gravatar_hit(self):
        """Test that Gravatar returns a hit for a known email hash."""
        config = Config()
        scanner = EmailScanner(config)
        # Just test it doesn't crash with a fake email
        hits = scanner._gravatar("test@example.com")
        assert isinstance(hits, list)

    def test_mx_lookup(self):
        config = Config()
        scanner = EmailScanner(config)
        hits = scanner._mx_lookup("test@gmail.com")
        assert isinstance(hits, list)

    def test_emailrep(self):
        config = Config()
        scanner = EmailScanner(config)
        hits = scanner._emailrep("test@example.com")
        assert isinstance(hits, list)


class TestPhoneScanner:
    def test_parse_phone_valid(self):
        config = Config()
        scanner = PhoneScanner(config)
        info = scanner._parse_phone("+1-555-123-4567")
        # May or may not be valid depending on library, but should return dict
        assert isinstance(info, dict)

    def test_parse_phone_invalid(self):
        config = Config()
        scanner = PhoneScanner(config)
        info = scanner._parse_phone("notaphone")
        assert info == {}


class TestDomainScanner:
    def test_dns_records(self):
        config = Config()
        scanner = DomainScanner(config)
        hits = scanner._dns("example.com")
        assert isinstance(hits, list)

    def test_rdap(self):
        config = Config()
        scanner = DomainScanner(config)
        hits = scanner._rdap("example.com")
        assert isinstance(hits, list)


class TestNameScanner:
    def test_username_permutations(self):
        config = Config()
        scanner = NameScanner(config)
        perms = scanner._username_permutations("John Smith")
        assert "johnsmith" in perms
        assert "john.smith" in perms
        assert "john_smith" in perms
        assert "jsmith" in perms

    def test_single_name(self):
        config = Config()
        scanner = NameScanner(config)
        perms = scanner._username_permutations("Alice")
        assert "alice" in perms

    def test_empty_name(self):
        config = Config()
        scanner = NameScanner(config)
        perms = scanner._username_permutations("")
        assert perms == []

    def test_three_part_name(self):
        config = Config()
        scanner = NameScanner(config)
        perms = scanner._username_permutations("John Michael Smith")
        assert "johnsmith" in perms
        assert "johnmichaelsmith" in perms


class TestURLScanner:
    def test_init(self):
        config = Config()
        scanner = URLScanner(config)
        assert scanner.name == "url_scanner"
        assert scanner.status == "BEST-EFFORT"


class TestScanManager:
    def test_registry(self):
        config = Config()
        manager = ScanManager(config)
        reg = manager.registry()
        names = [r[0] for r in reg]
        assert "username_scanner" in names
        assert "email_scanner" in names
        assert "phone_scanner" in names
        assert "domain_scanner" in names
        assert "name_scanner" in names
        assert "url_scanner" in names
        assert "browser" in names

    def test_confidence(self):
        config = Config()
        manager = ScanManager(config)
        assert manager._confidence("github") == "HIGH"
        assert manager._confidence("unknown") == "MEDIUM"

    def test_dedup_hits(self):
        config = Config()
        manager = ScanManager(config)
        hits = [
            {"platform": "github", "url": "https://github.com/a"},
            {"platform": "github", "url": "https://github.com/a"},
            {"platform": "github", "url": "https://github.com/b"},
        ]
        result = manager._dedupe_hits(hits)
        assert len(result) == 2

    def test_scan_usernames_empty(self):
        config = Config()
        config.hunt.workspace = Path("/nonexistent")
        manager = ScanManager(config)
        hits = manager.scan_usernames(["testuser"])
        assert isinstance(hits, list)

    def test_scan_emails_empty(self):
        config = Config()
        config.hunt.workspace = Path("/nonexistent")
        manager = ScanManager(config)
        hits = manager.scan_emails(["test@test.com"])
        assert isinstance(hits, list)
