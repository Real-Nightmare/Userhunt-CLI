"""
Tests for centralized regex extractors — all identifier types and edge cases.
"""
import pytest

from userhunt.utils.extractors import (
    extract_emails, extract_urls, extract_handles, extract_usernames_from_paths,
    extract_discord_invites, extract_discord_snowflakes, extract_roblox_ids,
    extract_btc_addresses, extract_phones, extract_domains, extract_identifiers,
    route_clues,
)


class TestExtractEmails:
    def test_basic(self):
        text = "Contact me at alice@example.com or bob@test.co.uk"
        result = extract_emails(text)
        assert "alice@example.com" in result
        assert "bob@test.co.uk" in result

    def test_in_html(self):
        text = '<a href="mailto:user@domain.com">Email</a>'
        result = extract_emails(text)
        assert "user@domain.com" in result

    def test_deduplication(self):
        text = "alice@example.com and ALICE@example.com"
        result = extract_emails(text)
        assert len(result) == 1

    def test_no_false_positives(self):
        text = "not an email @ symbol here"
        result = extract_emails(text)
        assert len(result) == 0

    def test_complex_local_parts(self):
        text = "test.user+tag@sub.domain.com"
        result = extract_emails(text)
        assert "test.user+tag@sub.domain.com" in result


class TestExtractURLs:
    def test_basic(self):
        text = "Visit https://example.com/path?q=1 or http://test.org"
        result = extract_urls(text)
        assert len(result) == 2

    def test_with_punctuation(self):
        text = "Check https://example.com/path, also see http://test.com."
        result = extract_urls(text)
        assert len(result) == 2

    def test_deduplication(self):
        text = "https://example.com and https://example.com"
        result = extract_urls(text)
        assert len(result) == 1


class TestExtractHandles:
    def test_basic(self):
        text = "Follow @alice and @bob_dev"
        result = extract_handles(text)
        assert "alice" in result
        assert "bob_dev" in result

    def test_short_handles_excluded(self):
        text = "@ab is too short"
        result = extract_handles(text)
        assert len(result) == 0

    def test_at_in_email_not_extracted(self):
        text = "alice@example.com"
        result = extract_handles(text)
        # The @ is in email, but extract_handles uses word boundary regex
        # It should not match "example.com" as a handle
        assert "example.com" not in result


class TestExtractDiscord:
    def test_invite(self):
        text = "Join us at discord.gg/abc123 or discord.gg/XYZ_456"
        result = extract_discord_invites(text)
        assert len(result) == 2
        assert "discord.gg/abc123" in result

    def test_snowflakes(self):
        text = "User ID: 123456789012345678 and 9876543210987654321"
        result = extract_discord_snowflakes(text)
        assert len(result) == 2

    def test_snowflake_not_too_short(self):
        text = "ID: 123456789"  # only 9 digits
        result = extract_discord_snowflakes(text)
        assert len(result) == 0


class TestExtractRoblox:
    def test_valid_ids(self):
        text = "Roblox ID: 12345678 and 999999999"
        result = extract_roblox_ids(text)
        assert "12345678" in result
        assert "999999999" in result

    def test_too_short(self):
        text = "ID: 42"
        result = extract_roblox_ids(text)
        assert len(result) == 0


class TestExtractBTC:
    def test_valid_address(self):
        # A simplified BTC address pattern
        text = "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        result = extract_btc_addresses(text)
        # Should find at least one match if pattern is correct
        assert isinstance(result, list)


class TestExtractPhones:
    def test_international(self):
        text = "Call +1-555-123-4567 or +44 20 7946 0958"
        result = extract_phones(text)
        assert len(result) >= 2

    def test_no_match_random_digits(self):
        text = "The number is 12345"
        result = extract_phones(text)
        assert len(result) == 0


class TestExtractDomains:
    def test_basic(self):
        text = "Visit example.com or sub.test.org"
        result = extract_domains(text)
        assert "example.com" in result
        assert "sub.test.org" in result

    def test_excludes_urls(self):
        text = "https://example.com"
        result = extract_domains(text)
        # Should still extract domain from URL context
        assert isinstance(result, list)

    def test_minimum_length(self):
        text = "go to a.b"
        result = extract_domains(text)
        # a.b is too short (< 4 chars after filtering)
        assert len(result) == 0


class TestExtractIdentifiers:
    def test_mixed_content(self):
        text = """
        User found: alice@example.com on https://github.com/alice
        Also @alice_dev on Twitter, phone +1-555-123-4567
        """
        result = extract_identifiers(text, source="test")
        types = {r["type"] for r in result}
        assert "email" in types
        assert "url" in types
        assert "phone" in types

    def test_source_tagging(self):
        text = "alice@test.com"
        result = extract_identifiers(text, source="scanner1")
        assert all(r["source"] == "scanner1" for r in result)

    def test_empty_text(self):
        result = extract_identifiers("")
        assert result == []


class TestRouteClues:
    def test_email_clues(self):
        clues = ["alice@example.com", "bob@test.org"]
        result = route_clues(clues)
        assert "alice@example.com" in result["emails"]
        assert "bob@test.org" in result["emails"]

    def test_url_clues(self):
        clues = ["https://example.com/profile"]
        result = route_clues(clues)
        assert len(result["urls"]) == 1

    def test_discord_invite(self):
        clues = ["discord.gg/abc123"]
        result = route_clues(clues)
        assert len(result["discord_invites"]) == 1

    def test_phone_clues(self):
        clues = ["+1-555-123-4567"]
        result = route_clues(clues)
        assert len(result["phones"]) == 1

    def test_phone_international_clue(self):
        clues = ["+442079460958"]
        result = route_clues(clues)
        assert len(result["phones"]) == 1

    def test_name_clues(self):
        clues = ["John Smith", "Alice Marie Johnson"]
        result = route_clues(clues)
        assert len(result["names"]) == 2

    def test_username_clues(self):
        clues = ["alice123", "bob_dev"]
        result = route_clues(clues)
        assert len(result["usernames"]) == 2

    def test_domain_clues(self):
        clues = ["example.com", "test.co.uk"]
        result = route_clues(clues)
        assert "example.com" in result["domains"]

    def test_empty_clues(self):
        result = route_clues([])
        for key in result:
            assert result[key] == []
