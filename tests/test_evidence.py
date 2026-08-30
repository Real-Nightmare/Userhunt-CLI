"""
Tests for EvidenceCollector — HTML parsing, profile extraction, image handling.
"""
import pytest
from unittest.mock import patch, Mock

from userhunt.core.evidence import EvidenceCollector
from userhunt.config import Config


class TestEvidenceCollector:
    def setup_method(self):
        self.config = Config()
        self.config.ai.api_key = ""  # disable AI for tests
        self.collector = EvidenceCollector(self.config)

    def test_parse_html_basic(self):
        html = """
        <html>
        <head>
            <title>Test User</title>
            <meta property="og:title" content="Alice Smith">
            <meta property="og:description" content="Developer and researcher">
            <meta property="og:image" content="https://example.com/avatar.jpg">
            <meta name="description" content="A bio here">
        </head>
        <body>
            <a href="https://github.com/alice">GitHub</a>
            <a href="https://twitter.com/alice">Twitter</a>
            <p>Contact: alice@test.com</p>
            <img src="https://example.com/photo1.jpg">
            <img src="https://example.com/photo2.png">
        </body>
        </html>
        """
        result = self.collector._parse_html(html, "https://example.com/alice")
        assert result["display_name"] == "Alice Smith"
        assert result["bio"] == "Developer and researcher"
        assert result["avatar_url"] == "https://example.com/avatar.jpg"
        assert "alice@test.com" in result["emails"]
        assert len(result["other_socials"]) >= 2
        assert "https://example.com/avatar.jpg" in result["images"]

    def test_parse_html_no_meta(self):
        html = "<html><head><title>Simple Page</title></head><body></body></html>"
        result = self.collector._parse_html(html, "https://example.com")
        assert result["display_name"] == "Simple Page"
        assert result["bio"] == ""

    def test_parse_html_social_links(self):
        html = """
        <html><body>
        <a href="https://instagram.com/user1">IG</a>
        <a href="https://youtube.com/channel/123">YT</a>
        <a href="https://example.com/not-social">Other</a>
        </body></html>
        """
        result = self.collector._parse_html(html, "https://test.com")
        assert len(result["other_socials"]) == 2

    def test_parse_html_email_extraction(self):
        html = """
        <html><body>
        <p>Contact: john@example.com or jane@test.org</p>
        </body></html>
        """
        result = self.collector._parse_html(html, "https://test.com")
        assert "john@example.com" in result["emails"]
        assert "jane@test.org" in result["emails"]

    def test_parse_html_images(self):
        html = """
        <html><body>
        <img src="https://cdn.example.com/pic1.jpg">
        <img src="https://cdn.example.com/pic2.png">
        <img src="/local/image.gif">
        </body></html>
        """
        result = self.collector._parse_html(html, "https://test.com")
        http_images = [i for i in result["images"] if i.startswith("http")]
        assert len(http_images) == 2

    def test_parse_html_image_limit(self):
        imgs = "\n".join(f'<img src="https://example.com/{i}.jpg">' for i in range(20))
        html = f"<html><body>{imgs}</body></html>"
        result = self.collector._parse_html(html, "https://test.com")
        assert len(result["images"]) <= 10

    def test_meta_content_helper(self):
        from bs4 import BeautifulSoup
        html = '<meta property="og:title" content="Test Title">'
        soup = BeautifulSoup(html, "lxml")
        assert self.collector._meta_content(soup, "og:title") == "Test Title"
        assert self.collector._meta_content(soup, "og:missing") == ""

    def test_visited_tracking(self):
        self.collector.visited.add("https://test.com")
        assert "https://test.com" in self.collector.visited

    def test_page_cache(self):
        self.collector._page_cache["https://test.com"] = {"display_name": "Cached"}
        assert "https://test.com" in self.collector._page_cache

    def test_playwright_unavailable(self):
        """When Playwright is not installed, fallback returns empty."""
        self.collector._playwright_available = False
        result = self.collector._fetch_page_playwright("https://test.com")
        assert result == {}

    @patch("userhunt.core.evidence.requests.get")
    def test_fetch_page_requests_success(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><head><title>OK</title></head><body></body></html>'
        mock_get.return_value = mock_resp

        result = self.collector._fetch_page_requests("https://test.com")
        assert result["display_name"] == "OK"

    @patch("userhunt.core.evidence.requests.get")
    def test_fetch_page_requests_404(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = self.collector._fetch_page_requests("https://test.com")
        assert result == {}


class TestIsLocalToolUrl:
    def test_localhost(self):
        from userhunt.scanners.browser import is_local_tool_url
        assert is_local_tool_url("http://127.0.0.1:5001") is True
        assert is_local_tool_url("http://localhost:5001") is True
        assert is_local_tool_url("http://0.0.0.0:8080") is True

    def test_external(self):
        from userhunt.scanners.browser import is_local_tool_url
        assert is_local_tool_url("https://example.com") is False
        assert is_local_tool_url("http://192.168.1.1:5001") is False
