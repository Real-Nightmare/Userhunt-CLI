"""
Tests for BrowserManager — Playwright integration, local tool URL handling.
"""
import pytest
from unittest.mock import patch, MagicMock

from userhunt.scanners.browser import BrowserManager, is_local_tool_url, LOCAL_TOOL_HOSTS
from userhunt.config import Config


class TestIsLocalToolUrl:
    def test_localhost_variants(self):
        assert is_local_tool_url("http://127.0.0.1:5001") is True
        assert is_local_tool_url("http://localhost:5001") is True
        assert is_local_tool_url("http://0.0.0.0:8080") is True
        assert is_local_tool_url("http://127.0.0.1") is True
        assert is_local_tool_url("http://localhost") is True

    def test_external_urls(self):
        assert is_local_tool_url("https://example.com") is False
        assert is_local_tool_url("http://192.168.1.1:5001") is False
        assert is_local_tool_url("http://10.0.0.1:8080") is False
        assert is_local_tool_url("https://spiderfoot.net") is False

    def test_empty_url(self):
        assert is_local_tool_url("") is False

    def test_malformed_url(self):
        assert is_local_tool_url("not-a-url") is False


class TestBrowserManager:
    def setup_method(self):
        self.config = Config()
        self.manager = BrowserManager(self.config)

    def test_init(self):
        assert self.manager._available is None  # not yet checked

    def test_cleanup_noop(self):
        """Cleanup should not raise even if nothing is running."""
        self.manager.cleanup()
        assert self.manager._browser is None

    def test_context_manager(self):
        with BrowserManager(self.config) as bm:
            assert bm is not None
        # Should exit cleanly

    @patch("userhunt.scanners.browser.subprocess.run")
    def test_install_playwright(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        self.manager._available = True
        result = self.manager.install()
        assert result is True

    @patch("userhunt.scanners.browser.subprocess.run")
    def test_install_playwright_failure(self, mock_run):
        mock_run.side_effect = Exception("install failed")
        self.manager._available = True
        result = self.manager.install()
        assert result is False

    def test_playwright_not_available(self):
        """When playwright is not installed, should return False."""
        with patch.dict("sys.modules", {"playwright": None, "playwright.sync_api": None}):
            self.manager._available = None
            assert self.manager.is_available() is False

    def test_fetch_page_no_playwright(self):
        """When Playwright unavailable, should return empty dict."""
        self.manager._available = False
        result = self.manager.fetch_page("https://example.com")
        assert result == {}

    def test_spiderfoot_scan_no_playwright(self):
        """When Playwright unavailable, should return empty list."""
        self.manager._available = False
        result = self.manager.spiderfoot_scan("example.com")
        assert result == []

    def test_run_tool_with_browser_no_playwright(self):
        self.manager._available = False
        result = self.manager.run_tool_with_browser("unknown_tool", "http://127.0.0.1:8080", "target")
        assert result == []


class TestBrowserManagerSpiderFoot:
    """Tests for SpiderFoot-specific behavior."""

    def setup_method(self):
        self.config = Config()
        self.manager = BrowserManager(self.config)

    def test_local_tool_no_timeout_constant(self):
        """Verify local tool URLs are recognized for no-timeout treatment."""
        local_urls = [
            "http://127.0.0.1:5001",
            "http://127.0.0.1:5001/scan",
            "http://localhost:5001/results",
            "http://0.0.0.0:8080",
        ]
        for url in local_urls:
            assert is_local_tool_url(url), f"{url} should be treated as local tool URL"
