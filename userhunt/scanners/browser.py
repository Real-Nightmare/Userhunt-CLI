"""
Browser manager — Playwright-based interactions with browser-dependent OSINT tools.

CRITICAL: Local tool web UIs (SpiderFoot at 127.0.0.1:5001, etc.) must NEVER
be timed out — they hold session state and evidence that gets wiped on timeout.
External page visits use generous timeouts instead.
"""
import re
import time
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from userhunt.config import Config


# Localhost patterns for tool web UIs — NEVER timeout these
LOCAL_TOOL_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0"}


def is_local_tool_url(url: str) -> bool:
    """Check if URL points to a local tool web UI (SpiderFoot, etc.)."""
    try:
        parsed = urlparse(url)
        return parsed.hostname in LOCAL_TOOL_HOSTS
    except Exception:
        return False


class BrowserManager:
    """
    Manages Playwright-based browser interactions.

    Key rules:
    - Local tool UIs (SpiderFoot, recon-ng, etc.) → NO timeout (they hold state)
    - External pages → configurable timeout (default 45s)
    - All browser operations are wrapped in try/except
    """

    def __init__(self, config: Config):
        self.config = config
        self._playwright = None
        self._browser = None
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Playwright is installed."""
        if self._available is not None:
            return self._available
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
        return self._available

    def install(self) -> bool:
        """Install Playwright and Chromium browser."""
        if not self.is_available():
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "playwright", "--quiet"],
                    check=False, capture_output=True, timeout=120,
                )
            except Exception:
                return False
            # Re-check
            self._available = None
            if not self.is_available():
                return False

        # Install Chromium
        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=False, capture_output=True, timeout=300,
            )
            return True
        except Exception:
            return False

    def fetch_page(self, url: str, wait_ms: int = 3000) -> Dict[str, Any]:
        """
        Fetch a page using Playwright.

        NO TIMEOUT for local tool URLs (SpiderFoot, etc.) — they hold session
        state and evidence. External URLs get a generous 60s timeout.
        """
        if not self.is_available():
            return {}

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                )
                page = context.new_page()

                is_local = is_local_tool_url(url)

                if is_local:
                    # NO timeout for local tool UIs — they hold evidence/state
                    page.goto(url, wait_until="domcontentloaded", timeout=0)
                else:
                    # Generous timeout for external pages
                    page.goto(url, timeout=60000, wait_until="domcontentloaded")

                # Wait for JS to render
                page.wait_for_timeout(wait_ms)

                html = page.content()
                title = page.title()

                # Take screenshot for evidence
                screenshot = None
                try:
                    screenshot_bytes = page.screenshot(type="png")
                    screenshot = screenshot_bytes
                except Exception:
                    pass

                browser.close()

                return {
                    "html": html,
                    "title": title,
                    "screenshot": screenshot,
                    "url": url,
                    "is_local_tool": is_local,
                }
        except Exception:
            return {}

    def spiderfoot_scan(
        self, target: str, sf_url: str = "http://127.0.0.1:5001"
    ) -> List[Dict[str, Any]]:
        """
        SpiderFoot scan — two modes:
        1. CLI mode (preferred): python sf.py -s target -t DOMAIN_NAME
        2. Web UI mode: Launch local server, interact via Playwright (no timeout)
        """
        # Try CLI mode first (more reliable)
        results = self._spiderfoot_cli(target)
        if results:
            return results

        # Fallback to Web UI mode
        return self._spiderfoot_webui(target, sf_url)

    def _spiderfoot_cli(self, target: str) -> List[Dict[str, Any]]:
        """Run SpiderFoot CLI: python sf.py -s target -t DOMAIN_NAME"""
        import subprocess
        import sys

        sf_path = self._find_spiderfoot()
        if not sf_path:
            return []

        try:
            # SpiderFoot CLI: python sf.py -s target -t DOMAIN_NAME
            result = subprocess.run(
                [sys.executable, str(sf_path), "-s", target, "-t", "DOMAIN_NAME"],
                capture_output=True, text=True, timeout=300,
            )
            results: List[Dict[str, Any]] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and ("@" in line or "http" in line or target.lower() in line.lower()):
                    results.append({
                        "source": "spiderfoot_cli",
                        "target": target,
                        "data": line[:500],
                    })
            return results
        except Exception:
            return []

    def _find_spiderfoot(self) -> Optional[Path]:
        """Find SpiderFoot installation."""
        workspace = Path("./userhunt_workspace")
        sf_path = workspace / "tools" / "spiderfoot" / "sf.py"
        if sf_path.exists():
            return sf_path
        return None

    def _spiderfoot_webui(self, target: str, sf_url: str) -> List[Dict[str, Any]]:
        """
        Interact with SpiderFoot web UI via Playwright.
        NO TIMEOUT — SpiderFoot's local UI holds all scan evidence.
        """
        if not self.is_available():
            return []

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                )
                page = context.new_page()

                # Navigate to SpiderFoot — NO timeout for local tool
                page.goto(sf_url, wait_until="domcontentloaded", timeout=0)
                page.wait_for_timeout(2000)

                # Look for the scan input field
                input_sel = (
                    'input[name="scan_target"], '
                    'input#scan_target, '
                    'input[type="text"][placeholder*="scan"], '
                    'input[type="text"][placeholder*="target"], '
                    'input[type="text"][placeholder*="domain"], '
                    'input[type="text"][placeholder*="name"]'
                )
                try:
                    page.wait_for_selector(input_sel, timeout=10000)
                except Exception:
                    browser.close()
                    return []

                # Fill target
                page.fill(input_sel, target)

                # Click scan button
                btn_sel = (
                    'button[type="submit"], '
                    'input[type="submit"], '
                    'button:has-text("Scan"), '
                    'a:has-text("Scan New")'
                )
                try:
                    page.click(btn_sel)
                except Exception:
                    page.keyboard.press("Enter")

                # Wait for scan to start — poll with NO timeout for local tool
                results_url_re = re.compile(r'scan_results|/scan/\w+')
                max_wait = 120
                start = time.time()
                found_results = False

                while time.time() - start < max_wait:
                    page.wait_for_timeout(5000)
                    current_url = page.url
                    if results_url_re.search(current_url):
                        found_results = True
                        break
                    content = page.content()
                    if "results" in content.lower() and target.lower() in content.lower():
                        found_results = True
                        break

                results: List[Dict[str, Any]] = []
                if found_results:
                    page.wait_for_timeout(5000)
                    rows = page.query_selector_all("tr, .result, .scan-result")
                    for row in rows[:100]:
                        text = row.inner_text()
                        if text.strip():
                            results.append({
                                "source": "spiderfoot",
                                "target": target,
                                "data": text.strip()[:500],
                            })

                browser.close()
                return results
        except Exception:
            return []

    def run_tool_with_browser(
        self, tool_name: str, tool_url: str, target: str, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        """
        Generic browser interaction for any tool that creates a local web UI.
        NO timeout on local URLs.
        """
        if not self.is_available():
            return []

        tool_handlers = {
            "spiderfoot": self.spiderfoot_scan,
        }

        handler = tool_handlers.get(tool_name)
        if handler:
            return handler(target=target, sf_url=tool_url, **kwargs)

        # Generic fallback — just fetch the page
        result = self.fetch_page(tool_url, wait_ms=5000)
        if result.get("html"):
            return [{
                "source": tool_name,
                "target": target,
                "data": result["html"][:2000],
                "title": result.get("title", ""),
            }]
        return []

    def cleanup(self) -> None:
        """Clean up any running browser instances."""
        try:
            if self._browser:
                self._browser.close()
                self._browser = None
            if self._playwright:
                self._playwright.stop()
                self._playwright = None
        except Exception:
            pass

    def __del__(self) -> None:
        self.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> None:
        self.cleanup()
