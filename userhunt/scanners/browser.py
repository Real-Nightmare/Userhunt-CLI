"""
Browser manager — Playwright-based interactions with browser-dependent OSINT tools.

CRITICAL: Local tool web UIs (SpiderFoot at 127.0.0.1:5001, etc.) must NEVER
be timed out — they hold session state and evidence that gets wiped on timeout.

SpiderFoot flow:
1. Try CLI first: python sf.py -s TARGET -t DOMAIN_NAME
2. If CLI fails, launch web server, open browser, click New Scan, fill target, submit
"""
import re
import time
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from userhunt.config import Config
from userhunt.utils.runner import run_tool_with_fallback, run_tool_simple
from userhunt.web.store import store


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
            self._available = None
            if not self.is_available():
                return False

        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=False, capture_output=True, timeout=300,
            )
            return True
        except Exception:
            return False

    def fetch_page(self, url: str, wait_ms: int = 3000) -> Dict[str, Any]:
        """Fetch a page using Playwright."""
        if not self.is_available():
            return {}
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                page = context.new_page()
                is_local = is_local_tool_url(url)
                if is_local:
                    page.goto(url, wait_until="domcontentloaded", timeout=0)
                else:
                    page.goto(url, timeout=60000, wait_until="domcontentloaded")
                page.wait_for_timeout(wait_ms)
                html = page.content()
                title = page.title()
                screenshot = None
                try:
                    screenshot = page.screenshot(type="png")
                except Exception:
                    pass
                browser.close()
                return {"html": html, "title": title, "screenshot": screenshot, "url": url, "is_local_tool": is_local}
        except Exception:
            return {}

    # ── SpiderFoot — CLI first, then browser ────────────────────────

    def spiderfoot_scan(
        self, target: str, sf_url: str = "http://127.0.0.1:5001"
    ) -> List[Dict[str, Any]]:
        """
        SpiderFoot scan with fallback:
        1. CLI: python sf.py -s TARGET -t ALL (most reliable)
        2. Web UI: launch server, Playwright clicks New Scan, fills target
        """
        # Try CLI first (more reliable, no browser needed)
        results = self._spiderfoot_cli(target)
        if results:
            return results

        # Fallback: launch web server + browser automation
        return self._spiderfoot_webui(target, sf_url)

    def _spiderfoot_cli(self, target: str) -> List[Dict[str, Any]]:
        """Run SpiderFoot CLI: python sf.py -s TARGET -t ALL"""
        sf_path = self._find_spiderfoot()
        if not sf_path:
            return []

        store.log(f"Running SpiderFoot CLI for: {target}", source="spiderfoot")
        stdout, stderr, rc = run_tool_with_fallback(
            tool_name="spiderfoot",
            cwd=str(sf_path.parent),
            timeout=self.config.hunt.tool_timeout,
            primary=[sys.executable, str(sf_path), "-s", target, "-t", "ALL"],
            fallbacks=[
                [sys.executable, "-m", "spiderfoot", "-s", target, "-t", "ALL"],
                [sys.executable, str(sf_path), "-s", target, "-t", "DOMAIN_NAME"],
            ],
        )

        results: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and ("@" in line or "http" in line or target.lower() in line.lower()):
                results.append({"source": "spiderfoot_cli", "target": target, "data": line[:500]})

        if stderr.strip():
            for line in stderr.splitlines()[:20]:
                store.tool_log("spiderfoot", line, direction="stderr")

        return results

    def _find_spiderfoot(self) -> Optional[Path]:
        """Find SpiderFoot installation."""
        workspace = self.config.hunt.workspace
        sf_path = workspace / "tools" / "spiderfoot" / "sf.py"
        if sf_path.exists():
            return sf_path
        return None

    def _spiderfoot_webui(self, target: str, sf_url: str) -> List[Dict[str, Any]]:
        """
        SpiderFoot web UI — launch server, wait for it, open browser,
        click New Scan, fill target, submit, wait for results.
        """
        if not self.is_available():
            store.log("Playwright not available — skipping SpiderFoot web UI", level="warn", source="spiderfoot")
            return []

        sf_path = self._find_spiderfoot()
        if not sf_path:
            return []

        # Step 1: Launch SpiderFoot web server in background
        store.log(f"Launching SpiderFoot web server for: {target}", source="spiderfoot")
        server_proc = None
        try:
            server_proc = subprocess.Popen(
                [sys.executable, str(sf_path), "-l", "127.0.0.1:5001"],
                cwd=str(sf_path.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            store.log(f"Failed to launch SpiderFoot server: {e}", level="error", source="spiderfoot")
            return []

        # Step 2: Wait for server to be ready (poll up to 30s)
        ready = False
        import socket
        for _ in range(60):
            time.sleep(0.5)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", 5001))
                sock.close()
                if result == 0:
                    ready = True
                    break
            except Exception:
                pass

        if not ready:
            store.log("SpiderFoot server failed to start", level="error", source="spiderfoot")
            if server_proc:
                server_proc.kill()
            return []

        store.log("SpiderFoot server ready — opening browser", source="spiderfoot")

        # Step 3: Use Playwright to interact with the web UI
        results: List[Dict[str, Any]] = []
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                page = context.new_page()

                # Navigate to SpiderFoot — NO timeout for local tool
                page.goto(sf_url, wait_until="domcontentloaded", timeout=0)
                page.wait_for_timeout(3000)

                # Step 4: Find and click "New Scan" or "Scan New Target"
                new_scan_sel = 'a:has-text("New Scan"), button:has-text("New Scan"), a:has-text("Scan New"), a[href*="new"], a:has-text("Scan")'
                try:
                    page.wait_for_selector(new_scan_sel, timeout=15000)
                    page.click(new_scan_sel)
                    page.wait_for_timeout(3000)
                except Exception:
                    # Already on scan page, continue
                    pass

                # Step 5: Fill the target input
                input_sel = (
                    'input[name="scan_target"], '
                    'input#scan_target, '
                    'input[name="target"], '
                    'input[type="text"][placeholder*="target"], '
                    'input[type="text"][placeholder*="scan"], '
                    'input[type="text"][placeholder*="domain"], '
                    'input[type="text"][placeholder*="name"], '
                    'input[type="text"]:first-of-type'
                )
                try:
                    page.wait_for_selector(input_sel, timeout=15000)
                    page.fill(input_sel, target)
                    page.wait_for_timeout(500)
                except Exception as e:
                    store.log(f"SpiderFoot: could not find input field: {e}", level="error", source="spiderfoot")
                    browser.close()
                    return results

                # Step 6: Select scan type (select "All" if available)
                scan_type_sel = 'select[name="scan_module_group"], select#scan_module_group'
                try:
                    page.wait_for_selector(scan_type_sel, timeout=5000)
                    page.select_option(scan_type_sel, label="All")
                except Exception:
                    pass  # No module group selector, continue

                # Step 7: Click the Scan/Submit button
                submit_sel = (
                    'button[type="submit"], '
                    'input[type="submit"], '
                    'button:has-text("Scan"), '
                    'button:has-text("Start"), '
                    'a:has-text("Scan")'
                )
                try:
                    page.click(submit_sel)
                except Exception:
                    page.keyboard.press("Enter")

                page.wait_for_timeout(5000)

                # Step 8: Wait for scan to complete and extract results
                store.log(f"SpiderFoot scan started for {target} — waiting for results...", source="spiderfoot")
                start_time = time.time()
                max_wait = 300  # 5 minutes max for scan to run

                while time.time() - start_time < max_wait:
                    page.wait_for_timeout(10000)
                    content = page.content().lower()

                    # Check if scan is complete
                    if "completed" in content or "finished" in content or "scan complete" in content:
                        break

                    # Check for results
                    if "results" in content and target.lower() in content:
                        # Try to extract table rows
                        rows = page.query_selector_all("tr")
                        if rows:
                            break

                # Step 9: Extract all result data
                # Try table rows first
                rows = page.query_selector_all("tr, .result, .scan-result, .list-group-item")
                for row in rows[:200]:
                    text = row.inner_text().strip()
                    if text and len(text) > 5:
                        results.append({
                            "source": "spiderfoot_web",
                            "target": target,
                            "data": text[:500],
                        })

                # Also try to get the full page content for parsing
                full_content = page.content()
                if len(results) < 10 and full_content:
                    # Parse any data elements
                    data_els = page.query_selector_all("td, .data, .result-data")
                    for el in data_els[:100]:
                        text = el.inner_text().strip()
                        if text and target.lower() in text.lower():
                            results.append({
                                "source": "spiderfoot_web",
                                "target": target,
                                "data": text[:500],
                            })

                browser.close()

        except Exception as e:
            store.log(f"SpiderFoot browser error: {e}", level="error", source="spiderfoot")
        finally:
            # Step 10: Kill the SpiderFoot server
            if server_proc:
                try:
                    server_proc.terminate()
                    server_proc.wait(timeout=5)
                except Exception:
                    try:
                        server_proc.kill()
                    except Exception:
                        pass

        return results

    def run_tool_with_browser(
        self, tool_name: str, tool_url: str, target: str, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        """Generic browser interaction for any tool that creates a local web UI."""
        if not self.is_available():
            return []
        tool_handlers = {"spiderfoot": self.spiderfoot_scan}
        handler = tool_handlers.get(tool_name)
        if handler:
            return handler(target=target, sf_url=tool_url, **kwargs)
        result = self.fetch_page(tool_url, wait_ms=5000)
        if result.get("html"):
            return [{"source": tool_name, "target": target, "data": result["html"][:2000], "title": result.get("title", "")}]
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
