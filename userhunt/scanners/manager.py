"""
Scan manager — orchestrates all OSINT scanners.
Wires together username, email, phone, domain, name, URL, and browser scanners.
Shows errors in terminal and logs to dashboard.
"""
import sys
import traceback
from typing import Any, Dict, List, Tuple

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.scanners.username import UsernameScanner
from userhunt.scanners.email import EmailScanner
from userhunt.scanners.domain import DomainScanner
from userhunt.scanners.phone import PhoneScanner
from userhunt.scanners.name import NameScanner
from userhunt.scanners.url import URLScanner
from userhunt.scanners.browser import BrowserManager
from userhunt.web.store import store


class ScanManager:
    """Orchestrates all OSINT scanners and browser tools."""

    HIGH_PLATFORMS = {
        "snapchat", "tiktok", "twitter", "x", "youtube", "github",
        "instagram", "roblox", "discord", "twitch", "reddit", "steam",
        "linkedin", "spotify", "keybase", "chess", "bluesky",
    }

    def __init__(self, config: Config):
        self.config = config
        self.scanners: List[BaseScanner] = [
            UsernameScanner(config),
            EmailScanner(config),
            DomainScanner(config),
            PhoneScanner(config),
            NameScanner(config),
            URLScanner(config),
        ]
        self.browser = BrowserManager(config)

    def registry(self) -> List[Tuple[str, str, str]]:
        """Return list of (name, status, description) for all scanners."""
        reg: List[Tuple[str, str, str]] = []
        for scanner in self.scanners:
            reg.append((scanner.name, scanner.status, getattr(scanner, "description", "")))
        reg.append(("browser", "BEST-EFFORT" if self.browser.is_available() else "NOT-INSTALLED",
                     "Playwright browser manager for SpiderFoot and JS-rendered pages"))
        return reg

    def _confidence(self, platform: str) -> str:
        p = platform.lower().replace(" ", "").replace("-", "")
        for hp in self.HIGH_PLATFORMS:
            if hp in p:
                return "HIGH"
        return "MEDIUM"

    def _dedupe_hits(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate hits by (platform, url)."""
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def _run_scanner(self, scanner, method_name: str, items: list, label: str) -> List[Dict[str, Any]]:
        """Run a single scanner method with error visibility."""
        try:
            method = getattr(scanner, method_name)
            found = method(items)
            hits = []
            for h in found:
                if "confidence" not in h:
                    h["confidence"] = self._confidence(h.get("platform", ""))
                hits.append(h)
            if found:
                print(f"  [green]✓[/green] {scanner.name}: {len(found)} hits", flush=True)
                store.log(f"{scanner.name}: {len(found)} hits", source=scanner.name)
            return hits
        except Exception as e:
            error_msg = f"{scanner.name} FAILED: {e}"
            print(f"  [red]✗[/red] {error_msg}", flush=True)
            store.log(error_msg, level="error", source=scanner.name)
            return []

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run all username-capable scanners."""
        print(f"  [bold]Running username scanners for: {', '.join(usernames[:3])}[/bold]", flush=True)
        store.log(f"Starting username scan: {usernames[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_usernames"):
                hits.extend(self._run_scanner(scanner, "scan_usernames", usernames, "username"))
        return self._dedupe_hits(hits)

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Run all email-capable scanners."""
        print(f"  [bold]Running email scanners for: {', '.join(emails[:3])}[/bold]", flush=True)
        store.log(f"Starting email scan: {emails[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_emails"):
                hits.extend(self._run_scanner(scanner, "scan_emails", emails, "email"))
        return self._dedupe_hits(hits)

    def scan_names(self, names: List[str]) -> List[Dict[str, Any]]:
        """Run all name-capable scanners."""
        print(f"  [bold]Running name scanners for: {', '.join(n[:20] for n in names[:3])}[/bold]", flush=True)
        store.log(f"Starting name scan: {names[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_names"):
                hits.extend(self._run_scanner(scanner, "scan_names", names, "name"))
        return self._dedupe_hits(hits)

    def scan_phones(self, phones: List[str]) -> List[Dict[str, Any]]:
        """Run all phone-capable scanners."""
        print(f"  [bold]Running phone scanners for: {len(phones)} number(s)[/bold]", flush=True)
        store.log(f"Starting phone scan: {phones[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_phones"):
                hits.extend(self._run_scanner(scanner, "scan_phones", phones, "phone"))
        return self._dedupe_hits(hits)

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Run all domain-capable scanners."""
        print(f"  [bold]Running domain scanners for: {', '.join(domains[:3])}[/bold]", flush=True)
        store.log(f"Starting domain scan: {domains[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_domains"):
                hits.extend(self._run_scanner(scanner, "scan_domains", domains, "domain"))
        return self._dedupe_hits(hits)

    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Run all URL-capable scanners."""
        print(f"  [bold]Running URL scanners for: {len(urls)} url(s)[/bold]", flush=True)
        store.log(f"Starting URL scan: {urls[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_urls"):
                hits.extend(self._run_scanner(scanner, "scan_urls", urls, "url"))
        return self._dedupe_hits(hits)

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        """Run all scanners that accept raw clues."""
        print(f"  [bold]Running clue scanners for: {len(clues)} clue(s)[/bold]", flush=True)
        store.log(f"Starting clue scan: {clues[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_clues"):
                hits.extend(self._run_scanner(scanner, "scan_clues", clues, "clue"))
        return self._dedupe_hits(hits)
