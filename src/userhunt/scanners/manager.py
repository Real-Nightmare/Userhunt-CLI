"""
Scan manager — orchestrates all OSINT scanners.
Wires together username, email, phone, domain, name, URL, and browser scanners.
"""
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

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run all username-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_usernames"):
                try:
                    found = scanner.scan_usernames(usernames)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Run all email-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_emails"):
                try:
                    found = scanner.scan_emails(emails)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_names(self, names: List[str]) -> List[Dict[str, Any]]:
        """Run all name-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_names"):
                try:
                    found = scanner.scan_names(names)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_phones(self, phones: List[str]) -> List[Dict[str, Any]]:
        """Run all phone-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_phones"):
                try:
                    found = scanner.scan_phones(phones)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Run all domain-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_domains"):
                try:
                    found = scanner.scan_domains(domains)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Run all URL-capable scanners."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_urls"):
                try:
                    found = scanner.scan_urls(urls)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        """Run all scanners that accept raw clues."""
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_clues"):
                try:
                    found = scanner.scan_clues(clues)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        return self._dedupe_hits(hits)[:self.config.hunt.max_hits]
