"""
Scan manager — orchestrates all OSINT scanners.
"""
import os
import subprocess
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.scanners.username import UsernameScanner
from userhunt.scanners.email import EmailScanner
from userhunt.scanners.domain import DomainScanner
from userhunt.scanners.phone import PhoneScanner


class ScanManager:
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
        ]
        self.tools: Dict[str, str] = {}

    def registry(self) -> List[Tuple[str, str, str]]:
        reg = []
        for scanner in self.scanners:
            reg.append((scanner.name, scanner.status, getattr(scanner, "description", "")))
        return reg

    def _confidence(self, platform: str) -> str:
        p = platform.lower().replace(" ", "").replace("-", "")
        for hp in self.HIGH_PLATFORMS:
            if hp in p:
                return "HIGH"
        return "MEDIUM"

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_usernames"):
                try:
                    found = scanner.scan_usernames(usernames)
                    for h in found:
                        h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception as exc:
                    pass
        seen = set()
        deduped = []
        for h in hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped[: self.config.hunt.max_hits]

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_emails"):
                try:
                    found = scanner.scan_emails(emails)
                    for h in found:
                        h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        seen = set()
        deduped = []
        for h in hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped[: self.config.hunt.max_hits]

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_clues"):
                try:
                    found = scanner.scan_clues(clues)
                    for h in found:
                        h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                except Exception:
                    pass
        seen = set()
        deduped = []
        for h in hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped[: self.config.hunt.max_hits]
