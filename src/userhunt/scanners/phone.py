"""
Phone scanner — phonenumbers, ignorant, phoneinfoga binary.
"""
import os
import sys
import re
import subprocess
from typing import List, Dict, Any

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class PhoneScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "phone_scanner"
        self.description = "Phone number intelligence"
        self.status = "CORE"

    def _parse_phone(self, phone: str) -> Dict[str, Any]:
        try:
            parsed = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed):
                return {}
            info = {
                "country": geocoder.description_for_number(parsed, "en"),
                "carrier": carrier.name_for_number(parsed, "en"),
                "timezones": timezone.time_zones_for_number(parsed),
                "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            }
            return info
        except Exception:
            return {}

    def _ignorant(self, phone: str) -> List[Dict[str, Any]]:
        hits = []
        ignorant_path = self.config.hunt.workspace / "tools" / "ignorant"
        if not ignorant_path.exists():
            return hits
        try:
            result = subprocess.run(
                [sys.executable, "-m", "ignorant", "-n", phone],
                capture_output=True, text=True, timeout=60, cwd=str(ignorant_path)
            )
            if result.stdout:
                hits.append(self._make_hit(platform="ignorant", url=f"ignorant://{phone}",
                                           confidence="MEDIUM", data=result.stdout[:2000]))
        except Exception:
            pass
        return hits

    def scan_phones(self, phones: List[str]) -> List[Dict[str, Any]]:
        all_hits = []
        for phone in phones[:50]:
            info = self._parse_phone(phone)
            if info:
                all_hits.append(self._make_hit(platform="phonenumbers", url=f"phone://{phone}",
                                               confidence="MEDIUM", data=info))
            all_hits.extend(self._ignorant(phone))
        seen = set()
        deduped = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        phone_like = [c for c in clues if re.search(r'\+?\d[\d\s\-\(\)]{7,15}\d', c)]
        return self.scan_phones(phone_like)
