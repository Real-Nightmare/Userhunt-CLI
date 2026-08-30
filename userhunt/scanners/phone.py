"""
Phone scanner — phonenumbers, ignorant, phoneinfoga binary.
All tools use streaming output — never lose data.
"""
import re
import subprocess
import sys
from typing import Any, Dict, List

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.utils.runner import run_tool_simple
from userhunt.web.store import store


class PhoneScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "phone_scanner"
        self.description = "Phone number intelligence: phonenumbers, ignorant, phoneinfoga"
        self.status = "CORE"

    def _parse_phone(self, phone: str) -> Dict[str, Any]:
        """Parse phone number via phonenumbers library."""
        try:
            parsed = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed):
                return {}
            return {
                "country": geocoder.description_for_number(parsed, "en"),
                "carrier": carrier.name_for_number(parsed, "en"),
                "timezones": timezone.time_zones_for_number(parsed),
                "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "type": str(phonenumbers.number_type(parsed)),
            }
        except Exception:
            return {}

    def _ignorant(self, phone: str) -> List[Dict[str, Any]]:
        """Run ignorant tool with streaming output."""
        hits: List[Dict[str, Any]] = []
        ignorant_path = self.config.hunt.workspace / "tools" / "ignorant"
        if not ignorant_path.exists():
            return hits
        store.log(f"Running ignorant for: {phone}", source="ignorant")
        stdout, stderr, rc = run_tool_simple(
            [sys.executable, "-m", "ignorant", "-n", phone],
            cwd=str(ignorant_path),
            timeout=self.config.hunt.tool_timeout,
            tool_name="ignorant",
        )
        if stdout.strip():
            hit = self._make_hit(
                platform="ignorant", url=f"ignorant://{phone}",
                confidence="MEDIUM", data=stdout[:5000],
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    def _phoneinfoga(self, phone: str) -> List[Dict[str, Any]]:
        """Run PhoneInfoga binary with streaming output."""
        hits: List[Dict[str, Any]] = []
        pf_path = self.config.hunt.workspace / "tools" / "phoneinfoga"
        if not pf_path.exists():
            return hits

        # PhoneInfoga is a Go binary, not a Python module
        binary = pf_path / "phoneinfoga"
        if binary.exists():
            scan_cmd = [str(binary), "scan", "-n", phone]
        else:
            import shutil
            which_binary = shutil.which("phoneinfoga")
            if which_binary:
                scan_cmd = [which_binary, "scan", "-n", phone]
            else:
                return hits

        store.log(f"Running phoneinfoga for: {phone}", source="phoneinfoga")
        stdout, stderr, rc = run_tool_simple(
            scan_cmd,
            cwd=str(pf_path) if pf_path.exists() else None,
            timeout=self.config.hunt.tool_timeout,
            tool_name="phoneinfoga",
        )
        if stdout.strip():
            hit = self._make_hit(
                platform="phoneinfoga", url=f"phoneinfoga://{phone}",
                confidence="MEDIUM", data=stdout[:5000],
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    def scan_phones(self, phones: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of phone numbers."""
        all_hits: List[Dict[str, Any]] = []
        store.log(f"Phone scan: {len(phones)} number(s)", source="phone_scanner")
        for phone in phones[:50]:
            info = self._parse_phone(phone)
            if info:
                hit = self._make_hit(
                    platform="phonenumbers", url=f"phone://{phone}",
                    confidence="MEDIUM", data=info,
                )
                all_hits.append(hit)
                store.add_hit(hit)
            try:
                all_hits.extend(self._ignorant(phone))
            except Exception:
                pass
            try:
                all_hits.extend(self._phoneinfoga(phone))
            except Exception:
                pass

        store.log(f"Phone scan complete: {len(all_hits)} hits", source="phone_scanner")
        # Deduplicate
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        phone_like = [c for c in clues if re.search(r'\+?\d[\d\s\-()]{7,15}\d', c)]
        return self.scan_phones(phone_like)
