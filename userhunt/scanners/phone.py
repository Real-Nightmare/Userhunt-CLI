"""
Phone scanner — phonenumbers, ignorant, phoneinfoga binary.
"""
import re
import subprocess
import sys
from typing import Any, Dict, List

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


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
        """Run ignorant tool against phone number."""
        hits: List[Dict[str, Any]] = []
        ignorant_path = self.config.hunt.workspace / "tools" / "ignorant"
        if not ignorant_path.exists():
            return hits
        try:
            result = subprocess.run(
                [sys.executable, "-m", "ignorant", "-n", phone],
                capture_output=True, text=True, timeout=60,
                cwd=str(ignorant_path),
            )
            if result.stdout.strip():
                hits.append(self._make_hit(
                    platform="ignorant", url=f"ignorant://{phone}",
                    confidence="MEDIUM", data=result.stdout[:2000],
                ))
        except Exception:
            pass
        return hits

    def _phoneinfoga(self, phone: str) -> List[Dict[str, Any]]:
        """Run PhoneInfoga: phoneinfoga scan -n PHONE_NUMBER"""
        hits: List[Dict[str, Any]] = []
        pf_path = self.config.hunt.workspace / "tools" / "phoneinfoga"
        if not pf_path.exists():
            return hits

        # PhoneInfoga is a Go binary, not a Python module
        # Try compiled binary first
        binary = pf_path / "phoneinfoga"
        if binary.exists():
            scan_cmd = [str(binary), "scan", "-n", phone]
        else:
            # Try to find binary in various locations
            import shutil
            which_binary = shutil.which("phoneinfoga")
            if which_binary:
                scan_cmd = [which_binary, "scan", "-n", phone]
            else:
                # Binary not found, skip
                return hits

        try:
            result = subprocess.run(
                scan_cmd,
                capture_output=True, text=True, timeout=60,
                cwd=str(pf_path) if pf_path.exists() else None,
            )
            if result.stdout.strip():
                hits.append(self._make_hit(
                    platform="phoneinfoga", url=f"phoneinfoga://{phone}",
                    confidence="MEDIUM", data=result.stdout[:2000],
                ))
        except Exception:
            pass
        return hits

    def scan_phones(self, phones: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of phone numbers."""
        all_hits: List[Dict[str, Any]] = []
        for phone in phones[:50]:
            info = self._parse_phone(phone)
            if info:
                all_hits.append(self._make_hit(
                    platform="phonenumbers", url=f"phone://{phone}",
                    confidence="MEDIUM", data=info,
                ))
            try:
                all_hits.extend(self._ignorant(phone))
            except Exception:
                pass
            try:
                all_hits.extend(self._phoneinfoga(phone))
            except Exception:
                pass

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
