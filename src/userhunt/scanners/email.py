"""
Email scanner — Holehe, Blackbird, Gravatar, emailrep, MX, h8mail, email2phonenumber.
"""
import os
import sys
import json
import hashlib
import subprocess
from typing import List, Dict, Any

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class EmailScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "email_scanner"
        self.description = "Email reconnaissance and validation"
        self.status = "CORE"

    def _gravatar(self, email: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            h = hashlib.md5(email.strip().lower().encode()).hexdigest()
            url = f"https://www.gravatar.com/avatar/{h}?d=404"
            resp = requests.get(url, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                profile_url = f"https://www.gravatar.com/{h}.json"
                try:
                    p = requests.get(profile_url, timeout=15)
                    if p.status_code == 200:
                        data = p.json()
                        entry = data.get("entry", [{}])[0] if data.get("entry") else {}
                        display_name = entry.get("displayName", "")
                        hits.append(self._make_hit(platform="gravatar", url=url, confidence="MEDIUM",
                                                   display_name=display_name, emails=[email]))
                except Exception:
                    hits.append(self._make_hit(platform="gravatar", url=url, confidence="LOW", emails=[email]))
        except Exception:
            pass
        return hits

    def _emailrep(self, email: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            resp = requests.get(f"https://emailrep.io/{email}", timeout=15, headers={"User-Agent": "USERHUNT"})
            if resp.status_code == 200:
                data = resp.json()
                hits.append(self._make_hit(platform="emailrep", url=f"https://emailrep.io/{email}",
                                           confidence="MEDIUM", data=data))
        except Exception:
            pass
        return hits

    def _mx_lookup(self, email: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            domain = email.split("@")[1]
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = [str(r.exchange) for r in answers]
            hits.append(self._make_hit(platform="mx", url=f"mx://{domain}", confidence="MEDIUM",
                                       data={"mx": mx_records, "domain": domain}))
        except Exception:
            pass
        return hits

    def _holehe(self, emails: List[str]) -> List[Dict[str, Any]]:
        hits = []
        holehe_path = self.config.hunt.workspace / "tools" / "holehe"
        if not holehe_path.exists():
            return hits
        for email in emails[:10]:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "holehe", "--no-update", email],
                    capture_output=True, text=True, timeout=120, cwd=str(holehe_path)
                )
                for line in result.stdout.splitlines():
                    if "[+]" in line:
                        parts = line.split("[+]")
                        if len(parts) >= 2:
                            platform = parts[1].strip()
                            hits.append(self._make_hit(platform=platform, url=f"holehe:{email}",
                                                       confidence="MEDIUM", emails=[email]))
            except Exception:
                pass
        return hits

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        email_like = [c for c in clues if "@" in c and "." in c.split("@")[-1]]
        return self.scan_emails(email_like)

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        all_hits = []
        for email in emails:
            all_hits.extend(self._gravatar(email))
            all_hits.extend(self._emailrep(email))
            all_hits.extend(self._mx_lookup(email))
        try:
            all_hits.extend(self._holehe(emails))
        except Exception:
            pass
        seen = set()
        deduped = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
