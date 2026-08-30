"""
Email scanner — Holehe, Blackbird, Gravatar, emailrep, MX, h8mail, email2phonenumber.
"""
import hashlib
import json
import subprocess
import sys
from typing import Any, Dict, List

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class EmailScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "email_scanner"
        self.description = "Email reconnaissance: Gravatar, emailrep, MX, Holehe, Blackbird, h8mail"
        self.status = "CORE"

    # ── Gravatar ────────────────────────────────────────────────────

    def _gravatar(self, email: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            md5_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
            avatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
            resp = requests.get(avatar_url, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                profile_url = f"https://www.gravatar.com/{md5_hash}.json"
                display_name = ""
                try:
                    p = requests.get(profile_url, timeout=15)
                    if p.status_code == 200:
                        data = p.json()
                        entry = data.get("entry", [{}])
                        if entry:
                            display_name = entry[0].get("displayName", "")
                except Exception:
                    pass
                hits.append(self._make_hit(
                    platform="Gravatar", url=avatar_url, confidence="MEDIUM",
                    display_name=display_name, emails=[email],
                ))
        except Exception:
            pass
        return hits

    # ── emailrep.io ─────────────────────────────────────────────────

    def _emailrep(self, email: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://emailrep.io/{email}", timeout=15,
                headers={"User-Agent": "Userhunt"},
            )
            if resp.status_code == 200:
                data = resp.json()
                hits.append(self._make_hit(
                    platform="emailrep", url=f"https://emailrep.io/{email}",
                    confidence="MEDIUM", data=data,
                ))
        except Exception:
            pass
        return hits

    # ── MX lookup ───────────────────────────────────────────────────

    def _mx_lookup(self, email: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            domain = email.split("@")[1]
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = [str(r.exchange) for r in answers]
            hits.append(self._make_hit(
                platform="MX", url=f"mx://{domain}", confidence="MEDIUM",
                data={"mx": mx_records, "domain": domain}, emails=[email],
            ))
        except Exception:
            pass
        return hits

    # ── Holehe ──────────────────────────────────────────────────────

    def _holehe(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Run Holehe: holehe email@gmail.com"""
        hits: List[Dict[str, Any]] = []
        holehe_path = self.config.hunt.workspace / "tools" / "holehe"
        if not holehe_path.exists():
            return hits
        for email in emails[:10]:
            try:
                # Holehe CLI: holehe email@gmail.com
                result = subprocess.run(
                    [sys.executable, "-m", "holehe", email],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(holehe_path),
                )
                for line in result.stdout.splitlines():
                    # Holehe output: [+] platform
                    if "[+]" in line:
                        parts = line.split("[+]")
                        if len(parts) >= 2:
                            platform = parts[1].strip()
                            hits.append(self._make_hit(
                                platform=platform, url=f"holehe:{email}",
                                confidence="MEDIUM", emails=[email],
                            ))
            except Exception:
                pass
        return hits

    # ── Blackbird (-e flag for emails) ──────────────────────────────

    def _blackbird_email(self, emails: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        bb_path = self.config.hunt.workspace / "tools" / "blackbird"
        if not bb_path.exists():
            return hits
        for email in emails[:5]:
            try:
                result = subprocess.run(
                    [sys.executable, "blackbird.py", "-e", email, "--json"],
                    capture_output=True, text=True, timeout=90,
                    cwd=str(bb_path),
                )
                for line in result.stdout.splitlines():
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        site = data.get("site", "blackbird")
                        if url and data.get("status") == "FOUND":
                            hits.append(self._make_hit(
                                platform=site, url=url, confidence="MEDIUM",
                                emails=[email],
                            ))
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass
        return hits

    # ── h8mail ──────────────────────────────────────────────────────

    def _h8mail(self, emails: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            import h8mail  # noqa: F401
            for email in emails[:5]:
                try:
                    from h8mail.utils.hunter import hunter_search
                    results = hunter_search(email)
                    if results:
                        hits.append(self._make_hit(
                            platform="h8mail", url=f"h8mail:{email}",
                            confidence="MEDIUM", emails=[email],
                            data=results[:2000] if isinstance(results, str) else str(results)[:2000],
                        ))
                except Exception:
                    pass
        except ImportError:
            pass
        return hits

    # ── email2phonenumber ───────────────────────────────────────────

    def _email2phonenumber(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Run email2phonenumber: python email2phonenumber.py scrape email"""
        hits: List[Dict[str, Any]] = []
        e2p_path = self.config.hunt.workspace / "tools" / "email2phonenumber"
        if not e2p_path.exists():
            return hits
        for email in emails[:3]:
            try:
                # email2phonenumber CLI: python email2phonenumber.py scrape email
                result = subprocess.run(
                    [sys.executable, "email2phonenumber.py", "scrape", email],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(e2p_path),
                )
                if result.stdout.strip():
                    hits.append(self._make_hit(
                        platform="email2phonenumber", url=f"e2p:{email}",
                        confidence="LOW", emails=[email],
                        data=result.stdout[:2000],
                    ))
            except Exception:
                pass
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        email_like = [c for c in clues if "@" in c and "." in c.split("@")[-1]]
        return self.scan_emails(email_like)

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []
        for email in emails:
            all_hits.extend(self._gravatar(email))
            all_hits.extend(self._emailrep(email))
            all_hits.extend(self._mx_lookup(email))
        try:
            all_hits.extend(self._holehe(emails))
        except Exception:
            pass
        try:
            all_hits.extend(self._blackbird_email(emails))
        except Exception:
            pass
        try:
            all_hits.extend(self._h8mail(emails))
        except Exception:
            pass
        try:
            all_hits.extend(self._email2phonenumber(emails))
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
