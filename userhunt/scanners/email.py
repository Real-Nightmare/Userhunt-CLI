"""
Email scanner — Holehe, Blackbird, Gravatar, emailrep, MX, h8mail, email2phonenumber.
ALL tools at MAXIMUM power — full database, all modules.
"""
import hashlib
import json
import subprocess
import sys
from typing import Any, Dict, List

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.utils.runner import run_tool_simple
from userhunt.web.store import store


class EmailScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "email_scanner"
        self.description = "Email recon: Gravatar, emailrep, MX, Holehe (120+ sites), Blackbird (400+ sites), h8mail, email2phonenumber — MAXIMUM power"
        self.status = "CORE"

    # ── Gravatar (full profile) ─────────────────────────────────────

    def _gravatar(self, email: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            md5_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
            avatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
            resp = requests.get(avatar_url, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                profile_url = f"https://www.gravatar.com/{md5_hash}.json"
                display_name = ""
                profile_data = {}
                try:
                    p = requests.get(profile_url, timeout=15)
                    if p.status_code == 200:
                        data = p.json()
                        entry = data.get("entry", [{}])
                        if entry:
                            display_name = entry[0].get("displayName", "")
                            profile_data = entry[0]
                except Exception:
                    pass
                hit = self._make_hit(
                    platform="Gravatar", url=avatar_url, confidence="MEDIUM",
                    display_name=display_name, emails=[email],
                    data=profile_data,
                )
                hits.append(hit)
                store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── emailrep.io (full report) ───────────────────────────────────

    def _emailrep(self, email: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://emailrep.io/{email}", timeout=15,
                headers={"User-Agent": "Userhunt"},
            )
            if resp.status_code == 200:
                data = resp.json()
                hit = self._make_hit(
                    platform="emailrep", url=f"https://emailrep.io/{email}",
                    confidence="MEDIUM", data=data,
                )
                hits.append(hit)
                store.add_hit(hit)
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
            hit = self._make_hit(
                platform="MX", url=f"mx://{domain}", confidence="MEDIUM",
                data={"mx": mx_records, "domain": domain}, emails=[email],
            )
            hits.append(hit)
            store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── Holehe — MAXIMUM (all 120+ modules) ─────────────────────────

    def _holehe(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        HOLEHE — MAXIMUM:
        holehe email@gmail.com
        Runs ALL 120+ modules (Twitter, Instagram, Spotify, etc.)
        No flags needed — it checks everything by default.
        """
        hits: List[Dict[str, Any]] = []
        holehe_path = self.config.hunt.workspace / "tools" / "holehe"
        if not holehe_path.exists():
            return hits
        for email in emails[:10]:
            store.log(f"Running Holehe (MAX - 120+ modules) for: {email}", source="holehe")
            stdout, stderr, rc = run_tool_simple(
                [sys.executable, "-m", "holehe", email],
                cwd=str(holehe_path),
                timeout=self.config.hunt.tool_timeout,
                tool_name="holehe",
            )
            for line in stdout.splitlines():
                if "[+]" in line:
                    parts = line.split("[+]")
                    if len(parts) >= 2:
                        platform = parts[1].strip()
                        hit = self._make_hit(
                            platform=platform, url=f"holehe:{email}",
                            confidence="MEDIUM", emails=[email],
                        )
                        hits.append(hit)
                        store.add_hit(hit)
        return hits

    # ── Blackbird -e — MAXIMUM (400+ sites) ─────────────────────────

    def _blackbird_email(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        BLACKBIRD (email mode) — MAXIMUM:
        blackbird.py -e EMAIL --json
        Checks 400+ platforms for email associations.
        """
        hits: List[Dict[str, Any]] = []
        bb_path = self.config.hunt.workspace / "tools" / "blackbird"
        if not bb_path.exists():
            return hits
        for email in emails[:5]:
            store.log(f"Running Blackbird email (MAX - 400+ sites) for: {email}", source="blackbird")
            stdout, stderr, rc = run_tool_simple(
                [sys.executable, "blackbird.py", "-e", email, "--json"],
                cwd=str(bb_path),
                timeout=self.config.hunt.tool_timeout,
                tool_name="blackbird",
            )
            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    site = data.get("site", "blackbird")
                    if url and data.get("status") == "FOUND":
                        hit = self._make_hit(
                            platform=site, url=url, confidence="MEDIUM",
                            emails=[email],
                        )
                        hits.append(hit)
                        store.add_hit(hit)
                except json.JSONDecodeError:
                    pass
        return hits

    # ── h8mail — MAXIMUM ────────────────────────────────────────────

    def _h8mail(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        h8mail — checks for breached email accounts.
        Uses Hunter API + local breach databases.
        """
        hits: List[Dict[str, Any]] = []
        try:
            import h8mail  # noqa: F401
            for email in emails[:5]:
                try:
                    from h8mail.utils.hunter import hunter_search
                    results = hunter_search(email)
                    if results:
                        hit = self._make_hit(
                            platform="h8mail", url=f"h8mail:{email}",
                            confidence="MEDIUM", emails=[email],
                            data=results[:5000] if isinstance(results, str) else str(results)[:5000],
                        )
                        hits.append(hit)
                        store.add_hit(hit)
                except Exception:
                    pass
        except ImportError:
            pass
        return hits

    # ── email2phonenumber — MAXIMUM ──────────────────────────────────

    def _email2phonenumber(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        email2phonenumber — scrape websites for phone number digits.
        email2phonenumber.py scrape -e EMAIL
        """
        hits: List[Dict[str, Any]] = []
        e2p_path = self.config.hunt.workspace / "tools" / "email2phonenumber"
        if not e2p_path.exists():
            return hits
        for email in emails[:3]:
            store.log(f"Running email2phonenumber (MAX) for: {email}", source="email2phonenumber")
            stdout, stderr, rc = run_tool_simple(
                [sys.executable, "email2phonenumber.py", "scrape", "-e", email],
                cwd=str(e2p_path),
                timeout=self.config.hunt.tool_timeout,
                tool_name="email2phonenumber",
            )
            if stdout.strip():
                hit = self._make_hit(
                    platform="email2phonenumber", url=f"e2p:{email}",
                    confidence="LOW", emails=[email],
                    data=stdout[:10000],
                )
                hits.append(hit)
                store.add_hit(hit)
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        email_like = [c for c in clues if "@" in c and "." in c.split("@")[-1]]
        return self.scan_emails(email_like)

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []
        store.log(f"Email scan: {len(emails)} email(s) — ALL tools at MAXIMUM", source="email_scanner")
        for email in emails:
            all_hits.extend(self._gravatar(email))
            all_hits.extend(self._emailrep(email))
            all_hits.extend(self._mx_lookup(email))
        try:
            all_hits.extend(self._holehe(emails))
        except Exception as e:
            store.log(f"Holehe error: {e}", level="error", source="holehe")
        try:
            all_hits.extend(self._blackbird_email(emails))
        except Exception as e:
            store.log(f"Blackbird email error: {e}", level="error", source="blackbird")
        try:
            all_hits.extend(self._h8mail(emails))
        except Exception as e:
            store.log(f"h8mail error: {e}", level="error", source="h8mail")
        try:
            all_hits.extend(self._email2phonenumber(emails))
        except Exception as e:
            store.log(f"email2phonenumber error: {e}", level="error", source="email2phonenumber")

        store.log(f"Email scan complete: {len(all_hits)} hits (MAXIMUM power)", source="email_scanner")
        # Deduplicate
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
