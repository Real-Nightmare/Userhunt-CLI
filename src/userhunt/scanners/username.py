"""
Username scanner — Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName, direct probers.
"""
import os
import sys
import json
import time
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class UsernameScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "username_scanner"
        self.description = "Username enumeration across 500+ sites"
        self.status = "CORE"
        self.wmn_data_path = config.hunt.workspace / "tools" / "WhatsMyName" / "wmn-data.json"
        self._wmn_sites: List[dict] = []

    def _load_wmn(self) -> List[dict]:
        if self._wmn_sites:
            return self._wmn_sites
        if self.wmn_data_path.exists():
            try:
                with open(self.wmn_data_path, "r") as f:
                    data = json.load(f)
                self._wmn_sites = [s for s in data.get("sites", []) if s.get("e_code") or s.get("e_string") or s.get("m_string")]
            except Exception:
                self._wmn_sites = []
        return self._wmn_sites

    def _probe_site(self, site: dict, username: str) -> Dict[str, Any]:
        url_template = site.get("url", "").replace("{account}", username)
        if not url_template:
            return {}
        try:
            resp = requests.get(url_template, timeout=15, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            status = resp.status_code
            text = resp.text.lower()
            e_code = site.get("e_code")
            e_string = site.get("e_string", "").lower()
            m_string = site.get("m_string", "").lower()
            found = False
            if e_code is not None and status == e_code:
                found = True
            elif e_string and e_string in text:
                found = True
            elif m_string and m_string not in text:
                found = True
            if found:
                return self._make_hit(
                    platform=site.get("name", site.get("site", "")),
                    url=url_template,
                    confidence="MEDIUM",
                    status_code=status,
                    display_name=site.get("name", ""),
                )
        except Exception:
            pass
        return {}

    def _direct_probers(self, username: str) -> List[Dict[str, Any]]:
        hits = []
        probers = [
            ("github", f"https://api.github.com/users/{username}", lambda r: r.status_code == 200),
            ("gitlab", f"https://gitlab.com/api/v4/users?username={username}", lambda r: r.status_code == 200 and r.json()),
            ("codeberg", f"https://codeberg.org/api/v1/users/{username}", lambda r: r.status_code == 200),
            ("keybase", f"https://keybase.io/{username}", lambda r: r.status_code == 200),
            ("reddit", f"https://www.reddit.com/user/{username}/about.json", lambda r: r.status_code == 200),
            ("hackernews", f"https://hn.algolia.com/api/v1/users/{username}", lambda r: r.status_code == 200),
            ("stackexchange", f"https://api.stackexchange.com/2.3/users/{username}", lambda r: r.status_code == 200),
            ("chess", f"https://api.chess.com/pub/player/{username}", lambda r: r.status_code == 200),
            ("bluesky", f"https://bsky.app/profile/{username}.bsky.social", lambda r: r.status_code == 200),
            ("mastodon", f"https://mastodon.social/api/v1/accounts/lookup?acct={username}", lambda r: r.status_code == 200),
            ("steam", f"https://steamcommunity.com/id/{username}", lambda r: r.status_code == 200),
            ("pinterest", f"https://www.pinterest.com/{username}/", lambda r: r.status_code == 200),
            ("linktree", f"https://linktr.ee/{username}", lambda r: r.status_code == 200),
            ("telegram", f"https://t.me/{username}", lambda r: r.status_code == 200),
            ("tiktok", f"https://www.tiktok.com/@{username}", lambda r: r.status_code == 200),
            ("twitch", f"https://www.twitch.tv/{username}", lambda r: r.status_code == 200),
            ("youtube", f"https://www.youtube.com/@{username}", lambda r: r.status_code == 200),
            ("snapchat", f"https://www.snapchat.com/add/{username}", lambda r: r.status_code == 200),
            ("instagram", f"https://www.instagram.com/{username}/", lambda r: r.status_code == 200),
            ("x", f"https://x.com/{username}", lambda r: r.status_code == 200),
            ("reddit_about", f"https://www.reddit.com/user/{username}/about.json", lambda r: r.status_code == 200),
            ("linktree", f"https://linktr.ee/{username}", lambda r: r.status_code == 200),
            ("spotify", f"https://open.spotify.com/user/{username}", lambda r: r.status_code == 200),
            ("roblox", f"https://www.roblox.com/users/profile?username={username}", lambda r: r.status_code == 200),
        ]
        headers = {"User-Agent": "Mozilla/5.0"}
        for platform, url, check in probers:
            try:
                resp = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
                if check(resp):
                    conf = "HIGH" if platform in ("github", "reddit", "steam", "x", "twitter", "tiktok", "instagram", "roblox") else "MEDIUM"
                    hits.append(self._make_hit(platform=platform, url=url, confidence=conf, status_code=resp.status_code))
            except Exception:
                pass
        return hits

    def _run_sherlock(self, usernames: List[str]) -> List[Dict[str, Any]]:
        hits = []
        sherlock_path = self.config.hunt.workspace / "tools" / "sherlock"
        if not sherlock_path.exists():
            return hits
        for username in usernames[:10]:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "sherlock_project.sherlock", "--print-found", "--timeout", "6", username],
                    capture_output=True, text=True, timeout=120, cwd=str(sherlock_path)
                )
                for line in result.stdout.splitlines():
                    if "https://" in line:
                        platform = line.split(":")[0].strip() if ":" in line else "sherlock"
                        url = line.strip()
                        hits.append(self._make_hit(platform=platform, url=url, confidence=self._confidence(platform)))
            except Exception:
                pass
        return hits

    def _run_maigret(self, usernames: List[str]) -> List[Dict[str, Any]]:
        hits = []
        maigret_path = self.config.hunt.workspace / "tools" / "maigret"
        if not maigret_path.exists():
            return hits
        for username in usernames[:5]:
            try:
                out_dir = self.config.hunt.workspace / "data" / f"maigret_{username}"
                out_dir.mkdir(parents=True, exist_ok=True)
                result = subprocess.run(
                    [sys.executable, "-m", "maigret", "--timeout", "6", "--top-sites", "150", "--json", username],
                    capture_output=True, text=True, timeout=180, cwd=str(maigret_path)
                )
                for f in out_dir.glob("*.json"):
                    try:
                        with open(f, "r") as fp:
                            data = json.load(fp)
                        if isinstance(data, list):
                            for item in data:
                                url = item.get("url", "")
                                if url:
                                    hits.append(self._make_hit(platform=item.get("site", "maigret"), url=url, confidence=self._confidence(item.get("site", ""))))
                    except Exception:
                        pass
            except Exception:
                pass
        return hits

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        all_hits = []
        sites = self._load_wmn()
        for username in usernames:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self._probe_site, site, username): site for site in sites[:300]}
                for future in as_completed(futures):
                    try:
                        hit = future.result()
                        if hit:
                            all_hits.append(hit)
                    except Exception:
                        pass
            all_hits.extend(self._direct_probers(username))
        try:
            all_hits.extend(self._run_sherlock(usernames))
        except Exception:
            pass
        try:
            all_hits.extend(self._run_maigret(usernames))
        except Exception:
            pass
        return all_hits
