"""
Username scanner — Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName, direct probers.
Includes keyless APIs and GitHub commit email harvesting.
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


# Platforms that count as HIGH confidence
HIGH_PLATFORMS = {
    "github", "reddit", "steam", "x", "twitter", "tiktok",
    "instagram", "roblox", "snapchat", "twitch", "youtube",
}


class UsernameScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "username_scanner"
        self.description = "Username enumeration across 500+ sites (Sherlock, Maigret, Nexfil, Blackbird, WMN, direct probes)"
        self.status = "CORE"
        self.wmn_data_path = (
            config.hunt.workspace / "tools" / "WhatsMyName" / "wmn-data.json"
        )
        self._wmn_sites: List[dict] = []

    def _confidence(self, platform: str) -> str:
        p = platform.lower().replace(" ", "").replace("-", "")
        for hp in HIGH_PLATFORMS:
            if hp in p:
                return "HIGH"
        return "MEDIUM"

    def _load_wmn(self) -> List[dict]:
        if self._wmn_sites:
            return self._wmn_sites
        if self.wmn_data_path.exists():
            try:
                with open(self.wmn_data_path, "r") as f:
                    data = json.load(f)
                self._wmn_sites = [
                    s for s in data.get("sites", [])
                    if s.get("e_code") or s.get("e_string") or s.get("m_string")
                ]
            except Exception:
                self._wmn_sites = []
        return self._wmn_sites

    # ── WhatsMyName runner ──────────────────────────────────────────

    def _probe_wmn_site(self, site: dict, username: str) -> Dict[str, Any]:
        url_template = site.get("url", "").replace("{account}", username)
        if not url_template:
            return {}
        try:
            resp = requests.get(
                url_template, timeout=15, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            status = resp.status_code
            text = resp.text.lower()
            e_code = site.get("e_code")
            e_string = (site.get("e_string") or "").lower()
            m_string = (site.get("m_string") or "").lower()

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
                    confidence=self._confidence(site.get("name", "")),
                    status_code=status,
                )
        except Exception:
            pass
        return {}

    # ── Direct platform probers ─────────────────────────────────────

    def _direct_probers(self, username: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        probers = [
            ("GitHub", f"https://api.github.com/users/{username}", lambda r: r.status_code == 200),
            ("GitLab", f"https://gitlab.com/api/v4/users?username={username}", lambda r: r.status_code == 200 and r.json()),
            ("Codeberg", f"https://codeberg.org/api/v1/users/{username}", lambda r: r.status_code == 200),
            ("Keybase", f"https://keybase.io/{username}", lambda r: r.status_code == 200),
            ("Reddit", f"https://www.reddit.com/user/{username}/about.json", lambda r: r.status_code == 200),
            ("HackerNews", f"https://hn.algolia.com/api/v1/users/{username}", lambda r: r.status_code == 200),
            ("Chess.com", f"https://api.chess.com/pub/player/{username}", lambda r: r.status_code == 200),
            ("Bluesky", f"https://bsky.app/profile/{username}.bsky.social", lambda r: r.status_code == 200),
            ("Mastodon", f"https://mastodon.social/api/v1/accounts/lookup?acct={username}", lambda r: r.status_code == 200),
            ("Steam", f"https://steamcommunity.com/id/{username}", lambda r: r.status_code == 200),
            ("Pinterest", f"https://www.pinterest.com/{username}/", lambda r: r.status_code == 200),
            ("Linktree", f"https://linktr.ee/{username}", lambda r: r.status_code == 200),
            ("Telegram", f"https://t.me/{username}", lambda r: r.status_code == 200),
            ("TikTok", f"https://www.tiktok.com/@{username}", lambda r: r.status_code == 200),
            ("Twitch", f"https://www.twitch.tv/{username}", lambda r: r.status_code == 200),
            ("YouTube", f"https://www.youtube.com/@{username}", lambda r: r.status_code == 200),
            ("Snapchat", f"https://www.snapchat.com/add/{username}", lambda r: r.status_code == 200),
            ("Instagram", f"https://www.instagram.com/{username}/", lambda r: r.status_code == 200),
            ("X", f"https://x.com/{username}", lambda r: r.status_code == 200),
            ("Spotify", f"https://open.spotify.com/user/{username}", lambda r: r.status_code == 200),
            ("Roblox", f"https://www.roblox.com/users/profile?username={username}", lambda r: r.status_code == 200),
        ]
        headers = {"User-Agent": "Mozilla/5.0"}
        for platform, url, check in probers:
            try:
                resp = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
                if check(resp):
                    conf = "HIGH" if platform.lower() in HIGH_PLATFORMS else "MEDIUM"
                    hits.append(self._make_hit(
                        platform=platform, url=url, confidence=conf,
                        status_code=resp.status_code,
                    ))
            except Exception:
                pass
        return hits

    # ── GitHub commit email harvest ─────────────────────────────────

    def _github_commit_emails(self, username: str) -> List[Dict[str, Any]]:
        """Harvest commit emails from a user's public GitHub events."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://api.github.com/users/{username}/events/public",
                timeout=15,
                headers={"User-Agent": "Userhunt", "Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code == 200:
                emails_found: set[str] = set()
                for event in resp.json()[:30]:
                    payload = event.get("payload", {})
                    for commit in payload.get("commits", []):
                        author = commit.get("author", {})
                        email = author.get("email", "")
                        if email and email.endswith("@users.noreply.github.com") is False:
                            emails_found.add(email)
                for email in emails_found:
                    hits.append(self._make_hit(
                        platform="github_commit",
                        url=f"github_events:{username}",
                        confidence="MEDIUM",
                        emails=[email],
                        data={"username": username},
                    ))
        except Exception:
            pass
        return hits

    # ── Roblox POST probe ───────────────────────────────────────────

    def _roblox_probe(self, username: str) -> List[Dict[str, Any]]:
        """Roblox POST to users.roblox.com/v1/usernames/users."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.post(
                "https://users.roblox.com/v1/usernames/users",
                json={"usernames": [username], "excludeBannedUsers": False},
                timeout=15,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                users = data.get("data", [])
                for user in users:
                    uid = user.get("id")
                    if uid:
                        hits.append(self._make_hit(
                            platform="roblox",
                            url=f"https://www.roblox.com/users/{uid}/profile",
                            confidence="HIGH",
                            display_name=user.get("displayName", ""),
                            data={"roblox_id": uid, "username": username},
                        ))
        except Exception:
            pass
        return hits

    # ── Tool runners (subprocess) ───────────────────────────────────

    def _run_sherlock(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run Sherlock: sherlock username --print-found --timeout 6"""
        hits: List[Dict[str, Any]] = []
        sherlock_path = self.config.hunt.workspace / "tools" / "sherlock"
        if not sherlock_path.exists():
            return hits
        for username in usernames[:10]:
            try:
                # Sherlock CLI: sherlock username --print-found
                result = subprocess.run(
                    [sys.executable, "-m", "sherlock_project.sherlock",
                     "--print-found", "--timeout", "6", username],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(sherlock_path),
                )
                for line in result.stdout.splitlines():
                    # Sherlock output format: "Platform: https://url"
                    if ":" in line and "https://" in line:
                        parts = line.split(":", 1)
                        platform = parts[0].strip()
                        url = parts[1].strip()
                        if url.startswith("http"):
                            hits.append(self._make_hit(
                                platform=platform, url=url,
                                confidence=self._confidence(platform),
                            ))
            except Exception:
                pass
        return hits

    def _run_maigret(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run Maigret: maigret username --timeout 30 --top-sites 500 --json ndjson"""
        hits: List[Dict[str, Any]] = []
        maigret_path = self.config.hunt.workspace / "tools" / "maigret"
        if not maigret_path.exists():
            return hits
        for username in usernames[:5]:
            try:
                # Maigret CLI: maigret username --timeout 30 --top-sites 500 --json ndjson
                out_file = self.config.hunt.workspace / "data" / f"maigret_{username}.json"
                out_file.parent.mkdir(parents=True, exist_ok=True)
                result = subprocess.run(
                    [sys.executable, "-m", "maigret",
                     "--timeout", "30", "--top-sites", "500",
                     "--json", "ndjson", "-o", str(out_file), username],
                    capture_output=True, text=True, timeout=300,
                    cwd=str(maigret_path),
                )
                if out_file.exists():
                    with open(out_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                item = json.loads(line)
                                url = item.get("url", "")
                                if url:
                                    site = item.get("site", "maigret")
                                    status = item.get("status", "")
                                    if status in ("Claimed", "Found", "Exists"):
                                        hits.append(self._make_hit(
                                            platform=site, url=url,
                                            confidence=self._confidence(site),
                                        ))
                            except json.JSONDecodeError:
                                pass
                    out_file.unlink(missing_ok=True)
            except Exception:
                pass
        return hits

    def _run_nexfil(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run Nexfil: nexfil -u username"""
        hits: List[Dict[str, Any]] = []
        nexfil_path = self.config.hunt.workspace / "tools" / "nexfil"
        if not nexfil_path.exists():
            return hits
        for username in usernames[:5]:
            try:
                # Nexfil CLI: nexfil -u username -t 10
                result = subprocess.run(
                    [sys.executable, "nexfil.py", "-u", username, "-t", "10"],
                    capture_output=True, text=True, timeout=90,
                    cwd=str(nexfil_path),
                )
                for line in result.stdout.splitlines():
                    # Nexfil output: [+] Platform: https://url
                    if "[+]" in line or "https://" in line:
                        hits.append(self._make_hit(
                            platform="nexfil", url=line.strip(),
                            confidence="MEDIUM", data={"username": username},
                        ))
            except Exception:
                pass

        return hits

    def _run_blackbird(self, usernames: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        bb_path = self.config.hunt.workspace / "tools" / "blackbird"
        if not bb_path.exists():
            return hits
        for username in usernames[:5]:
            try:
                result = subprocess.run(
                    [sys.executable, "blackbird.py", "-u", username, "--json"],
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
                                platform=site, url=url,
                                confidence=self._confidence(site),
                            ))
                    except json.JSONDecodeError:
                        if "https://" in line:
                            hits.append(self._make_hit(
                                platform="blackbird", url=line.strip(),
                                confidence="MEDIUM",
                            ))
            except Exception:
                pass
        return hits

    # ── Main scan entry point ───────────────────────────────────────

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []

        # WhatsMyName concurrent probes
        sites = self._load_wmn()
        for username in usernames:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(self._probe_wmn_site, site, username): site
                    for site in sites[:300]
                }
                for future in as_completed(futures):
                    try:
                        hit = future.result()
                        if hit:
                            all_hits.append(hit)
                    except Exception:
                        pass

        # Direct platform probes
        for username in usernames:
            all_hits.extend(self._direct_probers(username))
            all_hits.extend(self._github_commit_emails(username))
            all_hits.extend(self._roblox_probe(username))

        # External tools
        try:
            all_hits.extend(self._run_sherlock(usernames))
        except Exception:
            pass
        try:
            all_hits.extend(self._run_maigret(usernames))
        except Exception:
            pass
        try:
            all_hits.extend(self._run_nexfil(usernames))
        except Exception:
            pass
        try:
            all_hits.extend(self._run_blackbird(usernames))
        except Exception:
            pass

        return all_hits
