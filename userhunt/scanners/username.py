"""
Username scanner — Sherlock, Maigret, Nexfil, Blackbird, WhatsMyName, direct probers.
ALL tools configured to MAXIMUM power — full database, no limits.
"""
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.utils.runner import run_tool_simple, run_tool_with_fallback
from userhunt.web.store import store


# Platforms that count as HIGH confidence
HIGH_PLATFORMS = {
    "github", "reddit", "steam", "x", "twitter", "tiktok",
    "instagram", "roblox", "snapchat", "twitch", "youtube",
}


class UsernameScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "username_scanner"
        self.description = "Username enumeration across ALL sites (Sherlock, Maigret, Nexfil, Blackbird, WMN, direct probes) — MAXIMUM power"
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

    # ── WhatsMyName runner (ALL sites, max workers) ─────────────────

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

    # ── Direct platform probers (ALL platforms) ─────────────────────

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
            ("DeviantArt", f"https://www.deviantart.com/{username}", lambda r: r.status_code == 200),
            ("Flickr", f"https://www.flickr.com/people/{username}/", lambda r: r.status_code == 200),
            ("Gravatar", f"https://en.gravatar.com/{username}", lambda r: r.status_code == 200),
            ("Medium", f"https://medium.com/@{username}", lambda r: r.status_code == 200),
            ("Patreon", f"https://www.patreon.com/{username}", lambda r: r.status_code == 200),
            ("SoundCloud", f"https://soundcloud.com/{username}", lambda r: r.status_code == 200),
            ("Substack", f"https://{username}.substack.com", lambda r: r.status_code == 200),
            ("Vimeo", f"https://vimeo.com/{username}", lambda r: r.status_code == 200),
            ("GitBook", f"https://{username}.gitbook.io", lambda r: r.status_code == 200),
            ("npm", f"https://www.npmjs.com/~{username}", lambda r: r.status_code == 200),
            ("PyPI", f"https://pypi.org/user/{username}/", lambda r: r.status_code == 200),
            ("DockerHub", f"https://hub.docker.com/u/{username}", lambda r: r.status_code == 200),
            ("Keybase", f"https://keybase.io/{username}", lambda r: r.status_code == 200),
            ("About.me", f"https://about.me/{username}", lambda r: r.status_code == 200),
            ("Linktree", f"https://linktr.ee/{username}", lambda r: r.status_code == 200),
            ("Replit", f"https://replit.com/@{username}", lambda r: r.status_code == 200),
            ("HackerRank", f"https://www.hackerrank.com/{username}", lambda r: r.status_code == 200),
            ("LeetCode", f"https://leetcode.com/{username}", lambda r: r.status_code == 200),
            ("Bitbucket", f"https://bitbucket.org/{username}/", lambda r: r.status_code == 200),
            ("Gitea", f"https://gitea.com/{username}", lambda r: r.status_code == 200),
        ]
        headers = {"User-Agent": "Mozilla/5.0"}
        for platform, url, check in probers:
            try:
                resp = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
                if check(resp):
                    conf = "HIGH" if platform.lower() in HIGH_PLATFORMS else "MEDIUM"
                    hit = self._make_hit(
                        platform=platform, url=url, confidence=conf,
                        status_code=resp.status_code,
                    )
                    hits.append(hit)
                    store.add_hit(hit)
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
                    hit = self._make_hit(
                        platform="github_commit",
                        url=f"github_events:{username}",
                        confidence="MEDIUM",
                        emails=[email],
                        data={"username": username},
                    )
                    hits.append(hit)
                    store.add_hit(hit)
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
                        hit = self._make_hit(
                            platform="roblox",
                            url=f"https://www.roblox.com/users/{uid}/profile",
                            confidence="HIGH",
                            display_name=user.get("displayName", ""),
                            data={"roblox_id": uid, "username": username},
                        )
                        hits.append(hit)
                        store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── Tool runners — ALL AT MAXIMUM POWER ─────────────────────────

    def _run_sherlock(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """
        SHERLOCK — MAXIMUM with fallback commands:
        1. python -m sherlock_project.sherlock (module)
        2. python sherlock/sherlock.py (direct script)
        --print-found --timeout 60 --nsfw --ignore-exclusions --local
        """
        hits: List[Dict[str, Any]] = []
        sherlock_path = self.config.hunt.workspace / "tools" / "sherlock"
        if not sherlock_path.exists():
            store.log("Sherlock not found — skipping", level="warn", source="sherlock")
            return hits
        for username in usernames[:10]:
            store.log(f"Running Sherlock (MAX) for: {username}", source="sherlock")
            args = ["--print-found", "--timeout", "300", "--nsfw",
                    "--ignore-exclusions", "--local", username]
            stdout, stderr, rc = run_tool_with_fallback(
                tool_name="sherlock",
                cwd=str(sherlock_path),
                timeout=self.config.hunt.tool_timeout,
                primary=[sys.executable, "-m", "sherlock_project.sherlock"] + args,
                fallbacks=[
                    [sys.executable, "sherlock_project/sherlock.py"] + args,
                    [sys.executable, "-m", "sherlock"] + args,
                ],
            )
            for line in stdout.splitlines():
                if ":" in line and "https://" in line:
                    parts = line.split(":", 1)
                    platform = parts[0].strip()
                    url = parts[1].strip()
                    if url.startswith("http"):
                        hit = self._make_hit(
                            platform=platform, url=url,
                            confidence=self._confidence(platform),
                        )
                        hits.append(hit)
                        store.add_hit(hit)
            if stderr.strip():
                for line in stderr.splitlines()[:20]:
                    store.tool_log("sherlock", line, direction="stderr")
        return hits

    def _run_maigret(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """
        MAIGRET — MAXIMUM with fallback commands:
        1. python -m maigret (module)
        2. python maigret/__main__.py (direct script)
        --timeout 60 -n 500 --enrich --permute --with-domains
        NO --top-sites = SEARCH ALL SITES
        """
        hits: List[Dict[str, Any]] = []
        maigret_path = self.config.hunt.workspace / "tools" / "maigret"
        if not maigret_path.exists():
            store.log("Maigret not found — skipping", level="warn", source="maigret")
            return hits
        for username in usernames[:5]:
            store.log(f"Running Maigret (MAX - ALL SITES) for: {username}", source="maigret")
            out_file = self.config.hunt.workspace / "data" / f"maigret_{username}.json"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            args = ["--timeout", "60", "-n", "2550", "--enrich", "--permute",
                    "--with-domains", "--json", "ndjson", "-o", str(out_file), username]
            stdout, stderr, rc = run_tool_with_fallback(
                tool_name="maigret",
                cwd=str(maigret_path),
                timeout=self.config.hunt.tool_timeout,
                primary=[sys.executable, "-m", "maigret"] + args,
                fallbacks=[
                    [sys.executable, "maigret/__main__.py"] + args,
                    [sys.executable, "-m", "maigret.__main__"] + args,
                ],
            )
            # Parse ndjson output file
            if out_file.exists():
                try:
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
                                        hit = self._make_hit(
                                            platform=site, url=url,
                                            confidence=self._confidence(site),
                                        )
                                        hits.append(hit)
                                        store.add_hit(hit)
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
                out_file.unlink(missing_ok=True)
            # Also parse stdout for hits
            for line in stdout.splitlines():
                try:
                    item = json.loads(line)
                    url = item.get("url", "")
                    if url:
                        site = item.get("site", "maigret")
                        status = item.get("status", "")
                        if status in ("Claimed", "Found", "Exists"):
                            hit = self._make_hit(
                                platform=site, url=url,
                                confidence=self._confidence(site),
                            )
                            hits.append(hit)
                            store.add_hit(hit)
                except json.JSONDecodeError:
                    pass
            if stderr.strip():
                for line in stderr.splitlines()[:20]:
                    store.tool_log("maigret", line, direction="stderr")
        return hits

    def _run_nexfil(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """
        NEXFIL — MAXIMUM with fallback commands:
        1. python nexfil.py (direct script)
        2. python -m nexfil (module)
        -u USERNAME -t 30
        """
        hits: List[Dict[str, Any]] = []
        nexfil_path = self.config.hunt.workspace / "tools" / "nexfil"
        if not nexfil_path.exists():
            store.log("Nexfil not found — skipping", level="warn", source="nexfil")
            return hits
        for username in usernames[:5]:
            store.log(f"Running Nexfil (MAX) for: {username}", source="nexfil")
            args = ["-u", username, "-t", "30"]
            stdout, stderr, rc = run_tool_with_fallback(
                tool_name="nexfil",
                cwd=str(nexfil_path),
                timeout=self.config.hunt.tool_timeout,
                primary=[sys.executable, "nexfil.py"] + args,
                fallbacks=[
                    [sys.executable, "-m", "nexfil"] + args,
                    [sys.executable, "nexfil/nexfil.py"] + args,
                ],
            )
            for line in stdout.splitlines():
                if "[+]" in line or "https://" in line:
                    urls = re.findall(r'https?://[^\s]+', line)
                    for url in urls:
                        hit = self._make_hit(
                            platform="nexfil", url=url.strip(),
                            confidence="MEDIUM", data={"username": username},
                        )
                        hits.append(hit)
                        store.add_hit(hit)
            if stderr.strip():
                for line in stderr.splitlines()[:10]:
                    store.tool_log("nexfil", line, direction="stderr")
        return hits

    def _run_blackbird(self, usernames: List[str]) -> List[Dict[str, Any]]:
        """
        BLACKBIRD — MAXIMUM with fallback commands:
        1. python blackbird.py (direct script)
        2. python -m blackbird (module)
        -u USERNAME --json
        """
        hits: List[Dict[str, Any]] = []
        bb_path = self.config.hunt.workspace / "tools" / "blackbird"
        if not bb_path.exists():
            store.log("Blackbird not found — skipping", level="warn", source="blackbird")
            return hits
        for username in usernames[:5]:
            store.log(f"Running Blackbird (MAX) for: {username}", source="blackbird")
            args = ["-u", username, "--json"]
            stdout, stderr, rc = run_tool_with_fallback(
                tool_name="blackbird",
                cwd=str(bb_path),
                timeout=self.config.hunt.tool_timeout,
                primary=[sys.executable, "blackbird.py"] + args,
                fallbacks=[
                    [sys.executable, "-m", "blackbird"] + args,
                    [sys.executable, "blackbird/blackbird.py"] + args,
                ],
            )
            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    site = data.get("site", "blackbird")
                    if url and data.get("status") == "FOUND":
                        hit = self._make_hit(
                            platform=site, url=url,
                            confidence=self._confidence(site),
                        )
                        hits.append(hit)
                        store.add_hit(hit)
                except json.JSONDecodeError:
                    if "https://" in line:
                        urls = re.findall(r'https?://[^\s]+', line)
                        for url in urls:
                            hit = self._make_hit(
                                platform="blackbird", url=url.strip(),
                                confidence="MEDIUM",
                            )
                            hits.append(hit)
                            store.add_hit(hit)
            if stderr.strip():
                for line in stderr.splitlines()[:10]:
                    store.tool_log("blackbird", line, direction="stderr")
        return hits

    # ── Main scan entry point ───────────────────────────────────────

    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []

        # WhatsMyName — ALL sites, max workers
        sites = self._load_wmn()
        if sites:
            store.log(f"WhatsMyName: probing ALL {len(sites)} sites per username (max power)", source="wmn")
            for username in usernames:
                with ThreadPoolExecutor(max_workers=50) as executor:
                    # NO LIMIT — probe ALL sites
                    futures = {
                        executor.submit(self._probe_wmn_site, site, username): site
                        for site in sites  # ALL sites, not just 300
                    }
                    wmn_hits = 0
                    for future in as_completed(futures):
                        try:
                            hit = future.result()
                            if hit:
                                all_hits.append(hit)
                                store.add_hit(hit)
                                wmn_hits += 1
                        except Exception:
                            pass
                    store.update_scan_stats({"wmn_hits": wmn_hits})

        # Direct platform probes — ALL platforms
        for username in usernames:
            store.log(f"Direct probing ALL platforms: {username}", source="direct")
            all_hits.extend(self._direct_probers(username))
            all_hits.extend(self._github_commit_emails(username))
            all_hits.extend(self._roblox_probe(username))

        # External tools — ALL at maximum
        try:
            all_hits.extend(self._run_sherlock(usernames))
        except Exception as e:
            store.log(f"Sherlock error: {e}", level="error", source="sherlock")
        try:
            all_hits.extend(self._run_maigret(usernames))
        except Exception as e:
            store.log(f"Maigret error: {e}", level="error", source="maigret")
        try:
            all_hits.extend(self._run_nexfil(usernames))
        except Exception as e:
            store.log(f"Nexfil error: {e}", level="error", source="nexfil")
        try:
            all_hits.extend(self._run_blackbird(usernames))
        except Exception as e:
            store.log(f"Blackbird error: {e}", level="error", source="blackbird")

        store.log(f"Username scan complete: {len(all_hits)} total hits (MAXIMUM power)", source="username_scanner")
        return all_hits
