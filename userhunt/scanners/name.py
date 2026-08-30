"""
Name scanner — generates username permutations from full names,
validates name-to-email via Gravatar, queries Wikipedia and HackerNews.
"""
import hashlib
import itertools
import re
from typing import Any, Dict, List

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class NameScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "name_scanner"
        self.description = "Name→username permutations, Wikipedia, HN, Gravatar email validation"
        self.status = "CORE"

    # ── Username permutations ───────────────────────────────────────

    def _username_permutations(self, full_name: str) -> List[str]:
        """Generate username permutations from a full name."""
        parts = full_name.strip().split()
        if len(parts) < 2:
            # Single word — just return it
            return [parts[0].lower()] if parts else []

        first = parts[0].lower()
        last = parts[-1].lower()
        fi = first[0] if first else ""

        perms: List[str] = []
        # Common patterns
        perms.extend([
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{fi}{last}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{last}_{first}",
            f"{last}{fi}",
            f"{first}{last[0] if last else ''}",
            f"{fi}{last[0] if last else ''}",
        ])
        # With numbers
        perms.extend([
            f"{first}{last}01",
            f"{first}.{last}01",
            f"{fi}{last}01",
        ])
        # 3+ part names
        if len(parts) > 2:
            middle = parts[1].lower()
            perms.extend([
                f"{first}{middle}{last}",
                f"{fi}{middle}{last}",
                f"{first}.{last}",
            ])

        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for p in perms:
            # Only valid username chars
            cleaned = re.sub(r'[^a-z0-9._-]', '', p)
            if cleaned and cleaned not in seen and len(cleaned) >= 3:
                seen.add(cleaned)
                unique.append(cleaned)
        return unique[:30]

    # ── Name → email permutations via Gravatar ──────────────────────

    def _name_to_emails(self, full_name: str) -> List[Dict[str, Any]]:
        """Generate email permutations and validate via Gravatar."""
        hits: List[Dict[str, Any]] = []
        parts = full_name.strip().split()
        if len(parts) < 2:
            return hits

        first = parts[0].lower()
        last = parts[-1].lower()
        fi = first[0] if first else ""

        # Common email patterns
        email_templates = [
            "{first}.{last}", "{first}_{last}", "{first}{last}",
            "{fi}{last}", "{first}.{last}01", "{first}{last}01",
        ]
        # Common domains to try
        domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

        for template in email_templates:
            local = template.format(first=first, last=last, fi=fi)
            for domain in domains:
                email = f"{local}@{domain}"
                try:
                    md5_hash = hashlib.md5(email.encode()).hexdigest()
                    resp = requests.get(
                        f"https://www.gravatar.com/avatar/{md5_hash}?d=404",
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        hits.append(self._make_hit(
                            platform="gravatar_email",
                            url=f"gravatar://{email}",
                            confidence="MEDIUM",
                            emails=[email],
                            data={"name": full_name, "method": "email_permutation"},
                        ))
                except Exception:
                    pass
        return hits

    # ── Wikipedia opensearch ────────────────────────────────────────

    def _wikipedia(self, full_name: str) -> List[Dict[str, Any]]:
        """Search Wikipedia for pages matching the name."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                "https://en.wikipedia.org/w/api.php",
                params={
                    "action": "opensearch",
                    "search": full_name,
                    "limit": 5,
                    "format": "json",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if len(data) >= 4:
                    titles = data[1]
                    urls = data[3]
                    for title, url in zip(titles, urls):
                        if full_name.lower() in title.lower():
                            hits.append(self._make_hit(
                                platform="wikipedia", url=url,
                                confidence="LOW",
                                data={"title": title, "query": full_name},
                            ))
        except Exception:
            pass
        return hits

    # ── HackerNews Algolia ──────────────────────────────────────────

    def _hackernews(self, full_name: str) -> List[Dict[str, Any]]:
        """Search HackerNews via Algolia API for the name."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                "https://hn.algolia.com/api/v1/search",
                params={"query": full_name, "tags": "author_profile", "hitsPerPage": 5},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                for hit in data.get("hits", []):
                    username = hit.get("author", "")
                    if username:
                        hits.append(self._make_hit(
                            platform="hackernews",
                            url=f"https://news.ycombinator.com/user?id={username}",
                            confidence="LOW",
                            data={"hn_username": username, "query": full_name},
                        ))
        except Exception:
            pass
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_names(self, names: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of full names."""
        all_hits: List[Dict[str, Any]] = []
        for full_name in names[:50]:
            # Generate username permutations (returned as hits)
            perms = self._username_permutations(full_name)
            for perm in perms:
                all_hits.append(self._make_hit(
                    platform="name_permutation",
                    url=f"perm://{perm}",
                    confidence="LOW",
                    data={"permutation": perm, "source_name": full_name},
                ))

            # Name → email validation
            all_hits.extend(self._name_to_emails(full_name))

            # Wikipedia
            all_hits.extend(self._wikipedia(full_name))

            # HackerNews
            all_hits.extend(self._hackernews(full_name))

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
        """Treat multi-word clues as names."""
        names = [c for c in clues if " " in c and len(c) > 3]
        return self.scan_names(names)

    # For compatibility with ScanManager
    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        return []

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        return []
