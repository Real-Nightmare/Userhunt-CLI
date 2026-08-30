"""
Evidence collector — visits HIGH/MEDIUM hits and extracts profile data.
"""
import re
import json
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from userhunt.config import Config


class EvidenceCollector:
    SOCIAL_DOMAINS = {
        "instagram.com", "x.com", "twitter.com", "tiktok.com", "github.com",
        "youtube.com", "snapchat.com", "reddit.com", "spotify.com", "steam.com",
        "discord.gg", "t.me", "linktr.ee", "twitch.tv",
    }

    def __init__(self, config: Config):
        self.config = config
        self.visited: set = set()

    def visit_links(self, hits: List[Dict[str, Any]], round_num: int) -> None:
        cap = self.config.hunt.link_visit_cap
        visited = 0
        for hit in hits:
            if visited >= cap:
                break
            url = hit.get("url", "")
            if not url or url in self.visited:
                continue
            conf = hit.get("confidence", "MEDIUM")
            if conf not in ("HIGH", "MEDIUM"):
                continue
            self.visited.add(url)
            visited += 1
            evidence = self._fetch_page(url)
            if evidence:
                evidence["round"] = round_num
                evidence["source_hit"] = hit
                hit["profile_evidence"] = evidence
                hit["display_name"] = evidence.get("display_name", hit.get("display_name", ""))
                hit["bio"] = evidence.get("bio", hit.get("bio", ""))
                hit["avatar_url"] = evidence.get("avatar_url", "")
                hit["emails_found"] = evidence.get("emails", [])
                hit["other_socials"] = evidence.get("other_socials", [])

    def _fetch_page(self, url: str) -> Dict[str, Any]:
        try:
            resp = requests.get(url, timeout=20, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return {}
            text = resp.text
            soup = BeautifulSoup(text, "lxml")
            title = soup.title.string.strip() if soup.title else ""
            og_title = (soup.find("meta", property="og:title") or {}).get("content", "")
            og_desc = (soup.find("meta", property="og:description") or {}).get("content", "")
            meta_desc = (soup.find("meta", attrs={"name": "description"}) or {}).get("content", "")
            bio = og_desc or meta_desc or ""
            display_name = og_title or title
            avatar = ""
            og_img = soup.find("meta", property="og:image")
            if og_img:
                avatar = og_img.get("content", "")
            emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))[:10]
            socials = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                domain = urlparse(href).netloc.lower()
                for sd in self.SOCIAL_DOMAINS:
                    if sd in domain:
                        socials.append(href)
                        break
            socials = list(dict.fromkeys(socials))[:20]
            return {
                "url": url,
                "display_name": display_name[:200],
                "bio": bio[:500],
                "avatar_url": avatar,
                "emails": emails,
                "other_socials": socials,
            }
        except Exception:
            return {}
