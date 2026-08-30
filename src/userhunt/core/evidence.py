"""
Evidence collector — visits HIGH/MEDIUM hits and extracts profile data.
- No timeout for previously visited/cached pages
- Playwright fallback for JS-rendered pages
- Extracts images for AI profile inclusion
"""
import re
from typing import Any, Dict, List, Optional
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
        self.visited: set[str] = set()
        self._page_cache: Dict[str, Dict[str, Any]] = {}
        self._playwright_available: Optional[bool] = None

    def _is_playwright_available(self) -> bool:
        """Lazily check if Playwright is installed."""
        if self._playwright_available is not None:
            return self._playwright_available
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            self._playwright_available = True
        except ImportError:
            self._playwright_available = False
        return self._playwright_available

    def visit_links(self, hits: List[Dict[str, Any]], round_num: int) -> None:
        """Visit HIGH/MEDIUM hit URLs, extract profile evidence."""
        cap = self.config.hunt.link_visit_cap
        visited_count = 0

        for hit in hits:
            if visited_count >= cap:
                break
            url = hit.get("url", "")
            if not url:
                continue

            # Use cache for previously visited pages (no timeout needed)
            if url in self._page_cache:
                evidence = self._page_cache[url]
                self._apply_evidence(hit, evidence, round_num)
                continue

            if url in self.visited:
                continue

            conf = hit.get("confidence", "MEDIUM")
            if conf not in ("HIGH", "MEDIUM"):
                continue

            self.visited.add(url)
            visited_count += 1

            # Try requests first (with reasonable timeout)
            evidence = self._fetch_page_requests(url)

            # Fallback to Playwright if requests got nothing useful
            if not evidence or (not evidence.get("display_name") and not evidence.get("bio")):
                pw_evidence = self._fetch_page_playwright(url)
                if pw_evidence:
                    evidence = pw_evidence

            if evidence:
                self._page_cache[url] = evidence
                self._apply_evidence(hit, evidence, round_num)

    def _apply_evidence(
        self, hit: Dict[str, Any], evidence: Dict[str, Any], round_num: int
    ) -> None:
        """Apply extracted evidence data to a hit dict."""
        evidence["round"] = round_num
        evidence["source_hit"] = hit
        hit["profile_evidence"] = evidence
        if evidence.get("display_name"):
            hit["display_name"] = evidence["display_name"]
        if evidence.get("bio"):
            hit["bio"] = evidence["bio"]
        if evidence.get("avatar_url"):
            hit["avatar_url"] = evidence["avatar_url"]
        if evidence.get("images"):
            hit["images"] = evidence["images"]
        if evidence.get("emails"):
            hit["emails_found"] = evidence["emails"]
        if evidence.get("other_socials"):
            hit["other_socials"] = evidence["other_socials"]

    def _fetch_page_requests(self, url: str) -> Dict[str, Any]:
        """Fetch page via requests (standard HTTP, with timeout)."""
        try:
            resp = requests.get(
                url,
                timeout=20,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            if resp.status_code != 200:
                return {}
            return self._parse_html(resp.text, url)
        except Exception:
            return {}

    def _fetch_page_playwright(self, url: str) -> Dict[str, Any]:
        """Fetch page via Playwright (headless Chromium, no short timeout)."""
        if not self._is_playwright_available():
            return {}
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                )
                page = context.new_page()
                # Generous timeout for JS-rendered pages
                page.goto(url, timeout=45000, wait_until="domcontentloaded")
                page.wait_for_timeout(3000)  # let JS render
                html = page.content()
                browser.close()
                return self._parse_html(html, url)
        except Exception:
            return {}

    def _parse_html(self, html: str, url: str) -> Dict[str, Any]:
        """Parse HTML and extract profile evidence including images."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return {}

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        og_title = self._meta_content(soup, "og:title")
        og_desc = self._meta_content(soup, "og:description")
        meta_desc = ""
        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag:
            meta_desc = desc_tag.get("content", "") or ""

        bio = og_desc or meta_desc or ""
        display_name = og_title or title

        # Avatar / profile image
        avatar = ""
        og_img = soup.find("meta", property="og:image")
        if og_img:
            avatar = og_img.get("content", "")

        # Collect ALL images (for AI face/profile detection)
        images: List[str] = []
        if avatar:
            images.append(avatar)
        for img in soup.find_all("img", src=True):
            src = img["src"]
            if src and src.startswith("http") and src not in images:
                images.append(src)
            if len(images) >= 10:
                break

        # Emails visible on page
        text = soup.get_text(separator=" ")
        emails = list(set(re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text
        )))[:10]

        # Social links
        socials: List[str] = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            domain = urlparse(href).netloc.lower()
            for sd in self.SOCIAL_DOMAINS:
                if sd in domain:
                    socials.append(href)
                    break
            if len(socials) >= 20:
                break
        socials = list(dict.fromkeys(socials))

        return {
            "url": url,
            "display_name": (display_name or "")[:200],
            "bio": (bio or "")[:500],
            "avatar_url": avatar,
            "images": images,
            "emails": emails,
            "other_socials": socials,
        }

    @staticmethod
    def _meta_content(soup: BeautifulSoup, prop: str) -> str:
        tag = soup.find("meta", property=prop)
        if tag and tag.get("content"):
            return tag["content"]
        return ""
