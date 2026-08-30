"""
Confidence engine — rates hits HIGH/MEDIUM/LOW and applies consistency checks.
Never lowers a verified HIGH.
"""
import re
from typing import List, Dict, Any
from collections import defaultdict


class ConfidenceEngine:
    HIGH_PLATFORMS = {
        "snapchat", "tiktok", "twitter", "x", "youtube", "github",
        "instagram", "roblox", "discord", "twitch", "reddit", "steam",
        "linkedin", "spotify", "keybase", "chess", "bluesky",
    }
    LOW_PLATFORMS = {
        "aniworld", "wowhead", "nitrotype", "sketchfab", "smule", "xbox",
    }
    PARKED_RE = re.compile(
        r'domain\s+(?:is\s+)?(?:for\s+sale|parked|buy\s+this\s+domain)', re.I
    )
    DEAD_RE = re.compile(
        r'(404|not\s+found|doesn\'t\s+exist|no\s+results?|user\s+not\s+found)',
        re.I,
    )

    def score(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score, deduplicate, and sort hits by confidence."""
        # Build per-platform display name maps for consistency checks
        platform_names: Dict[str, List[str]] = defaultdict(list)
        for hit in hits:
            platform = self._normalize_platform(hit.get("platform", ""))
            dn = hit.get("display_name", "")
            if dn:
                platform_names[platform].append(dn)

        for hit in hits:
            platform = self._normalize_platform(hit.get("platform", ""))
            url = hit.get("url", "").lower()
            bio = hit.get("bio", "")
            display_name = hit.get("display_name", "")
            if "confidence" not in hit:
                hit["confidence"] = "MEDIUM"
            is_verified_high = hit.get("confidence") == "HIGH"

            # ── Parked / dead page → LOW ──
            if self.PARKED_RE.search(url) or self.PARKED_RE.search(bio):
                hit["confidence"] = "LOW"
                hit["verdict"] = "verify_false"
                continue
            if self.DEAD_RE.search(bio) or self.DEAD_RE.search(display_name):
                hit["confidence"] = "LOW"
                hit["verdict"] = "verify_false"
                continue

            # ── HIGH platform upgrade (only if not already HIGH) ──
            if hit.get("confidence") != "HIGH":
                for hp in self.HIGH_PLATFORMS:
                    if hp in platform:
                        hit["confidence"] = "HIGH"
                        break

            # ── LOW platform downgrade (only if not verified HIGH) ──
            if not is_verified_high:
                for lp in self.LOW_PLATFORMS:
                    if lp in platform:
                        hit["confidence"] = "LOW"
                        break

            # ── Consistency check ──
            names = platform_names.get(platform, [])
            if len(names) >= 2:
                unique_names = set(names)
                if len(unique_names) == 1:
                    # All matches use same display name → raise confidence
                    if hit.get("confidence") != "HIGH":
                        hit["confidence"] = "HIGH"
                        hit["notes"] = hit.get("notes", []) + [
                            "identity consistent"
                        ]
                else:
                    hit["notes"] = hit.get("notes", []) + ["identity conflict"]
                    # NEVER lower a verified HIGH
                    if hit.get("confidence") == "HIGH" and not is_verified_high:
                        hit["confidence"] = "MEDIUM"

        # ── Deduplication by (platform, url, query) ──
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for hit in hits:
            key = (
                hit.get("platform", "").lower(),
                hit.get("url", ""),
                hit.get("query", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(hit)

        # ── Sort: HIGH → MEDIUM → LOW ──
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        deduped.sort(key=lambda h: order.get(h.get("confidence", "MEDIUM"), 1))

        return deduped

    @staticmethod
    def _normalize_platform(platform: str) -> str:
        return platform.lower().replace(" ", "").replace("-", "")
