"""
Confidence engine — rates hits HIGH/MEDIUM/LOW and applies consistency checks.
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
    PARKED_RE = re.compile(r'domain\s+(?:is\s+)?(?:for\s+sale|parked|buy\s+this\s+domain)', re.I)
    DEAD_RE = re.compile(r'(404|not\s+found|doesn\'t\s+exist|no\s+results?|user\s+not\s+found)', re.I)

    def score(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        platform_names: Dict[str, List[str]] = defaultdict(list)
        platform_bios: Dict[str, List[str]] = defaultdict(list)
        for hit in hits:
            platform = hit.get("platform", "").lower().replace(" ", "").replace("-", "")
            dn = hit.get("display_name", "")
            bio = hit.get("bio", "")
            if dn:
                platform_names[platform].append(dn)
            if bio:
                platform_bios[platform].append(bio)
        for hit in hits:
            conf = hit.get("confidence", "MEDIUM")
            platform = hit.get("platform", "").lower().replace(" ", "").replace("-", "")
            url = hit.get("url", "").lower()
            if self.PARKED_RE.search(url) or self.PARKED_RE.search(hit.get("bio", "")):
                hit["confidence"] = "LOW"
                hit["verdict"] = "verify_false"
                continue
            if self.DEAD_RE.search(hit.get("bio", "")) or self.DEAD_RE.search(hit.get("display_name", "")):
                hit["confidence"] = "LOW"
                hit["verdict"] = "verify_false"
                continue
            if conf != "HIGH":
                for hp in self.HIGH_PLATFORMS:
                    if hp in platform:
                        hit["confidence"] = "HIGH"
                        break
            names = platform_names.get(platform, [])
            if len(names) >= 2:
                if len(set(names)) == 1:
                    if hit.get("confidence") != "HIGH":
                        hit["confidence"] = "HIGH"
                    hit["notes"] = hit.get("notes", []) + ["identity consistent"]
                else:
                    hit["notes"] = hit.get("notes", []) + ["identity conflict"]
                    if hit.get("confidence") == "HIGH":
                        hit["confidence"] = "MEDIUM"
        seen = set()
        deduped = []
        for hit in hits:
            key = (hit.get("platform", "").lower(), hit.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(hit)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        deduped.sort(key=lambda h: order.get(h.get("confidence", "MEDIUM"), 1))
        return deduped
