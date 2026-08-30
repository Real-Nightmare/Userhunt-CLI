"""
URL scanner — Photon spider, Wayback availability check.
"""
import subprocess
import sys
from typing import Any, Dict, List

import requests

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class URLScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "url_scanner"
        self.description = "URL reconnaissance: Photon spider, Wayback availability"
        self.status = "BEST-EFFORT"

    # ── Wayback availability ────────────────────────────────────────

    def _wayback_availability(self, url: str) -> List[Dict[str, Any]]:
        """Check Wayback Machine for archived versions of a URL."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://archive.org/wayback/available?url={url}",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                snapshot = data.get("archived_snapshots", {}).get("closest")
                if snapshot:
                    hits.append(self._make_hit(
                        platform="wayback",
                        url=snapshot.get("url", ""),
                        confidence="LOW",
                        data={
                            "original_url": url,
                            "timestamp": snapshot.get("timestamp", ""),
                            "status": snapshot.get("status", ""),
                        },
                    ))
        except Exception:
            pass
        return hits

    # ── Photon spider ───────────────────────────────────────────────

    def _photon(self, url: str) -> List[Dict[str, Any]]:
        """Run Photon: python photon.py -u url -o output"""
        hits: List[Dict[str, Any]] = []
        photon_path = self.config.hunt.workspace / "tools" / "Photon"
        if not photon_path.exists():
            return hits
        try:
            # Photon CLI: python photon.py -u https://example.com -o /path/to/output
            out_dir = self.config.hunt.workspace / "data" / f"photon_{hash(url)}"
            out_dir.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [sys.executable, "photon.py", "-u", url, "-o", str(out_dir)],
                capture_output=True, text=True, timeout=180,
                cwd=str(photon_path),
            )
            # Photon saves results to output directory
            found_urls = []
            for f in out_dir.glob("*"):
                if f.is_file():
                    try:
                        with open(f, "r") as fp:
                            for line in fp:
                                line = line.strip()
                                if line.startswith("http"):
                                    found_urls.append(line)
                    except Exception:
                        pass
            # Also check stdout
            stdout_urls = [l.strip() for l in result.stdout.splitlines() if l.strip().startswith("http")]
            found_urls.extend(stdout_urls)
            # Cleanup
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)
            if found_urls:
                hits.append(self._make_hit(
                    platform="Photon", url=f"photon://{url}",
                    confidence="LOW",
                    data={"found_urls": list(dict.fromkeys(found_urls))[:50]},
                ))
        except Exception:
            pass
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of URLs."""
        all_hits: List[Dict[str, Any]] = []
        for url in urls[:20]:
            all_hits.extend(self._wayback_availability(url))
            all_hits.extend(self._photon(url))

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
        url_like = [c for c in clues if c.startswith("http")]
        return self.scan_urls(url_like)

    # Compatibility
    def scan_usernames(self, usernames: List[str]) -> List[Dict[str, Any]]:
        return []

    def scan_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        return []
