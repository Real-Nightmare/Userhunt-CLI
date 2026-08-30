"""
Domain scanner — WHOIS, RDAP, DNS, crt.sh, Wayback, Sublist3r, theHarvester, waymore.
"""
import os
import sys
import json
import subprocess
import socket
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests
import dns.resolver

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class DomainScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "domain_scanner"
        self.description = "Domain reconnaissance and subdomain enumeration"
        self.status = "CORE"

    def _whois(self, domain: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            import whois as whois_mod
            data = whois_mod.whois(domain)
            hits.append(self._make_hit(platform="whois", url=f"whois://{domain}", confidence="MEDIUM", data=str(data)))
        except Exception:
            pass
        return hits

    def _dns(self, domain: str) -> List[Dict[str, Any]]:
        hits = []
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                vals = [str(r) for r in answers]
                hits.append(self._make_hit(platform=f"dns_{rtype.lower()}", url=f"dns://{domain}/{rtype}",
                                           confidence="MEDIUM", data={"type": rtype, "records": vals}))
            except Exception:
                pass
        return hits

    def _crt_sh(self, domain: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            resp = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                subdomains = list({entry.get("common_name", "") for entry in data[:100] if entry.get("common_name")})
                hits.append(self._make_hit(platform="crt_sh", url=f"https://crt.sh/?q={domain}",
                                           confidence="MEDIUM", subdomains=subdomains[:50]))
        except Exception:
            pass
        return hits

    def _wayback(self, domain: str) -> List[Dict[str, Any]]:
        hits = []
        try:
            resp = requests.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50",
                                timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                urls = [row[2] for row in data[1:51] if len(row) > 2]
                hits.append(self._make_hit(platform="wayback", url=f"http://web.archive.org/web/*/{domain}",
                                           confidence="MEDIUM", urls=urls[:30]))
        except Exception:
            pass
        return hits

    def _sublist3r(self, domain: str) -> List[Dict[str, Any]]:
        hits = []
        sublist3r_path = self.config.hunt.workspace / "tools" / "Sublist3r"
        if not sublist3r_path.exists():
            return hits
        try:
            result = subprocess.run(
                [sys.executable, "-m", "sublist3r", "-d", domain, "-t", "50", "-o", "-"],
                capture_output=True, text=True, timeout=120, cwd=str(sublist3r_path)
            )
            subs = [line.strip() for line in result.stdout.splitlines() if line.strip() and "." in line]
            hits.append(self._make_hit(platform="sublist3r", url=f"sublist3r://{domain}",
                                       confidence="MEDIUM", subdomains=subs[:50]))
        except Exception:
            pass
        return hits

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        domain_like = [c for c in clues if "." in c and not c.startswith("http") and len(c) > 4]
        return self.scan_domains(domain_like)

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        all_hits = []
        for domain in domains[:20]:
            all_hits.extend(self._whois(domain))
            all_hits.extend(self._dns(domain))
            all_hits.extend(self._crt_sh(domain))
            all_hits.extend(self._wayback(domain))
            all_hits.extend(self._sublist3r(domain))
        seen = set()
        deduped = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
