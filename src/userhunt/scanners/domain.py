"""
Domain scanner — WHOIS, RDAP, DNS, crt.sh, Wayback, ip-api, Sublist3r,
FinalRecon, waymore, theHarvester, EmailHarvester, Infoga.
"""
import json
import subprocess
import sys
from typing import Any, Dict, List

import requests
import dns.resolver

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner


class DomainScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "domain_scanner"
        self.description = "Domain recon: WHOIS, RDAP, DNS, crt.sh, Wayback, Sublist3r, FinalRecon, waymore"
        self.status = "CORE"

    # ── WHOIS ───────────────────────────────────────────────────────

    def _whois(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            import whois as whois_mod
            data = whois_mod.whois(domain)
            hits.append(self._make_hit(
                platform="whois", url=f"whois://{domain}",
                confidence="MEDIUM", data=str(data)[:5000],
            ))
        except Exception:
            pass
        return hits

    # ── RDAP ────────────────────────────────────────────────────────

    def _rdap(self, domain: str) -> List[Dict[str, Any]]:
        """RDAP lookup via public rdap.org endpoint."""
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://rdap.org/domain/{domain}", timeout=20,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("ldhName", domain)
                events = data.get("events", [])
                registrar = ""
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcards = entity.get("vcardArray", [None, []])
                        if len(vcards) > 1:
                            for item in vcards[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                hits.append(self._make_hit(
                    platform="rdap", url=f"https://rdap.org/domain/{domain}",
                    confidence="MEDIUM",
                    data={"name": name, "registrar": registrar, "events": events[:5]},
                ))
        except Exception:
            pass
        return hits

    # ── DNS ─────────────────────────────────────────────────────────

    def _dns(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                vals = [str(r) for r in answers]
                hits.append(self._make_hit(
                    platform=f"dns_{rtype.lower()}", url=f"dns://{domain}/{rtype}",
                    confidence="MEDIUM", data={"type": rtype, "records": vals},
                ))
            except Exception:
                pass
        return hits

    # ── ip-api.com ──────────────────────────────────────────────────

    def _ip_api(self, domain: str) -> List[Dict[str, Any]]:
        """Resolve domain to IP, then query ip-api.com for geolocation."""
        hits: List[Dict[str, Any]] = []
        try:
            import socket
            ip = socket.gethostbyname(domain)
            resp = requests.get(
                f"http://ip-api.com/json/{ip}", timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                hits.append(self._make_hit(
                    platform="ip-api", url=f"ip-api://{ip}",
                    confidence="MEDIUM",
                    data={"ip": ip, "country": data.get("country"),
                          "city": data.get("city"), "isp": data.get("isp"),
                          "org": data.get("org"), "as": data.get("as")},
                ))
        except Exception:
            pass
        return hits

    # ── crt.sh ──────────────────────────────────────────────────────

    def _crt_sh(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q={domain}&output=json", timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                subdomains = list({
                    entry.get("common_name", "")
                    for entry in data[:200]
                    if entry.get("common_name")
                })
                hits.append(self._make_hit(
                    platform="crt.sh", url=f"https://crt.sh/?q={domain}",
                    confidence="MEDIUM", subdomains=subdomains[:100],
                ))
        except Exception:
            pass
        return hits

    # ── Wayback CDX ─────────────────────────────────────────────────

    def _wayback(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50",
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = [row[2] for row in data[1:51] if len(row) > 2]
                hits.append(self._make_hit(
                    platform="wayback",
                    url=f"http://web.archive.org/web/*/{domain}",
                    confidence="MEDIUM", urls=urls[:30],
                ))
        except Exception:
            pass
        return hits

    # ── Sublist3r ───────────────────────────────────────────────────

    def _sublist3r(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "Sublist3r"
        if not path.exists():
            return hits
        try:
            result = subprocess.run(
                [sys.executable, "-m", "sublist3r", "-d", domain, "-t", "50", "-o", "-"],
                capture_output=True, text=True, timeout=120, cwd=str(path),
            )
            subs = [l.strip() for l in result.stdout.splitlines() if l.strip() and "." in l]
            if subs:
                hits.append(self._make_hit(
                    platform="Sublist3r", url=f"sublist3r://{domain}",
                    confidence="MEDIUM", subdomains=subs[:100],
                ))
        except Exception:
            pass
        return hits

    # ── FinalRecon ──────────────────────────────────────────────────

    def _finalrecon(self, domain: str) -> List[Dict[str, Any]]:
        """Run FinalRecon: python finalrecon.py --full --url http://target.com"""
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "finalrecon"
        if not path.exists():
            return hits
        try:
            # FinalRecon CLI: python finalrecon.py --full --url http://target.com
            result = subprocess.run(
                [sys.executable, "finalrecon.py", "--full", "--url", f"http://{domain}"],
                capture_output=True, text=True, timeout=300, cwd=str(path),
            )
            if result.stdout.strip():
                hits.append(self._make_hit(
                    platform="FinalRecon", url=f"finalrecon://{domain}",
                    confidence="MEDIUM", data=result.stdout[:5000],
                ))
        except Exception:
            pass
        return hits

    # ── waymore ─────────────────────────────────────────────────────

    def _waymore(self, domain: str) -> List[Dict[str, Any]]:
        """Run Waymore: python waymore.py -i domain -mode U -oU urls.txt"""
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "waymore"
        if not path.exists():
            return hits
        try:
            # Waymore CLI: python waymore.py -i domain -mode U -oU urls.txt
            out_file = self.config.hunt.workspace / "data" / f"waymore_{domain}.txt"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [sys.executable, "waymore.py", "-i", domain, "-mode", "U",
                 "-oU", str(out_file)],
                capture_output=True, text=True, timeout=300, cwd=str(path),
            )
            # Read URLs from output file
            urls = []
            if out_file.exists():
                with open(out_file, "r") as f:
                    urls = [l.strip() for l in f.readlines() if l.strip().startswith("http")]
                out_file.unlink(missing_ok=True)
            # Also check stdout
            stdout_urls = [l.strip() for l in result.stdout.splitlines() if l.strip().startswith("http")]
            urls.extend(stdout_urls)
            if urls:
                hits.append(self._make_hit(
                    platform="waymore", url=f"waymore://{domain}",
                    confidence="MEDIUM", urls=list(dict.fromkeys(urls))[:50],
                ))
        except Exception:
            pass
        return hits

    # ── theHarvester ────────────────────────────────────────────────

    def _theharvester(self, domain: str) -> List[Dict[str, Any]]:
        """Run theHarvester: python theHarvester.py -d domain -b all"""
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "theHarvester"
        if not path.exists():
            return hits
        try:
            # theHarvester CLI: python theHarvester.py -d domain -b all
            result = subprocess.run(
                [sys.executable, "theHarvester.py", "-d", domain, "-b", "all"],
                capture_output=True, text=True, timeout=180, cwd=str(path),
            )
            emails = [l.strip() for l in result.stdout.splitlines()
                       if "@" in l and domain in l]
            hosts = [l.strip() for l in result.stdout.splitlines()
                     if l.strip() and domain in l and "@" not in l]
            if emails or hosts:
                hits.append(self._make_hit(
                    platform="theHarvester", url=f"theharvester://{domain}",
                    confidence="MEDIUM",
                    data={"emails": emails[:50], "hosts": hosts[:50]},
                ))
        except Exception:
            pass
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        domain_like = [c for c in clues if "." in c and not c.startswith("http") and len(c) > 4]
        return self.scan_domains(domain_like)

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []
        for domain in domains[:20]:
            all_hits.extend(self._whois(domain))
            all_hits.extend(self._rdap(domain))
            all_hits.extend(self._dns(domain))
            all_hits.extend(self._ip_api(domain))
            all_hits.extend(self._crt_sh(domain))
            all_hits.extend(self._wayback(domain))
            all_hits.extend(self._sublist3r(domain))
            all_hits.extend(self._finalrecon(domain))
            all_hits.extend(self._waymore(domain))
            all_hits.extend(self._theharvester(domain))

        # Deduplicate
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
