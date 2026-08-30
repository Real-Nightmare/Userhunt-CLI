"""
Domain scanner — ALL tools at MAXIMUM power.
WHOIS, RDAP, DNS, crt.sh, Wayback, ip-api, Sublist3r, FinalRecon, waymore, theHarvester.
"""
import json
import subprocess
import sys
from typing import Any, Dict, List

import requests
import dns.resolver

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.utils.runner import run_tool_simple, run_tool_with_fallback
from userhunt.web.store import store


class DomainScanner(BaseScanner):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "domain_scanner"
        self.description = "Domain recon: WHOIS, RDAP, DNS, crt.sh, Wayback, ip-api, Sublist3r, FinalRecon, waymore, theHarvester — MAXIMUM power"
        self.status = "CORE"

    # ── WHOIS ───────────────────────────────────────────────────────

    def _whois(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            import whois as whois_mod
            data = whois_mod.whois(domain)
            hit = self._make_hit(
                platform="whois", url=f"whois://{domain}",
                confidence="MEDIUM", data=str(data)[:10000],
            )
            hits.append(hit)
            store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── RDAP ────────────────────────────────────────────────────────

    def _rdap(self, domain: str) -> List[Dict[str, Any]]:
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
                hit = self._make_hit(
                    platform="rdap", url=f"https://rdap.org/domain/{domain}",
                    confidence="MEDIUM",
                    data={"name": name, "registrar": registrar, "events": events[:5]},
                )
                hits.append(hit)
                store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── DNS (ALL record types) ─────────────────────────────────────

    def _dns(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        # Query ALL common record types
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "DNSKEY", "DS"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                vals = [str(r) for r in answers]
                hit = self._make_hit(
                    platform=f"dns_{rtype.lower()}", url=f"dns://{domain}/{rtype}",
                    confidence="MEDIUM", data={"type": rtype, "records": vals},
                )
                hits.append(hit)
                store.add_hit(hit)
            except Exception:
                pass
        return hits

    # ── ip-api.com ──────────────────────────────────────────────────

    def _ip_api(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            import socket
            ips = []
            try:
                ips = [ip for ip in socket.getaddrinfo(domain, None) if ip[0] == socket.AF_INET]
                ips = list({ip[4][0] for ip in ips})
            except Exception:
                ips = [socket.gethostbyname(domain)]

            for ip in ips[:5]:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    hit = self._make_hit(
                        platform="ip-api", url=f"ip-api://{ip}",
                        confidence="MEDIUM",
                        data={"ip": ip, "country": data.get("country"),
                              "city": data.get("city"), "isp": data.get("isp"),
                              "org": data.get("org"), "as": data.get("as"),
                              "lat": data.get("lat"), "lon": data.get("lon")},
                    )
                    hits.append(hit)
                    store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── crt.sh (certificate transparency) ───────────────────────────

    def _crt_sh(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                subdomains = list({
                    entry.get("common_name", "")
                    for entry in data[:500]
                    if entry.get("common_name")
                })
                hit = self._make_hit(
                    platform="crt.sh", url=f"https://crt.sh/?q=%25.{domain}",
                    confidence="MEDIUM", subdomains=subdomains[:200],
                )
                hits.append(hit)
                store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── Wayback CDX (ALL archived URLs) ─────────────────────────────

    def _wayback(self, domain: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10000",
                timeout=60,
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = [row[2] for row in data[1:10001] if len(row) > 2]
                hit = self._make_hit(
                    platform="wayback",
                    url=f"http://web.archive.org/web/*/{domain}",
                    confidence="MEDIUM", urls=urls[:500],
                )
                hits.append(hit)
                store.add_hit(hit)
        except Exception:
            pass
        return hits

    # ── Sublist3r — MAXIMUM (100 threads, all engines) ──────────────

    def _sublist3r(self, domain: str) -> List[Dict[str, Any]]:
        """
        SUBLIST3R — MAXIMUM:
        sublist3r.py -d DOMAIN -t 100
        100 threads (max), all search engines.
        """
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "Sublist3r"
        if not path.exists():
            return hits
        store.log(f"Running Sublist3r (MAX - 100 threads) for: {domain}", source="Sublist3r")
        stdout, stderr, rc = run_tool_with_fallback(
            tool_name="Sublist3r",
            cwd=str(path),
            timeout=self.config.hunt.tool_timeout,
            primary=[sys.executable, "sublist3r.py", "-d", domain, "-t", "100", "-o", "-"],
            fallbacks=[
                [sys.executable, "-m", "Sublist3r", "-d", domain, "-t", "100", "-o", "-"],
                [sys.executable, "Sublist3r/sublist3r.py", "-d", domain, "-t", "100", "-o", "-"],
            ],
        )
        subs = [l.strip() for l in stdout.splitlines() if l.strip() and "." in l]
        if subs:
            hit = self._make_hit(
                platform="Sublist3r", url=f"sublist3r://{domain}",
                confidence="MEDIUM", subdomains=subs[:200],
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    # ── FinalRecon — MAXIMUM (full scan, all modules) ───────────────

    def _finalrecon(self, domain: str) -> List[Dict[str, Any]]:
        """
        FINALRECON — MAXIMUM:
        finalrecon.py --full --url http://DOMAIN
        --full enables ALL modules: headers, whois, ssl, crawler, DNS, subdomains, dirs.
        """
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "finalrecon"
        if not path.exists():
            return hits
        store.log(f"Running FinalRecon (MAX - full scan) for: {domain}", source="FinalRecon")
        stdout, stderr, rc = run_tool_with_fallback(
            tool_name="FinalRecon",
            cwd=str(path),
            timeout=self.config.hunt.tool_timeout,
            primary=[sys.executable, "finalrecon.py", "--full", "--url", f"http://{domain}"],
            fallbacks=[
                [sys.executable, "-m", "finalrecon", "--full", "--url", f"http://{domain}"],
                [sys.executable, "finalrecon/finalrecon.py", "--full", "--url", f"http://{domain}"],
            ],
        )
        if stdout.strip():
            hit = self._make_hit(
                platform="FinalRecon", url=f"finalrecon://{domain}",
                confidence="MEDIUM", data=stdout[:20000],
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    # ── Waymore — MAXIMUM (Both mode, unlimited responses) ──────────

    def _waymore(self, domain: str) -> List[Dict[str, Any]]:
        """
        WAYMORE — MAXIMUM:
        waymore.py -i DOMAIN -mode B -l 0 -oU urls.txt
        -mode B = Both URLs AND Responses
        -l 0 = ALL responses (unlimited, default 5000)
        Searches: Wayback Machine, Common Crawl, AlienVault OTX,
        URLScan, VirusTotal, GhostArchive, Intelligence X.
        """
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "waymore"
        if not path.exists():
            return hits
        store.log(f"Running Waymore (MAX - mode B, unlimited) for: {domain}", source="waymore")
        out_file = self.config.hunt.workspace / "data" / f"waymore_{domain}.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        stdout, stderr, rc = run_tool_with_fallback(
            tool_name="waymore",
            cwd=str(path),
            timeout=self.config.hunt.tool_timeout,
            primary=[sys.executable, "waymore.py", "-i", domain,
                     "-mode", "B", "-l", "0", "-oU", str(out_file)],
            fallbacks=[
                [sys.executable, "-m", "waymore", "-i", domain,
                 "-mode", "B", "-l", "0", "-oU", str(out_file)],
                [sys.executable, "waymore/waymore.py", "-i", domain,
                 "-mode", "B", "-l", "0", "-oU", str(out_file)],
            ],
        )
        urls = []
        if out_file.exists():
            try:
                with open(out_file, "r") as f:
                    urls = [l.strip() for l in f.readlines() if l.strip().startswith("http")]
            except Exception:
                pass
            out_file.unlink(missing_ok=True)
        stdout_urls = [l.strip() for l in stdout.splitlines() if l.strip().startswith("http")]
        urls.extend(stdout_urls)
        if urls:
            hit = self._make_hit(
                platform="waymore", url=f"waymore://{domain}",
                confidence="MEDIUM", urls=list(dict.fromkeys(urls))[:1000],
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    # ── theHarvester — MAXIMUM (all sources, no limit) ──────────────

    def _theharvester(self, domain: str) -> List[Dict[str, Any]]:
        """
        THEHARVESTER — MAXIMUM:
        theHarvester.py -d DOMAIN -b all --limit 0
        -b all = all sources (crtsh, certspotter, commoncrawl, etc.)
        --limit 0 = no result cap (full database).
        """
        hits: List[Dict[str, Any]] = []
        path = self.config.hunt.workspace / "tools" / "theHarvester"
        if not path.exists():
            return hits
        store.log(f"Running theHarvester (MAX - all sources, no limit) for: {domain}", source="theHarvester")
        stdout, stderr, rc = run_tool_with_fallback(
            tool_name="theHarvester",
            cwd=str(path),
            timeout=self.config.hunt.tool_timeout,
            primary=[sys.executable, "theHarvester.py", "-d", domain, "-b", "all", "--limit", "0"],
            fallbacks=[
                [sys.executable, "-m", "theHarvester", "-d", domain, "-b", "all", "--limit", "0"],
                [sys.executable, "theHarvester/theHarvester.py", "-d", domain, "-b", "all", "--limit", "0"],
            ],
        )
        emails = [l.strip() for l in stdout.splitlines()
                   if "@" in l and domain in l]
        hosts = [l.strip() for l in stdout.splitlines()
                 if l.strip() and domain in l and "@" not in l]
        if emails or hosts:
            hit = self._make_hit(
                platform="theHarvester", url=f"theharvester://{domain}",
                confidence="MEDIUM",
                data={"emails": emails[:200], "hosts": hosts[:200]},
            )
            hits.append(hit)
            store.add_hit(hit)
        return hits

    # ── Scan entry points ───────────────────────────────────────────

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        domain_like = [c for c in clues if "." in c and not c.startswith("http") and len(c) > 4]
        return self.scan_domains(domain_like)

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        all_hits: List[Dict[str, Any]] = []
        store.log(f"Domain scan: {len(domains)} domain(s) — ALL tools at MAXIMUM", source="domain_scanner")
        for domain in domains[:20]:
            store.log(f"Scanning domain (MAX): {domain}", source="domain_scanner")
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

        store.log(f"Domain scan complete: {len(all_hits)} hits (MAXIMUM power)", source="domain_scanner")
        # Deduplicate
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
