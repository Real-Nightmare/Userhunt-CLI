"""
Scan manager — orchestrates all OSINT scanners.
Tracks per-tool status (pending/running/ok/fail/error) with hit counts and timing.
Provides live status dict for the CLI's Rich Live table.

IMPORTANT: All print output goes to stderr to avoid Rich Live display conflicts.
"""
import sys
import time
import threading
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from userhunt.config import Config
from userhunt.scanners.base import BaseScanner
from userhunt.scanners.username import UsernameScanner
from userhunt.scanners.email import EmailScanner
from userhunt.scanners.domain import DomainScanner
from userhunt.scanners.phone import PhoneScanner
from userhunt.scanners.name import NameScanner
from userhunt.scanners.url import URLScanner
from userhunt.scanners.browser import BrowserManager
from userhunt.web.store import store


def _log(msg: str) -> None:
    """Print to stderr so Rich Live doesn't swallow it."""
    sys.stderr.write(f"{msg}\n")
    sys.stderr.flush()


class ToolStatus:
    """Track the status of a single tool."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    OK = "OK"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"

    def __init__(self, name: str, category: str, description: str = ""):
        self.name = name
        self.category = category
        self.description = description
        self.status = self.PENDING
        self.hits = 0
        self.start_time: float = 0
        self.end_time: float = 0
        self.error: str = ""

    def start(self) -> None:
        self.status = self.RUNNING
        self.start_time = time.time()

    def finish_ok(self, hits: int) -> None:
        self.status = self.OK
        self.hits = hits
        self.end_time = time.time()

    def finish_fail(self, error: str) -> None:
        self.status = self.FAIL
        self.error = error[:100]
        self.end_time = time.time()

    def skip(self, reason: str = "") -> None:
        self.status = self.SKIPPED
        self.error = reason[:100]

    @property
    def elapsed(self) -> float:
        if self.start_time == 0:
            return 0
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time


class ScanManager:
    """Orchestrates all OSINT scanners and tracks per-tool live status."""

    HIGH_PLATFORMS = {
        "snapchat", "tiktok", "twitter", "x", "youtube", "github",
        "instagram", "roblox", "discord", "twitch", "reddit", "steam",
        "linkedin", "spotify", "keybase", "chess", "bluesky",
    }

    def __init__(self, config: Config):
        self.config = config
        self.scanners: List[BaseScanner] = [
            UsernameScanner(config),
            EmailScanner(config),
            DomainScanner(config),
            PhoneScanner(config),
            NameScanner(config),
            URLScanner(config),
        ]
        self.browser = BrowserManager(config)
        # Live tool status dict — keyed by tool name
        self.tool_status: Dict[str, ToolStatus] = {}
        # Callbacks fired on tool start/complete (for Live table refresh)
        self.on_tool_start: Optional[Callable[[], None]] = None
        self.on_tool_done: Optional[Callable[[], None]] = None
        self._callback_lock = threading.Lock()
        self._init_tool_status()

    def _init_tool_status(self) -> None:
        """Register all tools with PENDING status."""
        username_tools = [
            ("Sherlock", "username", "Sherlock — 500+ sites"),
            ("Maigret", "username", "Maigret — 2550 sites"),
            ("Nexfil", "username", "Nexfil — email-based username search"),
            ("Blackbird", "username", "Blackbird — 400+ sites"),
            ("WhatsMyName", "username", "WhatsMyName — ALL sites"),
            ("DirectProbes", "username", "Direct HTTP probes — 40+ platforms"),
            ("GitHubEvents", "username", "GitHub commit email harvest"),
            ("RobloxProbe", "username", "Roblox POST API"),
        ]
        email_tools = [
            ("Gravatar", "email", "Gravatar profile lookup"),
            ("emailrep", "email", "emailrep.io reputation"),
            ("MX_Lookup", "email", "DNS MX records"),
            ("Holehe", "email", "Holehe — 120+ modules"),
            ("BlackbirdEmail", "email", "Blackbird email mode — 400+ sites"),
            ("h8mail", "email", "h8mail breach check"),
            ("Email2Phone", "email", "email2phonenumber scrape"),
        ]
        phone_tools = [
            ("Phonenumbers", "phone", "Phonenumbers library parse"),
            ("Ignorant", "phone", "Ignorant — phone OSINT"),
            ("PhoneInfoga", "phone", "PhoneInfoga — Go binary"),
        ]
        domain_tools = [
            ("WHOIS", "domain", "WHOIS lookup"),
            ("RDAP", "domain", "RDAP registration data"),
            ("DNS", "domain", "DNS — ALL record types"),
            ("IP-API", "domain", "ip-api.com geolocation"),
            ("crt.sh", "domain", "Certificate transparency"),
            ("Wayback", "domain", "Wayback Machine CDX"),
            ("Sublist3r", "domain", "Sublist3r — 100 threads"),
            ("FinalRecon", "domain", "FinalRecon — full scan"),
            ("Waymore", "domain", "Waymore — mode B, unlimited"),
            ("theHarvester", "domain", "theHarvester — all sources"),
        ]
        name_tools = [
            ("NamePerms", "name", "Username permutations"),
            ("NameGravatar", "name", "Name→email Gravatar"),
            ("Wikipedia", "name", "Wikipedia opensearch"),
            ("HackerNews", "name", "HackerNews Algolia"),
        ]
        url_tools = [
            ("WaybackURL", "url", "Wayback availability"),
            ("Photon", "url", "Photon spider — 50 threads"),
        ]
        browser_tools = [
            ("Browser", "browser", "Playwright — SpiderFoot & JS pages"),
        ]

        all_tools = (username_tools + email_tools + phone_tools +
                     domain_tools + name_tools + url_tools + browser_tools)
        for name, cat, desc in all_tools:
            self.tool_status[name] = ToolStatus(name, cat, desc)

    def registry(self) -> List[Tuple[str, str, str]]:
        """Return list of (name, status, description) for all scanners."""
        reg: List[Tuple[str, str, str]] = []
        for scanner in self.scanners:
            reg.append((scanner.name, scanner.status, getattr(scanner, "description", "")))
        reg.append(("browser", "BEST-EFFORT" if self.browser.is_available() else "NOT-INSTALLED",
                     "Playwright browser manager for SpiderFoot and JS-rendered pages"))
        return reg

    def _confidence(self, platform: str) -> str:
        p = platform.lower().replace(" ", "").replace("-", "")
        for hp in self.HIGH_PLATFORMS:
            if hp in p:
                return "HIGH"
        return "MEDIUM"

    def _dedupe_hits(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def _fire_start(self) -> None:
        if self.on_tool_start:
            with self._callback_lock:
                try:
                    self.on_tool_start()
                except Exception:
                    pass

    def _fire_done(self) -> None:
        if self.on_tool_done:
            with self._callback_lock:
                try:
                    self.on_tool_done()
                except Exception:
                    pass

    def _run_tool(self, tool_name: str, func, *args, **kwargs) -> List[Dict[str, Any]]:
        """Run a tool function, tracking status live. Fires on_tool_start and on_tool_done callbacks."""
        ts = self.tool_status.get(tool_name)
        if ts:
            ts.start()
            _log(f"  ▶ {tool_name} started")
            store.log(f"▶ {tool_name} started", source=tool_name)
            self._fire_start()
        try:
            result = func(*args, **kwargs)
            hits = result if isinstance(result, list) else []
            if ts:
                ts.finish_ok(len(hits))
                elapsed = f"{ts.elapsed:.1f}s"
                _log(f"  ✓ {tool_name}: {len(hits)} hits ({elapsed})")
                store.log(f"✓ {tool_name}: {len(hits)} hits ({elapsed})", source=tool_name)
            self._fire_done()
            return hits
        except Exception as e:
            if ts:
                ts.finish_fail(str(e))
                _log(f"  ✗ {tool_name}: {e}")
                store.log(f"✗ {tool_name}: {e}", level="error", source=tool_name)
            self._fire_done()
            return []

    # ── Username scanner delegation ─────────────────────────────────

    def _run_tool_raw(self, tool_name: str, func, *args, **kwargs) -> List[Dict[str, Any]]:
        """Run a tool WITHOUT firing callbacks (safe for worker threads)."""
        ts = self.tool_status.get(tool_name)
        if ts:
            ts.start()
            _log(f"  \u25b6 {tool_name} started")
            store.log(f"\u25b6 {tool_name} started", source=tool_name)
        try:
            result = func(*args, **kwargs)
            hits = result if isinstance(result, list) else []
            if ts:
                ts.finish_ok(len(hits))
                _log(f"  \u2713 {tool_name}: {len(hits)} hits ({ts.elapsed:.1f}s)")
                store.log(f"\u2713 {tool_name}: {len(hits)} hits ({ts.elapsed:.1f}s)", source=tool_name)
            return hits
        except Exception as e:
            if ts:
                ts.finish_fail(str(e))
                _log(f"  \u2717 {tool_name}: {e}")
                store.log(f"\u2717 {tool_name}: {e}", level="error", source=tool_name)
            return []

    def _parallel_run(self, tools: list, label: str = "tools") -> List[Dict[str, Any]]:
        """Run tools in parallel, polling completion from main thread.
        Returns combined hits."""
        _log(f"  Launching {len(tools)} {label} in parallel...")
        all_hits: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(len(tools), 8)) as executor:
            futures = {
                executor.submit(self._run_tool_raw, name, func, *args): name
                for name, func, *args in tools
            }
            for future in as_completed(futures):
                try:
                    hits = future.result()
                    if hits:
                        all_hits.extend(hits)
                except Exception:
                    pass
                # Fire callback from main thread after each tool completes
                self._fire_done()
        return all_hits

    def scan_usernames(self, usernames: List[str], mode: str = "full") -> List[Dict[str, Any]]:
        """Run ALL username scanners in PARALLEL. mode: quick/full/deep."""
        _log(f"  Running {mode} username scanners for: {', '.join(usernames[:3])}")
        store.log(f"Starting {mode} username scan: {usernames[:5]}", source="scan_manager")

        username_scanner = None
        for s in self.scanners:
            if isinstance(s, UsernameScanner):
                username_scanner = s
                break
        if not username_scanner:
            return []

        # Build list of tools based on mode
        tools = [
            ("WhatsMyName", self._run_wmn, username_scanner, usernames),
            ("DirectProbes", self._run_direct_probers, username_scanner, usernames),
            ("GitHubEvents", self._run_github_events, username_scanner, usernames),
            ("RobloxProbe", self._run_roblox, username_scanner, usernames),
            ("Sherlock", username_scanner._run_sherlock, usernames),
            ("Maigret", username_scanner._run_maigret, usernames),
        ]
        if mode in ("full", "deep"):
            tools.extend([
                ("Nexfil", username_scanner._run_nexfil, usernames),
                ("Blackbird", username_scanner._run_blackbird, usernames),
            ])

        # Mark all as RUNNING before launch
        for name, _, _ in tools:
            ts = self.tool_status.get(name)
            if ts:
                ts.start()
        self._fire_start()  # single update from main thread

        all_hits = self._parallel_run(tools, "username tools")
        store.log(f"Username scan complete: {len(all_hits)} total hits", source="username_scanner")
        return self._dedupe_hits(all_hits)

    def _run_wmn(self, scanner: UsernameScanner, usernames: List[str]) -> List[Dict[str, Any]]:
        """Run WhatsMyName — ALL sites, max workers."""
        hits: List[Dict[str, Any]] = []
        sites = scanner._load_wmn()
        if not sites:
            return hits
        from concurrent.futures import ThreadPoolExecutor, as_completed
        for username in usernames:
            _log(f"    WhatsMyName: probing ALL {len(sites)} sites")
            store.log(f"WhatsMyName: probing ALL {len(sites)} sites", source="wmn")
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(scanner._probe_wmn_site, site, username): site for site in sites}
                for future in as_completed(futures):
                    try:
                        hit = future.result()
                        if hit:
                            hits.append(hit)
                            store.add_hit(hit)
                    except Exception:
                        pass
        return hits

    def _run_direct_probers(self, scanner: UsernameScanner, usernames: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for username in usernames:
            _log(f"    Direct probing ALL platforms: {username}")
            store.log(f"Direct probing ALL platforms: {username}", source="direct")
            hits.extend(scanner._direct_probers(username))
        return hits

    def _run_github_events(self, scanner: UsernameScanner, usernames: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for username in usernames:
            hits.extend(scanner._github_commit_emails(username))
        return hits

    def _run_roblox(self, scanner: UsernameScanner, usernames: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for username in usernames:
            hits.extend(scanner._roblox_probe(username))
        return hits

    # ── Email scanner delegation ────────────────────────────────────

    def scan_emails(self, emails: List[str], mode: str = "full") -> List[Dict[str, Any]]:
        """Run ALL email scanners in PARALLEL."""
        _log(f"  Running {mode} email scanners for: {', '.join(emails[:3])}")
        store.log(f"Starting {mode} email scan: {emails[:5]}", source="scan_manager")

        email_scanner = None
        for s in self.scanners:
            if isinstance(s, EmailScanner):
                email_scanner = s
                break
        if not email_scanner:
            return []

        tools = []
        if emails:
            tools.extend([
                ("Gravatar", email_scanner._gravatar, emails[0]),
                ("emailrep", email_scanner._emailrep, emails[0]),
                ("MX_Lookup", email_scanner._mx_lookup, emails[0]),
            ])
        tools.extend([
            ("Holehe", email_scanner._holehe, emails),
            ("BlackbirdEmail", email_scanner._blackbird_email, emails),
        ])
        if mode in ("full", "deep"):
            tools.extend([
                ("h8mail", email_scanner._h8mail, emails),
                ("Email2Phone", email_scanner._email2phonenumber, emails),
            ])

        for name, _, _ in tools:
            ts = self.tool_status.get(name)
            if ts:
                ts.start()
        self._fire_start()

        all_hits = self._parallel_run(tools, "email tools")

        seen = set()
        deduped = [h for h in all_hits if not ((k := (h.get("platform", "").lower(), h.get("url", ""))) in seen or seen.add(k))]
        store.log(f"Email scan complete: {len(deduped)} hits", source="email_scanner")
        return deduped

    # ── Name scanner delegation ─────────────────────────────────────

    def scan_names(self, names: List[str]) -> List[Dict[str, Any]]:
        _log(f"  Running name scanners for: {', '.join(n[:20] for n in names[:3])}")
        store.log(f"Starting name scan: {names[:5]}", source="scan_manager")

        name_scanner = None
        for s in self.scanners:
            if isinstance(s, NameScanner):
                name_scanner = s
                break
        if not name_scanner:
            return []

        all_hits: List[Dict[str, Any]] = []

        _log("    → Username permutations...")
        _log("    → Name→email Gravatar...")
        _log("    → Wikipedia...")
        _log("    → HackerNews...")
        all_hits = self._run_tool("NamePerms", name_scanner.scan_names, names)

        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = (h.get("platform", "").lower(), h.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        store.log(f"Name scan complete: {len(deduped)} hits", source="name_scanner")
        return deduped

    # ── Phone scanner delegation ────────────────────────────────────

    def scan_phones(self, phones: List[str], mode: str = "full") -> List[Dict[str, Any]]:
        """Run ALL phone scanners in PARALLEL."""
        _log(f"  Running phone scanners for: {len(phones)} number(s)")
        store.log(f"Starting phone scan: {phones[:5]}", source="scan_manager")

        phone_scanner = None
        for s in self.scanners:
            if isinstance(s, PhoneScanner):
                phone_scanner = s
                break
        if not phone_scanner:
            return []

        phone = phones[0] if phones else None
        if not phone:
            return []

        # Phonenumbers parse (inline)
        all_hits: List[Dict[str, Any]] = []
        info = phone_scanner._parse_phone(phone)
        if info:
            hit = phone_scanner._make_hit(platform="phonenumbers", url=f"phone://{phone}", confidence="MEDIUM", data=info)
            all_hits.append(hit)
            store.add_hit(hit)
        ts = self.tool_status.get("Phonenumbers")
        if ts:
            ts.start()
            ts.finish_ok(1 if info else 0)

        tools = [
            ("Ignorant", phone_scanner._ignorant, phone),
            ("PhoneInfoga", phone_scanner._phoneinfoga, phone),
        ]
        for name, _, _ in tools:
            ts2 = self.tool_status.get(name)
            if ts2:
                ts2.start()
        self._fire_start()

        all_hits.extend(self._parallel_run(tools, "phone tools"))

        seen = set()
        deduped = [h for h in all_hits if not ((k := (h.get("platform", "").lower(), h.get("url", ""))) in seen or seen.add(k))]
        store.log(f"Phone scan complete: {len(deduped)} hits", source="phone_scanner")
        return deduped

    # ── Domain scanner delegation ───────────────────────────────────

    def scan_domains(self, domains: List[str], mode: str = "full") -> List[Dict[str, Any]]:
        """Run ALL domain scanners in PARALLEL."""
        _log(f"  Running {mode} domain scanners for: {', '.join(domains[:3])}")
        store.log(f"Starting {mode} domain scan: {domains[:5]}", source="scan_manager")

        domain_scanner = None
        for s in self.scanners:
            if isinstance(s, DomainScanner):
                domain_scanner = s
                break
        if not domain_scanner:
            return []

        domain = domains[0] if domains else None
        if not domain:
            return []

        tools = [
            ("WHOIS", domain_scanner._whois, domain),
            ("RDAP", domain_scanner._rdap, domain),
            ("DNS", domain_scanner._dns, domain),
            ("IP-API", domain_scanner._ip_api, domain),
            ("crt.sh", domain_scanner._crt_sh, domain),
            ("Wayback", domain_scanner._wayback, domain),
        ]
        if mode in ("full", "deep"):
            tools.extend([
                ("Sublist3r", domain_scanner._sublist3r, domain),
                ("FinalRecon", domain_scanner._finalrecon, domain),
                ("Waymore", domain_scanner._waymore, domain),
                ("theHarvester", domain_scanner._theharvester, domain),
            ])

        for name, _, _ in tools:
            ts = self.tool_status.get(name)
            if ts:
                ts.start()
        self._fire_start()

        all_hits = self._parallel_run(tools, "domain tools")

        seen = set()
        deduped = [h for h in all_hits if not ((k := (h.get("platform", "").lower(), h.get("url", ""))) in seen or seen.add(k))]
        store.log(f"Domain scan complete: {len(deduped)} hits", source="domain_scanner")
        return deduped

    # ── URL scanner delegation ──────────────────────────────────────

    def scan_urls(self, urls: List[str], mode: str = "full") -> List[Dict[str, Any]]:
        """Run URL scanners in PARALLEL."""
        _log(f"  Running URL scanners for: {len(urls)} url(s)")
        store.log(f"Starting URL scan: {urls[:5]}", source="scan_manager")

        url_scanner = None
        for s in self.scanners:
            if isinstance(s, URLScanner):
                url_scanner = s
                break
        if not url_scanner:
            return []

        url = urls[0] if urls else None
        if not url:
            return []

        tools = [
            ("WaybackURL", url_scanner._wayback_availability, url),
            ("Photon", url_scanner._photon, url),
        ]
        for name, _, _ in tools:
            ts = self.tool_status.get(name)
            if ts:
                ts.start()
        self._fire_start()

        all_hits = self._parallel_run(tools, "URL tools")

        seen = set()
        deduped = [h for h in all_hits if not ((k := (h.get("platform", "").lower(), h.get("url", ""))) in seen or seen.add(k))]
        store.log(f"URL scan complete: {len(deduped)} hits", source="url_scanner")
        return deduped

    # ── Clue scanner ────────────────────────────────────────────────

    def scan_clues(self, clues: List[str]) -> List[Dict[str, Any]]:
        _log(f"  Running clue scanners for: {len(clues)} clue(s)")
        store.log(f"Starting clue scan: {clues[:5]}", source="scan_manager")
        hits: List[Dict[str, Any]] = []
        for scanner in self.scanners:
            if hasattr(scanner, "scan_clues"):
                try:
                    found = scanner.scan_clues(clues)
                    for h in found:
                        if "confidence" not in h:
                            h["confidence"] = self._confidence(h.get("platform", ""))
                        hits.append(h)
                    if found:
                        _log(f"  ✓ {scanner.name}: {len(found)} hits")
                except Exception as e:
                    _log(f"  ✗ {scanner.name}: {e}")
        return self._dedupe_hits(hits)

    # ── Status table for Rich Live ──────────────────────────────────

    def get_status_rows(self) -> List[Dict[str, Any]]:
        """Return ordered list of tool statuses for rendering in a Rich table."""
        rows = []
        for ts in self.tool_status.values():
            rows.append({
                "name": ts.name,
                "category": ts.category,
                "status": ts.status,
                "hits": ts.hits,
                "elapsed": ts.elapsed,
                "error": ts.error,
                "description": ts.description,
            })
        # Sort: running first, then pending, then ok/fail/skipped
        order = {ToolStatus.RUNNING: 0, ToolStatus.PENDING: 1, ToolStatus.OK: 2, ToolStatus.FAIL: 3, ToolStatus.SKIPPED: 4}
        rows.sort(key=lambda r: (order.get(r["status"], 5), r["category"], r["name"]))
        return rows
