"""
USERHUNT CLI — main entry point and interactive menu.
"""
import os
import sys
import json
import time
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import deque

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich import box

from userhunt.config import Config, AIConfig, AIProvider
from userhunt.ai.engine import AIEngine
from userhunt.scanners.manager import ScanManager
from userhunt.core.pivot import PivotEngine
from userhunt.core.evidence import EvidenceCollector
from userhunt.core.confidence import ConfidenceEngine
from userhunt.output.reporter import Reporter


console = Console()
config = Config()


def logo() -> None:
    art = """
[bold cyan]
██╗   ██╗██╗███████╗████████╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗ 
██║   ██║██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║█████╗     ██║   ██████╔╝██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║███╗██║██╔══╝  ██╔══██╗ 
 ╚████╔╝ ██║███████╗   ██║   ██║     ██║  ██║██║╚██╗██║███████╗██║  ██║
  ╚═══╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝ ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold yellow]Autonomous AI-Powered OSINT Toolkit — Deep Hunt Engine v2.0[/bold yellow]
"""
    console.print(Panel(art, border_style="cyan", padding=(0, 1)))


def status_bar() -> None:
    ws = config.hunt.workspace
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ai_status = "[green]ON[/green]" if config.ai.enabled else "[red]OFF[/red]"
    console.print(
        f"[dim]Workspace: {ws} | Time: {ts} | AI Engine: {ai_status} | "
        f"Model: {config.ai.model if config.ai.enabled else 'N/A'}[/dim]"
    )


def menu() -> None:
    console.clear()
    logo()
    status_bar()
    table = Table(box=box.ROUNDED, show_header=False, expand=True)
    table.add_column("Option", style="bold cyan", width=4)
    table.add_column("Action", style="white")
    options = [
        ("1", "Add USERNAMES"),
        ("2", "Add EMAILS"),
        ("3", "Add FULL NAMES"),
        ("4", "Add EXTRA CLUES (phones, links, Discord, Roblox, crypto, images, domains)"),
        ("5", "Show case"),
        ("6", "RUN FULL DEEP HUNT"),
        ("7", "Rebuild AI profile + PDF"),
        ("8", "Export JSON"),
        ("9", "Clear case"),
        ("10", "Tool registry"),
        ("11", "Pivot log"),
        ("12", "AI settings"),
        ("0", "Exit"),
    ]
    for opt, desc in options:
        table.add_row(f"[{opt}]", desc)
    console.print(table)


class Case:
    def __init__(self):
        self.usernames: list[str] = []
        self.emails: list[str] = []
        self.names: list[str] = []
        self.clues: list[str] = []
        self.hits: list[dict] = []
        self.pivot_log: deque = deque(maxlen=config.hunt.max_pivot_log)
        self.notes: deque = deque(maxlen=config.hunt.max_notes)
        self.profile_evidence: list[dict] = []
        self.ai_verdicts: list[dict] = []
        self.ai_profile: str = ""
        self.round: int = 0
        self.done_usernames: set[str] = set()
        self.done_emails: set[str] = set()
        self.done_domains: set[str] = set()

    def to_dict(self) -> dict:
        return {
            "usernames": self.usernames,
            "emails": self.emails,
            "names": self.names,
            "clues": self.clues,
            "hits": self.hits,
            "pivot_log": list(self.pivot_log),
            "notes": list(self.notes),
            "profile_evidence": self.profile_evidence,
            "ai_verdicts": self.ai_verdicts,
            "ai_profile": self.ai_profile,
            "round": self.round,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        tmp.replace(path)

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, "r") as f:
            data = json.load(f)
        self.usernames = data.get("usernames", [])
        self.emails = data.get("emails", [])
        self.names = data.get("names", [])
        self.clues = data.get("clues", [])
        self.hits = data.get("hits", [])
        self.pivot_log = deque(data.get("pivot_log", []), maxlen=config.hunt.max_pivot_log)
        self.notes = deque(data.get("notes", []), maxlen=config.hunt.max_notes)
        self.profile_evidence = data.get("profile_evidence", [])
        self.ai_verdicts = data.get("ai_verdicts", [])
        self.ai_profile = data.get("ai_profile", "")
        self.round = data.get("round", 0)


def parse_multi_line(prompt_text: str) -> list[str]:
    console.print(f"[bold yellow]{prompt_text}[/bold yellow]")
    console.print("[dim]Enter one per line. Empty line to finish. Comma-separated bulk also accepted.[/dim]")
    lines: list[str] = []
    bulk = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            if bulk:
                parts = [p.strip() for p in bulk.split(",") if p.strip()]
                lines.extend(parts)
                bulk = ""
            break
        if "," in line and not lines:
            bulk += line + "\n"
        else:
            if bulk:
                parts = [p.strip() for p in bulk.split(",") if p.strip()]
                lines.extend(parts)
                bulk = ""
            lines.append(line.strip())
    seen = set()
    deduped = []
    for item in lines:
        if item.lower() not in seen:
            seen.add(item.lower())
            deduped.append(item)
    return deduped


def route_clues(clues: list[str]) -> dict:
    result = {"emails": [], "urls": [], "discord_invites": [], "discord_snowflakes": [],
              "roblox_ids": [], "btc": [], "phones": [], "domains": [], "names": [], "usernames": []}
    email_re = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    url_re = re.compile(r'^https?://[^\s]+$', re.I)
    discord_invite_re = re.compile(r'discord\.gg/[A-Za-z0-9_-]+')
    snowflake_re = re.compile(r'\b(\d{17,20})\b')
    roblox_re = re.compile(r'\b(\d{3,16})\b')
    btc_re = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    phone_re = re.compile(r'\+?\d[\d\s\-\(\)]{7,15}\d')
    domain_re = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\b')
    for clue in clues:
        if email_re.match(clue):
            result["emails"].append(clue)
        elif url_re.match(clue):
            result["urls"].append(clue)
        elif discord_invite_re.search(clue):
            result["discord_invites"].append(clue)
        elif snowflake_re.search(clue):
            result["discord_snowflakes"].append(snowflake_re.search(clue).group(1))
        elif btc_re.search(clue):
            result["btc"].append(btc_re.search(clue).group(0))
        elif phone_re.search(clue) and not roblox_re.search(clue):
            result["phones"].append(clue)
        elif domain_re.search(clue) and "." in clue:
            result["domains"].append(domain_re.search(clue).group(1))
        elif re.search(r'[a-zA-Z]{3,16}', clue) and not url_re.match(clue):
            result["usernames"].append(clue)
    return result


def disk_check() -> bool:
    try:
        usage = os.statvfs(config.hunt.workspace)
        free_mb = (usage.f_bavail * usage.f_frsize) / (1024 * 1024)
        if free_mb < config.hunt.disk_abort_mb:
            console.print(f"[bold red]ABORT: Only {free_mb:.0f}MB free. Minimum {config.hunt.disk_abort_mb}MB required.[/bold red]")
            return False
        if free_mb < config.hunt.disk_warn_mb:
            console.print(f"[bold yellow]WARN: Only {free_mb:.0f}MB free.[/bold yellow]")
    except Exception:
        pass
    return True


def install_phase() -> None:
    ws = config.hunt.workspace
    dirs = {
        "tools": ws / "tools",
        "output": ws / "output",
        "data": ws / "data",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    marker = ws / ".installed"
    if marker.exists():
        return
    if not disk_check():
        sys.exit(1)
    console.print("[bold yellow]First run — installing dependencies and tools...[/bold yellow]")
    import subprocess
    packages = [
        "requests", "aiohttp", "colorama", "rich", "reportlab",
        "beautifulsoup4", "lxml", "requests-futures", "PySocks",
        "chardet", "phonenumbers", "dnspython", "python-whois",
        "exifread", "Pillow", "click", "pydantic", "tenacity",
        "python-dotenv", "geopy",
    ]
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Installing pip packages...", total=len(packages))
        for pkg in packages:
            progress.update(task, description=f"Installing {pkg}...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    check=False, capture_output=True, timeout=120
                )
            except Exception:
                pass
            progress.advance(task)
    repos = {
        "sherlock": "https://github.com/sherlock-project/sherlock.git",
        "maigret": "https://github.com/soxoj/maigret.git",
        "blackbird": "https://github.com/p1ngul1n0/blackbird.git",
        "nexfil": "https://github.com/thewhiteh4t/nexfil.git",
        "whatsmyname": "https://github.com/WebBreacher/WhatsMyName.git",
        "holehe": "https://github.com/megadose/holehe.git",
        "social_analyzer": "https://github.com/qeeqbox/social-analyzer.git",
        "theHarvester": "https://github.com/laramies/theHarvester.git",
        "Infoga": "https://github.com/m4ll0k/Infoga.git",
        "EmailHarvester": "https://github.com/maldevel/EmailHarvester.git",
        "email2phonenumber": "https://github.com/martinvigo/email2phonenumber.git",
        "ignorant": "https://github.com/megadose/ignorant.git",
        "phoneinfoga": "https://github.com/sundowndev/phoneinfoga.git",
        "GHunt": "https://github.com/mxrch/GHunt.git",
        "Osintgram": "https://github.com/Datalux/Osintgram.git",
        "snscrape": "https://github.com/JustAnotherArchivist/snscrape.git",
        "twint": "https://github.com/twintproject/twint.git",
        "Sublist3r": "https://github.com/aboul3la/Sublist3r.git",
        "OneForAll": "https://github.com/shmilylty/OneForAll.git",
        "finalrecon": "https://github.com/thewhiteh4t/finalrecon.git",
        "Sudomy": "https://github.com/screetsec/Sudomy.git",
        "Photon": "https://github.com/s0md3v/Photon.git",
        "spiderfoot": "https://github.com/smicallef/spiderfoot.git",
        "recon_ng": "https://github.com/lanmaster53/recon-ng.git",
        "metagoofil": "https://github.com/opsdisk/metagoofil.git",
        "pagodo": "https://github.com/opsdisk/pagodo.git",
        "EagleEye": "https://github.com/ThoughtfulDev/EagleEye.git",
        "linkedin2username": "https://github.com/initstring/linkedin2username.git",
        "social_mapper": "https://github.com/SpiderLabs/social_mapper.git",
        "marple": "https://github.com/soxoj/marple.git",
        "snoop": "https://github.com/snooppr/snoop.git",
    }
    tool_hints = {
        "GHunt": "Requires Google cookies. Run: ghunt login",
        "Osintgram": "Requires Instagram login. Run: python3 osintgram.py",
        "SpiderFoot": "Run: ./sf.py -l 127.0.0.1:5001",
        "recon_ng": "Run: recon-ng",
        "theHarvester": "Run: python3 theHarvester.py -d target.com",
        "finalrecon": "Run: python3 finalrecon.py --full https://target.com",
        "OneForAll": "Run: python3 oneforall.py --target target.com",
    }
    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console)
    with progress:
        task = progress.add_task("Cloning OSINT tools...", total=len(repos))
        for name, url in repos.items():
            progress.update(task, description=f"Cloning {name}...")
            dest = dirs["tools"] / name
            if not dest.exists():
                try:
                    subprocess.run(
                        ["git", "clone", "--depth", "1", url, str(dest)],
                        check=False, capture_output=True, timeout=180
                    )
                    req = dest / "requirements.txt"
                    if req.exists():
                        try:
                            subprocess.run(
                                [sys.executable, "-m", "pip", "install", "-r", str(req), "--quiet"],
                                check=False, capture_output=True, timeout=180
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            progress.advance(task)
    hints_path = dirs["tools"] / "manual_tools.txt"
    with open(hints_path, "w") as f:
        f.write("Manual tool launch hints:\n")
        for tool, hint in tool_hints.items():
            f.write(f"  {tool}: {hint}\n")
    marker.touch()
    console.print("[bold green]Installation complete.[/bold green]")


def ai_settings_menu() -> None:
    console.clear()
    console.print(Panel.fit("[bold cyan]AI SETTINGS[/bold cyan]", border_style="cyan"))
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Preset", style="bold cyan")
    table.add_column("Provider")
    table.add_column("Base URL")
    table.add_column("Model")
    presets = [
        ("1", "Groq Free", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        ("2", "OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("3", "Gemini (OpenAI-compat)", "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.0-flash"),
        ("4", "OpenRouter", "https://openrouter.ai/api/v1", "auto"),
        ("5", "Custom", "", ""),
    ]
    for p, name, url, model in presets:
        table.add_row(f"[{p}]", name, url, model)
    console.print(table)
    choice = Prompt.ask("Select preset", choices=["1", "2", "3", "4", "5"], default="1")
    if choice == "1":
        config.ai.provider = AIProvider.GROQ
        config.ai.base_url = "https://api.groq.com/openai/v1"
        config.ai.model = "llama-3.3-70b-versatile"
    elif choice == "2":
        config.ai.provider = AIProvider.OPENAI
        config.ai.base_url = "https://api.openai.com/v1"
        config.ai.model = "gpt-4o-mini"
    elif choice == "3":
        config.ai.provider = AIProvider.GEMINI
        config.ai.base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
        config.ai.model = "gemini-2.0-flash"
    elif choice == "4":
        config.ai.provider = AIProvider.OPENROUTER
        config.ai.base_url = "https://openrouter.ai/api/v1"
        config.ai.model = "auto"
    else:
        config.ai.provider = AIProvider.CUSTOM
        config.ai.base_url = Prompt.ask("Base URL").strip().strip('"').strip("'")
        config.ai.model = Prompt.ask("Model name").strip().strip('"').strip("'")
    key = Prompt.ask("API key", password=True).strip().strip('"').strip("'")
    if key:
        config.ai.api_key = key
        config.ai.enabled = True
        config.save_ai()
        console.print(f"[green]Key saved. Masked: {config.ai.mask_key()}[/green]")
    else:
        console.print("[yellow]No key provided. AI engine disabled.[/yellow]")


def show_case(case: Case) -> None:
    console.clear()
    logo()
    status_bar()
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Category", style="bold cyan")
    table.add_column("Count", style="bold yellow")
    table.add_column("Items")
    table.add_row("Usernames", str(len(case.usernames)), ", ".join(case.usernames[:10]) or "-")
    table.add_row("Emails", str(len(case.emails)), ", ".join(case.emails[:10]) or "-")
    table.add_row("Names", str(len(case.names)), ", ".join(case.names[:10]) or "-")
    table.add_row("Clues", str(len(case.clues)), ", ".join(case.clues[:10]) or "-")
    table.add_row("Hits", str(len(case.hits)), f"Round {case.round}")
    table.add_row("Pivot log", str(len(case.pivot_log)), "-")
    table.add_row("Notes", str(len(case.notes)), "-")
    console.print(table)


def run_deep_hunt(case: Case) -> None:
    if not case.usernames and not case.emails and not case.names and not case.clues:
        console.print("[bold red]Case is empty. Add identifiers first.[/bold red]")
        return
    if not disk_check():
        return
    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_manager = ScanManager(config)
    pivot_engine = PivotEngine(config)
    evidence_collector = EvidenceCollector(config)
    confidence_engine = ConfidenceEngine()
    reporter = Reporter(config)
    ai_engine = AIEngine(config) if config.ai.enabled else None
    start_time = time.time()
    console.print(f"[bold green]>> deep hunt starting (rounds 1-{config.hunt.max_rounds})[/bold green]")
    for rnd in range(1, config.hunt.max_rounds + 1):
        case.round = rnd
        console.print(f"[bold cyan]=== ROUND {rnd}/{config.hunt.max_rounds} ===[/bold cyan]")
        usernames = [u for u in case.usernames if u not in case.done_usernames]
        emails = [e for e in case.emails if e not in case.done_emails]
        if not usernames and not emails:
            console.print("[yellow]No new identifiers to hunt. Stopping.[/yellow]")
            break
        if usernames:
            console.print(f">> deep username: {', '.join(usernames[:5])} (round {rnd}/{config.hunt.max_rounds})")
            round_hits = scan_manager.scan_usernames(usernames)
            for hit in round_hits:
                if len(case.hits) >= config.hunt.max_hits:
                    break
                case.hits.append(hit)
            for u in usernames:
                case.done_usernames.add(u)
            console.print(f"   [dim]Username scan: {len(round_hits)} hits[/dim]")
        if emails:
            console.print(f">> deep email: {', '.join(emails[:5])} (round {rnd}/{config.hunt.max_rounds})")
            round_hits = scan_manager.scan_emails(emails)
            for hit in round_hits:
                if len(case.hits) >= config.hunt.max_hits:
                    break
                case.hits.append(hit)
            for e in emails:
                case.done_emails.add(e)
            console.print(f"   [dim]Email scan: {len(round_hits)} hits[/dim]")
        if case.clues:
            round_hits = scan_manager.scan_clues(case.clues)
            for hit in round_hits:
                if len(case.hits) >= config.hunt.max_hits:
                    break
                case.hits.append(hit)
            console.print(f"   [dim]Clue scan: {len(round_hits)} hits[/dim]")
        evidence_collector.visit_links(case.hits, round(rnd))
        case.hits = confidence_engine.score(case.hits)
        if ai_engine:
            ai_engine.review_round(case, rnd)
        new_pivots = pivot_engine.extract_pivots(case, rnd)
        case.pivot_log.extend(new_pivots)
        for pivot in new_pivots:
            val = pivot.get("value", "")
            action = pivot.get("action", "")
            if action == "queue_username" and val not in case.usernames:
                case.usernames.append(val)
            elif action == "queue_email" and val not in case.emails:
                case.emails.append(val)
        elapsed = time.time() - start_time
        console.print(f"[dim]Round {rnd} complete. {len(case.hits)} total hits. {elapsed:.1f}s elapsed.[/dim]")
        if rnd < config.hunt.max_rounds:
            try:
                if not Confirm.ask("Continue to next round?", default=True):
                    break
            except Exception:
                break
    case.save(output_dir / f"hunt_{timestamp}.json")
    reporter.generate_json(case, output_dir / f"hunt_{timestamp}.json")
    pdf_path = reporter.generate_pdf(case, output_dir / f"hunt_{timestamp}.pdf")
    console.print(f"[bold green]Hunt complete. {len(case.hits)} hits.[/bold green]")
    console.print(f"JSON: {output_dir / f'hunt_{timestamp}.json'}")
    console.print(f"PDF: {pdf_path}")


def rebuild_profile(case: Case) -> None:
    if not case.hits and not case.profile_evidence:
        console.print("[yellow]No data to build profile.[/yellow]")
        return
    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ai_engine = AIEngine(config) if config.ai.enabled else None
    if ai_engine:
        profile = ai_engine.build_profile(case)
        if profile:
            case.ai_profile = profile
    if not case.ai_profile:
        case.ai_profile = _heuristic_profile(case)
    reporter = Reporter(config)
    pdf_path = reporter.generate_pdf(case, output_dir / f"profile_{timestamp}.pdf")
    console.print(f"[green]Profile rebuilt. PDF: {pdf_path}[/green]")


def _heuristic_profile(case: Case) -> str:
    lines = ["OSINT Profile Summary (Heuristic)", "=" * 40, ""]
    if case.usernames:
        lines.append(f"Usernames: {', '.join(case.usernames[:20])}")
    if case.emails:
        lines.append(f"Emails: {', '.join(case.emails[:20])}")
    if case.names:
        lines.append(f"Names: {', '.join(case.names[:20])}")
    high = [h for h in case.hits if h.get("confidence") == "HIGH"]
    if high:
        lines.append(f"\nHigh-confidence hits ({len(high)}):")
        for h in high[:20]:
            lines.append(f"  - {h.get('platform','?')}: {h.get('url','?')}")
    return "\n".join(lines)


def export_json(case: Case) -> None:
    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"export_{timestamp}.json"
    case.save(path)
    console.print(f"[green]Exported to {path}[/green]")


def clear_case(case: Case) -> None:
    if Confirm.ask("Clear all case data?", default=False):
        case.usernames.clear()
        case.emails.clear()
        case.names.clear()
        case.clues.clear()
        case.hits.clear()
        case.pivot_log.clear()
        case.notes.clear()
        case.profile_evidence.clear()
        case.ai_verdicts.clear()
        case.ai_profile = ""
        case.round = 0
        case.done_usernames.clear()
        case.done_emails.clear()
        case.done_domains.clear()
        import shutil
        ws = config.hunt.workspace
        for d in ["tools", "output", "data"]:
            p = ws / d
            if p.exists():
                try:
                    shutil.rmtree(p)
                except Exception:
                    pass
        console.print("[yellow]Case cleared.[/yellow]")


def tool_registry() -> None:
    console.clear()
    logo()
    status_bar()
    from userhunt.scanners.manager import ScanManager
    sm = ScanManager(config)
    tools = sm.registry()
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status", style="bold yellow")
    table.add_column("Description")
    for name, status, desc in tools:
        color = "green" if status == "READY" else "yellow" if status == "BEST-EFFORT" else "red"
        table.add_row(name, f"[{color}]{status}[/{color}]", desc)
    console.print(table)


def pivot_log_view(case: Case) -> None:
    if not case.pivot_log:
        console.print("[dim]Pivot log is empty.[/dim]")
        return
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Round", style="bold cyan")
    table.add_column("Source")
    table.add_column("Found")
    table.add_column("Action")
    table.add_column("Reason")
    table.add_column("By")
    for entry in list(case.pivot_log)[-50:]:
        table.add_row(
            str(entry.get("round", "?")),
            entry.get("source", "?"),
            entry.get("found", "?"),
            entry.get("action", "?"),
            entry.get("reason", "?")[:40],
            entry.get("by", "?"),
        )
    console.print(table)


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    if ctx.invoked_subcommand is None:
        run_interactive()


def run_interactive() -> None:
    config.load()
    case = Case()
    ws = config.hunt.workspace
    ws.mkdir(parents=True, exist_ok=True)
    save_path = ws / "data" / "case.json"
    if save_path.exists():
        case.load(save_path)
    if not (ws / ".installed").exists():
        install_phase()
    if config.ai.enabled:
        console.print(f"[green]AI engine ready. Provider: {config.ai.provider.value} | Model: {config.ai.model}[/green]")
    else:
        console.print("[dim]AI engine off. Option [12] enables it. Hunt runs deterministic.[/dim]")
    while True:
        try:
            menu()
            choice = Prompt.ask("\nSelect option", choices=["0","1","2","3","4","5","6","7","8","9","10","11","12"], default="0")
        except Exception:
            choice = "0"
        if choice == "0":
            case.save(save_path)
            console.print("[yellow]Goodbye.[/yellow]")
            sys.exit(0)
        elif choice == "1":
            items = parse_multi_line("Enter usernames:")
            case.usernames.extend(items)
            console.print(f"[green]Added {len(items)} usernames.[/green]")
        elif choice == "2":
            items = parse_multi_line("Enter emails:")
            case.emails.extend(items)
            console.print(f"[green]Added {len(items)} emails.[/green]")
        elif choice == "3":
            items = parse_multi_line("Enter full names:")
            case.names.extend(items)
            console.print(f"[green]Added {len(items)} names.[/green]")
        elif choice == "4":
            items = parse_multi_line("Enter extra clues:")
            case.clues.extend(items)
            console.print(f"[green]Added {len(items)} clues.[/green]")
        elif choice == "5":
            show_case(case)
        elif choice == "6":
            run_deep_hunt(case)
        elif choice == "7":
            rebuild_profile(case)
        elif choice == "8":
            export_json(case)
        elif choice == "9":
            clear_case(case)
        elif choice == "10":
            tool_registry()
        elif choice == "11":
            pivot_log_view(case)
        elif choice == "12":
            ai_settings_menu()
        case.save(save_path)


if __name__ == "__main__":
    main()
