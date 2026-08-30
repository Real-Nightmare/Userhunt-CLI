"""
Userhunt CLI — main entry point and interactive menu.
Autonomous AI-powered OSINT toolkit with deep hunt engine.
Live dashboard at http://0.0.0.0:8000
"""
import os
import sys
import time
import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich import box
from rich.text import Text

from userhunt.config import Config, AIConfig, AIProvider
from userhunt.case import Case
from userhunt.ai.engine import AIEngine
from userhunt.scanners.manager import ScanManager
from userhunt.core.pivot import PivotEngine
from userhunt.core.evidence import EvidenceCollector
from userhunt.core.confidence import ConfidenceEngine
from userhunt.output.reporter import Reporter
from userhunt.utils.storage import check_disk, purge_temp_files
from userhunt.utils.extractors import route_clues
from userhunt.web.store import store as dashboard


console = Console()
config = Config()


# ── Branding ───────────────────────────────────────────────────────

def logo() -> None:
    art = """
[bold cyan]
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██╗   ██╗██╗███████╗████████╗██████╗  ██████╗ ██╗    ║
║   ██║   ██║██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║    ║
║   ██║   ██║██║█████╗     ██║   ██████╔╝██████╔╝██║    ║
║   ╚██╗ ██╔╝██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║    ║
║    ╚████╔╝ ██║███████╗   ██║   ██║     ██║  ██║██║    ║
║     ╚═══╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝    ║
║                                                          ║
║        Autonomous AI-Powered OSINT Toolkit v1.0.0        ║
║                    Deep Hunt Engine                       ║
║          Live Dashboard: http://0.0.0.0:8000             ║
╚══════════════════════════════════════════════════════════╝
[/bold cyan]"""
    console.print(Panel(art, border_style="cyan", padding=(0, 1)))


def status_bar() -> None:
    ws = config.hunt.workspace
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ai_status = "[green]ON[/green]" if config.ai.enabled else "[red]OFF[/red]"
    timeout_str = "none" if config.hunt.tool_timeout == 0 else f"{config.hunt.tool_timeout}s"
    console.print(
        f"[dim]Workspace: {ws} | Time: {ts} | AI: {ai_status} | "
        f"Model: {config.ai.model if config.ai.enabled else 'N/A'} | "
        f"Timeout: {timeout_str}[/dim]"
    )
    console.print("[dim]Dashboard: http://0.0.0.0:8000 | Upgrade: userhunt upgrade[/dim]")


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
        ("[6]", "▶ RUN FULL DEEP HUNT (default)"),
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


# ── Input handling ─────────────────────────────────────────────────

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
    # Dedupe order-preserving
    seen: set[str] = set()
    deduped: list[str] = []
    for item in lines:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


# ── AI settings ────────────────────────────────────────────────────

def ai_settings_menu() -> None:
    console.clear()
    console.print(Panel.fit("[bold cyan]AI SETTINGS — Built-in Free Providers[/bold cyan]", border_style="cyan"))
    
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("Provider", style="bold green")
    table.add_column("Model")
    table.add_column("Free Tier")
    table.add_column("Card?")
    table.add_column("Get Key From")
    
    free_providers = [
        ("1", "Groq Free (Fastest)", "llama-3.3-70b-versatile", "30 RPM, 1000/day", "No", "console.groq.com"),
        ("2", "Google Gemini Free", "gemini-2.0-flash", "1500/day, 10 RPM", "No", "ai.google.dev"),
        ("3", "Cerebras Free", "llama-3.3-70b", "5 RPM, 1M tokens/day", "No", "cloud.cerebras.ai"),
        ("4", "OpenRouter Free", "meta-llama/llama-3.3-70b-instruct:free", "20 RPM, 50/day", "No", "openrouter.ai"),
    ]
    for num, name, model, tier, card, source in free_providers:
        table.add_row(num, name, model, tier, card, source)
    console.print(table)
    
    console.print("\n[bold yellow]Paid / Custom Options:[/bold yellow]")
    paid_table = Table(box=box.ROUNDED, show_header=True, expand=True)
    paid_table.add_column("#", style="bold cyan", width=3)
    paid_table.add_column("Provider")
    paid_table.add_column("Base URL")
    paid_table.add_column("Model")
    paid_providers = [
        ("5", "Groq (Paid)", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        ("6", "OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("7", "Gemini (Paid)", "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.0-flash"),
        ("8", "OpenRouter (Paid)", "https://openrouter.ai/api/v1", "auto"),
        ("9", "Custom OpenAI-Compatible", "", ""),
    ]
    for num, name, url, model in paid_providers:
        paid_table.add_row(num, name, url, model)
    console.print(paid_table)
    
    choice = Prompt.ask("Select provider", choices=["1","2","3","4","5","6","7","8","9"], default="1")
    
    provider_map = {
        "1": (AIProvider.GROQ_FREE, "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        "2": (AIProvider.GEMINI_FREE, "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.0-flash"),
        "3": (AIProvider.CEREBRAS_FREE, "https://api.cerebras.ai/v1", "llama-3.3-70b"),
        "4": (AIProvider.OPENROUTER_FREE, "https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct:free"),
        "5": (AIProvider.GROQ, "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        "6": (AIProvider.OPENAI, "https://api.openai.com/v1", "gpt-4o-mini"),
        "7": (AIProvider.GEMINI, "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.0-flash"),
        "8": (AIProvider.OPENROUTER, "https://openrouter.ai/api/v1", "auto"),
    }
    
    if choice in provider_map:
        provider, base_url, model = provider_map[choice]
        config.ai.provider = provider
        config.ai.base_url = base_url
        config.ai.model = model
    else:
        config.ai.provider = AIProvider.CUSTOM
        config.ai.base_url = Prompt.ask("Base URL").strip().strip('"').strip("'")
        config.ai.model = Prompt.ask("Model name").strip().strip('"').strip("'")
    
    key = Prompt.ask("API key (free keys from provider website)", password=True).strip().strip('"').strip("'")
    if key:
        config.ai.api_key = key
        config.ai.enabled = True
        config.save_ai()
        console.print(f"[green]Key saved. Masked: {config.ai.mask_key()}[/green]")
        console.print(f"[green]Provider: {config.ai.provider.value} | Model: {config.ai.model}[/green]")
    else:
        console.print("[yellow]No key provided. AI engine disabled.[/yellow]")


# ── Show case ──────────────────────────────────────────────────────

def show_case(case: Case) -> None:
    console.clear()
    logo()
    status_bar()
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Category", style="bold cyan")
    table.add_column("Count", style="bold yellow")
    table.add_column("Items")
    table.add_row("Usernames", str(len(case.usernames)),
                  ", ".join(case.usernames[:10]) or "-")
    table.add_row("Emails", str(len(case.emails)),
                  ", ".join(case.emails[:10]) or "-")
    table.add_row("Names", str(len(case.names)),
                  ", ".join(case.names[:10]) or "-")
    table.add_row("Clues", str(len(case.clues)),
                  ", ".join(str(c)[:20] for c in case.clues[:10]) or "-")
    table.add_row("Hits", str(len(case.hits)), f"Round {case.round}")
    table.add_row("Pivot log", str(len(case.pivot_log)), "-")
    table.add_row("Notes", str(len(case.notes)), "-")
    console.print(table)
    Prompt.ask("\nPress Enter to continue")


def _make_live_status_table(scan_manager: ScanManager, rnd: int, total_rounds: int, elapsed: float, total_hits: int) -> Table:
    """Build the live-updating tool status table."""
    table = Table(
        title=f"[bold cyan]ROUND {rnd}/{total_rounds} — Tool Status[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        expand=True,
        border_style="cyan",
    )
    table.add_column("Tool", style="bold white", width=18)
    table.add_column("Category", style="dim", width=10)
    table.add_column("Status", width=10)
    table.add_column("Hits", justify="right", width=6)
    table.add_column("Time", justify="right", width=8)
    table.add_column("Error", style="red", width=30, no_wrap=True, overflow="ellipsis")
    
    status_colors = {
        "PENDING": "[dim]⏳ PENDING[/dim]",
        "RUNNING": "[bold yellow]🔄 RUNNING[/bold yellow]",
        "OK": "[bold green]✅ OK[/bold green]",
        "FAIL": "[bold red]❌ FAIL[/bold red]",
        "SKIPPED": "[dim]⏭ SKIP[/dim]",
    }
    
    rows = scan_manager.get_status_rows()
    for r in rows:
        elapsed_str = f"{r['elapsed']:.1f}s" if r['elapsed'] > 0 else "-"
        table.add_row(
            r["name"],
            r["category"],
            status_colors.get(r["status"], r["status"]),
            str(r["hits"]) if r["hits"] > 0 else "-",
            elapsed_str,
            r["error"],
        )
    
    # Summary footer
    ok_count = sum(1 for r in rows if r["status"] == "OK")
    fail_count = sum(1 for r in rows if r["status"] == "FAIL")
    running_count = sum(1 for r in rows if r["status"] == "RUNNING")
    pending_count = sum(1 for r in rows if r["status"] == "PENDING")
    total_tools = len(rows)
    
    table.add_section()
    table.add_row(
        f"[bold]TOTAL: {total_tools} tools[/bold]",
        "",
        f"[green]{ok_count}✅[/green] [red]{fail_count}❌[/red] [yellow]{running_count}🔄[/yellow] [dim]{pending_count}⏳[/dim]",
        f"[bold]{total_hits}[/bold]",
        f"{elapsed:.0f}s",
        "",
    )
    
    return table


# ── Deep hunt ──────────────────────────────────────────────────────

def run_deep_hunt(case: Case) -> None:
    if case.is_empty():
        console.print("[bold red]Case is empty. Add identifiers first.[/bold red]")
        return

    if not check_disk(config.hunt.workspace, config.hunt.disk_warn_mb, config.hunt.disk_abort_mb):
        return

    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    scan_manager = ScanManager(config)
    pivot_engine = PivotEngine(config)
    evidence_collector = EvidenceCollector(config)
    confidence_engine = ConfidenceEngine()
    reporter = Reporter(config)
    ai_engine = AIEngine(config) if config.ai.enabled else None

    start_time = time.time()

    # Initialize dashboard
    dashboard.reset()
    dashboard.start_timer()
    dashboard.set_status("scanning")
    dashboard.set_identifiers(case.usernames, case.emails, case.names)
    dashboard.log(
        f"Deep hunt starting: {len(case.usernames)} usernames, "
        f"{len(case.emails)} emails, {len(case.names)} names",
        source="hunt",
    )

    console.print(f"[bold green]>> Userhunt deep hunt starting (rounds 1-{config.hunt.max_rounds})[/bold green]")
    console.print("[bold green]>> Dashboard: http://0.0.0.0:8000[/bold green]")

    # Run the scan inside a Rich Live display for the tool status table
    # The scan blocks the main thread — that's intentional so the Live table works
    with Live(console=console, refresh_per_second=2, screen=False) as live:
        # Show initial table with all tools PENDING
        live.update(_make_live_status_table(scan_manager, 1, config.hunt.max_rounds, 0, 0))

        for rnd in range(1, config.hunt.max_rounds + 1):
            case.round = rnd
            case.reset_round_caps()

            if ai_engine:
                ai_engine.reset_round()

            dashboard.set_round(rnd, config.hunt.max_rounds)
            dashboard.log(f"=== ROUND {rnd}/{config.hunt.max_rounds} ===", source="hunt")

            # ── Username hunt ──
            usernames = [u for u in case.usernames if u not in case.done_usernames]
            if usernames:
                dashboard.log(f"Scanning {len(usernames)} username(s)...", source="username")
                console.print(f">> deep username: {', '.join(usernames[:5])} (round {rnd}/{config.hunt.max_rounds})")
                round_hits = scan_manager.scan_usernames(usernames)
                for hit in round_hits:
                    case.add_hit(hit)
                for u in usernames:
                    case.done_usernames.add(u)
                dashboard.log(f"Username scan: {len(round_hits)} hits", source="username")
                # Update live table after each scanner category
                live.update(_make_live_status_table(scan_manager, rnd, config.hunt.max_rounds, time.time() - start_time, len(case.hits)))

            # ── Email hunt ──
            emails = [e for e in case.emails if e not in case.done_emails]
            if emails:
                dashboard.log(f"Scanning {len(emails)} email(s)...", source="email")
                console.print(f">> deep email: {', '.join(emails[:5])} (round {rnd}/{config.hunt.max_rounds})")
                round_hits = scan_manager.scan_emails(emails)
                for hit in round_hits:
                    case.add_hit(hit)
                for e in emails:
                    case.done_emails.add(e)
                dashboard.log(f"Email scan: {len(round_hits)} hits", source="email")
                live.update(_make_live_status_table(scan_manager, rnd, config.hunt.max_rounds, time.time() - start_time, len(case.hits)))

            # ── Name hunt ──
            names = [n for n in case.names if n not in case.done_names]
            if names:
                dashboard.log(f"Scanning {len(names)} name(s)...", source="name")
                console.print(f">> deep name: {', '.join(n[:20] for n in names[:3])} (round {rnd}/{config.hunt.max_rounds})")
                round_hits = scan_manager.scan_names(names)
                for hit in round_hits:
                    case.add_hit(hit)
                for n in names:
                    case.done_names.add(n)
                dashboard.log(f"Name scan: {len(round_hits)} hits", source="name")
                live.update(_make_live_status_table(scan_manager, rnd, config.hunt.max_rounds, time.time() - start_time, len(case.hits)))

            # ── Phone hunt (from pivot-extracted phones) ──
            phones = list(case.done_phones)
            if phones:
                dashboard.log(f"Scanning {len(phones)} phone(s)...", source="phone")
                round_hits = scan_manager.scan_phones(phones)
                for hit in round_hits:
                    case.add_hit(hit)
                dashboard.log(f"Phone scan: {len(round_hits)} hits", source="phone")
                live.update(_make_live_status_table(scan_manager, rnd, config.hunt.max_rounds, time.time() - start_time, len(case.hits)))

            # ── Domain hunt (from pivot-extracted domains) ──
            domains = list(case.done_domains)
            if domains:
                dashboard.log(f"Scanning {len(domains)} domain(s)...", source="domain")
                round_hits = scan_manager.scan_domains(domains)
                for hit in round_hits:
                    case.add_hit(hit)
                dashboard.log(f"Domain scan: {len(round_hits)} hits", source="domain")
                live.update(_make_live_status_table(scan_manager, rnd, config.hunt.max_rounds, time.time() - start_time, len(case.hits)))

            # ── Clue hunt ──
            if case.clues:
                round_hits = scan_manager.scan_clues(case.clues)
                for hit in round_hits:
                    case.add_hit(hit)

            # ── Update dashboard identifiers ──
            dashboard.set_identifiers(case.usernames, case.emails, case.names)

            # ── Evidence collection (link visitor) ──
            dashboard.log("Collecting evidence from hit pages...", source="evidence")
            console.print("   [dim]Collecting evidence from hit pages...[/dim]")
            evidence_collector.visit_links(case.hits, rnd)

            # ── Confidence scoring ──
            case.hits = confidence_engine.score(case.hits)

            # ── AI review ──
            if ai_engine:
                dashboard.log("AI reviewing scan results...", source="ai")
                console.print("   [dim]AI reviewing scan results...[/dim]")
                ai_engine.review_round(case, rnd)

            # ── Pivot extraction and queueing ──
            pivots = pivot_engine.extract_pivots(case, rnd)
            applied = pivot_engine.apply_pivots_to_case(case, pivots)

            # Log pivots to dashboard
            for p in pivots:
                p["time"] = time.time()
                dashboard.add_pivot(p)

            # Show applied pivots
            new_usernames = [p for p in applied if p.get("action") == "queue_username"]
            new_emails = [p for p in applied if p.get("action") == "queue_email"]
            new_phones = [p for p in applied if p.get("action") == "queue_phone"]
            new_domains = [p for p in applied if p.get("action") == "queue_domain"]

            if new_usernames or new_emails or new_phones or new_domains:
                dashboard.log(
                    f"Pivots applied: {len(new_usernames)} usernames, "
                    f"{len(new_emails)} emails, {len(new_phones)} phones, "
                    f"{len(new_domains)} domains",
                    source="pivot",
                )

            # Queue new phones/domains for next-round scanning
            for p in new_phones:
                val = p.get("found", "")
                if val and val not in case.done_phones:
                    case.done_phones.add(val)
            for p in new_domains:
                val = p.get("found", "")
                if val and val not in case.done_domains:
                    case.done_domains.add(val)

            elapsed = time.time() - start_time
            dashboard.log(
                f"Round {rnd} complete. {len(case.hits)} total hits. "
                f"{len(pivots)} pivots found. {elapsed:.1f}s elapsed.",
                source="hunt",
            )
            console.print(
                f"[dim]Round {rnd} complete. {len(case.hits)} total hits. "
                f"{len(pivots)} pivots found. {elapsed:.1f}s elapsed.[/dim]"
            )

            # Update case save
            case.save(ws / "data" / "case.json")

            if rnd < config.hunt.max_rounds:
                try:
                    if not Confirm.ask("Continue to next round?", default=True):
                        break
                except Exception:
                    break

    # ── Mark as done ──
    dashboard.set_status("done")
    dashboard.log(f"Deep hunt complete! {len(case.hits)} total hits.", source="hunt")

    # ── Final tool status table (outside Live, stays on screen) ──
    console.print()
    console.print("[bold cyan]═══ FINAL TOOL STATUS ═══[/bold cyan]")
    _print_final_status_table(scan_manager, case)

    # ── Purge temp files ──
    purge_temp_files(config.hunt.workspace)

    # ── Generate outputs ──
    json_path = output_dir / f"hunt_{timestamp}.json"
    pdf_path = output_dir / f"hunt_{timestamp}.pdf"

    reporter.generate_json(case, json_path)
    reporter.generate_pdf(case, pdf_path)

    console.print(f"[bold green]Hunt complete. {len(case.hits)} hits.[/bold green]")
    console.print(f"  JSON: {json_path}")
    console.print(f"  PDF:  {pdf_path}")
    console.print("[bold green]Dashboard still running at http://0.0.0.0:8000[/bold green]")


def _print_final_status_table(scan_manager: ScanManager, case: Case) -> None:
    """Print the final static tool status table after hunt completes."""
    table = Table(box=box.ROUNDED, show_header=True, expand=True, border_style="green")
    table.add_column("Tool", style="bold white", width=18)
    table.add_column("Category", style="dim", width=10)
    table.add_column("Status", width=10)
    table.add_column("Hits", justify="right", width=6)
    table.add_column("Time", justify="right", width=10)
    table.add_column("Error", style="red", width=30, no_wrap=True, overflow="ellipsis")
    
    status_map = {
        "PENDING": "[dim]⏳ PENDING[/dim]",
        "RUNNING": "[bold yellow]🔄 RUNNING[/bold yellow]",
        "OK": "[bold green]✅ OK[/bold green]",
        "FAIL": "[bold red]❌ FAIL[/bold red]",
        "SKIPPED": "[dim]⏭ SKIP[/dim]",
    }
    
    for r in scan_manager.get_status_rows():
        elapsed_str = f"{r['elapsed']:.1f}s" if r['elapsed'] > 0 else "-"
        table.add_row(
            r["name"],
            r["category"],
            status_map.get(r["status"], r["status"]),
            str(r["hits"]) if r["hits"] > 0 else "-",
            elapsed_str,
            r["error"],
        )
    
    rows = scan_manager.get_status_rows()
    ok_count = sum(1 for r in rows if r["status"] == "OK")
    fail_count = sum(1 for r in rows if r["status"] == "FAIL")
    total = len(rows)
    
    table.add_section()
    table.add_row(
        f"[bold]SUMMARY: {ok_count}/{total} OK, {fail_count} FAILED[/bold]",
        "", "", f"[bold]{len(case.hits)}[/bold]", "", "",
    )
    console.print(table)


# ── Rebuild profile ────────────────────────────────────────────────

def rebuild_profile(case: Case) -> None:
    if not case.hits and not case.profile_evidence:
        console.print("[yellow]No data to build profile.[/yellow]")
        return

    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    ai_engine = AIEngine(config) if config.ai.enabled else None
    if ai_engine:
        console.print("[dim]Building AI profile (includes image analysis)...[/dim]")
        profile = ai_engine.build_profile(case)
        if profile:
            case.ai_profile = profile

    if not case.ai_profile:
        case.ai_profile = _heuristic_profile(case)

    reporter = Reporter(config)
    pdf_path = reporter.generate_pdf(case, output_dir / f"profile_{timestamp}.pdf")
    console.print(f"[green]Profile rebuilt. PDF: {pdf_path}[/green]")


def _heuristic_profile(case: Case) -> str:
    """Build profile from case data without AI."""
    lines = ["Userhunt — OSINT Profile Summary (Heuristic)", "=" * 50, ""]
    if case.usernames:
        lines.append(f"Usernames: {', '.join(case.usernames[:20])}")
    if case.emails:
        lines.append(f"Emails: {', '.join(case.emails[:20])}")
    if case.names:
        lines.append(f"Names: {', '.join(case.names[:20])}")

    high = [h for h in case.hits if h.get("confidence") == "HIGH"]
    if high:
        lines.append(f"\nHigh-confidence hits ({len(high)}):")
        for h in high[:30]:
            has_img = "📷" if h.get("avatar_url") or h.get("images") else ""
            lines.append(f"  - {h.get('platform', '?')}: {h.get('url', '?')} {has_img}")

    evidence_with_images = [h for h in case.hits if h.get("avatar_url")]
    if evidence_with_images:
        lines.append(f"\nProfile images found on {len(evidence_with_images)} platform(s):")
        for h in evidence_with_images[:10]:
            lines.append(f"  - {h.get('platform', '?')}: {h.get('avatar_url', '')}")

    return "\n".join(lines)


# ── Export ─────────────────────────────────────────────────────────

def export_json(case: Case) -> None:
    ws = config.hunt.workspace
    output_dir = ws / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"export_{timestamp}.json"
    reporter = Reporter(config)
    reporter.generate_json(case, path)
    console.print(f"[green]Exported to {path}[/green]")


# ── Clear case ─────────────────────────────────────────────────────

def clear_case(case: Case) -> None:
    if Confirm.ask("Clear all case data?", default=False):
        case.clear()
        import shutil
        ws = config.hunt.workspace
        for d in ["output", "data"]:
            p = ws / d
            if p.exists():
                try:
                    shutil.rmtree(p)
                except Exception:
                    pass
        console.print("[yellow]Case cleared.[/yellow]")


# ── Tool registry ──────────────────────────────────────────────────

def tool_registry() -> None:
    console.clear()
    logo()
    status_bar()
    sm = ScanManager(config)
    tools = sm.registry()
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status", style="bold yellow")
    table.add_column("Description")
    for name, status, desc in tools:
        if status == "READY":
            color = "green"
        elif status == "BEST-EFFORT":
            color = "yellow"
        elif status == "NOT-INSTALLED":
            color = "red"
        else:
            color = "white"
        table.add_row(name, f"[{color}]{status}[/{color}]", desc)
    console.print(table)
    Prompt.ask("\nPress Enter to continue")


# ── Pivot log ──────────────────────────────────────────────────────

def pivot_log_view(case: Case) -> None:
    pivots = case.pivot_log.as_list() if hasattr(case.pivot_log, "as_list") else list(case.pivot_log)
    if not pivots:
        console.print("[dim]Pivot log is empty.[/dim]")
        return
    table = Table(box=box.ROUNDED, show_header=True, expand=True)
    table.add_column("Round", style="bold cyan", width=6)
    table.add_column("Source", width=12)
    table.add_column("Found", width=30)
    table.add_column("Action", width=15)
    table.add_column("Reason", width=25)
    table.add_column("By", width=5)
    for entry in pivots[-50:]:
        table.add_row(
            str(entry.get("round", "?")),
            (entry.get("source", "?"))[:12],
            (entry.get("found", "?"))[:30],
            entry.get("action", "?"),
            (entry.get("reason", "?"))[:25],
            entry.get("by", "?"),
        )
    console.print(table)
    Prompt.ask("\nPress Enter to continue")


def _auto_hunt_prompt(case: Case, save_path: Path) -> None:
    """After adding identifiers, offer to start the deep hunt immediately."""
    count = len(case.usernames) + len(case.emails) + len(case.names)
    console.print(
        f"\n[bold cyan]Ready to hunt {count} identifier(s) across all tools:[/bold cyan]"
    )
    console.print("[dim]  Sherlock, Maigret, Blackbird, Nexfil, WhatsMyName, direct probes,[/dim]")
    console.print("[dim]  Holehe, Gravatar, emailrep, phonenumbers, phoneinfoga, DNS, WHOIS...[/dim]")
    console.print("[dim]  Dashboard: http://0.0.0.0:8000[/dim]")
    try:
        if Confirm.ask("\n[bold green]Start deep scan now?[/bold green]", default=True):
            case.save(save_path)
            run_deep_hunt(case)
    except Exception:
        pass


# ── Web dashboard startup ──────────────────────────────────────────

def _start_dashboard() -> None:
    """Start the live web dashboard in a background thread."""
    try:
        from userhunt.web.server import start_server_thread
        t = start_server_thread(host="0.0.0.0", port=8000)
        dashboard.log("Dashboard started at http://0.0.0.0:8000", source="system")
        console.print("[green]Dashboard running at http://0.0.0.0:8000[/green]")
        return t
    except Exception as e:
        console.print(f"[yellow]Dashboard failed to start: {e}[/yellow]")
        return None


# ── Click entry point ──────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--deep", is_flag=True, help="Run deep scan on saved case and exit")
@click.option("-u", "usernames", multiple=True, help="Usernames to hunt (can repeat)")
@click.option("-e", "emails", multiple=True, help="Emails to hunt (can repeat)")
@click.option("-n", "names", multiple=True, help="Full names to hunt (can repeat)")
@click.option("--timeout", "tool_timeout", type=int, default=None,
              help="Tool timeout in seconds (0=no timeout, default=0)")
@click.option("--no-dashboard", is_flag=True, help="Disable web dashboard")
@click.pass_context
def main(ctx: click.Context, deep: bool, usernames: tuple, emails: tuple, names: tuple,
         tool_timeout: int | None, no_dashboard: bool) -> None:
    """Userhunt CLI — Autonomous AI-powered OSINT toolkit.

    Default action is deep scan. Use --deep with -u/-e/-n flags for
    non-interactive mode, or run without flags for the interactive menu.
    Dashboard: http://0.0.0.0:8000

    Tools run with no timeout by default (0 = wait forever).
    Use --timeout N to limit each tool to N seconds.
    """
    if ctx.invoked_subcommand is not None:
        return

    config.load()

    # Apply CLI timeout override
    if tool_timeout is not None:
        config.hunt.tool_timeout = tool_timeout
        config.save_hunt()

    # Start dashboard (unless disabled)
    if not no_dashboard:
        _start_dashboard()

    # Non-interactive deep scan mode
    if deep or usernames or emails or names:
        case = Case(
            max_hits=config.hunt.max_hits,
            max_pivot_log=config.hunt.max_pivot_log,
            max_notes=config.hunt.max_notes,
        )
        ws = config.hunt.workspace
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "tools").mkdir(parents=True, exist_ok=True)
        (ws / "output").mkdir(parents=True, exist_ok=True)
        (ws / "data").mkdir(parents=True, exist_ok=True)

        save_path = ws / "data" / "case.json"
        if save_path.exists():
            case.load(save_path)

        marker = ws / ".installed"
        if not marker.exists():
            _install_phase(ws, marker)

        for u in usernames:
            case.add_username(u)
        for e in emails:
            case.add_email(e)
        for n in names:
            case.names.append(n)

        if not case.is_empty():
            timeout_str = "none" if config.hunt.tool_timeout == 0 else f"{config.hunt.tool_timeout}s"
            console.print(f"[bold green]Starting deep scan with {len(case.usernames)} usernames, {len(case.emails)} emails, {len(case.names)} names[/bold green]")
            console.print(f"[dim]Tool timeout: {timeout_str} | Dashboard: http://0.0.0.0:8000[/dim]")
            run_deep_hunt(case)
            case.save(save_path)
        else:
            console.print("[yellow]No identifiers to hunt. Use -u, -e, -n flags or run interactively.[/yellow]")
        return

    run_interactive()


# ── Clean command ──────────────────────────────────────────────────

@main.command()
@click.option("--deep", is_flag=True, help="Remove ALL workspace data including tools")
def clean(deep: bool) -> None:
    """Clean workspace to free disk space.

    Default: removes output files, temp data, and case state.
    --deep: also removes cloned OSINT tools (requires re-download on next run).
    """
    import shutil
    ws = config.hunt.workspace
    if not ws.exists():
        console.print("[dim]No workspace found.[/dim]")
        return

    freed = 0
    dirs_to_clean = []

    if deep:
        dirs_to_clean = ["output", "data", "tools"]
        console.print("[bold yellow]DEEP CLEAN: removing tools, output, and data...[/bold yellow]")
    else:
        dirs_to_clean = ["output", "data"]
        console.print("[yellow]Cleaning output and data (tools preserved)...[/yellow]")

    for d in dirs_to_clean:
        p = ws / d
        if p.exists():
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            shutil.rmtree(p, ignore_errors=True)
            freed += size
            console.print(f"  [green]✓ Removed {d}/ ({size / 1024 / 1024:.1f} MB)[/green]")

    # Clean __pycache__
    for pycache in ws.rglob("__pycache__"):
        size = sum(f.stat().st_size for f in pycache.rglob("*") if f.is_file())
        shutil.rmtree(pycache, ignore_errors=True)
        freed += size

    # Recreate dirs
    for d in ["output", "data", "tools"]:
        (ws / d).mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold green]Freed {freed / 1024 / 1024:.1f} MB[/bold green]")
    if deep:
        console.print("[dim]Tools removed. They will be re-downloaded on next run.[/dim]")


# ── Upgrade command ────────────────────────────────────────────────

@main.command()
def upgrade() -> None:
    """Upgrade Userhunt CLI to the latest version from GitHub."""
    from userhunt import __version__
    console.print(f"[cyan]Current version: {__version__}[/cyan]")
    console.print("[dim]Checking for updates...[/dim]")

    try:
        import subprocess
        # Fetch latest from origin
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        )
        repo_url = result.stdout.strip()
        console.print(f"[dim]Repository: {repo_url}[/dim]")

        # Fetch and check for new commits
        result = subprocess.run(
            ["git", "fetch", "origin"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            console.print(f"[red]Fetch failed: {result.stderr}[/red]")
            return

        # Check if we're behind
        result = subprocess.run(
            ["git", "rev-list", "HEAD..origin/main", "--count"],
            capture_output=True, text=True, timeout=10,
        )
        behind = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0

        if behind == 0:
            console.print("[green]Already up to date![/green]")
            return

        console.print(f"[yellow]{behind} new commit(s) available.[/yellow]")
        if not Confirm.ask("Pull update now?", default=True):
            return

        # Pull
        with console.status("[bold green]Pulling updates..."):
            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                capture_output=True, text=True, timeout=60,
            )

        if result.returncode == 0:
            console.print("[green]Pulled successfully![/green]")

            # Reinstall if needed
            if Confirm.ask("Reinstall package?", default=True):
                with console.status("[bold green]Reinstalling..."):
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-e", ".", "--quiet"],
                        capture_output=True, text=True, timeout=120,
                    )
                if result.returncode == 0:
                    console.print("[green]Reinstalled successfully![/green]")
                else:
                    console.print(f"[yellow]Reinstall warning: {result.stderr[:200]}[/yellow]")

            # Show new version
            result = subprocess.run(
                [sys.executable, "-c", "from userhunt import __version__; print(__version__)"],
                capture_output=True, text=True, timeout=10,
            )
            new_ver = result.stdout.strip() or "unknown"
            console.print(f"[bold green]Updated to v{new_ver}![/bold green]")
        else:
            console.print(f"[red]Pull failed: {result.stderr}[/red]")

    except Exception as e:
        console.print(f"[red]Upgrade failed: {e}[/red]")
        console.print("[dim]Manual upgrade: git pull origin main && pip install -e .[/dim]")


def run_interactive() -> None:
    """Main interactive loop."""
    config.load()
    case = Case(
        max_hits=config.hunt.max_hits,
        max_pivot_log=config.hunt.max_pivot_log,
        max_notes=config.hunt.max_notes,
    )
    ws = config.hunt.workspace
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "tools").mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(parents=True, exist_ok=True)
    (ws / "data").mkdir(parents=True, exist_ok=True)

    save_path = ws / "data" / "case.json"
    if save_path.exists():
        case.load(save_path)

    # First-run install
    marker = ws / ".installed"
    if not marker.exists():
        _install_phase(ws, marker)

    if config.ai.enabled:
        console.print(
            f"[green]AI engine ready. Provider: {config.ai.provider.value} | "
            f"Model: {config.ai.model}[/green]"
        )
    else:
        console.print("[dim]AI engine off. Option [12] enables it. Hunt runs deterministic.[/dim]")

    while True:
        try:
            menu()
            choice = Prompt.ask(
                "\nSelect option",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
                default="6",
            )
        except Exception:
            choice = "6"

        if choice == "0":
            case.save(save_path)
            console.print("[yellow]Goodbye.[/yellow]")
            sys.exit(0)
        elif choice == "1":
            items = parse_multi_line("Enter usernames:")
            for item in items:
                case.add_username(item)
            console.print(f"[green]Added {len(items)} usernames.[/green]")
            if items and not case.is_empty():
                _auto_hunt_prompt(case, save_path)
        elif choice == "2":
            items = parse_multi_line("Enter emails:")
            for item in items:
                case.add_email(item)
            console.print(f"[green]Added {len(items)} emails.[/green]")
            if items and not case.is_empty():
                _auto_hunt_prompt(case, save_path)
        elif choice == "3":
            items = parse_multi_line("Enter full names:")
            case.names.extend(items)
            console.print(f"[green]Added {len(items)} names.[/green]")
            if items and not case.is_empty():
                _auto_hunt_prompt(case, save_path)
        elif choice == "4":
            items = parse_multi_line("Enter extra clues:")
            routed = route_clues(items)
            for email in routed["emails"]:
                case.add_email(email)
            for username in routed["usernames"]:
                case.add_username(username)
            case.clues.extend(items)
            total = sum(len(v) for v in routed.values())
            console.print(f"[green]Added {len(items)} clues ({total} routed identifiers).[/green]")
            if items and not case.is_empty():
                _auto_hunt_prompt(case, save_path)
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


def _install_phase(ws: Path, marker: Path) -> None:
    """First-run installation: pip packages and git clone tools."""
    if not check_disk(ws, config.hunt.disk_warn_mb, config.hunt.disk_abort_mb):
        sys.exit(1)

    console.print("[bold yellow]First run — installing dependencies and tools...[/bold yellow]")

    # pip packages
    packages = [
        "requests", "aiohttp", "colorama", "rich", "reportlab",
        "beautifulsoup4", "lxml", "requests-futures", "PySocks",
        "chardet", "phonenumbers", "dnspython", "python-whois",
        "exifread", "Pillow", "click", "pydantic", "tenacity",
        "python-dotenv", "geopy", "playwright",
    ]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Installing pip packages...", total=len(packages))
        for pkg in packages:
            progress.update(task, description=f"Installing {pkg}...")
            try:
                import subprocess
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    check=False, capture_output=True, timeout=120,
                )
            except Exception:
                pass
            progress.advance(task)

    # Git clone tools
    repos = {
        "sherlock": "https://github.com/sherlock-project/sherlock.git",
        "maigret": "https://github.com/soxoj/maigret.git",
        "blackbird": "https://github.com/p1ngul1n0/blackbird.git",
        "nexfil": "https://github.com/thewhiteh4t/nexfil.git",
        "WhatsMyName": "https://github.com/WebBreacher/WhatsMyName.git",
        "holehe": "https://github.com/megadose/holehe.git",
        "social-analyzer": "https://github.com/qeeqbox/social-analyzer.git",
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
        "recon-ng": "https://github.com/lanmaster53/recon-ng.git",
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
        "SpiderFoot": "Run: python3 sf.py -l 127.0.0.1:5001 (local web UI — managed by Playwright)",
        "recon-ng": "Run: recon-ng",
        "theHarvester": "Run: python3 theHarvester.py -d target.com",
        "finalrecon": "Run: python3 finalrecon.py --full https://target.com",
        "OneForAll": "Run: python3 oneforall.py --target target.com",
    }

    tools_dir = ws / "tools"
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Cloning OSINT tools...", total=len(repos))
        for name, url in repos.items():
            progress.update(task, description=f"Cloning {name}...")
            dest = tools_dir / name
            if not dest.exists():
                try:
                    import subprocess
                    subprocess.run(
                        ["git", "clone", "--depth", "1", url, str(dest)],
                        check=False, capture_output=True, timeout=180,
                    )
                    req = dest / "requirements.txt"
                    if req.exists():
                        try:
                            subprocess.run(
                                [sys.executable, "-m", "pip", "install", "-r", str(req), "--quiet"],
                                check=False, capture_output=True, timeout=180,
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            progress.advance(task)

    # Install Playwright Chromium
    console.print("[dim]Installing Playwright Chromium for browser-based tools...[/dim]")
    try:
        import subprocess
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=False, capture_output=True, timeout=300,
        )
    except Exception:
        pass

    # Write manual tools hints
    hints_path = tools_dir / "manual_tools.txt"
    with open(hints_path, "w") as f:
        f.write("Manual tool launch hints:\n")
        for tool, hint in tool_hints.items():
            f.write(f"  {tool}: {hint}\n")

    marker.touch()
    console.print("[bold green]Installation complete.[/bold green]")


if __name__ == "__main__":
    main()
