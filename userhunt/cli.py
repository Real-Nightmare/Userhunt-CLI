"""
Userhunt CLI — main entry point and interactive menu.
Autonomous AI-powered OSINT toolkit with deep hunt engine.
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
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

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
║        Autonomous AI-Powered OSINT Toolkit v2.1          ║
║                    Deep Hunt Engine                       ║
╚══════════════════════════════════════════════════════════╝
[/bold cyan]"""
    console.print(Panel(art, border_style="cyan", padding=(0, 1)))


def status_bar() -> None:
    ws = config.hunt.workspace
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    
    # Show built-in free providers
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
    
    # Paid / custom options
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
    console.print(f"[bold green]>> Userhunt deep hunt starting (rounds 1-{config.hunt.max_rounds})[/bold green]")

    for rnd in range(1, config.hunt.max_rounds + 1):
        case.round = rnd
        case.reset_round_caps()

        if ai_engine:
            ai_engine.reset_round()

        console.print(f"[bold cyan]=== ROUND {rnd}/{config.hunt.max_rounds} ===[/bold cyan]")

        # ── Username hunt ──
        usernames = [u for u in case.usernames if u not in case.done_usernames]
        if usernames:
            console.print(f">> deep username: {', '.join(usernames[:5])} (round {rnd}/{config.hunt.max_rounds})")
            round_hits = scan_manager.scan_usernames(usernames)
            for hit in round_hits:
                if not case.can_add_hit():
                    break
                case.add_hit(hit)
            for u in usernames:
                case.done_usernames.add(u)
            console.print(f"   [dim]Username scan: {len(round_hits)} hits[/dim]")

        # ── Email hunt ──
        emails = [e for e in case.emails if e not in case.done_emails]
        if emails:
            console.print(f">> deep email: {', '.join(emails[:5])} (round {rnd}/{config.hunt.max_rounds})")
            round_hits = scan_manager.scan_emails(emails)
            for hit in round_hits:
                if not case.can_add_hit():
                    break
                case.add_hit(hit)
            for e in emails:
                case.done_emails.add(e)
            console.print(f"   [dim]Email scan: {len(round_hits)} hits[/dim]")

        # ── Name hunt ──
        names = [n for n in case.names if n not in case.done_names]
        if names:
            console.print(f">> deep name: {', '.join(n[:20] for n in names[:3])} (round {rnd}/{config.hunt.max_rounds})")
            round_hits = scan_manager.scan_names(names)
            for hit in round_hits:
                if not case.can_add_hit():
                    break
                case.add_hit(hit)
            for n in names:
                case.done_names.add(n)
            console.print(f"   [dim]Name scan: {len(round_hits)} hits[/dim]")

        # ── Clue hunt ──
        if case.clues:
            round_hits = scan_manager.scan_clues(case.clues)
            for hit in round_hits:
                if not case.can_add_hit():
                    break
                case.add_hit(hit)
            console.print(f"   [dim]Clue scan: {len(round_hits)} hits[/dim]")

        # ── Evidence collection (link visitor) ──
        console.print("   [dim]Collecting evidence from hit pages...[/dim]")
        evidence_collector.visit_links(case.hits, rnd)

        # ── Confidence scoring ──
        case.hits = confidence_engine.score(case.hits)

        # ── AI review ──
        if ai_engine:
            console.print("   [dim]AI reviewing scan results...[/dim]")
            ai_engine.review_round(case, rnd)

        # ── Pivot extraction and queueing ──
        pivots = pivot_engine.extract_pivots(case, rnd)
        applied = pivot_engine.apply_pivots_to_case(case, pivots)
        case.pivot_log.extend(pivots)

        elapsed = time.time() - start_time
        console.print(
            f"[dim]Round {rnd} complete. {len(case.hits)} total hits. "
            f"{len(pivots)} pivots found. {elapsed:.1f}s elapsed.[/dim]"
        )

        if rnd < config.hunt.max_rounds:
            try:
                if not Confirm.ask("Continue to next round?", default=True):
                    break
            except Exception:
                break

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
    try:
        if Confirm.ask("\n[bold green]Start deep scan now?[/bold green]", default=True):
            case.save(save_path)
            run_deep_hunt(case)
    except Exception:
        pass


# ── Click entry point ──────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--deep", is_flag=True, help="Run deep scan on saved case and exit")
@click.option("-u", "usernames", multiple=True, help="Usernames to hunt (can repeat)")
@click.option("-e", "emails", multiple=True, help="Emails to hunt (can repeat)")
@click.option("-n", "names", multiple=True, help="Full names to hunt (can repeat)")
@click.pass_context
def main(ctx: click.Context, deep: bool, usernames: tuple, emails: tuple, names: tuple) -> None:
    """Userhunt CLI — Autonomous AI-powered OSINT toolkit.

    Default action is deep scan. Use --deep with -u/-e/-n flags for
    non-interactive mode, or run without flags for the interactive menu.
    """
    if ctx.invoked_subcommand is not None:
        return

    # Non-interactive deep scan mode
    if deep or usernames or emails or names:
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
            console.print(f"[bold green]Starting deep scan with {len(case.usernames)} usernames, {len(case.emails)} emails, {len(case.names)} names[/bold green]")
            run_deep_hunt(case)
            case.save(save_path)
        else:
            console.print("[yellow]No identifiers to hunt. Use -u, -e, -n flags or run interactively.[/yellow]")
        return

    run_interactive()


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
