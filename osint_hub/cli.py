"""OSINT-HUB Command-Line Interface.

Commands:
  osint-hub scan <input> [--include-dorks] [--no-browser] [--i-have-consent] [--types ...] [--limit N]
  osint-hub serve [--port 8000]
  osint-hub db stats
  osint-hub db init [--force]
"""

from __future__ import annotations

import datetime
import hashlib
import sys
from pathlib import Path
from typing import List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel

from osint_hub.classify import classify_target, requires_confirmation
from osint_hub.executors import OSINTExecutor
from osint_hub.parse import get_db_stats, init_db, seed_db
from osint_hub.report import OSINTReporter
from osint_hub.router import route_target

app = typer.Typer(
    name="osint-hub",
    help="osint-hub: Automated OSINT aggregation, routing, and intelligence platform.",
    add_completion=False,
)
db_app = typer.Typer(name="db", help="Manage the local SQLite catalogue database.")
app.add_typer(db_app, name="db")

import os
console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = Path(os.getenv("ARSENAL_LOGS_DIR", str(PROJECT_ROOT / "logs")))
AUDIT_LOG_PATH = LOGS_DIR / "audit.log"


def log_audit_event(
    target: str,
    target_type: str,
    auto_open_count: int,
    api_hit_count: int,
    manual_count: int,
    skipped_count: int,
) -> None:
    """Append audit trail event with SHA-256 hashed target for privacy."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    target_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
    ts = datetime.datetime.now().isoformat()
    log_line = (
        f"{ts} | SHA256:{target_hash} | TYPE:{target_type} | "
        f"AUTO_OPEN:{auto_open_count} | API_HITS:{api_hit_count} | "
        f"MANUAL:{manual_count} | SKIPPED:{skipped_count}\n"
    )
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(log_line)


def verify_consent(i_have_consent: bool) -> bool:
    """Enforce authorization and consent banner before proceeding with OSINT reconnaissance."""
    if i_have_consent:
        return True

    banner_text = (
        "[bold red]⚠ OSINT-HUB AUTHORIZATION & INVESTIGATIVE CONSENT BANNER[/]\n\n"
        "[white]You are about to query public OSINT intelligence data sources, search engines, "
        "and investigative databases. By proceeding, you certify that you have lawful authorization, "
        "legitimate investigative mandate, or explicit consent to query these identifiers.[/]\n\n"
        "[dim](Tip: Use [bold cyan]--i-have-consent[/] on the command line to acknowledge this automatically.)[/]"
    )
    console.print(Panel(banner_text, border_style="red"))
    proceed = typer.confirm("Do you certify lawful mandate and consent to run this investigation?", default=False)
    return proceed


@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="The target indicator (domain, IP, email, username, phone, crypto address, hash, etc.)"),
    include_dorks: bool = typer.Option(False, "--include-dorks", "-d", help="Include Google Dork [D] entries."),
    no_browser: bool = typer.Option(False, "--no-browser", "-n", help="Do not auto-open URLs in browser (CLI/report only)."),
    i_have_consent: bool = typer.Option(False, "--i-have-consent", "-c", help="Certify lawful authorization and consent."),
    types: Optional[List[str]] = typer.Option(None, "--types", "-t", help="Force specific typology override (e.g. username, domain)."),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit number of auto-opened URLs."),
) -> None:
    """Run full automated OSINT investigation for a given target indicator."""
    if not verify_consent(i_have_consent):
        rprint("[bold red]Scan aborted by user. Lawful consent required to proceed.[/]")
        raise typer.Exit(code=1)

    # Ensure database is seeded
    seed_db()

    # 1. Classification
    if types and len(types) > 0:
        det_type = types[0].lower().strip()
        norm_val = target.strip()
        confidence = 1.0
        rprint(f"[bold cyan]Typology manually forced by user:[/] [bold green]{det_type}[/]")
    else:
        det_type, norm_val, confidence = classify_target(target)
        if requires_confirmation(confidence):
            rprint(
                f"[bold yellow]⚠ Low classification confidence ({confidence*100:.1f}%):[/] "
                f"Detected as [bold cyan]{det_type}[/] for '[bold white]{target}[/]'."
            )
            confirm = typer.confirm(f"Proceed with type '{det_type}'?", default=True)
            if not confirm:
                det_type = typer.prompt(
                    "Enter target typology (username, email, phone, domain, ipv4, ipv6, mac, url, image_file, hash, person_name, company, crypto_addr)",
                    default="unknown",
                )

    rprint(f"[bold green]✓ Target classified as:[/] [bold cyan]{det_type}[/] (Confidence: {confidence*100:.1f}%)")

    # 2. Routing
    plan = route_target(
        target=norm_val,
        target_type=det_type,
        confidence=confidence,
        include_dorks=include_dorks,
        limit=limit,
    )

    # 3. Execution (Phase B API Hits & Phase A Browser Dispatch)
    executor = OSINTExecutor(no_browser=no_browser)
    with console.status("[bold cyan]Executing Phase B automated API enrichment...[/]", spinner="dots"):
        api_results = executor.execute_phase_b(
            target=norm_val,
            target_type=det_type,
            planned_apis=plan.api_hits_planned,
        )

    # Phase A: Browser auto-open
    opened_count = 0
    if not no_browser and plan.auto_open:
        urls_to_open = [item.populated_url for item in plan.auto_open]
        opened_count = executor.execute_phase_a(urls_to_open, max_open=limit or 15)

    # 4. Reporting
    reporter = OSINTReporter()
    reporter.print_terminal_report(plan, api_results=api_results, opened_count=opened_count)

    json_path = reporter.export_json_report(plan, api_results=api_results, opened_count=opened_count)
    html_path = reporter.export_html_report(plan, api_results=api_results, opened_count=opened_count)

    rprint(f"\n[bold green]✓ Dossier Reports Exported Successfully:[/]")
    rprint(f"  • JSON: [cyan]{json_path}[/]")
    rprint(f"  • HTML: [cyan]{html_path}[/]")

    # 5. Audit Logging
    log_audit_event(
        target=norm_val,
        target_type=det_type,
        auto_open_count=len(plan.auto_open),
        api_hit_count=len(api_results),
        manual_count=len(plan.manual_followups),
        skipped_count=len(plan.skipped),
    )


@app.command("serve")
def serve_command(
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind web server to."),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind to."),
) -> None:
    """Launch the interactive OSINT-HUB Web UI dashboard."""
    import uvicorn
    from osint_hub.web import create_app

    seed_db()
    rprint(f"[bold cyan]⚡ Launching OSINT-HUB Web Dashboard on http://{host}:{port}...[/]")
    web_app = create_app()
    uvicorn.run(web_app, host=host, port=port, log_level="info")


@db_app.command("stats")
def db_stats_command() -> None:
    """Display SQLite catalogue database metrics and category distribution."""
    seed_db()
    stats = get_db_stats()

    console.print(Panel(
        f"[bold white]Total Tools:[/] [bold green]{stats['total_tools']}[/]  |  "
        f"[bold white]Sections:[/] [bold cyan]{stats['total_sections']}[/]  |  "
        f"[bold white]Unverified Sources:[/] [bold yellow]{stats['unverified_count']}[/]\n"
        f"[bold white]Flags Breakdown:[/] {stats['flags_breakdown']}",
        title="[bold cyan]📊 OSINT Catalogue Database Telemetry[/]",
        border_style="cyan",
    ))

    # Show top sections
    from rich.table import Table
    table = Table(title="Catalogue Section Breakdown", border_style="cyan")
    table.add_column("Section Name", style="bold white")
    table.add_column("Indexed Tools", justify="right", style="green")

    for section, count in list(stats["sections"].items())[:15]:
        table.add_row(section, str(count))

    console.print(table)


@db_app.command("init")
def db_init_command(
    force: bool = typer.Option(False, "--force", "-f", help="Force re-seed even if database exists."),
) -> None:
    """Initialize or re-seed the SQLite tools database from raw catalogue."""
    count = seed_db(force=force)
    rprint(f"[bold green]✓ Database initialized successfully with {count} tools.[/]")


if __name__ == "__main__":
    app()
