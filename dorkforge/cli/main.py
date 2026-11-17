from __future__ import annotations
import asyncio
import sys
import time
from pathlib import Path
from typing import List, Optional

# Ensure Windows console uses UTF-8 and does not crash on unicode glyphs
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ..models import DorkQuery, SearchResult, RunSummary, DorkTemplate
from ..audit import print_disclaimer, validate_authorization, log_audit_event
from ..config import load_config, save_config, get_config_path
from ..generator.engine import DorkGenerator
from ..generator.templates import template_registry
from ..engines import EngineDispatcher
from ..reporters import export_all, export_json, export_csv, export_markdown, export_html, export_sqlite

app = typer.Typer(
    name="dorkforge",
    help="⚡ DorkForge: Automated Multi-Engine Google Dorking & OSINT Reconnaissance Framework.",
    add_completion=False
)
templates_app = typer.Typer(help="Manage dork templates (list, add, remove).")
app.add_typer(templates_app, name="templates")

console = Console()

@app.callback()
def main_callback():
    """DorkForge OSINT Framework Callback."""
    pass

@app.command(name="disclaimer")
def show_disclaimer():
    """Print the legal and ethical authorization disclaimer."""
    print_disclaimer()

@app.command(name="generate")
def generate_dorks(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by template category"),
    keywords: Optional[List[str]] = typer.Option(None, "--keyword", "-k", help="Custom keywords"),
    filetypes: Optional[List[str]] = typer.Option(None, "--ext", "-e", help="Custom extensions/filetypes"),
    inurl: Optional[List[str]] = typer.Option(None, "--inurl", help="inurl terms"),
    intext: Optional[List[str]] = typer.Option(None, "--intext", help="intext terms"),
    intitle: Optional[List[str]] = typer.Option(None, "--intitle", help="intitle terms"),
    custom_op: Optional[List[str]] = typer.Option(None, "--operator", "-o", help="Raw custom operator strings"),
    dedupe: bool = typer.Option(True, "--dedupe/--no-dedupe", help="Deduplicate generated queries"),
    shuffle: bool = typer.Option(False, "--shuffle", "-s", help="Randomize query order"),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit number of generated queries"),
    output: Optional[Path] = typer.Option(None, "--output", help="Write generated queries to text file")
):
    """Generate combinatorial dork queries without executing them."""
    generator = DorkGenerator()
    queries = generator.generate(
        domain=domain,
        category=category,
        keywords=keywords,
        filetypes=filetypes,
        inurl=inurl,
        intext=intext,
        intitle=intitle,
        custom_operators=custom_op,
        dedupe=dedupe,
        shuffle=shuffle,
        limit=limit
    )

    log_audit_event("GENERATE", domain, f"Generated {len(queries)} dork queries (Category: {category or 'ALL'})")

    console.print(f"\n[bold cyan]⚡ DorkForge Generated [bold green]{len(queries)}[/bold green] Dork Queries for [bold yellow]{domain}[/bold yellow]:[/bold cyan]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Category", style="cyan", width=24)
    table.add_column("Dork Query Expression", style="white")

    for idx, q in enumerate(queries, 1):
        table.add_row(str(idx), q.category, q.query)

    console.print(table)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            for q in queries:
                f.write(f"{q.query}\n")
        console.print(f"\n[bold green]✓[/bold green] Exported {len(queries)} queries to [bold]{output}[/bold]\n")

@app.command(name="run")
def run_dorks(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by template category"),
    engines: Optional[List[str]] = typer.Option(None, "--engine", help="Search engines (google, bing, duckduckgo, brave, yandex)"),
    keywords: Optional[List[str]] = typer.Option(None, "--keyword", "-k", help="Custom keywords"),
    filetypes: Optional[List[str]] = typer.Option(None, "--ext", "-e", help="Custom extensions"),
    limit_per_query: int = typer.Option(5, "--limit", "-l", help="Max results per dork query"),
    max_dorks: Optional[int] = typer.Option(20, "--max-dorks", help="Maximum dorks to execute"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Output queries without sending HTTP requests"),
    authorized: bool = typer.Option(False, "--i-have-authorization", help="Certify explicit legal authorization to audit target"),
    output_dir: Optional[Path] = typer.Option(None, "--outdir", "-o", help="Directory to save report exports")
):
    """Generate and execute dorks across configured search engines."""
    # 1. Enforce safety & ethics authorization
    validate_authorization(domain, authorized=authorized, dry_run=dry_run)

    cfg = load_config()
    target_engines = engines or cfg.default_engines

    # 2. Generate queries
    generator = DorkGenerator()
    queries = generator.generate(
        domain=domain,
        category=category,
        keywords=keywords,
        filetypes=filetypes,
        limit=max_dorks
    )

    if not queries:
        console.print("[yellow]No dork queries generated matching criteria.[/yellow]")
        return

    console.print(f"\n[bold cyan]🎯 Target Domain:[/bold cyan] [bold yellow]{domain}[/bold yellow]")
    console.print(f"[bold cyan]🔍 Engines Configured:[/bold cyan] {', '.join(target_engines)}")
    console.print(f"[bold cyan]📋 Dorks to Execute:[/bold cyan] {len(queries)}\n")

    if dry_run:
        console.print(Panel(
            "\n".join([f"{i}. [dim]{q.category}:[/dim] {q.query}" for i, q in enumerate(queries, 1)]),
            title="[bold yellow]DRY RUN MODE (No HTTP Requests Sent)[/bold yellow]",
            border_style="yellow"
        ))
        log_audit_event("DRY_RUN", domain, f"Dry-run executed for {len(queries)} queries")
        return

    log_audit_event("EXECUTION_START", domain, f"Starting run: {len(queries)} dorks on {','.join(target_engines)}")

    # 3. Multi-Engine Dispatcher
    dispatcher = EngineDispatcher(engines=target_engines, config=cfg)
    all_findings: List[SearchResult] = []
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Executing dorks...", total=len(queries))

        for q in queries:
            progress.update(task, description=f"Querying: {q.query[:40]}...")
            try:
                # Async query execution
                findings = asyncio.run(dispatcher.execute_query(q, limit_per_engine=limit_per_query))
                all_findings.extend(findings)
            except Exception as e:
                pass
            progress.advance(task)

    dwell = time.time() - start_time
    from ..parsers.normalizer import deduplicate_results
    unique_findings = deduplicate_results(all_findings)

    # 4. Generate Summary Metrics
    cat_counts = {}
    eng_counts = {}
    for f in unique_findings:
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        eng_counts[f.engine] = eng_counts.get(f.engine, 0) + 1

    summary = RunSummary(
        target_domain=domain,
        total_queries=len(queries),
        executed_queries=len(queries),
        total_results=len(all_findings),
        unique_results=len(unique_findings),
        results_by_engine=eng_counts,
        results_by_category=cat_counts,
        execution_time_seconds=dwell
    )

    log_audit_event("EXECUTION_COMPLETE", domain, f"Discovered {len(unique_findings)} unique findings across {dwell:.1f}s")

    # 5. Display Table
    console.print(f"\n[bold green]✓ Execution Completed in {dwell:.2f}s![/bold green]")
    console.print(f"Total Results: [bold]{len(all_findings)}[/bold] | Unique Findings: [bold green]{len(unique_findings)}[/bold green]\n")

    if unique_findings:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Category", style="cyan", width=22)
        table.add_column("Title", style="white", width=35)
        table.add_column("URL", style="sky_blue2")
        table.add_column("Engine", style="green", width=12)

        for i, f in enumerate(unique_findings[:30], 1):
            table.add_row(str(i), f.category, f.title[:35], f.url, f.engine)

        console.print(table)
        if len(unique_findings) > 30:
            console.print(f"[dim]... and {len(unique_findings)-30} more findings recorded in reports.[/dim]")

    # 6. Auto-export to all formats
    target_outdir = output_dir or Path(cfg.output_directory)
    stem = f"dorkforge_{domain}_{int(time.time())}"
    paths = export_all(unique_findings, summary, target_outdir, stem)

    console.print("\n[bold cyan]📁 Intelligence Reports Exported:[/bold cyan]")
    for fmt, p in paths.items():
        console.print(f"  • [bold]{fmt.upper()}:[/bold] {p}")
    console.print("")

@templates_app.command(name="list")
def list_templates(category: Optional[str] = typer.Option(None, "--category", "-c")):
    """List all available dork templates and patterns."""
    templates = template_registry.get_all()
    if category:
        templates = template_registry.get_by_category(category)

    table = Table(title=f"Dork Templates Library ({len(templates)} templates)", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold yellow", width=24)
    table.add_column("Category", style="green", width=24)
    table.add_column("Pattern Expression", style="white")

    for t in templates:
        table.add_row(t.id, t.category, t.pattern)

    console.print(table)

@templates_app.command(name="import")
def import_templates(file: Path = typer.Argument(..., help="Path to custom YAML or JSON templates file")):
    """Import custom template file into the active registry."""
    if not file.exists():
        console.print(f"[bold red]File not found:[/bold red] {file}")
        sys.exit(1)
    count = template_registry.load_custom(file)
    console.print(f"[bold green]✓ Successfully imported {count} custom templates from {file}![/bold green]")

@app.command(name="config")
def show_config():
    """Display active DorkForge configuration."""
    cfg = load_config()
    cfg_path = get_config_path()
    import yaml
    formatted = yaml.dump(cfg.model_dump(), default_flow_style=False)
    console.print(Panel(formatted, title=f"DorkForge Config: {cfg_path}", border_style="cyan"))

def cli_entrypoint():
    app()

if __name__ == "__main__":
    cli_entrypoint()
