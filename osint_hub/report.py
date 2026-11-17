"""Reporting Engine for OSINT Investigations.

Outputs:
- Terminal: Interactive Rich tables (Detected Type, Auto-open, API hits, Manual followups, Skipped)
- JSON Report: reports/<input_slug>_<timestamp>.json
- HTML Report: reports/<input_slug>_<timestamp>.html (Jinja2 self-contained report)
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint_hub.executors import APIHitResult
from osint_hub.router import RoutedTool, RoutingPlan

import os
HUB_PKG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HUB_PKG_DIR.parent
REPORTS_DIR = Path(os.getenv("ARSENAL_REPORTS_DIR", str(PROJECT_ROOT / "reports")))
TEMPLATES_DIR = HUB_PKG_DIR / "templates"


def slugify(text: str) -> str:
    """Create filesystem-safe slug from input indicator."""
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", text).strip("_")
    return slug[:40] or "target"


class OSINTReporter:
    """Handles terminal display and artifact generation for investigation dossiers."""

    def __init__(self, reports_dir: Optional[Path] = None, templates_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.console = Console()

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True,
        )

    def print_terminal_report(
        self,
        plan: RoutingPlan,
        api_results: Optional[List[APIHitResult]] = None,
        opened_count: int = 0,
    ) -> None:
        """Render beautiful Rich terminal tables for scan results."""
        self.console.print()

        # Header summary panel
        conf_pct = f"{plan.confidence * 100:.1f}%"
        meta_text = (
            f"[bold cyan]Target:[/] [bold white]{plan.target}[/]  |  "
            f"[bold cyan]Typology:[/] [bold green]{plan.target_type.upper()}[/]  |  "
            f"[bold cyan]Confidence:[/] [bold yellow]{conf_pct}[/]\n"
            f"[bold cyan]Sections Queried:[/] {', '.join(plan.sections_queried) or 'None'}\n"
            f"[bold cyan]Browser Dispatch:[/] {opened_count} URLs launched in browser"
        )
        self.console.print(Panel(meta_text, title="[bold cyan]⚡ OSINT-HUB RECONNAISSANCE DOSSIER[/]", border_style="cyan"))

        # Empty categories notice if any
        if plan.empty_categories_notice:
            for notice in plan.empty_categories_notice:
                self.console.print(f"[bold yellow]⚠ NOTICE:[/] {notice}")

        # Table 1: API Enrichment Hits (Phase B)
        if api_results:
            api_table = Table(title="⚡ Automated Public API Telemetry (Phase B)", border_style="cyan")
            api_table.add_column("API Service", style="bold white", width=25)
            api_table.add_column("Status", width=12)
            api_table.add_column("Telemetry / Corroborated Findings", style="dim")

            for hit in api_results:
                if hit.status == "SUCCESS":
                    status_style = "[bold green]SUCCESS[/]"
                elif hit.status == "NOT_FOUND":
                    status_style = "[bold yellow]NOT FOUND[/]"
                elif hit.status == "SKIPPED":
                    status_style = "[bold cyan]SKIPPED[/]"
                else:
                    status_style = "[bold red]ERROR[/]"

                api_table.add_row(hit.service, status_style, hit.summary)

            self.console.print(api_table)

        # Table 2: Safe Auto-Open Tools (Phase A)
        open_table = Table(title=f"🌐 Web Intelligence Tools (Safe Auto-Open) [{len(plan.auto_open)}]", border_style="green")
        open_table.add_column("Tool Name", style="bold white", width=28)
        open_table.add_column("Category & Section", style="dim", width=28)
        open_table.add_column("Target Query URL", style="cyan")

        for item in plan.auto_open:
            name_display = item.tool.tool_name
            if item.tool.is_unverified:
                name_display += " [bold yellow]⚠[/]"
            cat_display = f"{item.tool.section} > {item.tool.category}"
            open_table.add_row(name_display, cat_display, item.populated_url)

        self.console.print(open_table)

        # Table 3: Manual Follow-ups (Local CLI Tools [T])
        if plan.manual_followups:
            cli_table = Table(title=f"💻 Manual Follow-ups (Local CLI Tools [T]) [{len(plan.manual_followups)}]", border_style="yellow")
            cli_table.add_column("Tool Name", style="bold white", width=28)
            cli_table.add_column("Section", style="dim", width=22)
            cli_table.add_column("Copy-Paste CLI Execution Command", style="bold green")

            for item in plan.manual_followups:
                name_display = item.tool.tool_name
                if item.tool.is_unverified:
                    name_display += " [bold yellow]⚠[/]"
                cli_table.add_row(name_display, item.tool.section, item.cli_command or "N/A")

            self.console.print(cli_table)

        # Table 4: Skipped Resources (R / D)
        if plan.skipped:
            skip_table = Table(title=f"🔒 Skipped Tools (Requires Registration [R] or Dorks [D]) [{len(plan.skipped)}]", border_style="red")
            skip_table.add_column("Tool Name", style="bold white", width=28)
            skip_table.add_column("Reason Skipped", style="bold red", width=35)
            skip_table.add_column("Resource Link", style="dim")

            for item in plan.skipped:
                name_display = item.tool.tool_name
                if item.tool.is_unverified:
                    name_display += " [bold yellow]⚠[/]"
                skip_table.add_row(name_display, item.skip_reason or "Skipped", item.populated_url)

            self.console.print(skip_table)

    def export_json_report(
        self,
        plan: RoutingPlan,
        api_results: Optional[List[APIHitResult]] = None,
        opened_count: int = 0,
    ) -> Path:
        """Export full investigation telemetry to a JSON file."""
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = slugify(plan.target)
        filename = f"{slug}_{ts}.json"
        out_path = self.reports_dir / filename

        report_dict: Dict[str, Any] = {
            "metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "target": plan.target,
                "detected_type": plan.target_type,
                "confidence": plan.confidence,
                "sections_queried": plan.sections_queried,
                "browser_opened_count": opened_count,
            },
            "api_results": [
                {
                    "service": r.service,
                    "target": r.target,
                    "url": r.url,
                    "status": r.status,
                    "summary": r.summary,
                    "data": r.data,
                }
                for r in (api_results or [])
            ],
            "auto_open_tools": [
                {
                    "name": item.tool.tool_name,
                    "section": item.tool.section,
                    "category": item.tool.category,
                    "description": item.tool.description,
                    "url": item.populated_url,
                    "is_unverified": item.tool.is_unverified,
                    "flags": item.tool.flags,
                }
                for item in plan.auto_open
            ],
            "manual_followups": [
                {
                    "name": item.tool.tool_name,
                    "section": item.tool.section,
                    "category": item.tool.category,
                    "description": item.tool.description,
                    "cli_command": item.cli_command,
                    "is_unverified": item.tool.is_unverified,
                    "url": item.populated_url,
                }
                for item in plan.manual_followups
            ],
            "skipped_tools": [
                {
                    "name": item.tool.tool_name,
                    "section": item.tool.section,
                    "category": item.tool.category,
                    "description": item.tool.description,
                    "url": item.populated_url,
                    "reason": item.skip_reason,
                    "is_unverified": item.tool.is_unverified,
                }
                for item in plan.skipped
            ],
            "empty_categories_notice": plan.empty_categories_notice,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)

        return out_path

    def export_html_report(
        self,
        plan: RoutingPlan,
        api_results: Optional[List[APIHitResult]] = None,
        opened_count: int = 0,
    ) -> Path:
        """Render self-contained HTML report via Jinja2."""
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = slugify(plan.target)
        filename = f"{slug}_{ts}.html"
        out_path = self.reports_dir / filename

        template = self.jinja_env.get_template("report.html.j2")
        rendered = template.render(
            target=plan.target,
            target_type=plan.target_type.upper(),
            confidence=plan.confidence,
            sections_queried=plan.sections_queried,
            empty_categories_notice=plan.empty_categories_notice,
            auto_open=plan.auto_open,
            manual_followups=plan.manual_followups,
            skipped=plan.skipped,
            api_results=api_results or [],
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        return out_path
