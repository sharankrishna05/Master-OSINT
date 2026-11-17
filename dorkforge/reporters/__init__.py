from __future__ import annotations
from pathlib import Path
from typing import List, Dict
from ..models import SearchResult, RunSummary
from .json_reporter import export_json
from .csv_reporter import export_csv
from .md_reporter import export_markdown
from .html_reporter import export_html
from .sqlite_reporter import export_sqlite

def export_all(
    results: List[SearchResult],
    summary: RunSummary,
    base_dir: Path,
    stem_name: str
) -> Dict[str, Path]:
    """Export results to all 5 formats (JSON, CSV, Markdown, HTML, SQLite)."""
    base_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": export_json(results, summary, base_dir / f"{stem_name}.json"),
        "csv": export_csv(results, base_dir / f"{stem_name}.csv"),
        "md": export_markdown(results, summary, base_dir / f"{stem_name}.md"),
        "html": export_html(results, summary, base_dir / f"{stem_name}.html"),
        "sqlite": export_sqlite(results, summary, base_dir / f"{stem_name}.db")
    }
    return paths
