from __future__ import annotations
import csv
from pathlib import Path
from typing import List
from ..models import SearchResult, RunSummary

def export_csv(results: List[SearchResult], output_path: Path) -> Path:
    """Export search results to CSV format."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "title", "url", "normalized_url", "category",
        "engine", "query", "domain", "confidence", "timestamp"
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "title": r.title,
                "url": r.url,
                "normalized_url": r.normalized_url,
                "category": r.category,
                "engine": r.engine,
                "query": r.query,
                "domain": r.domain,
                "confidence": r.confidence,
                "timestamp": r.timestamp
            })
    return output_path
