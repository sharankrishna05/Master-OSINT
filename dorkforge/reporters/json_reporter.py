from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any
from ..models import SearchResult, RunSummary

def export_json(results: List[SearchResult], summary: RunSummary, output_path: Path) -> Path:
    """Export search results and run metrics to a structured JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summary.model_dump(),
        "total_results": len(results),
        "results": [r.model_dump() for r in results]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return output_path
