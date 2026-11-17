from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import List
from ..models import SearchResult, RunSummary

def export_sqlite(results: List[SearchResult], summary: RunSummary, output_path: Path) -> Path:
    """Store reconnaissance results and execution summary in a relational SQLite database."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(output_path))
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_domain TEXT,
        total_queries INTEGER,
        executed_queries INTEGER,
        total_results INTEGER,
        unique_results INTEGER,
        execution_time_seconds REAL,
        timestamp TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        title TEXT,
        url TEXT,
        normalized_url TEXT,
        snippet TEXT,
        engine TEXT,
        query TEXT,
        category TEXT,
        domain TEXT,
        confidence REAL,
        timestamp TEXT,
        FOREIGN KEY (run_id) REFERENCES runs (id)
    )
    """)

    # Insert run summary
    cursor.execute("""
    INSERT INTO runs (target_domain, total_queries, executed_queries, total_results, unique_results, execution_time_seconds, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        summary.target_domain,
        summary.total_queries,
        summary.executed_queries,
        summary.total_results,
        summary.unique_results,
        summary.execution_time_seconds,
        summary.timestamp
    ))
    run_id = cursor.lastrowid

    # Insert findings
    for r in results:
        cursor.execute("""
        INSERT INTO findings (run_id, title, url, normalized_url, snippet, engine, query, category, domain, confidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            r.title,
            r.url,
            r.normalized_url,
            r.snippet,
            r.engine,
            r.query,
            r.category,
            r.domain,
            r.confidence,
            r.timestamp
        ))

    conn.commit()
    conn.close()
    return output_path
