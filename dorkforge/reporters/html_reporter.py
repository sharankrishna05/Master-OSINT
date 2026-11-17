from __future__ import annotations
import html
import json
from pathlib import Path
from typing import List
from ..models import SearchResult, RunSummary

def export_html(results: List[SearchResult], summary: RunSummary, output_path: Path) -> Path:
    """Generate an interactive HTML reconnaissance dashboard with charts, stats, and search."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Calculate domain distribution
    domains = {}
    for r in results:
        d = r.domain or "unknown"
        domains[d] = domains.get(d, 0) + 1

    top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:8]

    # Generate rows
    rows_html = []
    for idx, r in enumerate(results, 1):
        cat_badge = {
            "Sensitive Files": "background:#e11d48; color:#fff;",
            "Login & Admin Panels": "background:#f59e0b; color:#000;",
            "Directory Listing": "background:#d97706; color:#fff;",
            "Cloud Storage Exposure": "background:#8b5cf6; color:#fff;",
            "Infrastructure / DevOps": "background:#06b6d4; color:#000;",
            "Error / Stack Trace": "background:#ef4444; color:#fff;",
            "API Documentation": "background:#10b981; color:#000;"
        }.get(r.category, "background:#334155; color:#fff;")

        rows_html.append(f"""
        <tr>
            <td style="color:#64748b; font-family:monospace;">{idx}</td>
            <td>
                <div style="font-weight:600; color:#f8fafc; margin-bottom:4px;">{html.escape(r.title)}</div>
                <a href="{html.escape(r.url)}" target="_blank" rel="noopener" style="color:#38bdf8; text-decoration:none; font-family:monospace; font-size:12px; word-break:break-all;">{html.escape(r.url)} ↗</a>
                <div style="color:#94a3b8; font-size:12px; margin-top:4px;">{html.escape(r.snippet)}</div>
            </td>
            <td><span style="display:inline-block; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:700; {cat_badge}">{html.escape(r.category)}</span></td>
            <td><span style="background:#1e293b; color:#94a3b8; padding:3px 8px; border-radius:4px; font-size:11px; font-family:monospace;">{html.escape(r.engine)}</span></td>
            <td style="color:#94a3b8; font-size:11px; font-family:monospace;">{html.escape(r.query)}</td>
        </tr>
        """)

    # Category pills
    cat_pills = []
    for cat, count in sorted(summary.results_by_category.items(), key=lambda x: x[1], reverse=True):
        cat_pills.append(f"""
        <div style="background:#0f172a; border:1px solid #1e293b; padding:12px; border-radius:8px; flex:1; min-width:140px;">
            <div style="color:#64748b; font-size:11px; text-transform:uppercase; font-weight:700;">{html.escape(cat)}</div>
            <div style="color:#f8fafc; font-size:20px; font-weight:800; margin-top:4px;">{count}</div>
        </div>
        """)

    # Engine pills
    eng_pills = []
    for eng, count in sorted(summary.results_by_engine.items(), key=lambda x: x[1], reverse=True):
        eng_pills.append(f"""
        <div style="background:#0f172a; border:1px solid #1e293b; padding:10px 14px; border-radius:6px; display:inline-flex; align-items:center; gap:8px;">
            <span style="color:#38bdf8; font-weight:600; text-transform:capitalize;">{html.escape(eng)}</span>
            <span style="background:#1e293b; color:#f8fafc; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:700;">{count}</span>
        </div>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DorkForge Intelligence Report - {html.escape(summary.target_domain)}</title>
    <style>
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{ background:#030712; color:#f8fafc; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding:24px; line-height:1.5; }}
        .container {{ max-width:1400px; margin:0 auto; }}
        .header {{ background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:24px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; }}
        .title {{ font-size:24px; font-weight:800; color:#38bdf8; display:flex; align-items:center; gap:10px; }}
        .badge {{ background:#0284c7; color:#fff; font-size:12px; font-weight:700; padding:3px 8px; border-radius:6px; }}
        .kpi-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:24px; }}
        .kpi-card {{ background:#0f172a; border:1px solid #1e293b; padding:16px; border-radius:10px; }}
        .kpi-title {{ font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; }}
        .kpi-value {{ font-size:28px; font-weight:800; color:#f8fafc; margin-top:6px; }}
        .section-card {{ background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:20px; margin-bottom:24px; }}
        .section-title {{ font-size:16px; font-weight:700; color:#e2e8f0; margin-bottom:16px; border-bottom:1px solid #1e293b; padding-bottom:8px; }}
        .table-wrap {{ overflow-x:auto; }}
        table {{ width:100%; border-collapse:collapse; font-size:13px; text-align:left; }}
        th {{ background:#090d16; color:#94a3b8; font-weight:700; text-transform:uppercase; font-size:11px; padding:12px 14px; border-bottom:1px solid #1e293b; }}
        td {{ padding:12px 14px; border-bottom:1px solid #1e293b; vertical-align:top; }}
        tr:hover td {{ background:#1e293b33; }}
        .search-box {{ width:100%; background:#090d16; border:1px solid #1e293b; padding:10px 14px; border-radius:8px; color:#fff; font-size:14px; outline:none; margin-bottom:16px; }}
        .search-box:focus {{ border-color:#38bdf8; }}
        .footer {{ text-align:center; color:#64748b; font-size:12px; margin-top:32px; padding-top:16px; border-top:1px solid #1e293b; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <div class="title">
                    <span>⚡ DORKFORGE OSINT INTELLIGENCE REPORT</span>
                    <span class="badge">v1.0</span>
                </div>
                <div style="color:#94a3b8; font-size:13px; margin-top:6px;">Target: <strong style="color:#f8fafc;">{html.escape(summary.target_domain)}</strong> | Run Date: {html.escape(summary.timestamp)}</div>
            </div>
            <div>
                <button onclick="window.print()" style="background:#1e293b; border:1px solid #334155; color:#f8fafc; font-weight:700; padding:8px 16px; border-radius:6px; cursor:pointer;">Print / Export PDF</button>
            </div>
        </div>

        <!-- KPI Metrics -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Total Findings</div>
                <div class="kpi-value" style="color:#38bdf8;">{summary.total_results}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Unique Targets</div>
                <div class="kpi-value" style="color:#10b981;">{summary.unique_results}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Queries Executed</div>
                <div class="kpi-value" style="color:#f59e0b;">{summary.executed_queries} / {summary.total_queries}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Execution Time</div>
                <div class="kpi-value" style="color:#a855f7;">{summary.execution_time_seconds:.2f}s</div>
            </div>
        </div>

        <!-- Dashboard breakdown: Categories & Engines -->
        <div class="section-card">
            <div class="section-title">Findings by Category</div>
            <div style="display:flex; flex-wrap:wrap; gap:12px;">
                {''.join(cat_pills)}
            </div>
        </div>

        <div class="section-card">
            <div class="section-title">Telemetry by Search Engine & Top Asset Hosts</div>
            <div style="display:flex; flex-wrap:wrap; gap:12px; margin-bottom:16px;">
                {''.join(eng_pills)}
            </div>
            <div style="margin-top:12px; padding-top:12px; border-top:1px solid #1e293b;">
                <span style="font-size:12px; color:#64748b; font-weight:700; text-transform:uppercase;">Discovered Domains: </span>
                {' '.join([f'<span style="background:#090d16; border:1px solid #1e293b; color:#38bdf8; padding:3px 8px; border-radius:4px; font-size:11px; font-family:monospace; margin-right:6px;">{html.escape(d)} ({c})</span>' for d, c in top_domains])}
            </div>
        </div>

        <!-- Interactive Results Table -->
        <div class="section-card">
            <div class="section-title">Reconnaissance Findings ({len(results)})</div>
            <input type="text" id="filterInput" class="search-box" placeholder="Filter findings by title, URL, category, engine, or dork query..." onkeyup="filterTable()">
            <div class="table-wrap">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th style="width:40px;">#</th>
                            <th>Title & Target URL</th>
                            <th style="width:160px;">Category</th>
                            <th style="width:100px;">Engine</th>
                            <th style="width:260px;">Matched Dork Expression</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            DorkForge — Automated Defensive OSINT & Google Dorking Engine | Authorized Security Testing Only
        </div>
    </div>

    <script>
        function filterTable() {{
            const input = document.getElementById('filterInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('resultsTable');
            const tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {{
                const text = tr[i].textContent.toLowerCase();
                tr[i].style.display = text.includes(filter) ? '' : 'none';
            }}
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
