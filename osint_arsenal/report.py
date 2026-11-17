from __future__ import annotations
import csv
import io
import json
from html import escape

from .models import Investigation


def _summary_line(inv: Investigation) -> str:
    parts = [f"**Query:** {inv.query}", f"**Kind:** {inv.kind.value}"]
    if inv.subkind:
        parts.append(f"**Subkind:** {inv.subkind}")
    parts.append(f"**Status:** {inv.status}")
    return " · ".join(parts)


def to_json(inv: Investigation) -> str:
    return inv.model_dump_json(indent=2)


def to_csv(inv: Investigation) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source", "group", "status", "confidence", "url", "error", "duration_ms"])
    for r in inv.results:
        w.writerow([
            getattr(r, "module", None) or getattr(r, "job", ""),
            getattr(r, "category", None) or getattr(r, "group", ""),
            r.status.value,
            getattr(r, "confidence", ""),
            getattr(r, "url", "") or "",
            getattr(r, "error", "") or "",
            r.duration_ms,
        ])
    return buf.getvalue()


def to_markdown(inv: Investigation) -> str:
    lines = [f"# Arsenal Report — {inv.query}", "", _summary_line(inv), ""]
    if inv.verdict:
        v = inv.verdict
        lines += [
            f"## Verdict: {v.label} ({v.confidence})",
            f"Checked {v.checked} · Found {v.found} · Not found {v.not_found} · "
            f"Inconclusive {v.inconclusive} · Errors {v.errors}",
        ]
        for note in v.notes:
            lines.append(f"- {note}")
        lines.append("")
    if inv.followups:
        lines.append(f"**Followups:** {', '.join(inv.followups)}\n")
    if inv.summary:
        lines.append("## Summary")
        for k, v in inv.summary.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    # Group results
    groups: dict[str, list] = {}
    for r in inv.results:
        g = getattr(r, "group", None) or getattr(r, "category", "Misc")
        groups.setdefault(g, []).append(r)

    for group, results in sorted(groups.items()):
        lines.append(f"## {group}")
        for r in results:
            name = getattr(r, "module", None) or getattr(r, "job", "result")
            lines.append(f"### {name} — {r.status.value} ({r.duration_ms}ms)")
            payload = getattr(r, "data", None) or getattr(r, "evidence", None)
            if payload:
                lines.append("```json")
                lines.append(json.dumps(payload, indent=2, default=str)[:1500])
                lines.append("```")
        lines.append("")
    return "\n".join(lines)


def to_html(inv: Investigation) -> str:
    groups: dict[str, list] = {}
    for r in inv.results:
        g = getattr(r, "group", None) or getattr(r, "category", "Misc")
        groups.setdefault(g, []).append(r)

    def _render_card(r) -> str:
        name = getattr(r, "module", None) or getattr(r, "job", "result")
        payload = getattr(r, "data", None) or getattr(r, "evidence", None)
        error = getattr(r, "error", None)
        cls = "error" if r.status.value in ("error",) else \
              "found" if r.status.value == "found" else \
              "inconclusive" if r.status.value == "inconclusive" else "ok"
        body = ""
        if error:
            body = f"<p class='err'>{escape(str(error))}</p>"
        elif payload is not None:
            body = f"<pre>{escape(json.dumps(payload, indent=2, default=str))[:5000]}</pre>"
        return f"""
          <div class="card {cls}">
            <h3>{escape(name)} <span class="meta">{escape(getattr(r,'group',None) or getattr(r,'category',''))} · {r.duration_ms}ms</span></h3>
            {body}
          </div>"""

    groups_html = ""
    for g, results in sorted(groups.items()):
        cards = "".join(_render_card(r) for r in results)
        groups_html += f"<section><h2>{escape(g)}</h2><div class='grid'>{cards}</div></section>"

    verdict_html = ""
    if inv.verdict:
        v = inv.verdict
        verdict_html = (
            f"<p><span class='verdict {v.label}'>verdict: {v.label} "
            f"({v.confidence})</span></p>"
            f"<p>Checked {v.checked} · Found {v.found} · Not found {v.not_found} · "
            f"Inconclusive {v.inconclusive} · Errors {v.errors}</p>"
        )

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Arsenal — {escape(inv.query)}</title>
<style>
 body{{font:14px system-ui;max-width:1200px;margin:2rem auto;padding:1rem;
   color:#0f172a;background:#f8fafc}}
 h1{{margin:.2rem 0}} h2{{margin-top:2rem;border-bottom:2px solid #e2e8f0;
   padding-bottom:.3rem}}
 .summary{{color:#64748b;font-size:.9rem}}
 .grid{{display:grid;gap:1rem;
   grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}}
 .card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
   padding:1rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
 .card.error{{border-color:#ef4444;background:#fef2f2}}
 .card.found{{border-color:#22c55e}}
 .card.inconclusive{{border-color:#f59e0b}}
 .card h3{{margin:0 0 .5rem;font-size:.95rem}}
 .card .meta{{font-size:.75rem;color:#94a3b8;font-weight:400}}
 .card pre{{font-size:.72rem;overflow:auto;max-height:280px;
   background:#f1f5f9;padding:.5rem;border-radius:6px;white-space:pre-wrap}}
 .err{{color:#b91c1c;font-size:.85rem}}
 .verdict{{display:inline-block;padding:.15rem .6rem;border-radius:999px;
   background:#e2e8f0;font-weight:700}}
 .high{{background:#bbf7d0}} .medium{{background:#fef08a}}
 .low{{background:#fed7aa}} .insufficient{{background:#e2e8f0}}
</style></head><body>
<h1>Arsenal Report</h1>
<p class="summary">{escape(_summary_line(inv)).replace("**","")}</p>
{verdict_html}
{groups_html}
</body></html>"""
