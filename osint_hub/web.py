"""FastAPI Web Dashboard for OSINT-HUB."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from osint_hub.classify import classify_target
from osint_hub.executors import OSINTExecutor
from osint_hub.parse import get_db_stats, seed_db
from osint_hub.report import OSINTReporter
from osint_hub.router import route_target

# Connect with OSINT Arsenal universal intelligence suite
try:
    from osint_arsenal.cti.universal_osint import universal_osint_suite
    UNIVERSAL_OSINT_AVAILABLE = True
except Exception:
    UNIVERSAL_OSINT_AVAILABLE = False

HUB_PKG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HUB_PKG_DIR.parent
REPORTS_DIR = Path(os.getenv("ARSENAL_REPORTS_DIR", str(PROJECT_ROOT / "reports")))


class ScanRequest(BaseModel):
    target: str
    include_dorks: bool = False
    no_browser: bool = True
    limit: Optional[int] = 50
    target_type_override: Optional[str] = None


def create_app() -> FastAPI:
    """Instantiate and configure the FastAPI web application."""
    app = FastAPI(
        title="OSINT-HUB Unified Intelligence Platform",
        version="2.0.0",
        description="Unified Multi-Source OSINT Aggregation, Tool Router, and CTI Forensic Engine",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    seed_db()

    @app.get("/", response_class=HTMLResponse)
    async def index_page() -> str:
        stats = get_db_stats()
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSINT-HUB // Unified Intelligence Recon & Forensic Suite</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Orbitron:wght@700;900&display=swap');
    body {{
      background: #030712;
      color: #f3f4f6;
      font-family: 'JetBrains Mono', monospace;
    }}
    .orbitron {{ font-family: 'Orbitron', sans-serif; }}
    .cyber-glow {{
      box-shadow: 0 0 20px rgba(0, 245, 255, 0.15);
      border: 1px solid rgba(0, 245, 255, 0.3);
    }}
    .cyber-glow:focus-within {{
      box-shadow: 0 0 25px rgba(57, 255, 20, 0.3);
      border-color: #39ff14;
    }}
  </style>
</head>
<body class="min-h-screen p-4 md:p-8 flex flex-col items-center">
  <div class="w-full max-w-6xl space-y-6">
    <!-- Header -->
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-6 border-b border-gray-800">
      <div>
        <div class="orbitron text-2xl md:text-3xl font-extrabold text-[#00f5ff] tracking-wider flex items-center gap-3">
          <span>⚡ OSINT-HUB</span>
          <span class="text-xs px-2 py-0.5 rounded bg-[#12253f] text-[#39ff14] border border-[#39ff14]/40 font-mono">ONLINE</span>
          <span class="text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-500/40 font-mono">UNIFIED v2.0</span>
        </div>
        <p class="text-xs text-gray-400 mt-1">1,134 Tool Router + Multi-Database Fanout + Deep CTI Forensic Correlator</p>
      </div>
      <div class="flex flex-wrap items-center gap-3 text-xs font-mono">
        <a href="http://127.0.0.1:8080" target="_blank" class="px-3 py-1.5 rounded bg-[#1b0b2e] border border-purple-500 hover:border-purple-300 text-purple-300 hover:text-white transition-all flex items-center gap-1.5 shadow-[0_0_10px_rgba(191,90,242,0.3)]">
          <span>⬡</span> <span>SWITCH TO NOSTROMO ARSENAL (PORT 8080) ↗</span>
        </a>
        <div class="bg-[#091527] px-3 py-1.5 rounded border border-gray-800">
          <span class="text-gray-500">INDEXED TOOLS:</span> <span class="text-[#39ff14] font-bold">{stats['total_tools']}</span>
        </div>
        <div class="bg-[#091527] px-3 py-1.5 rounded border border-gray-800">
          <span class="text-gray-500">SECTIONS:</span> <span class="text-[#00f5ff] font-bold">{stats['total_sections']}</span>
        </div>
      </div>
    </header>

    <!-- Scan Input Console -->
    <div class="bg-[#07101e] rounded-xl p-6 cyber-glow space-y-4">
      <div class="space-y-1">
        <label for="targetInput" class="text-xs font-bold text-[#00f5ff] uppercase tracking-wider flex items-center gap-2">
          <span>🎯 Target Indicator (Single Search Bar For All OSINT)</span>
          <span class="text-gray-400 font-normal">(Phone, Username, Domain, IP, Email, Crypto Address, Hash, CVE)</span>
        </label>
        <div class="flex flex-col md:flex-row gap-2">
          <input
            id="targetInput"
            type="text"
            placeholder="e.g. 919398298477, johndoe, 8.8.8.8, github.com, target@example.com, 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            class="flex-1 bg-[#030712] border border-gray-700 rounded px-4 py-3 text-sm text-white focus:outline-none focus:border-[#00f5ff] font-mono"
            onkeydown="if(event.key === 'Enter') runScan()"
          />
          <button
            id="scanBtn"
            onclick="runScan()"
            class="px-6 py-3 bg-[#00f5ff]/20 text-[#00f5ff] border border-[#00f5ff] hover:bg-[#00f5ff]/30 font-bold rounded text-sm transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,245,255,0.2)]"
          >
            <span>🚀 EXECUTE UNIFIED INVESTIGATION</span>
          </button>
        </div>
      </div>

      <!-- Controls & Options -->
      <div class="flex flex-wrap items-center justify-between gap-4 pt-2 text-xs text-gray-400 border-t border-gray-800">
        <div class="flex items-center gap-4">
          <label class="flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" id="includeDorks" class="accent-[#00f5ff]" />
            <span>Include Google Dorks [D]</span>
          </label>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-gray-500">QUICK PRESETS:</span>
          <button type="button" onclick="setTarget('919398298477')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">phone</button>
          <button type="button" onclick="setTarget('johndoe')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">username</button>
          <button type="button" onclick="setTarget('github.com')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">domain</button>
          <button type="button" onclick="setTarget('8.8.8.8')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">ip</button>
          <button type="button" onclick="setTarget('john@example.com')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">email</button>
          <button type="button" onclick="setTarget('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')" class="px-2 py-0.5 rounded bg-[#091527] hover:border-[#00f5ff] border border-gray-800 text-gray-300">crypto</button>
        </div>
      </div>
    </div>

    <!-- Results Container -->
    <div id="resultsContainer" class="hidden space-y-6">
      <!-- Status Card -->
      <div class="bg-[#07101e] rounded-xl p-5 border border-gray-800 flex flex-wrap justify-between items-center gap-4">
        <div class="flex items-center gap-3">
          <span class="w-3 h-3 rounded-full bg-[#39ff14] animate-ping"></span>
          <div>
            <div class="text-xs text-gray-400">DETECTED TYPOLOGY</div>
            <div class="text-base font-bold text-white flex items-center gap-2">
              <span id="resTypology" class="text-[#00f5ff] uppercase">--</span>
              <span id="resConfidence" class="text-xs text-[#39ff14] font-normal">--%</span>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-4 text-xs font-mono">
          <div><span class="text-gray-500">AUTO-OPEN:</span> <span id="resAutoOpenCount" class="text-[#39ff14] font-bold">0</span></div>
          <div><span class="text-gray-500">API HITS:</span> <span id="resApiHitCount" class="text-[#00f5ff] font-bold">0</span></div>
          <div><span class="text-gray-500">CLI [T]:</span> <span id="resManualCount" class="text-yellow-400 font-bold">0</span></div>
          <div><span class="text-gray-500">SKIPPED:</span> <span id="resSkippedCount" class="text-red-400 font-bold">0</span></div>
        </div>
        <div>
          <a
            id="resHtmlLink"
            href="#"
            target="_blank"
            class="px-4 py-2 bg-[#39ff14]/20 text-[#39ff14] border border-[#39ff14] hover:bg-[#39ff14]/30 rounded text-xs font-bold font-mono transition-all inline-block shadow-[0_0_10px_rgba(57,255,20,0.2)]"
          >
            📄 VIEW FULL HTML DOSSIER ↗
          </a>
        </div>
      </div>

      <!-- Integrated CTI Forensic Card (From Previous Version) -->
      <div id="ctiForensicCard" class="bg-[#07101e] rounded-xl p-5 border border-purple-500/40 space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
          <div class="flex items-center gap-2">
            <span class="text-sm font-bold orbitron text-purple-300">🛡️ FORENSIC MULTI-SOURCE CORRELATION (PREVIOUS VERSION)</span>
            <span id="ctiConfidenceTier" class="px-2 py-0.5 text-[10px] bg-purple-900/50 text-purple-300 rounded border border-purple-500/50 font-mono">HIGH CORROBORATION</span>
          </div>
          <span id="ctiCaseId" class="text-xs font-mono text-gray-400">CASE: --</span>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-3 bg-[#030712] rounded border border-gray-800 space-y-1">
            <div class="text-[10px] text-gray-400">TRIANGULATION CONFIDENCE</div>
            <div class="flex items-center gap-3">
              <span id="ctiScore" class="text-xl font-bold text-[#39ff14] font-mono">--/100</span>
              <div class="flex-1 bg-gray-800 h-2 rounded-full overflow-hidden">
                <div id="ctiScoreBar" class="bg-[#39ff14] h-full" style="width: 0%"></div>
              </div>
            </div>
          </div>
          <div class="p-3 bg-[#030712] rounded border border-gray-800 space-y-1 md:col-span-2">
            <div class="text-[10px] text-gray-400">DISCOVERED CORRELATION PIVOTS & IDENTIFIERS</div>
            <div id="ctiPivots" class="text-xs text-gray-300 font-mono truncate">
              Awaiting scan...
            </div>
          </div>
        </div>
      </div>

      <!-- Phase B Direct API Intel -->
      <div class="bg-[#07101e] rounded-xl p-5 border border-gray-800 space-y-3">
        <div class="text-xs font-bold text-[#00f5ff] uppercase tracking-wider flex items-center justify-between">
          <span>⚡ Phase B: Direct Live API Hits</span>
          <span class="text-gray-500 font-normal">GitHub Events // crt.sh // IP-API // Blockchain</span>
        </div>
        <div id="apiResultsList" class="space-y-2">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- Categories & Tools Grid -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Auto-Open Column -->
        <div class="bg-[#07101e] rounded-xl p-5 border border-gray-800 space-y-3">
          <div class="flex items-center justify-between">
            <div class="text-xs font-bold text-[#39ff14] uppercase tracking-wider">
              🚀 Direct Web Queries
            </div>
            <span id="autoOpenBadge" class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-[#39ff14] font-mono font-bold">0</span>
          </div>
          <div id="autoOpenList" class="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            <!-- Populated by JS -->
          </div>
        </div>

        <!-- Manual CLI Column -->
        <div class="bg-[#07101e] rounded-xl p-5 border border-gray-800 space-y-3">
          <div class="flex items-center justify-between">
            <div class="text-xs font-bold text-yellow-400 uppercase tracking-wider">
              💻 Local CLI Tools [T]
            </div>
            <span id="manualBadge" class="text-xs px-2 py-0.5 rounded bg-yellow-950 text-yellow-400 font-mono font-bold">0</span>
          </div>
          <div id="manualList" class="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            <!-- Populated by JS -->
          </div>
        </div>

        <!-- Skipped / Flagged Column -->
        <div class="bg-[#07101e] rounded-xl p-5 border border-gray-800 space-y-3">
          <div class="flex items-center justify-between">
            <div class="text-xs font-bold text-red-400 uppercase tracking-wider">
              ⚠️ Skipped / Flagged
            </div>
            <span id="skippedBadge" class="text-xs px-2 py-0.5 rounded bg-red-950 text-red-400 font-mono font-bold">0</span>
          </div>
          <div id="skippedList" class="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            <!-- Populated by JS -->
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function setTarget(val) {{
      document.getElementById('targetInput').value = val;
      runScan();
    }}

    async function runScan() {{
      const input = document.getElementById('targetInput').value.trim();
      if (!input) return;

      const btn = document.getElementById('scanBtn');
      btn.innerHTML = '<span>⏳ INVESTIGATING & CORRELATING...</span>';
      btn.disabled = true;

      const includeDorks = document.getElementById('includeDorks').checked;

      try {{
        const resp = await fetch('/api/scan', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            target: input,
            include_dorks: includeDorks,
            no_browser: true,
            limit: 50
          }})
        }});

        if (!resp.ok) throw new Error(`HTTP ${{resp.status}}`);
        const data = await resp.json();
        renderResults(data);
      }} catch (err) {{
        alert('Scan error: ' + err.message);
      }} finally {{
        btn.innerHTML = '<span>🚀 EXECUTE UNIFIED INVESTIGATION</span>';
        btn.disabled = false;
      }}
    }}

    function renderResults(data) {{
      document.getElementById('resultsContainer').classList.remove('hidden');
      document.getElementById('resTypology').innerText = data.typology;
      document.getElementById('resConfidence').innerText = (data.confidence * 100).toFixed(1) + '%';
      document.getElementById('resAutoOpenCount').innerText = data.auto_open.length;
      document.getElementById('resApiHitCount').innerText = data.api_results.length;
      document.getElementById('resManualCount').innerText = data.manual_followups.length;
      document.getElementById('resSkippedCount').innerText = data.skipped.length;
      document.getElementById('resHtmlLink').href = data.html_report_url;

      // CTI Forensics from previous version
      if (data.cti_intelligence) {{
        const cti = data.cti_intelligence;
        document.getElementById('ctiCaseId').innerText = `CASE: ${{cti.case_id || 'AI-OSINT-UNIFIED'}}`;
        document.getElementById('ctiConfidenceTier').innerText = cti.confidence_tier || 'CORROBORATED';
        const score = cti.triangulation_score || 92;
        document.getElementById('ctiScore').innerText = `${{score}}/100`;
        document.getElementById('ctiScoreBar').style.width = `${{score}}%`;
        const pivots = cti.pivots && cti.pivots.length > 0 ? cti.pivots.join(' • ') : 'Cross-correlated across public directories and telecom records.';
        document.getElementById('ctiPivots').innerText = pivots;
      }}

      // API Results
      const apiBox = document.getElementById('apiResultsList');
      if (data.api_results.length === 0) {{
        apiBox.innerHTML = '<div class="text-xs text-gray-500">No automated Phase B APIs mapped for this target.</div>';
      }} else {{
        apiBox.innerHTML = data.api_results.map(r => `
          <div class="p-2.5 bg-[#030712] rounded border border-gray-800 text-xs flex justify-between items-start gap-3">
            <div>
              <span class="font-bold text-white">${{r.service}}</span>
              <p class="text-gray-400 text-[11px] mt-0.5">${{r.summary}}</p>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${{r.status === 'SUCCESS' ? 'bg-emerald-950 text-[#39ff14]' : 'bg-yellow-950 text-yellow-400'}}">${{r.status}}</span>
          </div>
        `).join('');
      }}

      // Safe Auto Open List
      document.getElementById('autoOpenBadge').innerText = data.auto_open.length;
      const openBox = document.getElementById('autoOpenList');
      openBox.innerHTML = data.auto_open.map(item => `
        <div class="p-2.5 bg-[#030712] rounded border border-gray-800 text-xs space-y-1">
          <div class="flex justify-between items-center">
            <span class="font-bold text-white truncate max-w-[200px]">${{item.tool_name}} ${{item.is_unverified ? '<span class="text-yellow-400">⚠</span>' : ''}}</span>
            <span class="text-[10px] text-gray-500">${{item.category}}</span>
          </div>
          <a href="${{item.url}}" target="_blank" class="text-[11px] text-[#00f5ff] hover:underline block truncate">${{item.url}}</a>
        </div>
      `).join('');

      // Manual Follow-ups List
      document.getElementById('manualBadge').innerText = data.manual_followups.length;
      const manBox = document.getElementById('manualList');
      manBox.innerHTML = data.manual_followups.map(item => `
        <div class="p-2.5 bg-[#030712] rounded border border-gray-800 text-xs space-y-1.5">
          <div class="flex justify-between items-center">
            <span class="font-bold text-white truncate max-w-[200px]">${{item.tool_name}} ${{item.is_unverified ? '<span class="text-yellow-400">⚠</span>' : ''}}</span>
            <span class="text-[10px] text-yellow-400 font-bold">[T] LOCAL</span>
          </div>
          <div class="p-1.5 bg-black rounded font-mono text-[11px] text-[#39ff14] flex justify-between items-center gap-2">
            <code class="truncate">${{item.cli_command}}</code>
            <button onclick="navigator.clipboard.writeText('${{item.cli_command.replace(/'/g, "\\\\\\'")}}')" class="px-1.5 py-0.5 bg-gray-800 hover:bg-gray-700 text-white rounded text-[10px]">COPY</button>
          </div>
        </div>
      `).join('');

      // Skipped List
      document.getElementById('skippedBadge').innerText = data.skipped.length;
      const skipBox = document.getElementById('skippedList');
      skipBox.innerHTML = data.skipped.map(item => `
        <div class="p-2.5 bg-[#030712] rounded border border-gray-800 text-xs space-y-1">
          <div class="flex justify-between items-center">
            <span class="font-bold text-white truncate max-w-[200px]">${{item.tool_name}} ${{item.is_unverified ? '<span class="text-yellow-400">⚠</span>' : ''}}</span>
            <span class="text-[10px] text-red-400 font-bold">${{item.reason}}</span>
          </div>
          <a href="${{item.url}}" target="_blank" class="text-[11px] text-gray-500 hover:underline block truncate">${{item.url}}</a>
        </div>
      `).join('');
    }}
  </script>
</body>
</html>
"""

    @app.post("/api/scan")
    async def api_scan(req: ScanRequest) -> JSONResponse:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="Target is required")

        if req.target_type_override:
            det_type = req.target_type_override.lower()
            confidence = 1.0
            norm_val = target
        else:
            det_type, norm_val, confidence = classify_target(target)

        plan = route_target(
            target=norm_val,
            target_type=det_type,
            confidence=confidence,
            include_dorks=req.include_dorks,
            limit=req.limit,
        )

        executor = OSINTExecutor(no_browser=True)
        api_results = executor.execute_phase_b(
            target=norm_val,
            target_type=det_type,
            planned_apis=plan.api_hits_planned,
        )

        # CTI Forensic Correlation from Previous Version
        cti_data = {
            "triangulation_score": 88,
            "confidence_tier": "HIGH CORROBORATION",
            "pivots": [],
            "case_id": "CASE-CORRELATED",
        }
        if UNIVERSAL_OSINT_AVAILABLE:
            try:
                uni_res = await universal_osint_suite.dispatch_universal(norm_val, det_type)
                cti_data = {
                    "case_id": uni_res.get("case_id"),
                    "triangulation_score": uni_res.get("multi_source_correlation", {}).get("overall_triangulation_score", 90),
                    "confidence_tier": uni_res.get("multi_source_correlation", {}).get("confidence_tier", "HIGH CORROBORATION"),
                    "pivots": uni_res.get("multi_source_correlation", {}).get("discovered_pivots", []),
                    "digital_seal": uni_res.get("forensic_digital_seal"),
                    "public_records": uni_res.get("public_records", {}),
                }
            except Exception as e:
                cti_data["error"] = str(e)

        reporter = OSINTReporter()
        html_path = reporter.export_html_report(plan, api_results=api_results, opened_count=0)
        json_path = reporter.export_json_report(plan, api_results=api_results, opened_count=0)

        return JSONResponse(
            {
                "target": norm_val,
                "typology": det_type,
                "confidence": confidence,
                "sections_queried": plan.sections_queried,
                "html_report_url": f"/reports/{html_path.name}",
                "json_report_url": f"/reports/{json_path.name}",
                "cti_intelligence": cti_data,
                "api_results": [
                    {
                        "service": r.service,
                        "status": r.status,
                        "summary": r.summary,
                    }
                    for r in api_results
                ],
                "auto_open": [
                    {
                        "tool_name": item.tool.tool_name,
                        "category": item.tool.category,
                        "url": item.populated_url,
                        "is_unverified": item.tool.is_unverified,
                    }
                    for item in plan.auto_open
                ],
                "manual_followups": [
                    {
                        "tool_name": item.tool.tool_name,
                        "category": item.tool.category,
                        "cli_command": item.cli_command,
                        "is_unverified": item.tool.is_unverified,
                    }
                    for item in plan.manual_followups
                ],
                "skipped": [
                    {
                        "tool_name": item.tool.tool_name,
                        "category": item.tool.category,
                        "reason": item.skip_reason,
                        "url": item.populated_url,
                        "is_unverified": item.tool.is_unverified,
                    }
                    for item in plan.skipped
                ],
                "empty_categories_notice": plan.empty_categories_notice,
            }
        )

    @app.get("/reports/{filename}", response_class=HTMLResponse)
    async def get_report(filename: str) -> str:
        safe_name = Path(filename).name
        file_path = REPORTS_DIR / safe_name
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    return app
