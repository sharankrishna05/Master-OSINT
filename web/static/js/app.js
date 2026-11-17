const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));

// ---- Tabs ----
$$(".tab").forEach(t => t.addEventListener("click", () => {
  $$(".tab").forEach(x => x.classList.toggle("active", x === t));
  $$(".panel").forEach(p => p.classList.toggle("hidden",
    p.id !== `tab-${t.dataset.tab}`));
}));

// ---- Lookup ----
$("#lookupGo").addEventListener("click", doLookup);
$("#lookupQuery").addEventListener("keydown", e => { if (e.key === "Enter") doLookup(); });

async function doLookup() {
  const kind = $("#lookupKind").value;
  const query = $("#lookupQuery").value.trim();
  const key = $("#lookupKey").value.trim();
  const followups = $("#lookupFollowups").checked;
  if (!query || !key) return;

  $("#lookupResults").innerHTML = "";
  $("#lookupVerdict").className = "verdict";
  $("#lookupVerdict").textContent = "…";

  const r = await fetch("/api/lookup", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": key },
    body: JSON.stringify({ kind, query, followups }),
  });
  if (!r.ok) { $("#lookupVerdict").textContent = await r.text(); return; }

  // Find the newest matching investigation
  await new Promise(res => setTimeout(res, 300));
  const list = await fetch("/api/investigations?kind=lookup&limit=5").then(x => x.json());
  const target = list.find(x => x.query === query) || list[0];
  if (!target) return;
  streamInv(target.id, "lookup");
}

// ---- WebCheck ----
$("#wcGo").addEventListener("click", doWebCheck);
$("#wcUrl").addEventListener("keydown", e => { if (e.key === "Enter") doWebCheck(); });

async function doWebCheck() {
  const url = $("#wcUrl").value.trim();
  const key = $("#wcKey").value.trim();
  if (!url || !key) return;
  $("#wcResults").innerHTML = "";
  $("#wcSummary").textContent = "…";

  const r = await fetch("/api/webcheck", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": key },
    body: JSON.stringify({ url }),
  });
  if (!r.ok) { $("#wcSummary").textContent = await r.text(); return; }
  await new Promise(res => setTimeout(res, 300));
  const list = await fetch("/api/investigations?kind=webcheck&limit=5").then(x => x.json());
  if (!list.length) return;
  streamInv(list[0].id, "webcheck");
}

// ---- Streaming ----
function streamInv(invId, mode) {
  const es = new EventSource(`/api/stream/${invId}`);
  es.addEventListener("result", e => addResult(mode, JSON.parse(e.data)));
  es.addEventListener("status", e => {
    const d = JSON.parse(e.data);
    if (d.status === "done") {
      if (mode === "lookup" && d.verdict) showVerdict(d.verdict);
      if (mode === "webcheck" && d.summary) showSummary(d.summary);
      refreshTable();
      es.close();
    }
  });
}

function addResult(mode, r) {
  const box = mode === "lookup" ? $("#lookupResults") : $("#wcResults");
  const el = document.createElement("div");
  el.className = `result ${r.status}`;
  const name = r.module || r.label || r.job || "result";
  const payload = r.evidence || r.data;
  const body = r.error
    ? `<pre>${esc(r.error)}</pre>`
    : `<pre>${esc(JSON.stringify(payload, null, 2).slice(0, 3000))}</pre>`;
  el.innerHTML = `
    <div class="name">${esc(name)}
      <span class="meta">· ${esc(r.category || r.group || "")} · ${r.duration_ms}ms</span></div>
    ${body}
  `;
  box.prepend(el);
}

function showVerdict(v) {
  const el = $("#lookupVerdict");
  el.className = `verdict ${v.label}`;
  el.innerHTML = `
    <div>${v.label.toUpperCase()} · ${v.confidence}</div>
    <div style="font-weight:400;font-size:.85rem;margin-top:.3rem">
      checked ${v.checked} · found ${v.found} · not found ${v.not_found} ·
      inconclusive ${v.inconclusive} · errors ${v.errors}
    </div>
    ${v.notes?.length ? `<ul>${v.notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
  `;
}

function showSummary(s) {
  $("#wcSummary").innerHTML = `
    <strong>${s.ok || 0}</strong> ok / <strong>${s.total || 0}</strong> total
    · ${s.duration_ms || 0}ms
    ${s.errors ? ` · <span style="color:#ef4444">${s.errors} errors</span>` : ""}
  `;
}

// ---- Directory ----
(async () => {
  const meta = await fetch("/api/directory/meta").then(r => r.json());
  const cat = $("#dirCategory"), plat = $("#dirPlatform");
  meta.categories.forEach(c => {
    const o = document.createElement("option");
    o.value = c.id; o.textContent = `${c.icon} ${c.name}`; cat.appendChild(o);
  });
  meta.platforms.forEach(p => {
    const o = document.createElement("option");
    o.value = p.id; o.textContent = p.name; plat.appendChild(o);
  });
})();

["#dirQ", "#dirCategory", "#dirPlatform", "#dirFree", "#dirOss"].forEach(s =>
  $(s).addEventListener("input", debounce(loadDirectory, 200)));

async function loadDirectory() {
  const params = new URLSearchParams();
  const q = $("#dirQ").value.trim();
  if (q) params.set("q", q);
  if ($("#dirCategory").value) params.set("category", $("#dirCategory").value);
  if ($("#dirPlatform").value) params.set("platform", $("#dirPlatform").value);
  if ($("#dirFree").checked) params.set("free", "true");
  if ($("#dirOss").checked) params.set("open_source", "true");

  const tools = await fetch(`/api/directory/tools?${params}`).then(r => r.json());
  $("#dirResults").innerHTML = tools.map(t => `
    <div class="card">
      <h3><a href="${esc(t.url)}" target="_blank" rel="noopener">${esc(t.name)}</a></h3>
      <p>${esc(t.description)}</p>
      <div>
        ${t.free ? '<span class="badge">free</span>' : ''}
        ${t.open_source ? '<span class="badge">OSS</span>' : ''}
        <span class="badge" style="background:#475569">${esc(t.category)}</span>
      </div>
      <div>${(t.tags||[]).slice(0,6).map(x => `<span class="tag">#${esc(x)}</span>`).join("")}</div>
    </div>
  `).join("") || "<p style='color:var(--muted)'>No tools matched.</p>";
}

// ---- Recent investigations ----
async function refreshTable() {
  const list = await fetch("/api/investigations?limit=30").then(r => r.json());
  $("#invTable tbody").innerHTML = list.map(i => `
    <tr>
      <td>${esc(i.query)}</td>
      <td>${esc(i.kind)} ${i.subkind ? "· " + esc(i.subkind) : ""}</td>
      <td>${esc(i.status)}</td>
      <td>${new Date(i.created_at).toLocaleString()}</td>
      <td>
        <a href="/api/investigations/${i.id}/report.html" target="_blank">HTML</a> ·
        <a href="/api/investigations/${i.id}/report.json" target="_blank">JSON</a> ·
        <a href="/api/investigations/${i.id}/report.csv" target="_blank">CSV</a> ·
        <a href="/api/investigations/${i.id}/report.md" target="_blank">MD</a>
      </td>
      <td><button class="del" data-id="${i.id}">×</button></td>
    </tr>`).join("");
  $$(".del").forEach(b => b.addEventListener("click", async () => {
    await fetch(`/api/investigations/${b.dataset.id}`, { method: "DELETE" });
    refreshTable();
  }));
}

function debounce(fn, ms) {
  let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); };
}

loadDirectory();
refreshTable();
