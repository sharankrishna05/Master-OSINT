/**
 * IntelBase Real-Time SSE Stream Client
 */

let activeEventSource = null;

function setQuery(email) {
  const input = document.getElementById("target-email");
  if (input) {
    input.value = email;
    startInvestigation(new Event("submit"));
  }
}

function startInvestigation(e) {
  if (e) e.preventDefault();

  const input = document.getElementById("target-email");
  const email = (input ? input.value : "").trim();
  if (!email) return;

  if (activeEventSource) {
    activeEventSource.close();
  }

  // Reset UI State
  const btn = document.getElementById("btn-scan");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin">⏳</span> <span>STREAMING...</span>`;
  }

  const badge = document.getElementById("stream-status-badge");
  if (badge) {
    badge.className = "px-2.5 py-1 rounded bg-[#00f5ff]/20 text-[#00f5ff] border border-[#00f5ff]/40 font-bold animate-pulse";
    badge.innerText = "● SSE CONNECTED";
  }

  document.getElementById("progress-container")?.classList.remove("hidden");
  document.getElementById("summary-cards")?.classList.remove("hidden");
  
  const tbody = document.getElementById("results-tbody");
  if (tbody) tbody.innerHTML = "";

  const breachContainer = document.getElementById("breach-container");
  if (breachContainer) {
    breachContainer.innerHTML = `<div class="text-center text-[#00f5ff] py-12 text-xs flex items-center justify-center gap-2"><span class="animate-spin">⏳</span> Querying HIBP breach databases...</div>`;
  }

  // Establish SSE connection (works both standalone and mounted under /intelbase/)
  const basePath = window.location.pathname.endsWith("/") ? window.location.pathname : window.location.pathname + "/";
  const sseUrl = `${basePath}lookup/stream?email=${encodeURIComponent(email)}`;
  activeEventSource = new EventSource(sseUrl);

  activeEventSource.addEventListener("start", (evt) => {
    const data = JSON.parse(evt.data);
    updateProgress(0, data.total_checkers, `ENUMERATING ${data.total_checkers} PLATFORMS...`);
  });

  activeEventSource.addEventListener("checker_result", (evt) => {
    const data = JSON.parse(evt.data);
    appendCheckerRow(data);
    updateProgress(data.completed, data.total, `CHECKED ${data.site_name} (${data.completed}/${data.total})`);
  });

  activeEventSource.addEventListener("hibp_result", (evt) => {
    const data = JSON.parse(evt.data);
    renderBreaches(data);
  });

  activeEventSource.addEventListener("complete", (evt) => {
    const data = JSON.parse(evt.data);
    renderComplete(data);
    finalizeScan();
  });

  activeEventSource.onerror = (err) => {
    console.warn("SSE stream ended or error:", err);
    finalizeScan();
  };
}

function updateProgress(current, total, label) {
  const percent = total > 0 ? Math.round((current / total) * 100) : 0;
  const bar = document.getElementById("progress-bar");
  const pText = document.getElementById("progress-percent");
  const pLabel = document.getElementById("progress-label");

  if (bar) bar.style.width = `${percent}%`;
  if (pText) pText.innerText = `${percent}%`;
  if (pLabel && label) pLabel.innerText = label;
}

function appendCheckerRow(item) {
  const tbody = document.getElementById("results-tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");
  tr.className = "border-b border-[#12253f] hover:bg-[#091527]/70 transition-colors";

  let statusBadge = "";
  if (item.exists === true) {
    statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-[#39ff14]/20 text-[#39ff14] border border-[#39ff14]/40">REGISTERED</span>`;
  } else if (item.exists === false) {
    statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-gray-800 text-gray-400">NOT FOUND</span>`;
  } else if (item.status === "RATE_LIMITED") {
    statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-[#ffd60a]/20 text-[#ffd60a] border border-[#ffd60a]/40">RATE LIMITED</span>`;
  } else {
    statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-900/40 text-red-400 border border-red-500/30">ERROR</span>`;
  }

  tr.innerHTML = `
    <td class="p-3 font-bold text-white flex items-center gap-2">
      <span>${item.exists ? "✅" : "⚪"}</span>
      <span>${item.site_name}</span>
    </td>
    <td class="p-3 text-gray-400">${item.category}</td>
    <td class="p-3">${statusBadge}</td>
    <td class="p-3 text-gray-400">${item.latency_ms} ms</td>
    <td class="p-3 text-right">
      ${item.login_url ? `<a href="${item.login_url}" target="_blank" class="px-2 py-1 rounded bg-[#00f5ff]/10 hover:bg-[#00f5ff]/25 text-[#00f5ff] text-[10px] font-bold">PORTAL ↗</a>` : "-"}
    </td>
  `;
  tbody.appendChild(tr);

  // Update counter
  const rows = tbody.querySelectorAll("tr").length;
  const countLabel = document.getElementById("results-count-label");
  if (countLabel) countLabel.innerText = `${rows} site(s) checked`;
}

function renderBreaches(data) {
  const container = document.getElementById("breach-container");
  const countBadge = document.getElementById("breach-count-badge");
  const cardCount = document.getElementById("card-breach-count");
  const cardStatus = document.getElementById("card-breach-status");
  const cardPw = document.getElementById("card-pw-status");

  if (countBadge) countBadge.innerText = `${data.breaches_count} Breach(es)`;
  if (cardCount) cardCount.innerText = data.breaches_count;

  if (!container) return;

  if (data.breaches_count === 0) {
    const msg = data.meta?.message || "No public data breach records found.";
    container.innerHTML = `
      <div class="text-center py-8 text-gray-400 text-xs space-y-2">
        <div class="text-2xl text-[#39ff14]">🛡️</div>
        <div class="font-bold text-white">Clean Threat Surface</div>
        <div class="text-[11px] text-gray-500">${msg}</div>
      </div>
    `;
    if (cardStatus) cardStatus.innerText = "Clean record across HIBP";
    if (cardPw) cardPw.innerText = "SECURE";
    return;
  }

  let hasPasswords = false;
  let html = `<div class="space-y-3">`;

  data.breaches.forEach((b) => {
    if (b.has_passwords) hasPasswords = true;
    html += `
      <div class="p-3 bg-[#030914] rounded-xl border ${b.has_passwords ? "border-red-500/60 shadow-[0_0_10px_rgba(255,0,60,0.2)]" : "border-[#162a4a]"} space-y-2">
        <div class="flex justify-between items-start gap-2">
          <div>
            <div class="font-bold text-white text-xs">${b.title}</div>
            <div class="text-[10px] text-[#00f5ff]">${b.domain || "Global Breach"}</div>
          </div>
          <span class="px-1.5 py-0.2 rounded text-[9px] font-bold ${b.has_passwords ? "bg-red-900/60 text-red-200 border border-red-500" : "bg-gray-800 text-gray-300"}">
            ${b.has_passwords ? "PASSWORDS COMPROMISED" : "METADATA ONLY"}
          </span>
        </div>
        <div class="text-[10px] text-gray-400">
          Breach Date: <span class="text-white">${b.breach_date}</span> • Pwned: <span class="text-white">${b.pwn_count ? b.pwn_count.toLocaleString() : "Unknown"}</span>
        </div>
        <div class="flex flex-wrap gap-1 pt-1">
          ${(b.data_classes || []).slice(0, 5).map(dc => `<span class="px-1.5 py-0.2 bg-[#091527] text-gray-300 rounded text-[9px] border border-gray-800">${dc}</span>`).join("")}
        </div>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;

  if (cardStatus) cardStatus.innerText = `${data.breaches_count} confirmed breach incidents`;
  if (cardPw) {
    cardPw.innerText = hasPasswords ? "COMPROMISED" : "NO PASSWORDS";
    cardPw.className = `text-2xl font-black orbitron my-2 ${hasPasswords ? "text-[#ff003c]" : "text-[#ffd60a]"}`;
  }
}

function renderComplete(data) {
  const risk = data.risk_assessment;
  if (!risk) return;

  const scoreElem = document.getElementById("card-risk-score");
  const badgeElem = document.getElementById("card-risk-badge");
  const reasonElem = document.getElementById("card-risk-reasoning");
  const regCount = document.getElementById("card-registered-count");
  const sitesRatio = document.getElementById("card-sites-ratio");

  if (scoreElem) {
    scoreElem.innerText = `${risk.score}/100`;
    if (risk.score >= 85) scoreElem.className = "text-3xl font-black orbitron text-[#ff003c]";
    else if (risk.score >= 65) scoreElem.className = "text-3xl font-black orbitron text-[#ff6b00]";
    else if (risk.score >= 30) scoreElem.className = "text-3xl font-black orbitron text-[#ffd60a]";
    else scoreElem.className = "text-3xl font-black orbitron text-[#39ff14]";
  }

  if (badgeElem) {
    badgeElem.innerText = risk.level;
    if (risk.level === "CRITICAL") badgeElem.className = "text-xs font-bold px-2 py-0.5 rounded bg-red-900/80 text-red-200 border border-red-500";
    else if (risk.level === "HIGH") badgeElem.className = "text-xs font-bold px-2 py-0.5 rounded bg-orange-900/80 text-orange-200 border border-orange-500";
    else if (risk.level === "MEDIUM") badgeElem.className = "text-xs font-bold px-2 py-0.5 rounded bg-yellow-900/80 text-yellow-200 border border-yellow-500";
    else badgeElem.className = "text-xs font-bold px-2 py-0.5 rounded bg-green-900/80 text-green-200 border border-green-500";
  }

  if (reasonElem) reasonElem.innerText = risk.reasoning;
  if (regCount) regCount.innerText = data.registered_sites_count;
  if (sitesRatio) sitesRatio.innerText = `${data.registered_sites_count} of ${data.total_sites_checked} platforms active`;

  updateProgress(data.total_sites_checked, data.total_sites_checked, `INVESTIGATION COMPLETED`);
}

function finalizeScan() {
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
  const btn = document.getElementById("btn-scan");
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = `<span>ASYNC PROBE</span> <span>➤</span>`;
  }
  const badge = document.getElementById("stream-status-badge");
  if (badge) {
    badge.className = "px-2.5 py-1 rounded bg-[#39ff14]/15 text-[#39ff14] border border-[#39ff14]/30 font-bold";
    badge.innerText = "● SSE COMPLETE";
  }
}
