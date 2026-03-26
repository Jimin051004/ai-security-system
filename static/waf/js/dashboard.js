function setClock() {
  const el = document.getElementById("clock");
  if (el) el.textContent = new Date().toLocaleString("ko-KR");
}
function applySummary(d) {
  const up = d.upstream_ok;
  const el = document.getElementById("upstream-status");
  if (el) {
    if (up === true) {
      el.innerHTML = '<span class="pill ok">연결됨</span>';
    } else if (up === false) {
      el.innerHTML = '<span class="pill bad">실패</span>';
      if (d.upstream_error) {
        el.innerHTML += '<span class="error-hint">' + escapeHtml(d.upstream_error) + "</span>";
      }
    } else {
      el.textContent = "…";
    }
  }
  const wafEl = document.getElementById("waf-enabled");
  if (wafEl) {
    wafEl.innerHTML = d.waf_enabled
      ? '<span class="pill ok">켜짐</span>'
      : '<span class="pill bad">꺼짐</span>';
  }
  const sev = document.getElementById("waf-severity");
  if (sev) sev.textContent = d.waf_block_min_severity;
  const bpm = document.getElementById("body-preview-max");
  if (bpm && d.body_preview_max != null) {
    bpm.textContent = String(d.body_preview_max) + " bytes";
  }
  const upd = document.getElementById("updated");
  if (upd) upd.textContent = "요약 갱신: " + new Date().toLocaleString("ko-KR");
}
function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
function trafficResultHtml(e) {
  if (e.blocked) {
    return '<span class="pill bad">차단</span>';
  }
  const c = Number(e.status_code);
  if (c >= 200 && c < 400) {
    return '<span class="pill ok">' + escapeHtml(String(c)) + "</span>";
  }
  return '<span class="pill bad">' + escapeHtml(String(c)) + "</span>";
}
function renderTraffic(events) {
  const body = document.getElementById("traffic-feed-body");
  const statTotal = document.getElementById("traffic-stat-total");
  const statBlocked = document.getElementById("traffic-stat-blocked");
  if (!body) return;
  if (!events || !events.length) {
    if (statTotal) statTotal.textContent = "0";
    if (statBlocked) statBlocked.textContent = "0";
    body.innerHTML =
      '<tr><td colspan="6" class="traffic-empty">기록 없음 · <code>' +
      window.location.origin +
      "/</code></td></tr>";
    renderDetections([]);
    return;
  }
  let blocked = 0;
  for (let i = 0; i < events.length; i++) {
    if (events[i].blocked) blocked += 1;
  }
  if (statTotal) statTotal.textContent = String(events.length);
  if (statBlocked) statBlocked.textContent = String(blocked);
  body.innerHTML = events
    .map(
      (e) =>
        "<tr><td>" +
        escapeHtml(e.time_iso) +
        "</td><td>" +
        escapeHtml(e.client_ip) +
        "</td><td>" +
        escapeHtml(e.method) +
        '</td><td class="col-path">' +
        escapeHtml(e.path) +
        "</td><td>" +
        trafficResultHtml(e) +
        '</td><td class="col-ua">' +
        escapeHtml(e.user_agent) +
        "</td></tr>"
    )
    .join("");
  renderDetections(events);
}
function renderDetections(events) {
  const body = document.getElementById("detections-feed-body");
  const foot = document.getElementById("detections-updated");
  if (!body) return;
  const rows = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (!e.blocked) continue;
    const fs = e.block_findings && e.block_findings.length ? e.block_findings : [null];
    for (let j = 0; j < fs.length; j++) {
      rows.push({ e: e, f: fs[j] });
    }
  }
  if (!rows.length) {
    body.innerHTML =
      '<tr><td colspan="11" class="traffic-empty">차단된 공격이 없습니다. 인젝션 등이 포함된 요청이 오면 OWASP·유형·위치·규칙이 여기에 표시됩니다.</td></tr>';
    if (foot) foot.textContent = "";
    return;
  }
  body.innerHTML = rows
    .map(({ e, f }) => {
      const o = f || {};
      return (
        "<tr><td>" +
        escapeHtml(e.time_iso) +
        "</td><td>" +
        escapeHtml(e.client_ip) +
        "</td><td>" +
        escapeHtml(e.method) +
        '</td><td class="col-path">' +
        escapeHtml(e.path) +
        "</td><td>" +
        escapeHtml(o.owasp_id || "—") +
        "</td><td>" +
        escapeHtml(o.category || "—") +
        "</td><td>" +
        escapeHtml(o.attack_type || "—") +
        "</td><td class=\"mono-stat\">" +
        escapeHtml(o.location || "—") +
        "</td><td class=\"mono-stat\">" +
        escapeHtml(o.rule_id || "—") +
        "</td><td>" +
        escapeHtml(o.severity || "—") +
        '</td><td class="col-detail">' +
        escapeHtml(o.evidence || "—") +
        "</td></tr>"
      );
    })
    .join("");
  if (foot) foot.textContent = "탐지 표: " + new Date().toLocaleString("ko-KR");
}
async function loadTraffic() {
  const foot = document.getElementById("traffic-updated");
  try {
    const r = await fetch("/__waf/api/traffic");
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderTraffic((await r.json()).events || []);
    if (foot) foot.textContent = "로그: " + new Date().toLocaleString("ko-KR");
  } catch (err) {
    if (foot) foot.textContent = "로그 오류";
  }
}
function renderClients(data) {
  const n = document.getElementById("clients-count");
  const sub = document.getElementById("clients-requests-total");
  const body = document.getElementById("clients-feed-body");
  if (!n || !body) return;
  const list = data.clients || [];
  const uniq = Number(data.unique_clients) || 0;
  n.textContent = String(uniq);
  let totalReq = 0;
  for (let i = 0; i < list.length; i++) {
    totalReq += Number(list[i].requests) || 0;
  }
  if (sub) {
    sub.textContent = uniq > 0 ? "· 통과 요청 " + totalReq + "회" : "";
  }
  if (!list.length) {
    body.innerHTML =
      '<tr><td colspan="5" class="traffic-empty">없음 · <code>' +
      window.location.origin +
      "/</code></td></tr>";
    return;
  }
  body.innerHTML = list
    .map(
      (c) =>
        "<tr><td>" +
        escapeHtml(c.client_ip) +
        "</td><td>" +
        escapeHtml(String(c.requests)) +
        "</td><td>" +
        escapeHtml(String(c.first_seen)) +
        "</td><td>" +
        escapeHtml(String(c.last_seen)) +
        '</td><td class="col-ua">' +
        escapeHtml(String(c.user_agent || "—")) +
        "</td></tr>"
    )
    .join("");
}
async function loadClients() {
  const foot = document.getElementById("clients-updated");
  try {
    const r = await fetch("/__waf/api/clients");
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderClients(await r.json());
    if (foot) foot.textContent = "접속자: " + new Date().toLocaleString("ko-KR");
  } catch (err) {
    if (foot) foot.textContent = "접속자 오류";
  }
}
function renderModules(data) {
  const body = document.getElementById("modules-feed-body");
  if (!body) return;
  const list = data.modules || [];
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="3" class="traffic-empty">없음</td></tr>';
    return;
  }
  body.innerHTML = list
    .map(
      (m) =>
        "<tr><td class=\"mono-stat\">" +
        escapeHtml(m.module_id) +
        "</td><td>" +
        escapeHtml(m.owasp_id) +
        "</td><td>" +
        escapeHtml(m.title) +
        "</td></tr>"
    )
    .join("");
}
async function loadModules() {
  const foot = document.getElementById("modules-updated");
  try {
    const r = await fetch("/__waf/api/modules");
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderModules(await r.json());
    if (foot) foot.textContent = "모듈: " + new Date().toLocaleString("ko-KR");
  } catch (err) {
    if (foot) foot.textContent = "모듈 API 오류";
  }
}
async function loadSummary() {
  try {
    const r = await fetch("/__waf/api/summary");
    if (!r.ok) throw new Error("HTTP " + r.status);
    applySummary(await r.json());
  } catch (e) {
    const el = document.getElementById("upstream-status");
    if (el) el.innerHTML = '<span class="pill bad">API 오류</span>';
  }
}
setClock();
setInterval(setClock, 1000);
(function bootFromDom() {
  const el = document.getElementById("waf-boot-data");
  if (!el) return;
  try {
    applySummary(JSON.parse(el.textContent));
  } catch (e) {
    console.error("WAF dashboard boot:", e);
  }
})();
const btn = document.getElementById("btn-refresh");
if (btn) {
  btn.addEventListener("click", () => {
    loadSummary();
    loadTraffic();
    loadClients();
    loadModules();
  });
}
setInterval(loadSummary, 15000);
loadTraffic();
setInterval(loadTraffic, 2000);
loadClients();
setInterval(loadClients, 2000);
loadModules();
