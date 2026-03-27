/* global window, document, console */

var rawEvents = [];
var lastBlockSummaryText = "";
var refreshTimers = { traffic: null, clients: null };

function setClock() {
  var el = document.getElementById("clock");
  if (el) el.textContent = new Date().toLocaleString("ko-KR");
}

function escapeHtml(s) {
  var d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

/** 서버 Severity enum 값(low/medium/high/critical/none) → 표시 라벨 */
function severityLabel(key) {
  var k = String(key || "").trim().toLowerCase();
  if (!k) return "—";
  if (k === "low") return "LOW";
  if (k === "medium") return "MEDIUM";
  if (k === "high") return "HIGH";
  if (k === "critical") return "CRITICAL";
  if (k === "none") return "NONE";
  return String(key || "").trim().toUpperCase();
}

function severityClassKey(key) {
  var k = String(key || "").trim().toLowerCase();
  if (k === "low" || k === "medium" || k === "high" || k === "critical" || k === "none") {
    return k;
  }
  return "unknown";
}

function severityBadgeHtml(severityRaw) {
  var raw = severityRaw == null ? "" : String(severityRaw).trim();
  if (!raw) {
    return (
      '<span class="sev-badge sev-unknown" aria-label="심각도 없음">' +
      escapeHtml("—") +
      "</span>"
    );
  }
  var cls = severityClassKey(raw);
  var label = severityLabel(raw);
  return (
    '<span class="sev-badge sev-' +
    cls +
    '" aria-label="심각도 ' +
    escapeHtml(label) +
    '">' +
    escapeHtml(label) +
    "</span>"
  );
}

function applySummary(d) {
  var up = d.upstream_ok;
  var el = document.getElementById("upstream-status");
  if (el) {
    if (up === true) {
      el.innerHTML =
        '<span class="pill ok" aria-label="업스트림 연결 정상">연결됨</span>';
    } else if (up === false) {
      el.innerHTML =
        '<span class="pill bad" aria-label="업스트림 연결 실패">실패</span>';
      if (d.upstream_error) {
        el.innerHTML +=
          '<span class="error-hint">' + escapeHtml(d.upstream_error) + "</span>";
      }
    } else {
      el.textContent = "…";
    }
  }
  var wafEl = document.getElementById("waf-enabled");
  if (wafEl) {
    wafEl.innerHTML = d.waf_enabled
      ? '<span class="pill ok" aria-label="WAF 활성">켜짐</span>'
      : '<span class="pill bad" aria-label="WAF 비활성">꺼짐</span>';
  }
  var sev = document.getElementById("waf-severity");
  if (sev) {
    var sevRaw =
      d.waf_block_min_severity != null && d.waf_block_min_severity !== ""
        ? String(d.waf_block_min_severity)
        : "";
    sev.innerHTML = sevRaw ? severityBadgeHtml(sevRaw) : severityBadgeHtml("");
  }
  var bpm = document.getElementById("body-preview-max");
  if (bpm && d.body_preview_max != null) {
    bpm.textContent = String(d.body_preview_max) + " bytes";
  }
  var ppo = document.getElementById("proxy-public-origin");
  if (ppo) {
    ppo.textContent = d.proxy_public_origin || window.location.origin || "—";
  }
  var ps = document.getElementById("process-started");
  if (ps) {
    ps.textContent = d.process_started_at || "—";
  }
  var envEl = document.getElementById("env-snapshot");
  if (envEl && d.env && typeof d.env === "object") {
    var parts = [];
    for (var k in d.env) {
      if (!Object.prototype.hasOwnProperty.call(d.env, k)) continue;
      parts.push(
        "<dt>" +
          escapeHtml(k) +
          "</dt><dd class=\"mono-stat\">" +
          escapeHtml(String(d.env[k])) +
          "</dd>"
      );
    }
    envEl.innerHTML = parts.join("");
  }
}

function trafficResultHtml(e) {
  if (e.blocked) {
    return '<span class="pill bad" aria-label="차단됨">차단</span>';
  }
  var c = Number(e.status_code);
  if (c >= 200 && c < 400) {
    return (
      '<span class="pill ok" aria-label="HTTP ' +
      escapeHtml(String(c)) +
      '">' +
      escapeHtml(String(c)) +
      "</span>"
    );
  }
  return (
    '<span class="pill bad" aria-label="HTTP ' +
    escapeHtml(String(c)) +
    '">' +
    escapeHtml(String(c)) +
    "</span>"
  );
}

function getFilteredEvents() {
  var method = (document.getElementById("filter-method") || {}).value || "";
  var blockedOnly = (document.getElementById("filter-blocked-only") || {}).checked;
  var pathQ = (
    (document.getElementById("filter-path") || {}).value || ""
  ).trim().toLowerCase();
  var ipQ = ((document.getElementById("filter-ip") || {}).value || "")
    .trim()
    .toLowerCase();
  var out = [];
  for (var i = 0; i < rawEvents.length; i++) {
    var e = rawEvents[i];
    if (method && String(e.method || "").toUpperCase() !== method.toUpperCase()) continue;
    if (blockedOnly && !e.blocked) continue;
    if (pathQ && String(e.path || "").toLowerCase().indexOf(pathQ) === -1) continue;
    if (ipQ && String(e.client_ip || "").toLowerCase().indexOf(ipQ) === -1) continue;
    out.push(e);
  }
  return out;
}

function renderLastBlockHighlight() {
  var body = document.getElementById("last-block-body");
  var btn = document.getElementById("btn-copy-last-block");
  lastBlockSummaryText = "";
  if (!body) return;
  for (var i = 0; i < rawEvents.length; i++) {
    var e = rawEvents[i];
    if (!e.blocked) continue;
    var fs = e.block_findings && e.block_findings.length ? e.block_findings : [null];
    var f = fs[0] || {};
    var lines = [
      "시각: " + (e.time_iso || "—"),
      "IP: " + (e.client_ip || "—"),
      (e.method || "—") + " " + (e.path || "—"),
      "규칙: " + (f.rule_id || "—"),
      "유형: " + (f.attack_type || "—"),
      "OWASP: " + (f.owasp_id || "—"),
    ];
    lastBlockSummaryText =
      [lines[0], lines[1], lines[2], lines[3], lines[4]].join("\n") +
      "\n심각도: " +
      severityLabel(f.severity) +
      "\n" +
      lines[5];
    body.innerHTML =
      "<span class=\"mono-stat\">" +
      escapeHtml([lines[0], lines[1], lines[2], lines[3]].join(" · ")) +
      "</span><br/><span class=\"last-block-detail\">" +
      escapeHtml(lines[4]) +
      " · " +
      severityBadgeHtml(f.severity) +
      "</span><br/><span class=\"last-block-detail\">" +
      escapeHtml(lines[5]) +
      "</span>";
    if (btn) btn.hidden = false;
    return;
  }
  body.textContent = "아직 차단 기록이 없습니다.";
  if (btn) btn.hidden = true;
}

function renderDetections(events) {
  var body = document.getElementById("detections-feed-body");
  var foot = document.getElementById("detections-updated");
  if (!body) return;
  var rows = [];
  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    if (!e.blocked) continue;
    var fs = e.block_findings && e.block_findings.length ? e.block_findings : [null];
    for (var j = 0; j < fs.length; j++) {
      rows.push({ e: e, f: fs[j] });
    }
  }
  if (!rows.length) {
    body.innerHTML =
      '<tr><td colspan="11" class="traffic-empty">차단 없음</td></tr>';
    if (foot) foot.textContent = "";
    return;
  }
  body.innerHTML = rows
    .map(function (_ref) {
      var e = _ref.e;
      var f = _ref.f;
      var o = f || {};
      var ev = o.evidence || "—";
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
        '</td><td class="mono-stat">' +
        escapeHtml(o.location || "—") +
        '</td><td class="mono-stat">' +
        escapeHtml(o.rule_id || "—") +
        "</td><td>" +
        severityBadgeHtml(o.severity) +
        '</td><td class="col-detail"><details class="evidence-fold"><summary>상세</summary><pre class="evidence-pre">' +
        escapeHtml(ev) +
        "</pre></details></td></tr>"
      );
    })
    .join("");
  if (foot) foot.textContent = "";
}

function renderTraffic(events) {
  var body = document.getElementById("traffic-feed-body");
  var statTotal = document.getElementById("traffic-stat-total");
  var statBlocked = document.getElementById("traffic-stat-blocked");
  if (!body) return;
  if (!events || !events.length) {
    if (statTotal) statTotal.textContent = "0";
    if (statBlocked) statBlocked.textContent = "0";
    body.innerHTML =
      '<tr><td colspan="6" class="traffic-empty">기록 없음</td></tr>';
    renderDetections([]);
    renderLastBlockHighlight();
    return;
  }
  var blocked = 0;
  for (var i = 0; i < events.length; i++) {
    if (events[i].blocked) blocked += 1;
  }
  if (statTotal) statTotal.textContent = String(events.length);
  if (statBlocked) statBlocked.textContent = String(blocked);
  body.innerHTML = events
    .map(function (e) {
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
        trafficResultHtml(e) +
        '</td><td class="col-ua">' +
        escapeHtml(e.user_agent) +
        "</td></tr>"
      );
    })
    .join("");
  renderDetections(events);
  renderLastBlockHighlight();
}

function computeLocalStatsFromBuffer(events) {
  var total = events.length;
  var blocked = 0;
  var ruleMap = {};
  var atkMap = {};
  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    if (!e.blocked) continue;
    blocked += 1;
    var fs = e.block_findings || [];
    for (var j = 0; j < fs.length; j++) {
      var f = fs[j] || {};
      var rid = String(f.rule_id || "").trim();
      var atk = String(f.attack_type || "").trim();
      if (rid) ruleMap[rid] = (ruleMap[rid] || 0) + 1;
      if (atk) atkMap[atk] = (atkMap[atk] || 0) + 1;
    }
  }
  function topMap(map, n) {
    var keys = Object.keys(map);
    keys.sort(function (a, b) {
      return map[b] - map[a];
    });
    return keys.slice(0, n).map(function (k) {
      return { key: k, count: map[k] };
    });
  }
  return {
    status: "ok",
    total_logged: total,
    blocked_count: blocked,
    passed_count: total - blocked,
    block_ratio: total ? blocked / total : 0,
    top_rule_ids: topMap(ruleMap, 5),
    top_attack_types: topMap(atkMap, 5),
    _source: "client_buffer",
  };
}

function applyStats(s, sourceNote) {
  var t = document.getElementById("kpi-total");
  var b = document.getElementById("kpi-blocked");
  var r = document.getElementById("kpi-ratio");
  var bar = document.getElementById("kpi-bar-fill");
  var ta = document.getElementById("kpi-top-attacks");
  var tr = document.getElementById("kpi-top-rules");
  var foot = document.getElementById("stats-updated");
  var donut = document.getElementById("kpi-donut");
  var donutPct = document.getElementById("kpi-donut-pct");
  var chips = document.getElementById("kpi-chips");
  if (!t || !b || !r) return;
  var total = Number(s.total_logged) || 0;
  var blocked = Number(s.blocked_count) || 0;
  var ratio = total ? (100 * blocked) / total : 0;
  t.textContent = String(total);
  b.textContent = String(blocked);
  r.textContent = (Math.round(ratio * 10) / 10).toFixed(1) + "%";
  if (bar) bar.style.width = Math.min(100, ratio).toFixed(1) + "%";
  if (donut) donut.style.setProperty("--kpi-pct", String(Math.min(100, ratio)));
  if (donutPct) donutPct.textContent = (Math.round(ratio * 10) / 10).toFixed(1) + "%";

  if (chips) {
    var atks = s.top_attack_types || [];
    if (!atks.length) {
      chips.innerHTML = "";
    } else {
      chips.innerHTML = atks
        .slice(0, 4)
        .map(function (x) {
          return (
            '<span class="kpi-chip">' +
            escapeHtml(x.key) +
            " · " +
            escapeHtml(String(x.count)) +
            "</span>"
          );
        })
        .join("");
    }
  }

  function fmtTop(items, label) {
    if (!items || !items.length) {
      return label + " —";
    }
    var parts = items.slice(0, 3).map(function (x) {
      return x.key + "(" + x.count + ")";
    });
    return label + " " + parts.join(", ");
  }
  if (ta) ta.textContent = fmtTop(s.top_attack_types, "공격");
  if (tr) tr.textContent = fmtTop(s.top_rule_ids, "규칙");

  if (foot) {
    foot.classList.remove("stats-source-local", "stats-source-ok");
    var ts = new Date().toLocaleString("ko-KR");
    if (sourceNote === "local") {
      foot.classList.add("stats-source-local");
      foot.textContent = ts + " · 버퍼";
    } else {
      foot.classList.add("stats-source-ok");
      foot.textContent = ts + " · 서버";
    }
  }
}

async function loadStats() {
  try {
    var res = await fetch("/__waf/api/stats");
    if (!res.ok) throw new Error("HTTP " + res.status);
    applyStats(await res.json(), "server");
  } catch (err) {
    applyStats(computeLocalStatsFromBuffer(rawEvents), "local");
  }
}

async function loadTraffic() {
  var foot = document.getElementById("traffic-updated");
  try {
    var res = await fetch("/__waf/api/traffic");
    if (!res.ok) throw new Error("HTTP " + res.status);
    rawEvents = (await res.json()).events || [];
    renderTraffic(getFilteredEvents());
    if (foot) foot.textContent = "";
  } catch (err) {
    if (foot) foot.textContent = "오류";
  }
}

/** 로그·차단 KPI·상단 요약 카드(연결/WAF/심각도/본문 등)를 같은 주기로 동기화 */
async function syncTrafficAndKpi() {
  await loadTraffic();
  await loadStats();
  await fetchAndApplySummary(false);
}

function renderClients(data) {
  var n = document.getElementById("clients-count");
  var sub = document.getElementById("clients-requests-total");
  var body = document.getElementById("clients-feed-body");
  if (!n || !body) return;
  var list = data.clients || [];
  var uniq = Number(data.unique_clients) || 0;
  n.textContent = String(uniq);
  var totalReq = 0;
  for (var i = 0; i < list.length; i++) {
    totalReq += Number(list[i].requests) || 0;
  }
  if (sub) {
    sub.textContent = uniq > 0 ? "· 통과 요청 " + totalReq + "회" : "";
  }
  if (!list.length) {
    body.innerHTML =
      '<tr><td colspan="5" class="traffic-empty">없음 · <code>' +
      escapeHtml(window.location.origin) +
      "/</code></td></tr>";
    return;
  }
  body.innerHTML = list
    .map(function (c) {
      return (
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
      );
    })
    .join("");
}

async function loadClients() {
  var foot = document.getElementById("clients-updated");
  try {
    var res = await fetch("/__waf/api/clients");
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderClients(await res.json());
    if (foot) foot.textContent = "";
  } catch (err) {
    if (foot) foot.textContent = "오류";
  }
}

/** @param {boolean} refreshStatsAfter true면 apply 직후 loadStats (수동 갱신 등) */
async function fetchAndApplySummary(refreshStatsAfter) {
  try {
    var res = await fetch("/__waf/api/summary");
    if (!res.ok) throw new Error("HTTP " + res.status);
    applySummary(await res.json());
    if (refreshStatsAfter) await loadStats();
  } catch (e) {
    var el = document.getElementById("upstream-status");
    if (el)
      el.innerHTML =
        '<span class="pill bad" aria-label="요약 API 오류">API 오류</span>';
  }
}

async function loadSummary() {
  await fetchAndApplySummary(true);
}

function stopAutoRefresh() {
  if (refreshTimers.traffic) clearInterval(refreshTimers.traffic);
  if (refreshTimers.clients) clearInterval(refreshTimers.clients);
  refreshTimers.traffic = refreshTimers.clients = null;
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimers.traffic = setInterval(function () {
    syncTrafficAndKpi();
  }, 2000);
  refreshTimers.clients = setInterval(loadClients, 2000);
}

function onFilterChange() {
  renderTraffic(getFilteredEvents());
}

function exportJsonBlob() {
  var json = JSON.stringify(rawEvents, null, 2);
  var blob = new Blob([json], { type: "application/json;charset=utf-8" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "waf-traffic-buffer.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function copyBufferJson() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(rawEvents, null, 2));
    var foot = document.getElementById("traffic-updated");
    if (foot) foot.textContent = "클립보드에 복사됨";
  } catch (e) {
    var foot2 = document.getElementById("traffic-updated");
    if (foot2) foot2.textContent = "복사 실패 (브라우저 권한)";
  }
}

setClock();
setInterval(setClock, 1000);

(function bootFromDom() {
  var el = document.getElementById("waf-boot-data");
  if (!el) return;
  try {
    applySummary(JSON.parse(el.textContent));
  } catch (e) {
    console.error("WAF dashboard boot:", e);
  }
})();

var btn = document.getElementById("btn-refresh");
if (btn) {
  btn.addEventListener("click", function () {
    syncTrafficAndKpi();
    loadClients();
  });
}

var autoChk = document.getElementById("auto-refresh");
if (autoChk) {
  autoChk.addEventListener("change", function () {
    if (autoChk.checked) startAutoRefresh();
    else stopAutoRefresh();
  });
}

["filter-method", "filter-blocked-only", "filter-path", "filter-ip"].forEach(function (id) {
  var node = document.getElementById(id);
  if (node) node.addEventListener("change", onFilterChange);
  if (node) node.addEventListener("input", onFilterChange);
});

var btnEx = document.getElementById("btn-export-json");
if (btnEx) btnEx.addEventListener("click", exportJsonBlob);
var btnCp = document.getElementById("btn-copy-json");
if (btnCp) btnCp.addEventListener("click", copyBufferJson);
var btnLb = document.getElementById("btn-copy-last-block");
if (btnLb) {
  btnLb.addEventListener("click", function () {
    if (!lastBlockSummaryText) return;
    navigator.clipboard.writeText(lastBlockSummaryText).catch(function () {});
  });
}

syncTrafficAndKpi();
loadClients();
if (autoChk && autoChk.checked) startAutoRefresh();
