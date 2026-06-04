/* global window, document, console */

var rawEvents = [];
var lastBlockSummaryText = "";
var refreshTimers = { main: null };
var lastSqlSchema = null;
var notificationBaselineReady = false;

/** 같은 출처 세션 쿠키 포함. */
function wafApiFetch(url, init) {
  var o = init ? Object.assign({}, init) : {};
  if (!o.credentials) {
    o.credentials = "same-origin";
  }
  return fetch(url, o);
}

function hideDashAsyncError() {
  var bar = document.getElementById("dash-async-error-banner");
  var txt = document.getElementById("dash-async-error-text");
  if (txt) txt.textContent = "";
  if (bar) bar.hidden = true;
}

function reportDashAsyncError(step, err) {
  console.error("[WAF Dashboard]", step || "", err);
  var bar = document.getElementById("dash-async-error-banner");
  var txt = document.getElementById("dash-async-error-text");
  if (bar && txt) {
    bar.hidden = false;
    var msg =
      err && err.message
        ? String(err.message)
        : typeof err === "string"
          ? err
          : "알 수 없는 오류";
    txt.textContent = (step ? step + ": " : "") + msg + " · F12 Console 참고";
  }
}

/** 자동 갱신에서 Promise 예외가 삼켜지지 않게 래핑 */
function runDashAsync(fn, step) {
  Promise.resolve(fn()).catch(function (err) {
    reportDashAsyncError(step, err);
  });
}

// 현재 선택된 사이트 필터 (빈 문자열 = 전체)
var activeSite = (function () {
  try {
    var bootEl = document.getElementById("waf-boot-data");
    if (bootEl) {
      var boot = JSON.parse(bootEl.textContent);
      if (boot && boot.active_site) return boot.active_site;
    }
    return new URLSearchParams(window.location.search).get("site") || "";
  } catch (e) {
    return "";
  }
}());

// body 속성에서 admin 여부 / 사용자 사이트 읽기
var isAdmin = (document.body.getAttribute("data-is-admin") === "true");
var userSite = document.body.getAttribute("data-user-site") || "";

/** 요약/API에서 받은 site_cards (표시 이름·프록시 URL). */
var lastSiteCards = [];

function siteDisplayName(siteId) {
  var idStr = siteId ? String(siteId) : "";
  if (!idStr) return "";
  for (var i = 0; i < lastSiteCards.length; i++) {
    var c = lastSiteCards[i];
    if (c && String(c.site_id || "") === idStr) {
      return String(c.label || c.site_id || idStr);
    }
  }
  return idStr;
}

function refreshActiveSiteBadge() {
  var badge = document.getElementById("active-site-badge");
  if (!badge) return;
  notificationBaselineReady = false;
  if (!activeSite) {
    badge.hidden = true;
    return;
  }
  badge.hidden = false;
  badge.textContent = "사이트: " + siteDisplayName(activeSite);
}

function siteQuery() {
  return activeSite ? "?site=" + encodeURIComponent(activeSite) : "";
}

function wafPage() {
  return (document.body && document.body.getAttribute("data-waf-page")) || "overview";
}

var pipelineHintTotals = { stats: -1, clients: -1 };
/** 페이지 로드 시 서버가 내려준 통계(API 실패·빈 traffic 버퍼로 덮어쓰이지 않게 보존). */
var bootstrapStatsSnapshot = null;

function refreshPipelineHint() {
  var el = document.getElementById("pipeline-hint-banner");
  if (!el) return;
  try {
    if (
      typeof sessionStorage !== "undefined" &&
      sessionStorage.getItem("waf_hide_pipeline_hint") === "1"
    ) {
      el.hidden = true;
      return;
    }
  } catch (e) {}
  var st = pipelineHintTotals.stats < 0 ? 0 : Number(pipelineHintTotals.stats) || 0;
  var cu = pipelineHintTotals.clients < 0 ? 0 : Number(pipelineHintTotals.clients) || 0;
  el.hidden = st > 0 || cu > 0;
}

function setClock() {
  var el = document.getElementById("clock");
  if (!el) return;
  var d = new Date();
  el.textContent = d.toLocaleString("ko-KR");
  if (el.tagName === "TIME" && el.setAttribute) {
    el.setAttribute("datetime", d.toISOString());
  }
}

function escapeHtml(s) {
  var d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

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

function coerceWafEnabled(v) {
  if (v === true || v === "true" || v === 1 || v === "1") return true;
  if (v === false || v === "false" || v === 0 || v === "0") return false;
  return !!v;
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
  var centralScope = String(d.summary_scope || "") === "central";
  var up = d.upstream_ok;
  var el = document.getElementById("upstream-status");
  if (el) {
    if (centralScope && up !== true && up !== false) {
      el.innerHTML =
        '<span class="pill muted" aria-label="중앙 집계">중앙 DB · 워커 업스트림은 미표시</span>';
    } else if (up === true) {
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
    if (centralScope && (d.waf_enabled === undefined || d.waf_enabled === null)) {
      wafEl.innerHTML =
        '<span class="pill muted" title="사이드바 「사이트 필터」에서 사이트를 고르면 중앙에 저장되는 WAF On/Off가 표시됩니다">중앙 정책 · 사이트 선택 후 전환 · <span class="mono-stat">/__proxy/health</span></span>';
    } else {
    var wafOn = coerceWafEnabled(d.waf_enabled);
    wafEl.innerHTML = wafOn
      ? '<button type="button" id="waf-toggle-btn" class="pill ok waf-toggle-pill" aria-pressed="true" title="WAF 끄기">켜짐</button>'
      : '<button type="button" id="waf-toggle-btn" class="pill bad waf-toggle-pill" aria-pressed="false" title="WAF 켜기">꺼짐</button>';
    }
  }
  var sev = document.getElementById("waf-severity");
  if (sev) {
    if (centralScope && (d.waf_block_min_severity === undefined || d.waf_block_min_severity === null || String(d.waf_block_min_severity) === "")) {
      sev.innerHTML =
        '<span class="pill muted">워커별</span>';
    } else {
    var sevRaw =
      d.waf_block_min_severity != null && d.waf_block_min_severity !== ""
        ? String(d.waf_block_min_severity)
        : "";
    sev.innerHTML = sevRaw ? severityBadgeHtml(sevRaw) : severityBadgeHtml("");
    }
  }
  var bpm = document.getElementById("body-preview-max");
  if (bpm && d.body_preview_max != null && d.body_preview_max !== "") {
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
  // 사이트 목록 카드
  var sitesEl = document.getElementById("sites-list");
  if (sitesEl) {
    var ids = d.sites || [];
    var cardsIn = Array.isArray(d.site_cards) ? d.site_cards : [];
    lastSiteCards = cardsIn.length
      ? cardsIn
      : ids.map(function (sid) {
          return {
            site_id: sid,
            label: sid,
            public_url: "",
            waf_enabled: true,
          };
        });
    if (!lastSiteCards.length) {
      sitesEl.textContent = "아직 트래픽 없음 (프록시 워커를 실행해 요청을 보내보세요)";
    } else {
      sitesEl.innerHTML = lastSiteCards
        .map(function (c) {
          var lid = escapeHtml(String(c.site_id || ""));
          var lab = escapeHtml(String(c.label || c.site_id || ""));
          var url = String(c.public_url || "").trim();
          var wafOff =
            typeof c.waf_enabled === "boolean" &&
            !c.waf_enabled;
          var title =
            escapeHtml(url) + (wafOff ? "\n중앙 WAF: 꺼짐(통과 우선 모드)" : "");
          var tag = lab + (wafOff ? " · <span class='muted'>WAF끔</span>" : "");
          return (
            '<span class="kpi-chip site-chip' +
            (wafOff ? " site-chip-waf-off" : "") +
            '" style="cursor:pointer" data-site="' +
            lid +
            '" title="' +
            title +
            '">' +
            tag +
            "</span>"
          );
        })
        .join(" ");
    }
  }
  refreshActiveSiteBadge();
  var tsCard = document.getElementById("sidebar-traffic-db");
  if (tsCard && d.traffic_store && typeof d.traffic_store === "object") {
    var cn = document.getElementById("sidebar-store-count");
    var rp = document.getElementById("sidebar-store-path");
    var apEl = document.getElementById("sidebar-auth-db-path");
    var ts = d.traffic_store;
    var nrow = ts.stored_row_count != null ? String(ts.stored_row_count) : "—";
    var dbp = ts.traffic_log_db_resolved ? String(ts.traffic_log_db_resolved) : "—";
    if (cn) cn.textContent = nrow;
    if (rp) {
      rp.textContent = dbp;
      rp.setAttribute("title", dbp);
    }
    if (apEl && d.auth_db_path) {
      var apath = String(d.auth_db_path);
      apEl.textContent = apath;
      apEl.setAttribute("title", apath);
    }
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
  var siteQ = ((document.getElementById("filter-site") || {}).value || "").trim();
  var out = [];
  for (var i = 0; i < rawEvents.length; i++) {
    var e = rawEvents[i];
    if (method && String(e.method || "").toUpperCase() !== method.toUpperCase()) continue;
    if (blockedOnly && !e.blocked) continue;
    if (pathQ && String(e.path || "").toLowerCase().indexOf(pathQ) === -1) continue;
    if (ipQ && String(e.client_ip || "").toLowerCase().indexOf(ipQ) === -1) continue;
    if (siteQ && String(e.site_id || "") !== siteQ) continue;
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
  body.textContent = "—";
  if (btn) btn.hidden = true;
}

function formatOverviewTime(value) {
  if (!value) return "방금";
  var d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value).slice(11, 16) || "방금";
  var diff = Math.max(0, Date.now() - d.getTime());
  var min = Math.round(diff / 60000);
  if (min < 1) return "방금";
  if (min < 60) return min + "분 전";
  var hr = Math.round(min / 60);
  if (hr < 24) return hr + "시간 전";
  return d.toLocaleDateString("ko-KR");
}

function renderOverviewThreatLog() {
  var list = document.getElementById("overview-threat-list");
  if (!list) return;
  var rows = [];
  for (var i = 0; i < rawEvents.length; i++) {
    var e = rawEvents[i];
    if (!e || !e.blocked) continue;
    var f = e.block_findings && e.block_findings.length ? e.block_findings[0] || {} : {};
    rows.push({ e: e, f: f });
    if (rows.length >= 5) break;
  }
  if (!rows.length) {
    list.innerHTML = '<div class="overview-threat-empty">No threats</div>';
    return;
  }
  list.innerHTML = rows
    .map(function (_ref) {
      var e = _ref.e;
      var f = _ref.f;
      var title = f.attack_type || f.category || "Blocked Malicious IP";
      var ip = e.client_ip || "unknown";
      var path = e.path || "/";
      return (
        '<div class="overview-threat-item">' +
        '<div class="overview-threat-main"><strong>' +
        escapeHtml(title) +
        '</strong><small>' +
        escapeHtml(ip + " · " + path) +
        "</small></div>" +
        '<span class="overview-threat-time">' +
        escapeHtml(formatOverviewTime(e.time_iso)) +
        "</span></div>"
      );
    })
    .join("");
}

function parseEventTime(value) {
  if (!value) return null;
  var d = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function overviewTimeBuckets(events) {
  var total = [0, 0, 0, 0, 0, 0, 0];
  var blocked = [0, 0, 0, 0, 0, 0, 0];
  var src = events && events.length ? events : [];
  for (var i = 0; i < src.length; i++) {
    var e = src[i];
    var d = parseEventTime(e && e.time_iso);
    var hour = d ? d.getHours() : 0;
    var idx = Math.max(0, Math.min(6, Math.floor(hour / 4)));
    total[idx] += 1;
    if (e && e.blocked) blocked[idx] += 1;
  }
  return { total: total, blocked: blocked };
}

function overviewPathFromBuckets(values, baseY) {
  var max = Math.max.apply(null, values.concat([1]));
  var pts = values.map(function (v, i) {
    var x = (360 / (values.length - 1)) * i;
    var y = 98 - (v / max) * 72;
    if (v === 0 && max <= 1) y = baseY;
    return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
  });
  return pts
    .map(function (p, i) {
      return (i === 0 ? "M" : "L") + p[0] + " " + p[1];
    })
    .join(" ");
}

function topAttackBreakdown(events) {
  var map = {};
  var blocked = 0;
  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    if (!e || !e.blocked) continue;
    blocked += 1;
    var fs = e.block_findings || [];
    var f = fs.length ? fs[0] || {} : {};
    var key = String(f.attack_type || f.category || f.rule_id || "Blocked").trim();
    map[key] = (map[key] || 0) + 1;
  }
  var keys = Object.keys(map).sort(function (a, b) {
    return map[b] - map[a];
  });
  return keys.slice(0, 2).map(function (k) {
    return { key: k, count: map[k], pct: blocked ? Math.round((map[k] / blocked) * 100) : 0 };
  });
}

function aiSecondPassSummary(events) {
  var count = 0;
  var last = null;
  var attackMap = {};
  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    var fs = e && e.block_findings ? e.block_findings : [];
    for (var j = 0; j < fs.length; j++) {
      var f = fs[j] || {};
      if (String(f.rule_id || "").toUpperCase() !== "AI-SECOND-PASS") continue;
      count += 1;
      if (!last) last = { e: e, f: f };
      var atk = String(f.attack_type || "AI Second Pass").trim();
      attackMap[atk] = (attackMap[atk] || 0) + 1;
    }
  }
  var attacks = Object.keys(attackMap).sort(function (a, b) {
    return attackMap[b] - attackMap[a];
  });
  return { count: count, last: last, topAttack: attacks.length ? attacks[0] : "" };
}

function renderAiSecondPassOverview(events) {
  var state = document.getElementById("ai-second-pass-state");
  var countEl = document.getElementById("ai-second-pass-count");
  var lastEl = document.getElementById("ai-second-pass-last");
  if (!state && !countEl && !lastEl) return;
  var s = aiSecondPassSummary(events || []);
  if (countEl) countEl.textContent = String(s.count) + "건";
  if (state) {
    state.className = s.count ? "pill ok" : "pill muted";
    state.textContent = s.count ? "AI 보조 차단 발생" : "AI 보조 차단 없음";
  }
  if (lastEl) {
    if (!s.last) {
      lastEl.textContent = "최근 AI 판단: —";
    } else {
      lastEl.textContent =
        "최근 AI 판단: " +
        (s.last.f.attack_type || "AI Second Pass") +
        " · " +
        (s.last.e.path || "/");
    }
  }
}

function renderPreviewPage(events) {
  var src = events || rawEvents || [];
  var ai = aiSecondPassSummary(src);
  var aiCount = document.getElementById("preview-ai-count");
  var aiState = document.getElementById("preview-ai-state");
  if (aiCount) aiCount.textContent = String(ai.count);
  if (aiState) aiState.textContent = ai.count ? "AI 보조 차단 발생" : "AI 보조 차단 없음";

  var recent = document.getElementById("preview-recent-threat");
  if (!recent) return;
  var row = null;
  for (var i = 0; i < src.length; i++) {
    if (src[i] && src[i].blocked) {
      row = src[i];
      break;
    }
  }
  if (!row) return;
  var f = row.block_findings && row.block_findings.length ? row.block_findings[0] || {} : {};
  recent.innerHTML =
    "<strong>" +
    escapeHtml(f.attack_type || f.rule_id || "차단 이벤트") +
    "</strong><span>" +
    escapeHtml((row.method || "—") + " " + (row.path || "/")) +
    " · " +
    severityBadgeHtml(f.severity) +
    "</span>";
}

function updateOverviewChartsFromEvents() {
  var events = rawEvents || [];
  renderAiSecondPassOverview(events);
  var buckets = overviewTimeBuckets(events);
  var bars = document.querySelectorAll("#overview-bar-chart span");
  if (bars.length) {
    var maxBar = Math.max.apply(null, buckets.blocked.concat([1]));
    for (var bi = 0; bi < bars.length; bi++) {
      var h = buckets.blocked[bi] ? Math.max(12, Math.round((buckets.blocked[bi] / maxBar) * 88)) : 8;
      bars[bi].style.setProperty("--h", String(h) + "%");
      bars[bi].setAttribute("title", "차단 " + String(buckets.blocked[bi] || 0) + "건");
    }
  }
  var totalLine = document.getElementById("overview-line-total");
  var blockedLine = document.getElementById("overview-line-blocked");
  var area = document.getElementById("overview-line-area");
  var totalPath = overviewPathFromBuckets(buckets.total, 96);
  var blockedPath = overviewPathFromBuckets(buckets.blocked, 102);
  if (totalLine) totalLine.setAttribute("d", totalPath);
  if (blockedLine) blockedLine.setAttribute("d", blockedPath);
  if (area) area.setAttribute("d", totalPath + " L360 112 L0 112Z");

  var rings = document.querySelectorAll(".overview-mini-ring");
  var top = topAttackBreakdown(events);
  for (var ri = 0; ri < rings.length; ri++) {
    var item = top[ri] || { key: ri === 0 ? "Blocked" : "Passed", pct: 0 };
    rings[ri].style.setProperty("--pct", String(Math.max(2, item.pct)));
    var span = rings[ri].querySelector("span");
    var small = rings[ri].querySelector("small");
    if (span) span.textContent = String(item.pct) + "%";
    if (small) small.textContent = item.key;
  }

  var total = events.length;
  var blockedCount = 0;
  var recentCount = 0;
  var now = Date.now();
  for (var i = 0; i < events.length; i++) {
    if (events[i] && events[i].blocked) blockedCount += 1;
    var d = parseEventTime(events[i] && events[i].time_iso);
    if (d && now - d.getTime() <= 10 * 60 * 1000) recentCount += 1;
  }
  var loadPct = Math.min(100, Math.round((recentCount / 30) * 100));
  var threatPct = total ? Math.round((blockedCount / total) * 100) : 0;
  var loadBar = document.getElementById("overview-traffic-load-bar");
  var threatBar = document.getElementById("overview-threat-pressure-bar");
  var loadLabel = document.getElementById("overview-traffic-load-label");
  var threatLabel = document.getElementById("overview-threat-pressure-label");
  if (loadBar) loadBar.style.setProperty("--value", String(Math.max(4, loadPct)) + "%");
  if (threatBar) threatBar.style.setProperty("--value", String(Math.max(4, threatPct)) + "%");
  if (loadLabel) loadLabel.textContent = "10m " + String(recentCount);
  if (threatLabel) threatLabel.textContent = String(threatPct) + "% blocked";
}

function renderOverviewVisuals() {
  renderOverviewThreatLog();
  updateOverviewChartsFromEvents();
}

function recentNotificationRows(events) {
  var out = [];
  var src = events && events.length ? events : rawEvents;
  for (var i = 0; i < src.length; i++) {
    var e = src[i];
    if (!e || !e.blocked) continue;
    var f = e.block_findings && e.block_findings.length ? e.block_findings[0] || {} : {};
    out.push({ e: e, f: f });
    if (out.length >= 7) break;
  }
  return out;
}

function notificationKey(row) {
  var e = row && row.e ? row.e : {};
  var f = row && row.f ? row.f : {};
  return [
    e.id != null ? String(e.id) : "",
    e.time_iso || "",
    e.client_ip || "",
    e.method || "",
    e.path || "",
    f.rule_id || "",
  ].join("|");
}

function notificationReadStorageKey() {
  return "waf_read_notifications:" + (activeSite || "all");
}

function getReadNotificationKeys() {
  try {
    var raw = sessionStorage.getItem(notificationReadStorageKey()) || "[]";
    var arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.map(String);
  } catch (e) {
    return [];
  }
}

function setReadNotificationKeys(keys) {
  try {
    var uniq = [];
    var seen = {};
    for (var i = 0; i < keys.length; i++) {
      var k = String(keys[i] || "");
      if (!k || seen[k]) continue;
      seen[k] = true;
      uniq.push(k);
    }
    sessionStorage.setItem(notificationReadStorageKey(), JSON.stringify(uniq.slice(0, 80)));
  } catch (e) {}
}

function unreadNotificationRows(rows) {
  var read = getReadNotificationKeys();
  var seen = {};
  for (var i = 0; i < read.length; i++) seen[read[i]] = true;
  return rows.filter(function (row) {
    return !seen[notificationKey(row)];
  });
}

function markNotificationsRead(rows) {
  var read = getReadNotificationKeys();
  for (var i = 0; i < rows.length; i++) {
    read.push(notificationKey(rows[i]));
  }
  setReadNotificationKeys(read);
}

function updateNotificationBadge(rows) {
  var count = document.getElementById("topbar-notify-count");
  if (!count) return;
  var currentRows = rows || recentNotificationRows(rawEvents);
  if (!notificationBaselineReady) {
    markNotificationsRead(currentRows);
    notificationBaselineReady = true;
  }
  var unread = unreadNotificationRows(currentRows);
  count.textContent = String(Math.min(99, unread.length));
  count.hidden = unread.length <= 0;
}

function renderTopbarNotifications(events) {
  var list = document.getElementById("topbar-notification-list");
  var count = document.getElementById("topbar-notify-count");
  if (!list && !count) return;
  var rows = recentNotificationRows(events);
  updateNotificationBadge(rows);
  if (!list) return;
  if (!rows.length) {
    list.innerHTML = '<div class="topbar-notification-empty">No alerts</div>';
    return;
  }
  list.innerHTML = rows
    .map(function (_ref) {
      var e = _ref.e;
      var f = _ref.f;
      var title = f.attack_type || f.category || f.rule_id || "Blocked Request";
      var detail = (e.client_ip || "unknown") + " · " + (e.method || "GET") + " " + (e.path || "/");
      return (
        '<div class="topbar-notification-item">' +
        '<div class="topbar-notification-main"><strong>' +
        escapeHtml(title) +
        '</strong><small>' +
        escapeHtml(detail) +
        "</small></div>" +
        '<span class="topbar-notification-time">' +
        escapeHtml(formatOverviewTime(e.time_iso)) +
        "</span></div>"
      );
    })
    .join("");
}

function setNotificationPanelOpen(open) {
  var btn = document.getElementById("topbar-notify-btn");
  var panel = document.getElementById("topbar-notification-panel");
  if (!btn || !panel) return;
  panel.hidden = !open;
  btn.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    var rows = recentNotificationRows(rawEvents);
    markNotificationsRead(rows);
    updateNotificationBadge(rows);
  }
}

async function refreshTopbarNotifications() {
  try {
    var res = await wafApiFetch("/__waf/api/traffic" + siteQuery());
    if (!res.ok) throw new Error("HTTP " + res.status);
    var events = (await res.json()).events || [];
    rawEvents = events;
    renderTopbarNotifications(events);
  } catch (e) {
    renderTopbarNotifications(rawEvents);
  }
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
    body.innerHTML = '<tr><td colspan="13" class="traffic-empty">No detections</td></tr>';
    if (foot) foot.textContent = "";
    return;
  }
  body.innerHTML = rows
    .map(function (_ref) {
      var e = _ref.e;
      var f = _ref.f;
      var o = f || {};
      var ev = o.evidence || "—";
      var eid = e.id != null ? String(e.id) : "";
      var delTd =
        eid !== ""
          ? '<td class="col-actions"><button type="button" class="btn-ghost btn-del-compact btn-del-traffic" data-event-id="' +
            escapeHtml(eid) +
            '" aria-label="이 요청 로그 삭제">삭제</button></td>'
          : '<td class="col-actions">—</td>';
      return (
        "<tr><td>" +
        escapeHtml(e.time_iso) +
        '</td><td class="col-site">' +
        escapeHtml(e.site_id || "—") +
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
        (String(o.rule_id || "").toUpperCase() === "AI-SECOND-PASS"
          ? '<span class="pill ok">AI</span> ' + escapeHtml(o.attack_type || "AI Second Pass")
          : escapeHtml(o.attack_type || "—")) +
        '</td><td class="mono-stat">' +
        escapeHtml(o.location || "—") +
        '</td><td class="mono-stat">' +
        escapeHtml(o.rule_id || "—") +
        "</td><td>" +
        severityBadgeHtml(o.severity) +
        '</td><td class="col-detail"><details class="evidence-fold"><summary>보기</summary><pre class="evidence-pre">' +
        escapeHtml(ev) +
        "</pre></details></td>" +
        delTd +
        "</tr>"
      );
    })
    .join("");
  if (foot) foot.textContent = "";
}

function renderTrafficFeedOnly(events) {
  var body = document.getElementById("traffic-feed-body");
  var statTotal = document.getElementById("traffic-stat-total");
  var statBlocked = document.getElementById("traffic-stat-blocked");
  if (!body) return;
  if (!events || !events.length) {
    if (statTotal) statTotal.textContent = "0";
    if (statBlocked) statBlocked.textContent = "0";
    body.innerHTML =
      '<tr><td colspan="8" class="traffic-empty">기록 없음</td></tr>';
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
      var eid = e.id != null ? String(e.id) : "";
      var delTd =
        eid !== ""
          ? '<td class="col-actions"><button type="button" class="btn-ghost btn-del-compact btn-del-traffic" data-event-id="' +
            escapeHtml(eid) +
            '" aria-label="이 요청 로그 삭제">삭제</button></td>'
          : '<td class="col-actions">—</td>';
      return (
        "<tr><td>" +
        escapeHtml(e.time_iso) +
        '</td><td class="col-site">' +
        escapeHtml(e.site_id || "—") +
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
        "</td>" +
        delTd +
        "</tr>"
      );
    })
    .join("");
}

function renderTraffic(events) {
  renderTrafficFeedOnly(events);
  if (document.getElementById("detections-feed-body")) {
    renderDetections(events);
  }
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
  var total = Number(s.total_logged) || 0;
  pipelineHintTotals.stats = total;
  refreshPipelineHint();
  var cc = document.getElementById("connect-site-logged-count");
  if (cc) cc.textContent = String(total);
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
  var blocked = Number(s.blocked_count) || 0;
  var ratio = total ? (100 * blocked) / total : 0;
  var healthScore = Math.max(0, Math.min(100, 100 - ratio));
  t.textContent = String(total);
  b.textContent = String(blocked);
  r.textContent = (Math.round(ratio * 10) / 10).toFixed(1) + "%";
  if (bar) bar.style.width = Math.min(100, ratio).toFixed(1) + "%";
  if (donut) {
    if (donut.classList && donut.classList.contains("overview-score-ring")) {
      donut.style.setProperty("--kpi-pct", String(healthScore.toFixed(1)));
    } else {
      donut.style.setProperty("--kpi-pct", String(Math.min(100, ratio)));
    }
  }
  if (donutPct) {
    if (donut && donut.classList && donut.classList.contains("overview-score-ring")) {
      donutPct.textContent = String(Math.round(healthScore)) + "%";
    } else {
      donutPct.textContent = (Math.round(ratio * 10) / 10).toFixed(1) + "%";
    }
  }
  var scoreLabel = document.getElementById("overview-score-label");
  if (scoreLabel) {
    scoreLabel.textContent = healthScore >= 85 ? "Healthy" : healthScore >= 65 ? "Watch" : "At Risk";
  }

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
    foot.classList.remove("stats-source-boot");
    foot.textContent = "";
  }
}

async function loadStats() {
  try {
    var res = await wafApiFetch("/__waf/api/stats" + siteQuery());
    if (!res.ok) throw new Error("HTTP " + res.status);
    applyStats(await res.json(), "server");
  } catch (err) {
    var buf = computeLocalStatsFromBuffer(rawEvents);
    if (buf.total_logged > 0) {
      applyStats(buf, "local");
    } else if (
      bootstrapStatsSnapshot &&
      typeof bootstrapStatsSnapshot === "object" &&
      Number(bootstrapStatsSnapshot.total_logged) > 0
    ) {
      applyStats(bootstrapStatsSnapshot, "boot");
    } else {
      applyStats(buf, "local");
    }
  }
}

async function fetchTrafficEvents() {
  var res = await wafApiFetch("/__waf/api/traffic" + siteQuery());
  if (!res.ok) throw new Error("HTTP " + res.status);
  rawEvents = (await res.json()).events || [];
  renderTopbarNotifications(rawEvents);
}

async function loadTrafficPage() {
  var foot = document.getElementById("traffic-updated");
  try {
    await fetchTrafficEvents();
    renderTraffic(getFilteredEvents());
    if (foot) foot.textContent = "";
  } catch (err) {
    if (foot) foot.textContent = "오류";
  }
}

async function loadDetectionsPage() {
  var foot = document.getElementById("detections-updated");
  try {
    await fetchTrafficEvents();
    renderDetections(rawEvents);
    if (foot) foot.textContent = "";
  } catch (err) {
    if (foot) foot.textContent = "오류";
  }
}

async function syncOverviewPage() {
  try {
    await fetchTrafficEvents();
    renderLastBlockHighlight();
    renderOverviewVisuals();
    await loadStats();
    await fetchAndApplySummary(false);
  } catch (e) {
    await loadStats();
    await fetchAndApplySummary(false);
  }
}

async function syncPreviewPage() {
  try {
    await fetchTrafficEvents();
    renderPreviewPage(rawEvents);
  } catch (e) {
    renderPreviewPage(rawEvents);
  }
}

async function syncTrafficAndKpi() {
  var foot = document.getElementById("traffic-updated");
  try {
    await fetchTrafficEvents();
    renderTraffic(getFilteredEvents());
    if (foot) foot.textContent = "";
  } catch (err) {
    if (foot) foot.textContent = "오류";
  }
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
  pipelineHintTotals.clients = uniq;
  refreshPipelineHint();
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
  var bodyPre = document.getElementById("clients-feed-body");
  try {
    var res = await wafApiFetch("/__waf/api/clients" + siteQuery());
    if (!res.ok) {
      var detailMsg = "";
      try {
        var je = await res.json();
        detailMsg = (je && je.detail) ? String(je.detail) : "";
      } catch (eErr) {}
      if (bodyPre) {
        if (res.status === 401) {
          bodyPre.innerHTML =
            '<tr><td colspan="5" class="traffic-empty">세션이 만료되었거나 API에 쿠키가 전달되지 않았습니다. ' +
            '<a href="/login">로그인</a> 후 이 주소(<code>' +
            escapeHtml(window.location.origin || "") +
            '</code>)로 다시 접속해 주세요.</td></tr>';
        } else {
          bodyPre.innerHTML =
            '<tr><td colspan="5" class="traffic-empty">API 오류 HTTP ' +
            String(res.status) +
            (detailMsg ? ": " + escapeHtml(detailMsg) : "") +
            "</td></tr>";
        }
      }
      if (foot) foot.textContent = "오류";
      return;
    }
    renderClients(await res.json());
    if (foot) foot.textContent = "";
  } catch (err) {
    if (bodyPre) {
      bodyPre.innerHTML =
        '<tr><td colspan="5" class="traffic-empty">통신 오류 · 네트워크 또는 프록시를 확인하세요.</td></tr>';
    }
    if (foot) foot.textContent = "오류";
  }
}

async function loadSites() {
  try {
    var res = await wafApiFetch("/__waf/api/sites");
    if (!res.ok) return;
    var d = await res.json();
    var ids = d.sites || [];
    var cardsRaw = Array.isArray(d.site_cards) ? d.site_cards : [];
    lastSiteCards = cardsRaw.length
      ? cardsRaw
      : ids.map(function (sid) {
          return {
            site_id: sid,
            label: sid,
            public_url: "",
            waf_enabled: true,
          };
        });
    // 사이드바 셀렉트
    var sel = document.getElementById("site-filter-select");
    if (sel) {
      var opts = '<option value="">전체 사이트</option>';
      for (var i = 0; i < lastSiteCards.length; i++) {
        var c = lastSiteCards[i];
        var cid = escapeHtml(String(c.site_id || ""));
        var lab = escapeHtml(String(c.label || c.site_id || ""));
        opts +=
          '<option value="' +
          cid +
          '"' +
          (String(c.site_id || "") === activeSite ? " selected" : "") +
          ' title="' +
          escapeHtml(String(c.public_url || "")) +
          '">' +
          lab +
          "</option>";
      }
      sel.innerHTML = opts;
    }
    // 로그 페이지 내 사이트 필터 셀렉트
    var fsel = document.getElementById("filter-site");
    if (fsel) {
      var fopts = '<option value="">전체</option>';
      for (var j = 0; j < lastSiteCards.length; j++) {
        var fc = lastSiteCards[j];
        var fcid = escapeHtml(String(fc.site_id || ""));
        var flap = escapeHtml(String(fc.label || fc.site_id || ""));
        fopts +=
          '<option value="' +
          fcid +
          '"' +
          (String(fc.site_id || "") === activeSite ? " selected" : "") +
          ' title="' +
          escapeHtml(String(fc.public_url || "")) +
          '">' +
          flap +
          "</option>";
      }
      fsel.innerHTML = fopts;
    }
    refreshActiveSiteBadge();
  } catch (e) {}
}

async function apiDeleteTrafficEvent(id) {
  var res = await wafApiFetch("/__waf/api/traffic/" + encodeURIComponent(String(id)), {
    method: "DELETE",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function apiResetAllTraffic() {
  var res = await wafApiFetch("/__waf/api/traffic/reset", {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function putWafEnabled(enabled) {
  var url =
    (typeof window !== "undefined" && window.location && window.location.origin
      ? window.location.origin
      : "") + "/__waf/api/settings/waf-enabled";
  var payload = JSON.stringify({
    enabled: !!enabled,
    site_id: activeSite || "",
  });
  var res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: payload,
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function fetchAndApplySummary(refreshStatsAfter) {
  try {
    var res = await wafApiFetch("/__waf/api/summary" + siteQuery());
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

function applyStoreInfo(d) {
  var r = document.getElementById("store-db-resolved");
  var e = document.getElementById("store-db-env");
  var h = document.getElementById("store-db-hint");
  var c = document.getElementById("store-row-count");
  var lim = document.getElementById("input-snapshot-limit");
  var mx = document.getElementById("input-max-rows");
  var dbInp = document.getElementById("input-traffic-log-db");
  if (r) r.textContent = d.traffic_log_db_resolved || "—";
  if (e) e.textContent = d.traffic_log_db_env ? d.traffic_log_db_env : "(미설정 · 기본 파일 사용)";
  if (h) h.textContent = d.traffic_log_db_default_hint || "—";
  if (c) c.textContent = String(d.stored_row_count != null ? d.stored_row_count : "—");
  if (lim && d.snapshot_limit != null) lim.value = String(d.snapshot_limit);
  if (mx && d.max_stored_rows != null) mx.value = String(d.max_stored_rows);
  if (dbInp) dbInp.value = d.traffic_log_db_env == null ? "" : String(d.traffic_log_db_env);
}

async function loadStoreInfo() {
  var msg = document.getElementById("store-save-msg");
  try {
    var res = await wafApiFetch("/__waf/api/settings/traffic-store");
    if (!res.ok) throw new Error("HTTP " + res.status);
    applyStoreInfo(await res.json());
    if (msg) msg.textContent = "";
  } catch (err) {
    if (msg) msg.textContent = "불러오기 실패";
  }
}

async function saveStoreSettings() {
  var lim = document.getElementById("input-snapshot-limit");
  var mx = document.getElementById("input-max-rows");
  var msg = document.getElementById("store-save-msg");
  var snap = lim ? parseInt(String(lim.value), 10) : 500;
  var maxR = mx ? parseInt(String(mx.value), 10) : 0;
  var res = await wafApiFetch("/__waf/api/settings/traffic-store", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ snapshot_limit: snap, max_stored_rows: maxR }),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  applyStoreInfo(await res.json());
  if (msg) msg.textContent = "저장됨";
}

async function applyDbPathFromSettings() {
  var dbInp = document.getElementById("input-traffic-log-db");
  var msg = document.getElementById("store-db-apply-msg");
  var raw = dbInp ? String(dbInp.value || "") : "";
  if (msg) msg.textContent = "적용 중…";
  var res = await wafApiFetch("/__waf/api/settings/traffic-store", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ traffic_log_db: raw }),
  });
  if (!res.ok) {
    var detail = "";
    try {
      var j = await res.json();
      detail = (j && j.detail) || "";
    } catch (e) {}
    if (msg) msg.textContent = detail ? String(detail) : "적용 실패 (HTTP " + res.status + ")";
    throw new Error("HTTP " + res.status);
  }
  applyStoreInfo(await res.json());
  if (msg) msg.textContent = "재연결됨";
}

function stopAutoRefresh() {
  if (refreshTimers.main) clearInterval(refreshTimers.main);
  refreshTimers.main = null;
}

function tickPageRefresh() {
  var p = wafPage();
  if (p === "overview") {
    runDashAsync(syncOverviewPage, "개요");
  } else if (p === "detections") {
    runDashAsync(loadDetectionsPage, "탐지·차단");
    runDashAsync(loadStats, "통계");
  } else if (p === "traffic") {
    runDashAsync(loadTrafficPage, "프록시 로그");
    runDashAsync(loadStats, "통계");
  } else if (p === "clients") {
    runDashAsync(loadClients, "접속자");
    runDashAsync(loadStats, "통계");
  } else if (p === "settings") {
    runDashAsync(loadStoreInfo, "저장소");
    if (isAdmin) runDashAsync(loadUsers, "사용자");
  } else if (p === "connect") {
    runDashAsync(loadStats, "사이트 연결");
  } else if (p === "preview") {
    runDashAsync(syncPreviewPage, "UI Preview");
  }
  /* sql: 자동 갱신 없음 — 스키마/결과 깜빡임 방지 */
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimers.main = setInterval(tickPageRefresh, 2000);
}

function onFilterChange() {
  renderTraffic(getFilteredEvents());
}

function exportJsonBlob() {
  var json = JSON.stringify(rawEvents, null, 2);
  var blob = new Blob([json], { type: "application/json;charset=utf-8" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "waf-traffic-snapshot.json";
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

async function refreshCurrentPage() {
  hideDashAsyncError();
  var p = wafPage();
  if (p === "overview") {
    await syncOverviewPage();
    await loadClients();
  } else if (p === "detections") {
    await loadDetectionsPage();
    await loadStats();
    await loadClients();
  } else if (p === "traffic") {
    await loadTrafficPage();
    await loadStats();
    await loadClients();
  } else if (p === "clients") {
    await loadClients();
    await loadStats();
  } else if (p === "settings") {
    await loadStoreInfo();
    await loadStats();
    if (isAdmin) await loadUsers();
  } else if (p === "sql") {
    await loadSqlSchema();
  } else if (p === "connect") {
    await loadStats();
  } else if (p === "preview") {
    await syncPreviewPage();
  }
}

function updateConnectWorkerBundleHrefs() {
  var inp = document.getElementById("connect-worker-upstream");
  if (!inp) return;
  var u = normalizeConnectUpstreamInput(inp.value);
  if (!u) u = "http://127.0.0.1:3000";
  var q = "?upstream=" + encodeURIComponent(u);
  var env = document.getElementById("connect-download-env");
  if (env) env.setAttribute("href", "/__waf/api/me/proxy-worker-env" + q);
  var zip = document.getElementById("connect-download-zip");
  if (zip) zip.setAttribute("href", "/__waf/api/me/worker-connect-zip" + q);
  ["macos", "linux", "windows"].forEach(function (os) {
    var link = document.getElementById("connect-install-" + os);
    if (link) link.setAttribute("href", "/__waf/api/me/install/" + os + q);
  });
}

function normalizeConnectUpstreamInput(raw) {
  var t = String(raw || "").trim();
  var hash = t.indexOf("#");
  if (hash >= 0) t = t.slice(0, hash).trim();
  while (t.length > 0 && t.charAt(t.length - 1) === "/") {
    t = t.slice(0, -1);
  }
  return t;
}

async function persistConnectUpstreamHintAfterNormalize() {
  var inp = document.getElementById("connect-worker-upstream");
  var msg = document.getElementById("connect-copy-msg");
  if (!inp) return;
  var n = normalizeConnectUpstreamInput(inp.value);
  if (!n || !/^https?:\/\//i.test(n)) return;
  try {
    var res = await wafApiFetch("/__waf/api/me/public-url-hint", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ public_url: n }),
    });
    if (!res.ok) {
      var detail = "";
      try {
        var je = await res.json();
        detail = je && je.detail ? String(je.detail) : "";
      } catch (err) {}
      if (msg && detail) msg.textContent = detail;
      return;
    }
    if (msg) msg.textContent = "설치 설정을 저장했습니다.";
    if (document.body && document.body.dataset.memberNeedsInstall === "true") {
      setTimeout(function () {
        window.location.reload();
      }, 650);
    }
  } catch (e) {
    if (msg) msg.textContent = "저장 요청 실패 · 네트워크 확인";
  }
}

function refreshConnectUpstreamFieldDisplay() {
  var inp = document.getElementById("connect-worker-upstream");
  if (!inp) return;
  var n = normalizeConnectUpstreamInput(inp.value);
  if (inp.value.trim() !== n) inp.value = n;
  updateConnectWorkerBundleHrefs();
}

function buildConnectEnvPasteText() {
  var root = document.getElementById("connect-page-data");
  var inp = document.getElementById("connect-worker-upstream");
  if (!root || !inp) return "";
  var central = root.getAttribute("data-central") || "";
  var sid = root.getAttribute("data-site-id") || "";
  var tok = root.getAttribute("data-token") || "";
  var upstream = normalizeConnectUpstreamInput(inp.value);
  if (!upstream) upstream = "http://127.0.0.1:3000";
  if (!central || !sid || !tok) return "";
  return (
    "CENTRAL_DASHBOARD_URL=" +
    central +
    "\nSENSOR_TOKEN=" +
    tok +
    "\nSITE_ID=" +
    sid +
    "\nUPSTREAM_URL=" +
    upstream +
    "\n"
  );
}

function connectCopyFeedbackEl() {
  return (
    document.getElementById("connect-copy-msg") ||
    document.getElementById("connect-copy-msg-admin")
  );
}

function wireConnectPageUI() {
  if (document.body.dataset.wafConnectCopyBound !== "1") {
    document.body.dataset.wafConnectCopyBound = "1";
    document.body.addEventListener("click", onConnectCopyClick);
  }

  var inp = document.getElementById("connect-worker-upstream");
  if (!inp || inp.dataset.connectBundleWired === "1") return;
  var wantsBundle =
    document.getElementById("connect-download-env") ||
    document.getElementById("connect-download-zip") ||
    document.getElementById("connect-install-macos") ||
    document.getElementById("connect-install-linux") ||
    document.getElementById("connect-install-windows");
  if (!wantsBundle) return;

  inp.dataset.connectBundleWired = "1";
  updateConnectWorkerBundleHrefs();
  inp.addEventListener("input", updateConnectWorkerBundleHrefs);
  inp.addEventListener("change", updateConnectWorkerBundleHrefs);
  inp.addEventListener("blur", function () {
    refreshConnectUpstreamFieldDisplay();
  });
  inp.addEventListener("paste", function () {
    setTimeout(function () {
      refreshConnectUpstreamFieldDisplay();
    }, 0);
  });

  ["connect-install-macos", "connect-install-linux", "connect-install-windows"].forEach(function (id) {
    var installLink = document.getElementById(id);
    if (!installLink || installLink.dataset.wafWired) return;
    installLink.dataset.wafWired = "1";
    installLink.addEventListener("click", function () {
      refreshConnectUpstreamFieldDisplay();
      var msg = connectCopyFeedbackEl();
      if (msg) msg.textContent = "설치 파일을 내려받습니다 · 설정은 자동 저장됩니다.";
      if (document.body && document.body.dataset.memberNeedsInstall === "true") {
        setTimeout(function () {
          window.location.reload();
        }, 1200);
      }
    });
  });

  var copyAll = document.getElementById("connect-copy-all-env");
  if (copyAll && !copyAll.dataset.wafWired) {
    copyAll.dataset.wafWired = "1";
    copyAll.addEventListener("click", function () {
      var msg = connectCopyFeedbackEl();
      var text = buildConnectEnvPasteText();
      if (!text) {
        if (msg) msg.textContent = "복사할 설정이 없습니다 · SITE_ID·토큰을 확인하세요.";
        return;
      }
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        if (msg) msg.textContent = "이 브라우저에서는 클립보드 API를 쓸 수 없습니다.";
        return;
      }
      Promise.resolve(navigator.clipboard.writeText(text)).then(
        function () {
          if (msg) msg.textContent = "환경 변수 줄을 복사했습니다 · .env 에 붙여넣기 하세요.";
        },
        function () {
          if (msg) msg.textContent = "복사 실패 · HTTPS와 브라우저 권한을 확인하세요.";
        }
      );
    });
  }
}

function onConnectCopyClick(ev) {
  var btn = ev.target.closest(".js-connect-copy");
  if (!btn) return;
  var text = btn.getAttribute("data-copy") || "";
  var msg = connectCopyFeedbackEl();
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
    if (msg) msg.textContent = "이 브라우저에서는 클립보드 API를 쓸 수 없습니다.";
    return;
  }
  Promise.resolve(navigator.clipboard.writeText(text)).then(
    function () {
      if (msg) msg.textContent = "복사했습니다.";
    },
    function () {
      if (msg) msg.textContent = "복사 실패 · HTTPS와 브라우저 권한을 확인하세요.";
    }
  );
}

// ─── 사용자 관리 (admin 전용) ─────────────────────────────────────────────

function renderUsers(users) {
  var body = document.getElementById("users-table-body");
  var foot = document.getElementById("users-updated");
  if (!body) return;
  if (!users || !users.length) {
    body.innerHTML = '<tr><td colspan="5" class="traffic-empty">등록된 계정 없음</td></tr>';
    if (foot) foot.textContent = "";
    return;
  }
  body.innerHTML = users.map(function (u) {
    var delBtn = u.username === "admin"
      ? '<td class="col-actions">—</td>'
      : '<td class="col-actions"><button type="button" class="btn-ghost btn-del-compact btn-del-user" data-username="' +
        escapeHtml(u.username) + '" aria-label="' + escapeHtml(u.username) + ' 삭제">삭제</button></td>';
    return (
      "<tr><td>" + escapeHtml(u.username) +
      "</td><td>" + (u.is_admin ? '<span class="user-badge-admin">관리자</span>' : "일반") +
      "</td><td>" + escapeHtml(u.site_id || "전체") +
      '</td><td class="mono-stat">' + escapeHtml((u.created_at || "—").split("T")[0]) +
      "</td>" + delBtn + "</tr>"
    );
  }).join("");
  if (foot) foot.textContent = new Date().toLocaleString("ko-KR") + " 기준";
}

async function loadUsers() {
  var body = document.getElementById("users-table-body");
  try {
    var res = await wafApiFetch("/__waf/api/users");
    if (!res.ok) throw new Error("HTTP " + res.status);
    var d = await res.json();
    renderUsers(d.users || []);
  } catch (err) {
    if (body) body.innerHTML = '<tr><td colspan="5" class="traffic-empty">불러오기 실패</td></tr>';
  }
}

async function createUser(username, password, siteId, isAdminUser) {
  var res = await wafApiFetch("/__waf/api/users", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ username: username, password: password, site_id: siteId, is_admin: isAdminUser }),
  });
  if (!res.ok) {
    var j = await res.json().catch(function () { return {}; });
    throw new Error((j && j.detail) || "HTTP " + res.status);
  }
  return res.json();
}

async function deleteUser(username) {
  var res = await wafApiFetch("/__waf/api/users/" + encodeURIComponent(username), {
    method: "DELETE",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    var j = await res.json().catch(function () { return {}; });
    throw new Error((j && j.detail) || "HTTP " + res.status);
  }
  return res.json();
}

function sqlFindTable(schema, name) {
  var tables = (schema && schema.tables) || [];
  for (var i = 0; i < tables.length; i++) {
    if (tables[i].name === name) return tables[i];
  }
  return null;
}

function showSqlColumnsForTable(tableName) {
  var panel = document.getElementById("sql-columns-panel");
  var title = document.getElementById("sql-columns-title");
  var ul = document.getElementById("sql-column-list");
  if (!panel || !ul || !lastSqlSchema) return;
  var t = sqlFindTable(lastSqlSchema, tableName);
  if (!t || !t.columns || !t.columns.length) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  if (title) title.textContent = "컬럼 · " + tableName;
  ul.innerHTML = t.columns
    .map(function (c) {
      var pk = c.pk ? " · PK" : "";
      var nn = c.notnull ? " · NOT NULL" : "";
      return (
        "<li><span class=\"mono-stat\">" +
        escapeHtml(c.name) +
        "</span> <span class=\"sql-col-type\">" +
        escapeHtml(c.type || "") +
        "</span><span class=\"sql-col-flags\">" +
        escapeHtml(pk + nn) +
        "</span></li>"
      );
    })
    .join("");
}

async function loadSqlSchema() {
  var nameEl = document.getElementById("sql-db-name");
  var pathEl = document.getElementById("sql-db-path");
  var listEl = document.getElementById("sql-table-list");
  try {
    var res = await wafApiFetch("/__waf/api/sql-console/schema");
    if (!res.ok) throw new Error("HTTP " + res.status);
    var d = await res.json();
    lastSqlSchema = d;
    if (nameEl) nameEl.textContent = d.db_display_name || "—";
    if (pathEl) pathEl.textContent = d.db_path_resolved || "—";
    if (listEl) {
      var tables = d.tables || [];
      listEl.innerHTML = tables
        .map(function (t) {
          return (
            "<li><button type=\"button\" class=\"sql-table-btn js-sql-pick-table\" data-table=\"" +
            escapeHtml(t.name) +
            "\">" +
            escapeHtml(t.name) +
            ' <span class="sql-table-type">' +
            escapeHtml(t.type || "") +
            "</span></button></li>"
          );
        })
        .join("");
      if (!tables.length) {
        listEl.innerHTML = '<li class="sql-empty-li">테이블 없음</li>';
      }
    }
    var cp = document.getElementById("sql-columns-panel");
    if (cp) cp.hidden = true;
  } catch (e) {
    if (nameEl) nameEl.textContent = "오류";
    if (pathEl) pathEl.textContent = String(e.message || e);
    if (listEl) listEl.innerHTML = "";
  }
}

function renderSqlResultTable(cols, rows) {
  var wrap = document.getElementById("sql-results-table-wrap");
  if (!wrap) return;
  if (!cols.length) {
    wrap.innerHTML =
      '<p class="sql-results-msg mono-stat">컬럼이 없는 결과입니다.</p>';
    return;
  }
  var th = cols
    .map(function (c) {
      return "<th scope=\"col\">" + escapeHtml(String(c)) + "</th>";
    })
    .join("");
  var tr = (rows || [])
    .map(function (r) {
      return (
        "<tr>" +
        r
          .map(function (cell) {
            return (
              "<td class=\"mono-stat\">" +
              escapeHtml(cell == null ? "" : String(cell)) +
              "</td>"
            );
          })
          .join("") +
        "</tr>"
      );
    })
    .join("");
  wrap.innerHTML =
    '<table class="traffic-table sql-result-table"><thead><tr>' +
    th +
    "</tr></thead><tbody>" +
    tr +
    "</tbody></table>";
}

async function runSqlQuery() {
  var ed = document.getElementById("sql-editor");
  var msg = document.getElementById("sql-run-msg");
  var wrap = document.getElementById("sql-results-table-wrap");
  var empty = document.getElementById("sql-results-empty");
  if (!ed) return;
  var sql = ed.value;
  if (msg) msg.textContent = "실행 중…";
  try {
    var res = await wafApiFetch("/__waf/api/sql-console/query", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ sql: sql }),
    });
    var data = await res.json().catch(function () {
      return {};
    });
    if (!res.ok) {
      if (msg) msg.textContent = data.detail ? String(data.detail) : "실패 (HTTP " + res.status + ")";
      return;
    }
    if (msg) {
      var n = data.row_count != null ? data.row_count : 0;
      msg.textContent =
        String(n) +
        "행" +
        (data.truncated ? " (최대 " + String(data.max_rows || "") + "행까지만)" : "");
    }
    if (empty) empty.hidden = true;
    if (wrap) {
      wrap.hidden = false;
      renderSqlResultTable(data.columns || [], data.rows || []);
    }
  } catch (e) {
    if (msg) msg.textContent = String(e.message || e);
  }
}

setClock();
setInterval(setClock, 1000);

document.addEventListener(
  "click",
  function (ev) {
    // 사이트 칩 클릭 → 사이트 필터 전환
    var notifyBtn = ev.target && ev.target.closest && ev.target.closest("#topbar-notify-btn");
    if (notifyBtn) {
      ev.preventDefault();
      ev.stopPropagation();
      var panel = document.getElementById("topbar-notification-panel");
      var willOpen = !panel || panel.hidden;
      setNotificationPanelOpen(willOpen);
      if (willOpen) {
        runDashAsync(refreshTopbarNotifications, "최근 알림");
      }
      return;
    }
    var notifyWrap = ev.target && ev.target.closest && ev.target.closest(".topbar-notification-wrap");
    if (!notifyWrap) {
      setNotificationPanelOpen(false);
    }
    var siteChip = ev.target && ev.target.closest && ev.target.closest(".site-chip");
    if (siteChip) {
      ev.preventDefault();
      var siteVal = siteChip.getAttribute("data-site") || "";
      activeSite = activeSite === siteVal ? "" : siteVal;
      var sel = document.getElementById("site-filter-select");
      if (sel) sel.value = activeSite;
      refreshActiveSiteBadge();
      refreshCurrentPage();
      return;
    }
    var resetBtn = ev.target && ev.target.closest && ev.target.closest(".js-traffic-reset-all");
    if (resetBtn) {
      ev.preventDefault();
      if (
        !window.confirm(
          "저장된 프록시·탐지 로그를 모두 삭제할까요? SQLite 기록이 사라지며 되돌릴 수 없습니다."
        )
      ) {
        return;
      }
      resetBtn.disabled = true;
      apiResetAllTraffic()
        .then(function () {
          return refreshCurrentPage();
        })
        .catch(function (err) {
          console.error("로그 초기화 실패:", err);
        })
        .finally(function () {
          document.querySelectorAll(".js-traffic-reset-all").forEach(function (b) {
            try {
              b.disabled = false;
            } catch (e) {}
          });
        });
      return;
    }
    var sqlPick = ev.target && ev.target.closest && ev.target.closest(".js-sql-pick-table");
    if (sqlPick) {
      ev.preventDefault();
      var tn = sqlPick.getAttribute("data-table") || "";
      var edSql = document.getElementById("sql-editor");
      if (edSql && tn) edSql.value = "SELECT * FROM " + tn + " LIMIT 100";
      showSqlColumnsForTable(tn);
      return;
    }
    var delBtn = ev.target && ev.target.closest && ev.target.closest(".btn-del-traffic");
    if (delBtn) {
      ev.preventDefault();
      var delId = delBtn.getAttribute("data-event-id");
      if (!delId) return;
      delBtn.disabled = true;
      apiDeleteTrafficEvent(delId)
        .then(function () {
          return refreshCurrentPage();
        })
        .catch(function (err) {
          console.error("로그 삭제 실패:", err);
        })
        .finally(function () {
          try {
            delBtn.disabled = false;
          } catch (e) {}
        });
      return;
    }
    var btn = ev.target && ev.target.closest && ev.target.closest("#waf-toggle-btn");
    if (!btn) return;
    ev.preventDefault();
    ev.stopPropagation();
    if (isAdmin && !activeSite) {
      alert(
        "관리자는 사이드바 「사이트 필터」에서 사이트를 선택한 뒤 WAF를 켜거나 끕니다."
      );
      return;
    }
    var on = btn.classList.contains("ok");
    btn.disabled = true;
    putWafEnabled(!on)
      .then(function () {
        return fetchAndApplySummary(true);
      })
      .catch(function (err) {
        console.error("WAF 토글 실패:", err);
        try {
          btn.disabled = false;
        } catch (e) {}
      });
  },
  true
);

(function bootFromDom() {
  var el = document.getElementById("waf-boot-data");
  if (!el) return;
  try {
    var boot = JSON.parse(el.textContent);
    bootstrapStatsSnapshot = boot.dashboard_stats && typeof boot.dashboard_stats === "object"
      ? boot.dashboard_stats
      : null;
    applySummary(boot);
    if (bootstrapStatsSnapshot) {
      applyStats(bootstrapStatsSnapshot, "boot");
    }
    pipelineHintTotals.stats = Number(boot.traffic_total_logged) || 0;
    pipelineHintTotals.clients = -1;
    refreshPipelineHint();
    renderTopbarNotifications(rawEvents);
    if (wafPage() === "preview") {
      renderPreviewPage(rawEvents);
    }
    hideDashAsyncError();
  } catch (e) {
    console.error("WAF dashboard boot:", e);
    reportDashAsyncError("페이지 부트(JSON/초기값)", e);
  }
})();

var btnDismissHint = document.getElementById("pipeline-hint-dismiss");
if (btnDismissHint) {
  btnDismissHint.addEventListener("click", function () {
    try {
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem("waf_hide_pipeline_hint", "1");
      }
    } catch (e) {}
    refreshPipelineHint();
  });
}

var btnDashErrDismiss = document.getElementById("dash-async-error-dismiss");
if (btnDashErrDismiss) {
  btnDashErrDismiss.addEventListener("click", hideDashAsyncError);
}

var btn = document.getElementById("btn-refresh");
if (btn) {
  btn.addEventListener("click", function () {
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    refreshCurrentPage()
      .catch(function (err) {
        reportDashAsyncError("수동 갱신", err);
      })
      .finally(function () {
        btn.disabled = false;
        btn.removeAttribute("aria-busy");
      });
  });
}

var autoChk = document.getElementById("auto-refresh");
if (autoChk) {
  autoChk.addEventListener("change", function () {
    if (autoChk.checked) startAutoRefresh();
    else stopAutoRefresh();
  });
}

["filter-method", "filter-blocked-only", "filter-path", "filter-ip", "filter-site"].forEach(function (id) {
  var node = document.getElementById(id);
  if (node) node.addEventListener("change", onFilterChange);
  if (node) node.addEventListener("input", onFilterChange);
});

// 사이드바 사이트 셀렉트
var selSite = document.getElementById("site-filter-select");
if (selSite) {
  selSite.addEventListener("change", function () {
    activeSite = selSite.value;
    refreshActiveSiteBadge();
    refreshCurrentPage();
    loadSites();
  });
}

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

var formStore = document.getElementById("form-traffic-store");
if (formStore) {
  formStore.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var msg = document.getElementById("store-save-msg");
    if (msg) msg.textContent = "저장 중…";
    saveStoreSettings()
      .catch(function () {
        if (msg) msg.textContent = "저장 실패";
      });
  });
}

var btnApplyDb = document.getElementById("btn-apply-db-path");
if (btnApplyDb) {
  btnApplyDb.addEventListener("click", function () {
    btnApplyDb.disabled = true;
    applyDbPathFromSettings()
      .catch(function () {})
      .finally(function () {
        try {
          btnApplyDb.disabled = false;
        } catch (e) {}
      });
  });
}

document.body.classList.add("dashboard-ready");

function wireUserManagementUI() {
  // admin 전용 카드 표시
  var card = document.getElementById("card-user-management");
  if (!card) return;
  if (!isAdmin) return;
  card.hidden = false;

  // 신규 계정 등록
  var form = document.getElementById("form-create-user");
  if (form && !form.dataset.wafWired) {
    form.dataset.wafWired = "1";
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      var msg = document.getElementById("user-create-msg");
      var username = (document.getElementById("input-new-username") || {}).value || "";
      var password = (document.getElementById("input-new-password") || {}).value || "";
      var siteId = (document.getElementById("input-new-site-id") || {}).value || "";
      var isAdminUser = !!(document.getElementById("input-new-is-admin") || {}).checked;
      if (!username || !password) return;
      try {
        await createUser(username, password, siteId, isAdminUser);
        if (msg) { msg.textContent = "✓ 계정 생성 완료"; msg.style.color = "var(--ok)"; }
        form.reset();
        await loadUsers();
      } catch (err) {
        if (msg) { msg.textContent = "✗ " + err.message; msg.style.color = "var(--bad)"; }
      }
    });
  }

  // 삭제 버튼 (이벤트 위임)
  var tableBody = document.getElementById("users-table-body");
  if (tableBody && !tableBody.dataset.wafWired) {
    tableBody.dataset.wafWired = "1";
    tableBody.addEventListener("click", async function (e) {
      var btn = e.target.closest(".btn-del-user");
      if (!btn) return;
      var username = btn.getAttribute("data-username");
      if (!username) return;
      if (!confirm(username + " 계정을 삭제하시겠습니까?")) return;
      try {
        await deleteUser(username);
        await loadUsers();
      } catch (err) {
        alert("삭제 실패: " + err.message);
      }
    });
  }
}

function pageBoot() {
  var p = wafPage();
  if (p === "overview") {
    runDashAsync(syncOverviewPage, "개요");
    runDashAsync(loadClients, "접속자");
  } else if (p === "detections") {
    runDashAsync(loadDetectionsPage, "탐지·차단");
    runDashAsync(loadStats, "통계");
    runDashAsync(loadClients, "접속자");
  } else if (p === "traffic") {
    runDashAsync(loadTrafficPage, "프록시 로그");
    runDashAsync(loadStats, "통계");
    runDashAsync(loadClients, "접속자");
  } else if (p === "clients") {
    runDashAsync(loadClients, "접속자");
  } else if (p === "settings") {
    runDashAsync(loadStoreInfo, "저장소");
    runDashAsync(loadStats, "통계");
    wireUserManagementUI();
    if (isAdmin) runDashAsync(loadUsers, "사용자");
  } else if (p === "sql") {
    runDashAsync(loadSqlSchema, "SQL 콘솔");
  } else if (p === "connect") {
    wireConnectPageUI();
    runDashAsync(loadStats, "사이트 연결");
  }
  loadSites();
  if (autoChk && autoChk.checked) startAutoRefresh();
}

pageBoot();

var btnSqlRun = document.getElementById("btn-sql-run");
if (btnSqlRun) {
  btnSqlRun.addEventListener("click", function () {
    btnSqlRun.disabled = true;
    runSqlQuery()
      .catch(function () {})
      .finally(function () {
        try {
          btnSqlRun.disabled = false;
        } catch (e) {}
      });
  });
}
var btnSqlClear = document.getElementById("btn-sql-clear");
if (btnSqlClear) {
  btnSqlClear.addEventListener("click", function () {
    var ed = document.getElementById("sql-editor");
    if (ed) ed.value = "";
  });
}
var sqlEditor = document.getElementById("sql-editor");
if (sqlEditor) {
  sqlEditor.addEventListener("keydown", function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
      ev.preventDefault();
      runSqlQuery();
    }
  });
}
