function setClock() {
  document.getElementById("clock").textContent = new Date().toLocaleString("ko-KR");
}
function applyAccess(a) {
  if (!a) return;
  const t = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v != null && String(v).length ? v : "—";
  };
  t("acc-client-ip", a.client_ip);
  t("acc-xff", a.x_forwarded_for);
  t("acc-xri", a.x_real_ip);
  t("acc-host", a.host_header);
  t("acc-method", a.method);
  t("acc-path", a.path);
  t("acc-url", a.full_url);
  t("acc-referer", a.referer);
  t("acc-lang", a.accept_language);
  t("acc-ua", a.user_agent);
}
function applySummary(d) {
  if (d.access) applyAccess(d.access);
  const up = d.upstream_ok;
  const el = document.getElementById("upstream-status");
  if (up === true) {
    el.innerHTML = '<span class="pill ok">연결됨</span>';
  } else if (up === false) {
    el.innerHTML = '<span class="pill bad">연결 실패</span>';
    if (d.upstream_error) el.innerHTML += '<span class="error-hint">' + escapeHtml(d.upstream_error) + "</span>";
  } else {
    el.textContent = "확인 중…";
  }
  document.getElementById("waf-enabled").innerHTML =
    d.waf_enabled
      ? '<span class="pill ok">켜짐</span>'
      : '<span class="pill bad">꺼짐</span>';
  document.getElementById("waf-severity").textContent = d.waf_block_min_severity;
  document.getElementById("body-preview").textContent = d.body_preview_max + " bytes";
  document.getElementById("updated").textContent =
    "마지막 갱신: " + new Date().toLocaleString("ko-KR");
}
function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
function trafficResultHtml(e) {
  if (e.blocked) {
    return '<span class="pill bad">WAF 차단</span>';
  }
  const c = Number(e.status_code);
  if (c >= 200 && c < 400) {
    return '<span class="pill ok">' + escapeHtml(String(c)) + "</span>";
  }
  return '<span class="pill bad">' + escapeHtml(String(c)) + "</span>";
}
function renderTraffic(events) {
  const body = document.getElementById("traffic-feed-body");
  if (!body) return;
  if (!events || !events.length) {
    body.innerHTML =
      '<tr><td colspan="6" class="traffic-empty">아직 기록이 없습니다. 다른 탭에서 <code>' + window.location.origin + '/</code> 등 <strong>프록시 경유</strong>로 접속해 보세요.</td></tr>';
    return;
  }
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
}
async function loadTraffic() {
  const foot = document.getElementById("traffic-updated");
  try {
    const r = await fetch("/__waf/api/traffic");
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    renderTraffic(data.events || []);
    if (foot) {
      foot.textContent = "로그 갱신: " + new Date().toLocaleString("ko-KR");
    }
  } catch (err) {
    if (foot) foot.textContent = "로그 API 오류";
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
    sub.textContent =
      uniq > 0 ? "· 누적 프록시 요청 " + totalReq + "회 (표시 중인 IP 기준)" : "";
  }
  if (!list.length) {
    body.innerHTML =
      '<tr><td colspan="5" class="traffic-empty">아직 업스트림으로 나간 요청이 없습니다. 팀원은 <code>' +
      window.location.origin +
      '/</code> 로 접속하면 IP가 잡힙니다.</td></tr>';
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
    if (foot) {
      foot.textContent = "접속자 갱신: " + new Date().toLocaleString("ko-KR");
    }
  } catch (err) {
    if (foot) foot.textContent = "접속자 API 오류";
  }
}
async function loadSummary() {
  try {
    const r = await fetch("/__waf/api/summary");
    if (!r.ok) throw new Error("HTTP " + r.status);
    applySummary(await r.json());
  } catch (e) {
    document.getElementById("upstream-status").innerHTML =
      '<span class="pill bad">API 오류</span>';
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
document.getElementById("btn-refresh").addEventListener("click", () => {
  loadSummary();
  loadTraffic();
  loadClients();
});
document.getElementById("btn-refresh-2").addEventListener("click", () => {
  loadSummary();
  loadTraffic();
  loadClients();
});
setInterval(loadSummary, 15000);
loadTraffic();
setInterval(loadTraffic, 2000);
loadClients();
setInterval(loadClients, 2000);
