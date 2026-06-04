/**
 * 프록시가 업스트림 HTML에 삽입해 로드한다.
 * fetch/XHR 403 + JSON 본문(blocked)이면 /__waf/blocked 로 이동.
 */
(function () {
  "use strict";
  if (window.__wafInterceptorInstalled) return;
  window.__wafInterceptorInstalled = true;

  function reqUrl(input) {
    try {
      if (typeof input === "string") return input;
      if (input && typeof input.url === "string") return input.url;
    } catch (e) {}
    return "";
  }

  function isWafSelf(url) {
    var s = String(url || "");
    // scan-fragment 의 403 은 차단 페이지로 보내야 함(해시 페이로드 탐지)
    if (s.indexOf("/__waf/api/scan-fragment") !== -1) return false;
    return s.indexOf("/__waf/") !== -1;
  }

  var BLOCK_PAYLOAD_KEY = "__waf_block_payload";

  function wafRedirect(data) {
    if (!data || !data.blocked) return;
    /* 차단 페이지에서 전체 findings·증거(서버 JSON 그대로)를 쓰도록 저장. 쿼리만 쓰면 길이·건수 제한. */
    try {
      sessionStorage.setItem(BLOCK_PAYLOAD_KEY, JSON.stringify(data));
    } catch (e) {}
    var f = (data.findings && data.findings[0]) || {};
    var p = new URLSearchParams({
      owasp_id: f.owasp_id || "",
      category: f.category || "",
      attack_type: f.attack_type || "WAF 차단",
      rule_id: f.rule_id || "",
      severity: f.severity || "high",
      location: f.location || "",
      evidence: (f.evidence || "").slice(0, 480),
    });
    window.location.replace("/__waf/blocked?" + p.toString());
  }

  function tryParseBlocked(raw) {
    try {
      wafRedirect(JSON.parse(raw));
    } catch (e) {}
  }

  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    var reqU = reqUrl(input);
    return origFetch.call(this, input, init).then(function (resp) {
      if (resp.status === 403 && !isWafSelf(reqU)) {
        resp
          .clone()
          .text()
          .then(tryParseBlocked)
          .catch(function () {});
      }
      return resp;
    });
  };

  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function () {
    this._wafUrl = arguments[1];
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    var xhr = this;
    function onDone() {
      if (xhr.readyState !== 4 || xhr.status !== 403) return;
      if (isWafSelf(xhr._wafUrl)) return;
      tryParseBlocked(xhr.responseText);
    }
    xhr.addEventListener("readystatechange", onDone);
    return origSend.apply(this, arguments);
  };

  function reportLocationHash() {
    try {
      if (String(location.pathname || "").indexOf("/__waf/blocked") === 0) return;
      var h = location.hash || "";
      if (!h || h === "#") return;
      fetch("/__waf/api/scan-fragment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ fragment: h }),
      }).catch(function () {});
    } catch (e) {}
  }

  window.addEventListener("hashchange", reportLocationHash);
  if (document.readyState === "complete") {
    reportLocationHash();
  } else {
    window.addEventListener("load", reportLocationHash);
  }
})();
