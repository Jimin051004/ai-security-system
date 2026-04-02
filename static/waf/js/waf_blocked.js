/**
 * WAF 차단 페이지 — OWASP Top 10 : 2025
 * AI Security System
 *
 * 역할:
 *  1. 서버 boot JSON에서 alert_message를 읽어 브라우저 알림 표시
 *  2. 페이지 내 OWASP 2025 카테고리 설명 동적 삽입
 */
(function () {
  "use strict";

  /* ── OWASP Top 10 : 2025 카테고리 정의 ─────────────────────────────── */
  var OWASP_2025 = {
    "A01:2025": {
      title: "Broken Access Control",
      ko:    "손상된 접근 제어",
      desc:  "인가되지 않은 기능·데이터에 대한 접근 제어가 실패하여 권한 없는 사용자가 민감한 리소스에 접근할 수 있는 취약점입니다.",
      cwe:   ["CWE-22", "CWE-284", "CWE-285", "CWE-639", "CWE-918"],
    },
    "A02:2025": {
      title: "Security Misconfiguration",
      ko:    "보안 설정 오류",
      desc:  "기본 자격증명 사용, 불필요한 기능 활성화, 누락된 보안 헤더 등 잘못된 보안 구성으로 인한 취약점입니다.",
      cwe:   ["CWE-16", "CWE-611", "CWE-732"],
    },
    "A03:2025": {
      title: "Software Supply Chain Failures",
      ko:    "소프트웨어 공급망 취약점",
      desc:  "서드파티 라이브러리·컴포넌트·CI/CD 파이프라인의 무결성 검증 실패로 인한 공급망 공격입니다.",
      cwe:   ["CWE-494", "CWE-829", "CWE-1104"],
    },
    "A04:2025": {
      title: "Cryptographic Failures",
      ko:    "암호화 실패",
      desc:  "전송 중·저장 중 데이터를 보호하지 않거나 취약한 암호 알고리즘·키 길이를 사용하여 민감 정보가 노출되는 취약점입니다.",
      cwe:   ["CWE-259", "CWE-327", "CWE-328", "CWE-330"],
    },
    "A05:2025": {
      title: "Injection",
      ko:    "인젝션",
      desc:  "신뢰할 수 없는 데이터가 인터프리터에 명령·쿼리의 일부로 삽입되는 취약점입니다. SQL · OS Command · XSS · LDAP · XPath · SSTI 등을 포함합니다.",
      cwe:   ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"],
    },
    "A06:2025": {
      title: "Insecure Design",
      ko:    "안전하지 않은 설계",
      desc:  "설계·아키텍처 단계에서 보안 제어가 누락되어 발생하는 구조적 취약점입니다. 위협 모델링 부재가 주요 원인입니다.",
      cwe:   ["CWE-73", "CWE-183", "CWE-209", "CWE-602"],
    },
    "A07:2025": {
      title: "Authentication Failures",
      ko:    "인증 실패",
      desc:  "인증·세션 관리의 결함으로 공격자가 타 사용자 계정을 탈취하거나 인증을 우회할 수 있는 취약점입니다.",
      cwe:   ["CWE-255", "CWE-287", "CWE-295", "CWE-297", "CWE-384"],
    },
    "A08:2025": {
      title: "Software and Data Integrity Failures",
      ko:    "소프트웨어·데이터 무결성 실패",
      desc:  "코드·데이터의 무결성 검증 없이 신뢰하는 취약점으로, 안전하지 않은 역직렬화나 CI/CD 파이프라인 조작을 포함합니다.",
      cwe:   ["CWE-345", "CWE-426", "CWE-502", "CWE-829"],
    },
    "A09:2025": {
      title: "Security Logging and Alerting Failures",
      ko:    "보안 로깅·모니터링 실패",
      desc:  "보안 이벤트가 로깅·모니터링되지 않아 침해 사고를 탐지·대응하지 못하는 취약점입니다.",
      cwe:   ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
    },
    "A10:2025": {
      title: "Mishandling of Exceptional Conditions",
      ko:    "예외 조건 부적절 처리",
      desc:  "비정상적인 입력·조건에서 발생하는 예외를 처리하지 못해 스택 트레이스·내부 경로·DB 오류 등 민감 정보가 노출되거나 애플리케이션이 비정상 종료되는 취약점입니다.",
      cwe:   ["CWE-209", "CWE-390", "CWE-391", "CWE-544", "CWE-636", "CWE-1321"],
    },
  };

  /* ── boot 데이터 파싱 ────────────────────────────────────────────────── */
  function readBootData() {
    var el = document.getElementById("waf-block-boot");
    if (!el) return {};
    try { return JSON.parse(el.textContent) || {}; } catch (_) { return {}; }
  }

  /* ── 브라우저 alert ──────────────────────────────────────────────────── */
  function showAlert(boot) {
    var msg = boot.alert_message ||
      "[WAF 차단] 보안 위협 패턴이 탐지되어 요청이 차단되었습니다.";
    try { window.alert(msg); } catch (_) {}
  }

  /* ── 페이지 내 OWASP 카테고리 설명 삽입 ─────────────────────────────── */
  function injectOwaspInfo() {
    var infoBox = document.getElementById("wb-owasp-info");
    if (!infoBox) return;

    /* finding 카드에서 OWASP ID 수집 */
    var badges = document.querySelectorAll(".wb-owasp-badge");
    var seen   = {};
    var ids    = [];
    for (var i = 0; i < badges.length; i++) {
      var id = (badges[i].textContent || "").trim();
      if (id && !seen[id]) { seen[id] = true; ids.push(id); }
    }
    if (!ids.length) return;

    var html = "";
    ids.forEach(function (owaspId) {
      var info = OWASP_2025[owaspId];
      if (!info) return;
      var cweTags = (info.cwe || []).map(function (c) {
        return '<span class="wb-cwe-tag">' + c + '</span>';
      }).join(" ");
      html +=
        '<div style="margin-bottom:' + (ids.length > 1 ? "1rem" : "0") + '">' +
          '<div class="wb-owasp-info-title">' +
            '<span style="margin-right:.5rem;background:#8b5cf6;color:#fff;' +
            'padding:.1rem .5rem;border-radius:4px;font-size:.7rem;">' +
            owaspId + '</span>' +
            info.title + ' <span style="color:#64748b;font-weight:400">— ' + info.ko + '</span>' +
          '</div>' +
          '<div class="wb-owasp-info-desc">' + info.desc + '</div>' +
          (cweTags ? '<div class="wb-owasp-cwe-list">' + cweTags + '</div>' : '') +
        '</div>';
    });

    if (html) {
      infoBox.innerHTML = html;
      infoBox.removeAttribute("hidden");
    }
  }

  /* ── 심각도 배지에 한국어 레이블 추가 ───────────────────────────────── */
  function localizeSevPills() {
    var map = { CRITICAL: "크리티컬", HIGH: "하이", MEDIUM: "미디엄", LOW: "로우" };
    var pills = document.querySelectorAll(".wb-sev-pill");
    for (var i = 0; i < pills.length; i++) {
      var raw = (pills[i].textContent || "").trim().toUpperCase();
      if (map[raw]) {
        pills[i].textContent = raw + " · " + map[raw];
      }
    }
  }

  /* ── 메인 초기화 ─────────────────────────────────────────────────────── */
  function init() {
    var boot = readBootData();
    showAlert(boot);
    injectOwaspInfo();
    localizeSevPills();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
