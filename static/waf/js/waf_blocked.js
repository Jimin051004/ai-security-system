/**
 * 차단 페이지: 서버가 #waf-block-boot JSON에 넣은 alert_message 로 브라우저 알림 표시.
 */
(function () {
  function showBlockAlert() {
    var el = document.getElementById("waf-block-boot");
    var msg = "요청이 WAF에 의해 차단되었습니다.";
    if (el && el.textContent) {
      try {
        var data = JSON.parse(el.textContent);
        if (data && typeof data.alert_message === "string" && data.alert_message.length) {
          msg = data.alert_message;
        }
      } catch (_) {
        /* 기본 문구 사용 */
      }
    }
    try {
      window.alert(msg);
    } catch (_) {
      /* alert 불가 환경 */
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", showBlockAlert);
  } else {
    showBlockAlert();
  }
})();
