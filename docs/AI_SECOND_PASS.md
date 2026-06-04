# AI 2차 탐지/차단

룰 기반 WAF가 먼저 요청을 검사하고, 차단 후보가 없지만 의심스러운 요청만 로컬 AI 모델이 한 번 더 판정한다.

## 무료 모델 실행

```bash
brew install ollama
ollama serve
ollama pull qwen2.5:7b-instruct
```

가벼운 노트북이면 `qwen2.5:3b-instruct`를 대신 써도 된다.

## 환경 변수

```env
AI_SECOND_PASS_ENABLED=true
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
AI_MODEL=qwen2.5:7b-instruct
AI_BLOCK_MIN_CONFIDENCE=0.75
AI_SECOND_PASS_TIMEOUT_SEC=3.0
AI_SECOND_PASS_MODE=suspicious
```

`AI_SECOND_PASS_MODE=suspicious`는 룰 finding이 있거나 SQLi/XSS/경로 탐색 같은 의심 패턴이 있을 때만 모델을 호출한다. `always`는 모든 요청을 검사하므로 느릴 수 있다.

## 차단 정책

- 기존 룰이 명확히 차단하는 요청은 즉시 차단한다.
- 기존 룰로 차단되지 않은 의심 요청은 AI가 JSON으로 판정한다.
- `malicious=true`이고 confidence가 `AI_BLOCK_MIN_CONFIDENCE` 이상이면 `AI-SECOND-PASS` 규칙으로 차단한다.
- Ollama가 꺼져 있거나 JSON 파싱에 실패하면 기존 룰 정책만 적용한다.
- `confidence`가 기준보다 낮으면 악성 후보여도 통과시키고, 상태에는 `allow_low_confidence`로 남긴다.

## AI에 전달되는 데이터

요청 전체 원문이 아니라 `method`, `path`, `query_string`, 일부 안전한 headers, `body_preview`, 1차 룰 finding만 전달한다. `cookie`, `authorization`, `password`, `token`, `api_key`, `secret` 계열 값은 마스킹한다.

## 상태 확인

프록시 워커는 AI 2차 판단 상태를 health와 워커 콘솔에 표시한다.

```bash
curl http://127.0.0.1:8081/__proxy/health
```

응답의 `ai_second_pass` 필드에서 아래 값을 확인한다.

| 필드 | 의미 |
|---|---|
| `enabled` | AI 2차 판단 활성화 여부 |
| `provider` | 현재는 `ollama` |
| `model` | 사용 모델명 |
| `mode` | `suspicious` 또는 `always` |
| `last_decision` | `never_run`, `calling`, `allow`, `allow_low_confidence`, `block`, `unavailable` 등 |
| `last_error_type` | `timeout`, `invalid_json`, `http_error`, `request_error` 등 |
| `last_latency_ms` | 최근 모델 호출 지연시간 |

관리자 로그인 후 워커 콘솔에서도 확인할 수 있다.

```text
http://127.0.0.1:8081/__waf/worker/logs
GET /__waf/worker/api/ai-status
```

중앙 대시보드는 DB에 저장된 `AI-SECOND-PASS` 차단 이벤트를 기준으로 AI 보조 차단 건수와 최근 AI 판단을 표시한다.

## 구현 파일

| 파일 | 역할 |
|---|---|
| `ai_second_pass.py` | AI 호출, 응답 파싱, 상태 추적, 민감정보 마스킹 |
| `main.py` | WAF gate와 AI 차단 연동, `/__proxy/health` 상태 노출 |
| `waf_worker_console.py` | 워커 AI 상태 API 제공 |
| `templates/worker_logs.html` | 워커 콘솔 AI 상태 표시 |
| `templates/dashboard/partials/overview.html` | 중앙 대시보드 AI 이벤트 요약 |
| `static/waf/js/dashboard.js` | AI 이벤트 렌더링 |
| `verification/ai_second_pass_test.py` | AI 2차 판단 단위/통합 테스트 |
