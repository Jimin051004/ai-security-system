# 10-3. 데이터/API 설계

## 1. 데이터 구조 목적

AI 판단 결과를 기존 WAF Finding 구조와 호환되게 유지하면서, 운영 상태와 실패 원인을 확인할 수 있는 최소한의 상태 데이터를 추가한다.

## 2. 내부 데이터 구조

### 2-1. AISecondPassVerdict

| 필드 | 타입 | 설명 |
|---|---|---|
| `malicious` | boolean | 모델이 악성으로 판단했는지 여부 |
| `confidence` | number | 0.0~1.0 신뢰도 |
| `attack_type` | string | SQL Injection, XSS, SSRF 등 공격 유형 |
| `severity` | Severity | none/low/medium/high/critical |
| `reason` | string | 짧은 판단 근거 |
| `recommended_action` | string | allow 또는 block |
| `raw` | object | 원본 모델 응답 중 안전하게 보관 가능한 값 |

### 2-2. AISecondPassStatus

| 필드 | 타입 | 설명 |
|---|---|---|
| `enabled` | boolean | AI 2차 판단 활성화 여부 |
| `provider` | string | 현재는 `ollama` |
| `model` | string | 사용 모델명 |
| `mode` | string | `suspicious` 또는 `always` |
| `last_attempt_iso` | string | 최근 호출 시각 |
| `last_ok` | boolean/null | 최근 호출 성공 여부 |
| `last_latency_ms` | number/null | 최근 호출 지연시간 |
| `last_error_type` | string | timeout, invalid_json, http_error 등 |
| `last_decision` | string | skipped, allow, block, unavailable |

## 3. 환경 변수

| 번호 | 변수 | 기본값 | 설명 |
|---|---|---|---|
| 3-1 | `AI_SECOND_PASS_ENABLED` | false | AI 2차 판단 활성화 |
| 3-2 | `AI_PROVIDER` | ollama | AI 제공자 |
| 3-3 | `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama API 주소 |
| 3-4 | `AI_MODEL` | `qwen2.5:7b-instruct` | 사용할 모델 |
| 3-5 | `AI_BLOCK_MIN_CONFIDENCE` | 0.75 | 차단 최소 신뢰도 |
| 3-6 | `AI_SECOND_PASS_TIMEOUT_SEC` | 3.0 | 모델 호출 timeout |
| 3-7 | `AI_SECOND_PASS_MODE` | suspicious | 호출 범위 |
| 3-8 | `AI_SECOND_PASS_BODY_MAX_CHARS` | 1600 | AI에 전달할 본문 최대 길이 |
| 3-9 | `AI_SECOND_PASS_LOG_ALLOW` | false | allow 판단도 상태/로그에 남길지 여부 |

## 4. API 설계

### 4-1. 프록시 Health 확장

| 항목 | 내용 |
|---|---|
| Method | GET |
| Path | `/__proxy/health` |
| 목적 | 기존 health에 AI 상태 요약 추가 |
| 인증 | 없음. 민감정보는 포함하지 않음 |

응답 예시:

```json
{
  "status": "ok",
  "ai_second_pass": {
    "enabled": true,
    "provider": "ollama",
    "model": "qwen2.5:7b-instruct",
    "mode": "suspicious",
    "last_ok": true,
    "last_latency_ms": 812,
    "last_error_type": "",
    "last_decision": "block"
  }
}
```

### 4-2. AI 상태 API

| 항목 | 내용 |
|---|---|
| Method | GET |
| Path | `/__waf/worker/api/ai-status` |
| 목적 | 워커 콘솔 또는 중앙 대시보드에서 AI 상태 조회 |
| 인증 | 워커 콘솔 admin 세션 필요 |

응답 예시:

```json
{
  "enabled": true,
  "provider": "ollama",
  "model": "qwen2.5:7b-instruct",
  "mode": "suspicious",
  "block_min_confidence": 0.75,
  "body_max_chars": 1600,
  "last_attempt_iso": "2026-05-28 14:30:00",
  "last_ok": false,
  "last_error_type": "timeout",
  "last_decision": "unavailable"
}
```

## 5. DB 저장 설계

### 5-1. 1차 구현 범위

기존 `block_findings_json`에 `AI-SECOND-PASS` Finding을 저장한다. 별도 컬럼은 추가하지 않는다.

### 5-2. 후속 확장 후보

| 번호 | 컬럼 | 필요성 |
|---|---|---|
| 5-2-1 | `ai_attempted` | AI 호출 여부 통계 |
| 5-2-2 | `ai_decision` | allow/block/unavailable |
| 5-2-3 | `ai_confidence` | AI 판단 신뢰도 |
| 5-2-4 | `ai_latency_ms` | 성능 분석 |

## 6. 오류 코드/상태값

| 상태 | 의미 | 차단 여부 |
|---|---|---|
| `skipped_disabled` | 기능 비활성화 | 기존 정책 |
| `skipped_not_suspicious` | 의심 조건 불충족 | 기존 정책 |
| `http_error` | Ollama HTTP 오류 | 기존 정책 |
| `timeout` | 모델 응답 시간 초과 | 기존 정책 |
| `invalid_json` | JSON 파싱 실패 | 기존 정책 |
| `allow` | AI 허용 판단 | 통과 |
| `block` | AI 차단 판단 | 차단 |
