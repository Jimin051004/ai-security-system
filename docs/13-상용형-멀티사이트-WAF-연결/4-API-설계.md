# 13-4. API 설계

## 1. 설계 목표

대시보드에서 사이트 등록, origin 수정, 정책 변경, 룰 ON/OFF, 예외 경로, IP 정책을 관리할 수 있게 한다.

기존 API는 유지하고, 신규 API는 `/__waf/api/sites` 하위로 추가한다.

## 2. 인증/인가 공통 규칙

| 번호 | 규칙 | 설명 |
|---|---|---|
| 2-1 | 모든 관리 API는 로그인 필요 | `_require_api_auth()` 사용 |
| 2-2 | admin은 모든 사이트 관리 가능 | `is_admin=True` |
| 2-3 | 일반 사용자는 자기 `site_id`만 조회/수정 | `_effective_site()` 확장 |
| 2-4 | 설정 변경은 감사 로그 기록 | `audit_logs` 저장 |
| 2-5 | sensor ingest는 세션 대신 sensor token 사용 | 기존 `/__waf/api/ingest` 유지 |

## 3. 사이트 목록 API

## 3-1. `GET /__waf/api/sites`

### 입력

없음.

### 출력

```json
{
  "status": "ok",
  "sites": [
    {
      "site_id": "shop",
      "display_name": "쇼핑몰",
      "domains": ["shop.example.com"],
      "origin_url": "http://127.0.0.1:3001",
      "mode": "block",
      "status": "active",
      "last_seen_iso": "2026-05-28 12:00:00"
    }
  ]
}
```

### 보안

일반 사용자는 자기 사이트만 반환한다.

## 4. 사이트 등록 API

## 4-1. `POST /__waf/api/sites`

### 입력

```json
{
  "site_id": "shop",
  "display_name": "쇼핑몰",
  "domain": "shop.example.com",
  "origin_url": "http://127.0.0.1:3001",
  "mode": "detect",
  "ai_second_pass_enabled": true
}
```

### 처리

| 순서 | 처리 |
|---|---|
| 1 | 로그인 확인 |
| 2 | `site_id`, `domain`, `origin_url` 정규화 |
| 3 | domain 중복 확인 |
| 4 | origin URL SSRF 방어 검증 |
| 5 | `sites`, `site_routes`, `site_policies` 저장 |
| 6 | audit log 저장 |

### 출력

```json
{
  "status": "ok",
  "site_id": "shop",
  "domain": "shop.example.com",
  "origin_url": "http://127.0.0.1:3001",
  "mode": "detect"
}
```

### 오류

| 상태 | 이유 |
|---|---|
| 400 | 잘못된 domain/origin |
| 401 | 로그인 필요 |
| 403 | 권한 없음 |
| 409 | 이미 등록된 domain 또는 site_id |

## 5. 사이트 수정 API

## 5-1. `PUT /__waf/api/sites/{site_id}`

### 입력

```json
{
  "display_name": "쇼핑몰 운영",
  "origin_url": "http://10.0.0.5:3000",
  "status": "active"
}
```

### 처리

1. 권한 확인
2. origin URL 검증
3. 변경 전/후 audit log 저장
4. site route 업데이트

## 6. 정책 변경 API

## 6-1. `PUT /__waf/api/sites/{site_id}/policy`

### 입력

```json
{
  "mode": "block",
  "min_severity": "high",
  "ai_second_pass_enabled": true,
  "ai_block_min_confidence": 0.7,
  "fail_mode": "fail_open"
}
```

### 정책 의미

| 값 | 의미 |
|---|---|
| `detect` | 탐지만 하고 origin으로 전달 |
| `block` | 정책 조건 충족 시 차단 |
| `disabled` | WAF 검사 비활성 |
| `fail_open` | 정책 조회 실패 시 요청 통과 |
| `fail_closed` | 정책 조회 실패 시 요청 차단 |

## 7. 룰 설정 API

## 7-1. `GET /__waf/api/sites/{site_id}/rules`

사이트별 룰 활성 상태를 반환한다.

## 7-2. `PUT /__waf/api/sites/{site_id}/rules/{rule_id}`

### 입력

```json
{
  "enabled": false,
  "severity_override": "medium"
}
```

### 보안

룰 비활성화는 audit log에 반드시 남긴다.

## 8. 예외 경로 API

## 8-1. `GET /__waf/api/sites/{site_id}/exceptions`

예외 목록 조회.

## 8-2. `POST /__waf/api/sites/{site_id}/exceptions`

### 입력

```json
{
  "path_pattern": "/health",
  "method": "GET",
  "rule_id": "",
  "reason": "헬스 체크 경로"
}
```

### 검증

| 항목 | 검증 |
|---|---|
| `path_pattern` | `/`로 시작해야 함 |
| `rule_id` | 비어 있거나 존재하는 룰이어야 함 |
| `reason` | 1자 이상 필요 |

## 9. IP 정책 API

## 9-1. `POST /__waf/api/sites/{site_id}/ip-policies`

### 입력

```json
{
  "ip_cidr": "192.168.0.0/24",
  "action": "allow",
  "reason": "사내망"
}
```

### 처리

Python `ipaddress`로 CIDR을 검증한다.

## 10. Gateway 내부 API/함수 설계

## 10-1. `resolve_site_for_request(request)`

### 입력

FastAPI `Request`

### 출력

```python
ResolvedSite(
    site_id="shop",
    domain="shop.example.com",
    origin_url="http://127.0.0.1:3001",
    mode="block",
    min_severity="high",
    ai_second_pass_enabled=True,
)
```

## 10-2. `forward_to_origin(request, resolved_site, full_path)`

### 역할

기존 `_forward()`를 확장하여 사이트별 origin으로 요청을 전달한다.

## 10-3. `apply_site_policy(ctx, findings, resolved_site)`

### 역할

탐지 결과와 사이트 정책을 기준으로 최종 행동을 결정한다.

| 출력 | 의미 |
|---|---|
| `allow` | 정상 통과 |
| `detect_only` | 탐지 기록 후 통과 |
| `block` | 차단 응답 |
| `disabled` | 검사 생략 |

## 11. DNS/TLS 안내 API

## 11-1. `GET /__waf/api/sites/{site_id}/connect-guide`

### 출력

```json
{
  "domain": "shop.example.com",
  "dns": {
    "type": "A",
    "target": "203.0.113.10"
  },
  "caddyfile_example": "shop.example.com { reverse_proxy 127.0.0.1:8081 }",
  "health_check_url": "https://shop.example.com/__proxy/health"
}
```

## 12. 기존 API와의 호환

| 기존 API | 유지 여부 | 변경 |
|---|---|---|
| `/__waf/api/summary` | 유지 | site query 지원 계속 |
| `/__waf/api/traffic` | 유지 | 신규 `requests/detections` 기반으로 점진 변경 |
| `/__waf/api/ingest` | 유지 | 신규 이벤트 테이블에도 저장 |
| `/__waf/api/settings/waf-enabled` | 유지 | 내부적으로 `site_policies.mode`로 연결 |
