# 14. OWASP 전체 모듈 차단 구현

## 1. 구현 목적

A01~A10 전체 모듈이 단순 스켈레톤이 아니라 실제 요청 기반 `Finding`을 만들고, WAF 차단 기준에 걸리면 공통 차단 페이지로 연결되도록 구현한다.

## 2. 구현 범위

| 번호 | 모듈 | 구현 내용 | 대표 차단 트리거 |
|---|---|---|---|
| 2-1 | A01 Broken Access Control | 관리자 경로, IDOR, 권한 상승 파라미터, 경로 순회 탐지 | `/admin`, `role=admin` |
| 2-2 | A02 Security Misconfiguration | `.env`, `.git`, debug, actuator, 백업 파일 접근 탐지 | `/.env`, `/actuator/env` |
| 2-3 | A03 Software Supply Chain Failures | 외부 CDN/패키지 주입, lockfile 접근, 원격 설치 스크립트 탐지 | `/package-lock.json` |
| 2-4 | A04 SSRF | 기존 SSRF 룰 유지 | `url=http://169.254.169.254/...` |
| 2-5 | A05 Injection | 기존 Injection 룰 유지 | SQLi, XSS, Command Injection |
| 2-6 | A06 Insecure Design | 기존 비즈니스 로직/권한/가격 조작 룰 유지 | `isAdmin=true` |
| 2-7 | A07 Authentication Failures | 기본 계정, 약한 비밀번호, JWT alg none, 세션 우회 값 탐지 | `username=admin&password=admin` |
| 2-8 | A08 Integrity Failures | 기존 업로드/역직렬화/XXE 룰 유지 | `filename=shell.php` |
| 2-9 | A09 Logging and Alerting Failures | 로그 인젝션, 로깅 비활성화, 추적 방해 헤더, 공격 도구 UA 탐지 | `log=disabled` |
| 2-10 | A10 Exceptional Conditions | 기존 예외/오류 유발 룰 유지 | `/api/Products/undefined` |

## 3. 차단 흐름

```text
1. 요청 수신
2. `detector.scan_request()`가 A01~A10 전체 모듈 실행
3. 각 모듈이 요청 path/query/header/body에서 룰 매칭
4. `Finding` 생성
5. `waf_blocking_findings()`가 기본 high 이상 또는 A05 인젝션을 차단 후보로 선택
6. `main.py`가 공통 WAF 차단 페이지 또는 JSON 403 반환
7. 탐지/차단 이벤트가 대시보드 로그에 저장
```

## 4. 보안 고려사항

| 번호 | 항목 | 설명 |
|---|---|---|
| 4-1 | 휴리스틱 한계 | 요청 기반 룰이므로 실제 취약 여부가 아니라 공격 의심 요청을 차단한다 |
| 4-2 | 오탐 가능성 | `/admin`, `.env`, `log=disabled` 같은 시연용 룰은 운영 환경에서 예외 정책이 필요할 수 있다 |
| 4-3 | 민감정보 로그 | 인증 관련 탐지는 evidence 길이를 제한하고, 대시보드 출력은 escape되어야 한다 |
| 4-4 | 안전한 실습 범위 | Juice Shop, 로컬 랩, 허가된 시연 환경에서만 페이로드를 사용한다 |

## 5. 테스트

추가 테스트:

```text
verification/owasp_all_modules_blocking.py
```

검증 내용:

| 번호 | 검증 |
|---|---|
| 5-1 | A01~A10 각 모듈이 대표 요청에서 `Finding`을 생성 |
| 5-2 | 생성된 Finding이 기본 차단 기준 `Severity.HIGH`에서 차단 후보에 포함 |
| 5-3 | 대시보드 `/__waf/api/modules`에서 전체 모듈 상태가 `rules`로 표시 |

## 6. 남은 한계

| 번호 | 한계 | 개선 방향 |
|---|---|---|
| 6-1 | 응답 본문 기반 스캔은 아직 제한적 | A02/A10 응답 스캔 추가 |
| 6-2 | A09는 메타 성격이 강함 | 이벤트 저장 실패/알림 누락 자체를 점검하는 운영 메타 룰 추가 |
| 6-3 | 사이트별 룰 ON/OFF 미완성 | 멀티 사이트 정책 구현과 연결 |
| 6-4 | 룰 민감도 조정 미완성 | 대시보드에서 사이트별 severity override 제공 |
