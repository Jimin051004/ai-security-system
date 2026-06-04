# 15. OWASP A01~A10 차단 시연 페이로드

## 1. 시연 전제

모든 시연은 로컬 랩 또는 허가된 졸업작품 환경에서만 수행한다.

| 구분 | 주소 |
|---|---|
| 원본 Juice Shop | `http://192.168.100.155:3001` |
| WAF 경유 Juice Shop | `http://192.168.100.155:8081` |
| 대시보드 | `http://192.168.100.155:8090/login` |

차단 페이지를 보려면 반드시 WAF 경유 주소인 `8081`로 요청한다.

```text
원본 확인: http://192.168.100.155:3001/...
차단 확인: http://192.168.100.155:8081/...
```

## 2. 시연 방식

| 번호 | 방식 | 의미 |
|---|---|---|
| 2-1 | 원본 주소로 먼저 요청 | WAF가 없으면 요청이 애플리케이션까지 도달함을 확인 |
| 2-2 | WAF 주소로 같은 요청 | WAF가 탐지 후 403 차단 페이지를 표시 |
| 2-3 | 대시보드 확인 | 탐지·차단 로그에 OWASP 항목과 rule_id가 저장됨 |

## 3. A01~A10 입력 위치와 페이로드

| OWASP | 입력 위치 | WAF 차단 URL 또는 입력값 | 기대 차단 룰 |
|---|---|---|---|
| A01 Broken Access Control | 주소창 path | `http://192.168.100.155:8081/admin` | `A01-BAC-001` |
| A01 Broken Access Control | 주소창 query | `http://192.168.100.155:8081/?role=admin` | `A01-BAC-003` |
| A02 Security Misconfiguration | 주소창 path | `http://192.168.100.155:8081/.env` | `A02-CONFIG-001` |
| A02 Security Misconfiguration | 주소창 path | `http://192.168.100.155:8081/actuator/env` | `A02-CONFIG-002` |
| A03 Software Supply Chain Failures | 주소창 path | `http://192.168.100.155:8081/package-lock.json` | `A03-SUPPLY-003` |
| A03 Software Supply Chain Failures | 주소창 query | `http://192.168.100.155:8081/?script=https://unpkg.com/test.js` | `A03-SUPPLY-001` |
| A04 SSRF | 주소창 query | `http://192.168.100.155:8081/?url=http://169.254.169.254/latest/meta-data` | `A04-SSRF-001` |
| A05 Injection | Juice Shop 검색창 또는 주소창 query | `http://192.168.100.155:8081/rest/products/search?q=' OR 1=1--` | `A05-*` |
| A06 Insecure Design | 주소창 query | `http://192.168.100.155:8081/?isAdmin=true` | `A06-ROLE-001` |
| A07 Authentication Failures | 주소창 query 또는 로그인 요청 | `http://192.168.100.155:8081/login?username=admin&password=admin` | `A07-AUTH-001` |
| A08 Integrity Failures | 파일 업로드 요청 body | `filename="shell.php"` | `A08-UPLOAD-001` |
| A09 Logging and Alerting Failures | 주소창 query | `http://192.168.100.155:8081/?log=disabled` | `A09-LOG-002` |
| A10 Exceptional Conditions | 주소창 path | `http://192.168.100.155:8081/api/Products/undefined` | `A10-UNDEF-001` |

## 4. 브라우저만으로 쉬운 시연 순서

브라우저 주소창만으로 바로 차단 페이지를 보여주기 쉬운 순서:

| 순서 | OWASP | URL |
|---|---|---|
| 1 | A01 | `http://192.168.100.155:8081/admin` |
| 2 | A02 | `http://192.168.100.155:8081/.env` |
| 3 | A03 | `http://192.168.100.155:8081/package-lock.json` |
| 4 | A04 | `http://192.168.100.155:8081/?url=http://169.254.169.254/latest/meta-data` |
| 5 | A05 | `http://192.168.100.155:8081/rest/products/search?q=' OR 1=1--` |
| 6 | A06 | `http://192.168.100.155:8081/?isAdmin=true` |
| 7 | A07 | `http://192.168.100.155:8081/login?username=admin&password=admin` |
| 8 | A09 | `http://192.168.100.155:8081/?log=disabled` |
| 9 | A10 | `http://192.168.100.155:8081/api/Products/undefined` |

A08은 파일 업로드 body가 필요해서 브라우저 주소창보다 `curl` 또는 Burp/DevTools 요청 재전송이 적합하다.

## 5. A08 curl 시연

```bash
curl -i -X POST "http://192.168.100.155:8081/upload" \
  -F 'file=@README.md;filename=shell.php'
```

기대 결과:

```text
HTTP/1.1 403 Forbidden
WAF 차단 페이지 또는 JSON 차단 응답
rule_id: A08-UPLOAD-001
```

## 6. 발표 설명 문장

```text
같은 요청을 원본 Juice Shop으로 보내면 애플리케이션까지 도달하지만,
WAF 경유 주소로 보내면 요청이 origin에 도달하기 전에 OWASP A01~A10 모듈 중 하나에서 탐지되고,
공통 차단 페이지와 대시보드 로그로 연결됩니다.
```

## 7. 주의사항

| 번호 | 주의 | 설명 |
|---|---|---|
| 7-1 | 실제 공격 성공과 WAF 차단 성공은 다름 | 모든 페이로드가 Juice Shop에서 실제 취약점 성공을 보장하는 것은 아님 |
| 7-2 | 발표에서는 차단 성공 중심 | 목적은 WAF가 공격성 요청을 origin 이전에 차단하는 과정을 보여주는 것 |
| 7-3 | 원본 직접 요청은 비교용 | WAF 우회가 아니라 보호 전/후 차이를 보여주기 위한 로컬 시연 |
| 7-4 | 허가된 환경에서만 사용 | 실제 외부 사이트에 사용하지 않음 |
