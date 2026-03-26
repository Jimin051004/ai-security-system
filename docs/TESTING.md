# 테스트 가이드

## 1. 자동 테스트 (pytest)

업스트림(Juice Shop 등) **없이** 돌아가는 테스트와, 앱 import 시 필요한 최소 설정만 사용한다.

```bash
cd /path/to/ai-security-system
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

- `tests/test_detector_policy.py` — 차단 심각도·finding 집계 로직
- `tests/test_app_health.py` — `GET /__proxy/health` 가 200·JSON 키 반환

---

## 2. 수동 테스트 (전체 흐름)

### 준비

1. 업스트림 실행 (예: Juice Shop)  
   `docker compose -f docker-compose.yml up -d`  
2. 프록시 실행  
   ```bash
   cp .env.example .env
   source .venv/bin/activate
   uvicorn main:app --host 127.0.0.1 --port 8080
   ```

### 헬스

```bash
curl -s http://127.0.0.1:8080/__proxy/health | python3 -m json.tool
```

`status`, `upstream`, `waf_enabled`, `waf_block_min_severity` 가 보이면 정상.

### 프록시 통과 (WAF가 막지 않을 때)

지금 OWASP 모듈이 스켈레톤이면 대부분 **통과**한다.

```bash
curl -sI "http://127.0.0.1:8080/"
curl -sI "http://127.0.0.1:8080/api/Challenges"
```

업스트림이 떠 있으면 `HTTP/1.1 200` 또는 리다이렉트 등이 온다. **502** 이면 `UPSTREAM_URL`·포트·Docker 여부를 확인.

### WAF 끄고 비교 (순수 프록시만)

터미널에서:

```bash
export WAF_ENABLED=false
uvicorn main:app --host 127.0.0.1 --port 8080
```

헬스 JSON 에 `"waf_enabled": false` 인지 확인. 동작 차이는 **탐지 모듈에 finding이 생긴 뒤**에 두드러진다 (2단계 구현 후).

### 차단(403) 확인 — 모듈에 탐지가 있을 때

`WAF_BLOCK_MIN_SEVERITY` 이상의 finding이 나오면 403 JSON이 온다.  
지금은 스켈레톤이라 막히는 경우가 거의 없다. `owasp/a05.py` 등에 시그니처를 넣은 뒤 예:

```bash
curl -s "http://127.0.0.1:8080/search?q=test%27%20OR%201%3D1--"
```

(실제 403 여부는 규칙 구현에 따름.)

---

## 3. 자주 나는 증상

| 증상 | 점검 |
|------|------|
| 502 Upstream unreachable | `UPSTREAM_URL`, 업스트림 프로세스/Docker |
| 연결 거부 | uvicorn 포트(8080)·`--host` |
| import 오류 | 저장소 루트에서 실행, `PYTHONPATH` 또는 `cd` 확인 |

---

## 4. 다른 업스트림으로 바꿔 테스트

`.env` 만 수정:

```env
UPSTREAM_URL=http://다른호스트:포트
```

재시작 후 같은 `curl` 로 헬스·루트 요청을 반복하면 된다.
