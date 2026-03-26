# AI Security System

**탐지 · 차단 · 대응 · 기록**을 축으로 하는 AI 기반 리버스 프록시 WAF · [OWASP Top 10:2025](https://owasp.org/Top10/2025/) · 보안 코딩 개선 제안 (FastAPI, 로컬 LLM)

## 업스트림 웹 앱 (Juice Shop) + 프록시

1. **Juice Shop** (Docker): 프로젝트 루트에서 `docker compose up -d` 후 브라우저에서 `http://127.0.0.1:3000` 으로 동작 확인.
2. **가상환경·의존성:** `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. **프록시:** `cp .env.example .env` 후 `UPSTREAM_URL` 을 그대로 두고, `uvicorn main:app --host 127.0.0.1 --port 8080` 실행 → `http://127.0.0.1:8080` 으로 Juice Shop에 접속. 헬스: `http://127.0.0.1:8080/__proxy/health`

일부 리다이렉트가 업스트림 포트(3000)를 가리킬 수 있어, 데모 중에는 주소창이 8080을 유지하는지 확인하면 된다.
