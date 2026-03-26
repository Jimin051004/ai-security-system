# AI Security System

**탐지 · 차단 · 대응 · 기록**을 축으로 하는 AI 기반 리버스 프록시 WAF · [OWASP Top 10:2025](https://owasp.org/Top10/2025/) · 보안 코딩 개선 제안 (FastAPI, 로컬 LLM)

## 문서 (`docs/`)

| 문서 | 설명 |
|------|------|
| [docs/PLAN.md](docs/PLAN.md) | 전체 계획서 |
| [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) | 다음 구현 작업 순서 |
| [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) | Juice Shop·Docker·LAN 데모 가이드 |

목록만 보기: [docs/README.md](docs/README.md)

## 업스트림 웹 앱 (Juice Shop) + 프록시

1. **Juice Shop** (Docker): `cp .env.example .env` 후 **`docker compose -f docker-compose.yml up -d`** — 호스트 포트는 **`3001:3000`** (`http://127.0.0.1:3001`). `docker compose up` 만 쓰면 같은 디렉터리의 `compose.yaml` 등과 **병합**되어 다시 3000을 쓰려다 실패할 수 있다. 자세한 점검은 [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) §4.
2. **가상환경·의존성:** `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. **프록시(로컬만):** `cp .env.example .env` 후 `uvicorn main:app --host 127.0.0.1 --port 8080` → `http://127.0.0.1:8080` , 헬스: `/__proxy/health`

**같은 Wi‑Fi의 다른 사람이 접속**해 공격·데모할 때는 [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) 를 본다.

일부 리다이렉트가 업스트림 포트를 가리킬 수 있어, 데모 중에는 주소창이 기대한 호스트·포트를 유지하는지 확인하면 된다.
