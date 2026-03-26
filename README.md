# AI Security System

**탐지 · 차단 · 대응 · 기록**을 축으로 하는 AI 기반 리버스 프록시 WAF · [OWASP Top 10:2025](https://owasp.org/Top10/2025/) · 보안 코딩 개선 제안 (FastAPI, 로컬 LLM)

## 문서 (`docs/`)

| 문서 | 설명 |
|------|------|
| [docs/PLAN.md](docs/PLAN.md) | 전체 계획서 |
| [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) | 다음 구현 작업 순서 |
| [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) | Juice Shop·Docker·LAN 데모 가이드 |
| [docs/TESTING.md](docs/TESTING.md) | 테스트 (pytest, curl) |

목록만 보기: [docs/README.md](docs/README.md)

## 업스트림 웹 앱 (Juice Shop) + 프록시

### 처음 한 번 (가상환경 없으면 `source` / `uvicorn` 오류 남)

저장소 루트에서 **순서대로**:

```bash
cd /path/to/ai-security-system
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
test -f .env || cp .env.example .env
```

이후 터미널을 새로 열 때마다: `cd ... && source .venv/bin/activate` 후 `uvicorn` 실행.

**venv 없이 한 줄로 실행만 하려면:**  
`python3 -m uvicorn main:app --host 127.0.0.1 --port 8080`  
(이때도 `pip install -r requirements.txt` 는 사용자/venv 중 한 곳에는 한 번 필요.)

1. **Juice Shop** (Docker): **`docker compose -f docker-compose.yml up -d`** — 호스트 포트 **`3001:3000`** (`http://127.0.0.1:3001`). `docker compose up` 만 쓰면 `compose.yaml` 등과 **병합**될 수 있다. 자세한 점검은 [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) §4.
2. **프록시:** (위에서 `activate` 한 상태에서) `uvicorn main:app --host 127.0.0.1 --port 8080` → `http://127.0.0.1:8080` , 헬스: `/__proxy/health` (`.env` 의 `WAF_*`). 타깃은 **`UPSTREAM_URL`만** 바꿔 교체.

**같은 Wi‑Fi의 다른 사람이 접속**해 공격·데모할 때는 [docs/JUICE_SHOP_NETWORK_SETUP.md](docs/JUICE_SHOP_NETWORK_SETUP.md) 를 본다.

일부 리다이렉트가 업스트림 포트를 가리킬 수 있어, 데모 중에는 주소창이 기대한 호스트·포트를 유지하는지 확인하면 된다.
