# Juice Shop · WAF 프록시 — 네트워크(다른 사람 접속) 데모 가이드

같은 Wi‑Fi/LAN의 다른 PC·폰에서 Juice Shop이나 프록시(WAF 앞단)로 접속해 공격·테스트할 때 사용한다. **본인 소유·허가된 네트워크**에서만 사용하고, 인터넷에 그대로 노출하지 않는 것을 권장한다.

---

## 1. 사전 준비

- [Docker](https://docs.docker.com/get-docker/) / Docker Desktop 설치 및 실행
- Python 3.11+ (프록시 사용 시)
- 호스트 PC와 공격자(또는 팀원) 기기가 **같은 네트워크**에 있음

---

## 2. 저장소 받기

```bash
git clone https://github.com/Jimin051004/ai-security-system.git
cd ai-security-system
cp .env.example .env
```

Juice Shop이 호스트의 **어느 포트**에 붙는지는 `docker-compose.yml`의 `ports: - "3001:3000"` 한 줄로만 정해진다(`.env`와 무관). 기본 호스트 포트는 **3001**이다.

---

## 3. 이 PC의 LAN IP 확인

다른 사람이 접속할 주소는 `http://<이_PC의_IP>:포트` 형태다.

### macOS

```bash
ipconfig getifaddr en0
```

Wi‑Fi가 아니면 `en1` 등일 수 있다. 전체 확인:

```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### Linux

```bash
hostname -I | awk '{print $1}'
```

### Windows (PowerShell)

```powershell
(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).IPAddress
```

아래 예시에서는 **호스트 IP를 `192.168.0.10`** 이라고 가정한다. 실제로는 위에서 나온 값으로 바꾼다.

---

## 4. Juice Shop 기동 (Docker)

프로젝트 루트에서:

```bash
docker compose pull
docker compose up -d
```

이 저장소의 `docker-compose.yml`은 **`3001:3000`**(호스트 3001 → 컨테이너 내부 3000)으로 붙인다.  
같은 네트워크의 다른 사람은 다음으로 **직접** Juice Shop에 접속할 수 있다.

- **직접 접속 URL:** `http://192.168.0.10:3001`  
  (WAF 프록시를 거치지 않음 — 순수 타깃 앱만 테스트할 때)

호스트 포트를 바꾸려면 `docker-compose.yml`에서 `"3002:3000"`처럼 **왼쪽 숫자만** 수정한 뒤 `docker compose up -d`를 다시 실행하고, **`.env`의 `UPSTREAM_URL` 포트도 동일하게** 맞춘다.

컨테이너 중지:

```bash
docker compose down
```

---

## 5. WAF 프록시(FastAPI) 기동 — 다른 사람이 프록시로만 들어오게 할 때

프록시 프로세스가 돌아가는 PC와 Docker(Juice Shop)가 **같은 머신**이면, 업스트림은 루프백으로 두면 된다.

### 5.1 가상환경·패키지

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 5.2 환경 변수

```bash
cp .env.example .env   # 이미 했다면 생략
```

`.env` 내용 예시(프록시와 Juice Shop이 **같은 PC**):

```env
UPSTREAM_URL=http://127.0.0.1:3001
```

다른 머신에만 Juice Shop이 있고 프록시만 여기 있는 경우에는, 그 머신의 IP와 포트로 바꾼다. 예:

```env
UPSTREAM_URL=http://192.168.0.20:3001
```

### 5.3 uvicorn을 LAN에 바인딩

**`127.0.0.1`이 아니라 `0.0.0.0`** 으로 띄워야 다른 기기에서 접속할 수 있다.

```bash
source .venv/bin/activate
set -a && [ -f .env ] && . ./.env && set +a
uvicorn main:app --host 0.0.0.0 --port 8080
```

Windows PowerShell에서 `.env` 로드가 번거로우면, 일회성으로:

```powershell
$env:UPSTREAM_URL="http://127.0.0.1:3001"
uvicorn main:app --host 0.0.0.0 --port 8080
```

- **프록시 경유 접속 URL:** `http://192.168.0.10:8080`  
- **프록시 헬스 확인:** `http://192.168.0.10:8080/__proxy/health`

---

## 6. 방화벽

다른 사람이 끊기면 호스트 OS 방화벽에서 **TCP 3001**(직접 Juice Shop, compose 기준), **TCP 8080**(프록시) 허용이 필요할 수 있다.

- **macOS:** 시스템 설정 → 네트워크 → 방화벽 옵션에서 `Python` 또는 터미널/도커 허용
- **Windows:** 고급 보안이 포함된 Windows Defender 방화벽 → 인바운드 규칙에서 포트 허용

---

## 7. 접속 정리 (예: 호스트 IP = 192.168.0.10)

| 목적 | URL |
|------|-----|
| Juice Shop 직접 (WAF 없음) | `http://192.168.0.10:3001` |
| WAF 프록시 경유 | `http://192.168.0.10:8080` |
| 프록시 상태 확인 | `http://192.168.0.10:8080/__proxy/health` |

---

## 8. 자주 있는 이슈

- **호스트 포트 충돌 (`address already in use`):** `docker-compose.yml`의 `"3001:3000"`에서 호스트 쪽(왼쪽)을 예: `3002`로 바꾸고, `.env`의 `UPSTREAM_URL` 포트도 맞춘 뒤 `docker compose up -d`를 다시 실행한다. 예전에 Docker가 3000을 쓰려다 실패한 경우, 프로젝트 루트 `.env`에 **`JUICE_SHOP_HOST_PORT=3000` 같은 줄이 있으면 삭제**한다(현재 compose는 이 변수를 쓰지 않지만, 혼동을 막기 위함).
- **리다이렉트가 `localhost`·다른 포트로 감:** Juice Shop이 절대 URL을 줄 때 발생할 수 있다. 주소창을 다시 `http://<LAN-IP>:8080`(또는 Juice Shop 직접 포트)으로 맞춘다.
- **`docker compose` 프로젝트 이름 오류:** 이 저장소 `docker-compose.yml` 상단에 `name: ai-security-system` 이 있다. 폴더 경로만 바꿔서 실행하면 된다.
- **상대방이 접속 불가:** 같은 Wi‑Fi인지, IP가 맞는지, 방화벽·VPN(게스트 격리) 여부를 확인한다.

---

## 9. 보안 주의

- Juice Shop은 **의도적으로 취약한** 애플리케이션이다. 공용 인터넷에 포트 포워딩하지 말 것.
- 수업·CTF·허가된 랩 외부에서는 노출 범위를 최소화할 것.

---

*OWASP Juice Shop: [https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)*
