#!/usr/bin/env bash
# ── WAF 프록시 워커 실행 (중앙에서 받은 wjdtmdcjf 계정용 .env 가정) ─────────────────
#
# 브라우저에서 할 일:
#   1)중앙 대시보드(예 http://중앙:8080)에 wjdtmdcjf 등으로 로그인
#   2)설정 → 「프록시용 .env 받기」로 파일 저장 후, 이 저장소 루트에서 아래처럼 이름 변경
#
# 사용:
#   bash scripts/teammate_waf_worker.sh          # 안내 출력 + 의존성 후 프록시 기동
#   bash scripts/teammate_waf_worker.sh print   # 복사용 명령 블록만 출력
#
# 환경 변수:
#   LISTEN_PORT=8081  (기본 8081)
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${LISTEN_PORT:-8081}"

_lan_hint() {
  if command -v ipconfig >/dev/null 2>&1; then
    ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
  else
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [[ -z "${ip:-}" ]]; then
    ip="<이_PC_LAN_IP>"
  fi
  echo "$ip"
}

if [[ "${1:-}" == "print" ]]; then
  cat <<'USAGE'
────────────────────────────────────────────────────────
[1] 중앙(예 http://192.168.100.155:8080) 접속 · wjdtmdcjf 로그인 · 설정 화면
    「프록시용 .env 받기」(또는 가입 URL 힌트 링크) 저장

[2] 저장한 파일을 이 프로젝트 루트에 복사 후 이름 변경
    (터미널 예시 · 경로는 본인 PC에 맞게)
    mv ~/Downloads/waf-worker.env  /ABS/PATH/ai-security-system/.env

[3] 이 저장소에서 한 줄로 처리 (가상환경 + 의존성 + 프록시)
────────────────────────────────────────────────────────
USAGE
  echo ""
  echo "cd \"${ROOT}\" && LISTEN_PORT=${PORT} bash scripts/teammate_waf_worker.sh"
  echo ""
  cat <<USAGE2
────────────────────────────────────────────────────────
[또는] 직렬 명령 (Linux/mac 공통 패턴):

  cd "${ROOT}"
  test -x system/bin/python || python3 -m venv system
  . system/bin/activate && pip install -U pip && pip install -r requirements.txt
  set -a && . ./.env && set +a
  python3 -m uvicorn main:app --host 0.0.0.0 --port $PORT

[4] 팀 접속 안내 · 중요 · :3000 직링크 금지
    예) http://$( _lan_hint ):$PORT/#/
────────────────────────────────────────────────────────
USAGE2
  exit 0
fi

echo "▶ 저장소 루트: $ROOT"
if [[ ! -f .env ]]; then
  echo "✖ .env 파일이 없습니다."
  echo "  중앙 대시보드 → 설정 → 「프록시용 .env 받기」로 받은 파일을 여기 이름을 .env 로 두세요."
  echo "  (안내문만 필요하면):  bash scripts/teammate_waf_worker.sh print"
  exit 1
fi

if [[ ! -x system/bin/python ]]; then
  echo "▶ 가상환경 만들기(system/)…"
  python3 -m venv system
fi
# shellcheck disable=SC1091
source system/bin/activate

echo "▶ 의존성 설치(requirements.txt)…"
pip install -q -U pip && pip install -q -r requirements.txt

echo "▶ 환경 로드 (.env)…"
set -a
# shellcheck disable=SC1091
source .env
set +a

lip=$(_lan_hint)
echo ""
echo "▶ 프록시 기동 포트 ${PORT}"
echo "   팀은 브라우저로  http://${lip}:${PORT}/  접속 (~:3000 직접 X)"
echo "   진단: http://${lip}:${PORT}/__proxy/health"
echo ""

exec python3 -m uvicorn main:app --host 0.0.0.0 --port "${PORT}"
