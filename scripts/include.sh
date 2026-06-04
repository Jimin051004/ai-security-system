# 프로젝트 루트 + 가상환경만 (각 스크립트에서 .env 로드 후 필요 시 변수 덮어쓰기)
# shellcheck shell=bash
WAF_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
cd "$WAF_PROJECT_ROOT" || exit 1

if [[ -f "system/bin/activate" ]]; then
  # shellcheck source=/dev/null
  source "system/bin/activate"
fi

waf_load_dotenv() {
  if [[ -f ".env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source ".env"
    set +a
  fi
}
