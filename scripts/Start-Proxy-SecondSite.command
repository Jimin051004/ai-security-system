#!/usr/bin/env bash
# 두 번째 사이트 프록시 — .env의 SITE_ID와 관계없이 이 창에서는 아래 값 고정
set -e
source "$(dirname "$0")/include.sh"
waf_load_dotenv
export SITE_ID="${SITE_ID_SECOND:-other_app}"
export UPSTREAM_URL="${UPSTREAM_URL_SECOND:-http://127.0.0.1:3002}"
exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8082 --reload
