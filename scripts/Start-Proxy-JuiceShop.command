#!/usr/bin/env bash
# Finder에서 더블클릭 → Juice Shop 앞 WAF 프록시 (기본 포트 8081)
# .env에 SITE_ID, UPSTREAM_URL이 있으면 사용. 없으면 기본값.
set -e
source "$(dirname "$0")/include.sh"
waf_load_dotenv
export SITE_ID="${SITE_ID:-juiceshop}"
export UPSTREAM_URL="${UPSTREAM_URL:-http://127.0.0.1:3001}"
exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8081 --reload
