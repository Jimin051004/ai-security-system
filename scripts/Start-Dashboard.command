#!/usr/bin/env bash
# Finder에서 더블클릭 → 중앙 대시보드 (기본 포트 8080)
set -e
source "$(dirname "$0")/include.sh"
waf_load_dotenv
exec python3 -m uvicorn dashboard_app:app --host 0.0.0.0 --port 8080 --reload
