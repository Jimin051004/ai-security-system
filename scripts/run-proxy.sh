#!/usr/bin/env bash
# README와 동일: 프록시(WAF) + Juice Shop 데모용 uvicorn
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f system/bin/activate ]]; then
  # shellcheck source=/dev/null
  source system/bin/activate
elif [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
else
  echo "가상환경이 없습니다. README대로: python3 -m venv system && source system/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload
