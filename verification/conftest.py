"""검증 스위트: `main` import 전 환경 변수 고정."""

from __future__ import annotations

import os

# main.py 가 import 시점에 요구하는 유효 URL (실제 업스트림 호출은 각 케이스마다 없을 수 있음)
os.environ.setdefault("UPSTREAM_URL", "http://127.0.0.1:3001")
os.environ.setdefault("WAF_ENABLED", "true")
os.environ.setdefault("WAF_BLOCK_MIN_SEVERITY", "high")
