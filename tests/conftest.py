"""Pytest loads this first — set env before `main` reads UPSTREAM_URL."""

from __future__ import annotations

import os

# Valid URL required at import time by main.py (업스트림은 테스트마다 실제로 안 쓸 수 있음)
os.environ.setdefault("UPSTREAM_URL", "http://127.0.0.1:3001")
os.environ.setdefault("WAF_ENABLED", "true")
os.environ.setdefault("WAF_BLOCK_MIN_SEVERITY", "high")
