# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI-based reverse-proxy WAF (FastAPI) targeting OWASP Top 10:2025, built as a graduation project. A per-site proxy worker scans traffic with rule-based OWASP modules plus an optional local-LLM "second pass", blocks attacks, and reports to a central multi-site dashboard. The demo target is OWASP Juice Shop.

**Language convention:** docs, docstrings, comments, commit context, and user-facing UI are in Korean. Per `.cursor/rules/change-summary.mdc`, always end a response that changed the repo with a short Korean summary of what/why changed. Per `.cursor/rules/github-sync.mdc`, ask before committing/pushing unless the user explicitly requested it.

## Commands

```bash
# Setup (venv folder is conventionally named "system")
python3 -m venv system && source system/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
test -f .env || cp .env.example .env

# Tests (run from repo root; pytest.ini sets testpaths=verification)
python3 -m pytest -q                                   # full suite
python3 -m pytest verification/detector_policy.py -q   # single file
python3 -m pytest -q -k "block"                        # by keyword

# Run (3-terminal local demo; make targets load .env automatically)
make deps               # create venv + install
make dashboard          # central dashboard  dashboard_app:app on :8080
make proxy-juiceshop    # WAF proxy worker   main:app on :8081 (SITE_ID=juiceshop → UPSTREAM_URL=:3001)
make proxy-second       # second worker      main:app on :8082
docker compose -f docker-compose.yml up -d   # Juice Shop upstream on host port 3001

# Full Docker stack (WAF + dashboard + Caddy TLS; add --profile demo for Juice Shop)
docker compose -f docker-compose.waf.yml up -d
```

**Dependency gotcha:** `requirements.txt` omits `itsdangerous` (needed by `SessionMiddleware`) and `python-multipart` (needed by `Form(...)` endpoints). If test collection fails with `ModuleNotFoundError: itsdangerous` or `Form data requires...`, `pip install itsdangerous python-multipart`.

**Test conventions:** test files in `verification/` do NOT use the `test_*.py` naming scheme (`pytest.ini` sets `python_files = *.py`). `verification/conftest.py` pins env vars (`UPSTREAM_URL`, `TRAFFIC_LOG_DB=:memory:`, etc.) before `main` is imported — `main.py` exits at import time if `UPSTREAM_URL` is not a full URL. Tests run without any live upstream. After implementing/changing an OWASP module, add or extend a matching test in `verification/`.

## Architecture

Two separate FastAPI apps that share library modules and SQLite files:

1. **`main.py` — WAF proxy worker** (one process per protected site). Request flow:
   - `request_snapshot.request_to_context()` → immutable `RequestContext` (method, path, query, headers, body preview; injects `x-real-ip` if absent)
   - `detector.scan_request()` runs every module in `owasp.MODULES`
   - `detector.waf_blocking_findings()` selects findings ≥ `WAF_BLOCK_MIN_SEVERITY` — **plus all `A05-*` (injection) findings regardless of severity**
   - If nothing blocks but the request looks suspicious, `ai_second_pass.judge_request_with_ai()` optionally asks a local Ollama model (`AI_SECOND_PASS_ENABLED`); it fails open to the rule policy on timeout/invalid JSON
   - Block → 403 page via `waf_block_response.py` (+ `waf_rule_explain.py`); pass → forward to upstream via httpx, rewriting absolute upstream URLs in HTML/JS/JSON responses
   - Everything is logged via `traffic_log.py` and pushed (ingest POST) to the central dashboard; with no `CENTRAL_DASHBOARD_URL`/`SENSOR_TOKEN` it auto-falls back to `http://127.0.0.1:8080` + the local admin's sensor token

2. **`dashboard_app.py` — central dashboard** (:8080). Aggregates ingested logs from all workers, manages login/sessions (`auth.py`), site registration/policies (`site_registry.py`), and per-site WAF on/off that workers poll and obey (`WAF_FOLLOW_SITE_POLICY`).

**OWASP modules (`owasp/a01.py`–`a10.py`):** each exposes `MODULE_ID`, `OWASP_ID`, `TITLE`, and `async scan(ctx) -> ModuleScanResult`, and is registered in the `MODULES` tuple in `owasp/__init__.py`. Shared types (`RequestContext`, `Finding`, `Severity`, `clean_result`) live in `owasp/types.py`. All ten modules currently have rule implementations — the "skeleton" status table in `.cursor/rules/owasp-top10-2025-workflow.mdc` is outdated, but its workflow guidance (fixed A01–A10 ↔ file mapping, reference docs order, proposing next work in official OWASP order) still applies. The dashboard's rules/skeleton label comes from `_RULES_IMPLEMENTATION_MODULES` in `dashboard_app.py` — update it if module status changes.

**Storage:** two SQLite files that the dashboard and ALL workers must share on the same disk — `waf_traffic.sqlite3` (`traffic_log.py`, path via `TRAFFIC_LOG_DB`) and `waf_auth.sqlite3` (`auth.py`, PBKDF2 password hashes, sensor tokens). `site_registry.py` is imported optionally by `main.py`; without it the worker runs in single-site `UPSTREAM_URL` mode, with it the Host header routes to registered origins.

**URL namespace:** all WAF-owned routes are prefixed `/__waf/*` (dashboard UI/API/static) and `/__proxy/*` (worker health) so they never collide with upstream app routes (Juice Shop uses `/login`, `/dashboard`, etc.). Worker-local log console: `/__waf/worker/*` (`waf_worker_console.py`). Dashboard UI lives in `templates/` + `static/waf/`; served under `/__waf/static/...`.

**Configuration** is entirely env-var driven via `.env` (python-dotenv). `.env.example` is the authoritative, heavily-commented reference for every knob (severity threshold, AI second pass, ingest, multisite, DB paths).

## Key Docs

- `docs/PLAN.md` — overall plan; `docs/IMPLEMENTATION_ROADMAP.md` — work order
- `docs/TESTING.md` — pytest + manual curl flows; `docs/JUICE_SHOP_NETWORK_SETUP.md` — Docker/LAN demo
- `docs/OWASP_TOP10_2025_PDF_정리.md` — Juice Shop challenge/difficulty table used to prioritize module work
- `docs/15-OWASP-차단-시연-페이로드.md` — demo attack payloads per module
