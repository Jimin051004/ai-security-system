# 프로젝트 루트에 두고: make deps → make dashboard / make proxy-juiceshop
.PHONY: help deps dashboard proxy-juiceshop proxy-second teammate-proxy teammate-proxy-help

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PY := $(ROOT)/system/bin/python
PIP := $(ROOT)/system/bin/pip

help:
	@echo "make deps             - 가상환경(system/) 만들고 pip install -r requirements.txt"
	@echo "make dashboard        - 중앙 대시보드 (0.0.0.0:8080)"
	@echo "make proxy-juiceshop  - 프록시 SITE_ID=juiceshop :8081"
	@echo "make proxy-second     - 프록시 SITE_ID=other_app :8082"
	@echo "make teammate-proxy-help — 팀원용 복사용 명령 블록 (wjdtmdcjf .env)"
	@echo "make teammate-proxy  — 프로젝트 루트에 .env 있을 때 의존성+main.py 워커 기동(LISTEN_PORT=)"
	@echo ".env 가 있으면 SITE_ID / UPSTREAM_URL 반영"
	@echo "(맥) 프록시: WAF_FALLBACK_CENTRAL_URL 없으면 en0/en1 IP로 http://<IP>:8080 자동 설정"
	@echo "(맥) proxy-juiceshop: 미설정 시 SITE_DISPLAY_NAME=Juice shop1 (중앙 사이트 필터 표시명)"

deps:
	cd "$(ROOT)" && ( \
	  test -x system/bin/python || python3 -m venv system; \
	  "$(PIP)" install -U pip && "$(PIP)" install -r requirements.txt \
	)

dashboard:
	cd "$(ROOT)" && ( \
	  test -f system/bin/activate && . system/bin/activate; \
	  test -f .env && set -a && . ./.env && set +a; \
	  exec python3 -m uvicorn dashboard_app:app --host 0.0.0.0 --port 8080 --reload \
	)

proxy-juiceshop:
	cd "$(ROOT)" && ( \
	  test -f system/bin/activate && . system/bin/activate; \
	  test -f .env && set -a && . ./.env && set +a; \
	  export SITE_ID=$${SITE_ID:-juiceshop}; \
	  export UPSTREAM_URL=$${UPSTREAM_URL:-http://127.0.0.1:3001}; \
	  export SITE_DISPLAY_NAME="$${SITE_DISPLAY_NAME:-Juice shop1}"; \
	  if [ -z "$$WAF_FALLBACK_CENTRAL_URL" ]; then \
	    LAN_IP="$$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"; \
	    [ -n "$$LAN_IP" ] && export WAF_FALLBACK_CENTRAL_URL="http://$$LAN_IP:8080" ; \
	  fi; \
	  if [ -n "$$CENTRAL_DASHBOARD_URL" ]; then echo "[proxy-juiceshop] ingest → $$CENTRAL_DASHBOARD_URL"; \
	  elif [ -n "$$WAF_FALLBACK_CENTRAL_URL" ]; then echo "[proxy-juiceshop] ingest → $$WAF_FALLBACK_CENTRAL_URL (폴백)"; fi; \
	  exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8081 --reload \
	)

proxy-second:
	cd "$(ROOT)" && ( \
	  test -f system/bin/activate && . system/bin/activate; \
	  test -f .env && set -a && . ./.env && set +a; \
	  export SITE_ID=$${SITE_ID_SECOND:-other_app}; \
	  export UPSTREAM_URL=$${UPSTREAM_URL_SECOND:-http://127.0.0.1:3002}; \
	  if [ -z "$$WAF_FALLBACK_CENTRAL_URL" ]; then \
	    LAN_IP="$$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"; \
	    [ -n "$$LAN_IP" ] && export WAF_FALLBACK_CENTRAL_URL="http://$$LAN_IP:8080" ; \
	  fi; \
	  if [ -n "$$CENTRAL_DASHBOARD_URL" ]; then echo "[proxy-second] ingest → $$CENTRAL_DASHBOARD_URL"; \
	  elif [ -n "$$WAF_FALLBACK_CENTRAL_URL" ]; then echo "[proxy-second] ingest → $$WAF_FALLBACK_CENTRAL_URL (폴백)"; fi; \
	  exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8082 --reload \
	)

teammate-proxy-help:
	cd "$(ROOT)" && bash scripts/teammate_waf_worker.sh print

teammate-proxy:
	cd "$(ROOT)" && LISTEN_PORT=$${LISTEN_PORT:-8081} bash scripts/teammate_waf_worker.sh


