# WAF 애플리케이션 Docker 이미지
# 빌드: docker build -f docker/waf/Dockerfile -t waf-app .
FROM python:3.11-slim

WORKDIR /app

# 시스템 패키지 (curl: 헬스체크용)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# 의존성만 먼저 설치 (소스 변경 시 캐시 레이어 재사용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 앱 소스 전체 복사
COPY . .

# SQLite DB 영속 디렉터리 (docker volume 마운트 대상)
RUN mkdir -p /app/data
ENV TRAFFIC_LOG_DB=/app/data/waf_traffic.sqlite3
ENV WAF_AUTH_DB=/app/data/waf_auth.sqlite3

# WAF 프록시 + 대시보드를 단일 프로세스로 실행
# (대용량 트래픽이라면 main:app / dashboard_app:app 을 별도 서비스로 분리)
EXPOSE 8000

# uvicorn: workers=2 (CPU-bound 룰 스캔이 없어서 2개면 충분)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
