# WAF 대시보드 Docker 이미지
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data
ENV TRAFFIC_LOG_DB=/app/data/waf_traffic.sqlite3
ENV WAF_AUTH_DB=/app/data/waf_auth.sqlite3

EXPOSE 8080

CMD ["uvicorn", "dashboard_app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
