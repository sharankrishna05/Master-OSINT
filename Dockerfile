FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARSENAL_HOST=0.0.0.0 \
    ARSENAL_PORT=8080 \
    ARSENAL_DATA_DIR=/app/data \
    ARSENAL_REPORTS_DIR=/app/reports \
    ARSENAL_LOGS_DIR=/app/logs

RUN apt-get update && apt-get install -y --no-install-recommends \
        whois traceroute dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /app/data /app/reports /app/logs /app/plugins \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.getenv('PORT') or os.getenv('ARSENAL_PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=4)"

CMD ["python", "-m", "osint_arsenal", "serve"]
