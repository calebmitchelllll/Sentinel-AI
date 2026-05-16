FROM python:3.11-slim

WORKDIR /app

# python:3.11-slim already ships ca-certificates for pip TLS; no apt needed.

COPY services/requirements.txt /app/services/requirements.txt
RUN pip install --no-cache-dir -r /app/services/requirements.txt

COPY services /app/services

ENV PORT=8000 PYTHONUNBUFFERED=1
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8000/health', timeout=3); sys.exit(0)" || exit 1

CMD ["uvicorn", "services.nemoclaw_runner:app", "--host", "0.0.0.0", "--port", "8000"]
