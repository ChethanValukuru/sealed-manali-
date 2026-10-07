FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY monitor.py .

# Phase 2-style hardening; compose adds cap_drop ALL, no-new-privileges, read_only.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
RUN useradd -u 10001 -m -d /home/appuser appuser
USER 10001
EXPOSE 8005

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://localhost:8005/health').status==200 else sys.exit(1)"

CMD ["uvicorn", "monitor:app", "--host", "0.0.0.0", "--port", "8005"]
