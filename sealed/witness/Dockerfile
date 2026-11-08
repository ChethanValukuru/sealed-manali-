FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY witness.py ./

# Independent transparency-log witness. Runs as root ONLY to own its data volume;
# cap_drop ALL + no-new-privileges + read-only rootfs (compose) remove the
# privileges root would carry. Its Ed25519 key + state live in /data (gitignored).
ENV WITNESS_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8006

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://localhost:8006/health').status==200 else sys.exit(1)"

CMD ["uvicorn", "witness:app", "--host", "0.0.0.0", "--port", "8006"]
