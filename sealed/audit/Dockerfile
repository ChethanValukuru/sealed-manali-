FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY chain.py log.py verify.py tamper_demo.py ./

# Audit runs as root ONLY to own the data volume; cap_drop ALL + no-new-privileges
# + read-only rootfs (compose) remove the privileges that root would otherwise
# carry. Keys + log live in the /data volume (gitignored, not in the image).
ENV AUDIT_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://localhost:8001/health').status==200 else sys.exit(1)"

CMD ["uvicorn", "log:app", "--host", "0.0.0.0", "--port", "8001"]
