FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt requirements-kafka.txt ./
RUN pip install -r requirements.txt -r requirements-kafka.txt

COPY app ./app
COPY data ./data
COPY scripts ./scripts
COPY run.py kafka_worker.py ./

# Download the latest MITRE CWE + CAPEC catalogues at build time (not committed to git).
# If data/ already contains cwec_*.xml (offline builds), pass --build-arg FETCH_DATA=0.
ARG FETCH_DATA=1
RUN if [ "$FETCH_DATA" = "1" ]; then python scripts/update_data.py --dest data; fi \
 && ls data/cwec_*.xml > /dev/null

# a home directory: gunicorn's control server needs a writable place for its socket
RUN useradd --uid 10001 --create-home appuser && chown -R appuser /app/data
USER appuser

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4).status==200 else 1)"

# One process, many threads: the work is I/O-bound, the CWE/CAPEC indexes, caches, async jobs
# and the NVD rate limiter are per process, so one process keeps NVD within its limit.
# Scale with more containers and split NVD_RATE_LIMIT between them (and the Kafka worker).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "16", "--timeout", "600", "run:app"]
