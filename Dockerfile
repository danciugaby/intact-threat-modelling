FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY data ./data
COPY scripts ./scripts
COPY run.py kafka_worker.py ./

# Download the latest MITRE CWE + CAPEC catalogues at build time (not committed to git).
# If data/ already contains cwec_*.xml (offline builds), pass --build-arg FETCH_DATA=0.
ARG FETCH_DATA=1
RUN if [ "$FETCH_DATA" = "1" ]; then python scripts/update_data.py --dest data; fi \
 && ls data/cwec_*.xml > /dev/null

RUN useradd --uid 10001 --no-create-home appuser && chown -R appuser /app/data
USER appuser

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4).status==200 else 1)"

# Threads, not processes: the CWE/CAPEC indexes are loaded once per worker process.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "8", "--timeout", "600", "run:app"]
