#!/usr/bin/env bash
# Start the threat-modelling sandbox: mock Risk Assessment (+ offline NVD) on :5100 and the
# API on :5000. Used by the Codespaces devcontainer; works on any machine with Python 3.11+.
#
#   bash sandbox/start.sh            # live NVD/KEV/EPSS, Groq if GROQ_API_KEY is set
#   OFFLINE=1 bash sandbox/start.sh  # no internet needed: recorded NVD data, no KEV/EPSS/LLM
#   bash sandbox/start.sh stop
set -euo pipefail
cd "$(dirname "$0")/.."
RUN=sandbox/.run
mkdir -p "$RUN"

stop() {
  for p in api mock; do
    if [ -f "$RUN/$p.pid" ]; then kill "$(cat "$RUN/$p.pid")" 2>/dev/null || true; rm -f "$RUN/$p.pid"; fi
  done
}
if [ "${1:-}" = "stop" ]; then stop; echo "sandbox stopped"; exit 0; fi
stop

PY=$(command -v python3 || command -v python)

# Install dependencies if they are missing (e.g. the Codespace's postCreateCommand failed).
if ! "$PY" -c "import flask, gunicorn, requests, groq, jwt, flask_sqlalchemy" >/dev/null 2>&1; then
  echo "Installing Python dependencies (first run)..."
  "$PY" -m pip install -q -r requirements-dev.txt || {
    echo "pip install failed - see the errors above." >&2
    exit 1
  }
fi

if ! ls data/cwec_*.xml >/dev/null 2>&1; then
  echo "Downloading MITRE CWE/CAPEC catalogues..."
  "$PY" scripts/update_data.py --dest data || {
    echo "Download failed; using the small test catalogue (fewer CWE names/mitigations)."
    cp tests/fixtures/cwec_sample.xml data/cwec_sample.xml
    export CWEC_FILE_PATH=data/cwec_sample.xml
  }
fi

MOCK=http://127.0.0.1:5100
export RISK_ASSESSMENT_GET_TOPOLOGY_URL="$MOCK/ra/topologies/{topology_id}/assets"
export RISK_ASSESSMENT_GET_ASSET_URL="$MOCK/ra/assets/{asset_id}"
export SQLALCHEMY_DATABASE_URI="sqlite:///$PWD/$RUN/sandbox.db"
export AUTH_ENABLED=false
export LOG_LEVEL=${LOG_LEVEL:-INFO}
if [ -n "${GROQ_API_KEY:-}" ] && [ "${OFFLINE:-0}" != "1" ]; then
  export LLM_PROVIDER=groq
else
  export LLM_PROVIDER=none
fi
if [ "${OFFLINE:-0}" = "1" ]; then
  export NVD_API_URL="$MOCK/nvd/rest/json/cves/2.0" NVD_RATE_LIMIT=1000 KEV_ENABLED=false EPSS_ENABLED=false
fi

# setsid + nohup fully detach the servers: Codespaces kills processes left in the
# lifecycle command's session when postStartCommand returns.
setsid nohup "$PY" sandbox/mock_services.py --host 127.0.0.1 --port 5100 > "$RUN/mock.log" 2>&1 < /dev/null &
echo $! > "$RUN/mock.pid"
setsid nohup "$PY" -m gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 8 --timeout 600 run:app \
  > "$RUN/api.log" 2>&1 < /dev/null &
echo $! > "$RUN/api.pid"

for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1; then
    echo "Sandbox ready: http://localhost:5000/api/docs  (LLM: $LLM_PROVIDER, offline: ${OFFLINE:-0})"
    echo "Try: bash sandbox/demo.sh    Logs: $RUN/api.log"
    exit 0
  fi
  sleep 1
done
echo "API did not start; see $RUN/api.log" >&2
tail -n 30 "$RUN/api.log" >&2
exit 1
