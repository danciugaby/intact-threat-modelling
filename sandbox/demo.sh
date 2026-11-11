#!/usr/bin/env bash
# Walk through the main API features against a running sandbox (bash sandbox/start.sh).
set -euo pipefail
API=${API:-http://127.0.0.1:5000}
PILOT=${1:-health}
j() { python -m json.tool --no-ensure-ascii; }

# Start the sandbox if it isn't running (e.g. after a Codespace restart).
if ! curl -fsS "$API/health" >/dev/null 2>&1; then
  echo "API not running on $API - starting the sandbox..."
  bash "$(dirname "$0")/start.sh"
fi

echo "== Health";  curl -fsS "$API/health" | j
echo "== Pilots";  curl -fsS "$API/pilots" | python -c 'import json,sys; [print(" ", p["key"], "-", p["name"]) for p in json.load(sys.stdin)]'

echo "== Device threat model (Cisco IOS XE, pilot=$PILOT)"
curl -fsS -X POST "$API/analysis" -H 'content-type: application/json' \
  -d "{\"device_data\": {\"cpe\": \"cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*\", \"deviceName\": \"Edge router\"}, \"pilot\": \"$PILOT\", \"limit\": 3}" \
  | python -c '
import json, sys
m = json.load(sys.stdin)
print("  selected", m["metadata"]["cves_selected"], "of", m["metadata"]["cves_found"], "CVEs; LLM:", m["metadata"]["llm"]["provider"])
for v in m["vulnerabilities"]:
    r = v["risk"]
    print("  %s %5.1f  %s  KEV=%s  %s" % (r["priority"], r["score"], v["id"], r["known_exploited"], r["attack_vector"]))
print("  standards:", ", ".join(m["summary"]["regulatory_references"]))'

echo "== Topology analysis (demo topology '$PILOT', async job)"
JOB=$(curl -fsS "$API/topologies/$PILOT/analysis?pilot=$PILOT&limit=3&async=true" | python -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
echo "  job $JOB"
for _ in $(seq 1 120); do
  STATUS=$(curl -fsS "$API/jobs/$JOB" | python -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  [ "$STATUS" = done ] || [ "$STATUS" = failed ] && break
  sleep 2
done
curl -fsS "$API/jobs/$JOB" | python -c '
import json, sys
j = json.load(sys.stdin)
if j["status"] != "done":
    sys.exit("  job " + j["status"] + ": " + j.get("error", ""))
final = j["result"]["results"][-1]
print("  entry points:", [e["asset"] for e in final["entry_points"]])
for p in final["attack_paths"][:5]:
    print("  path", round(p["path_score"], 1), ":", " -> ".join(p["assets"]))
print("  choke points:", [c["asset"] for c in final["choke_points"][:3]])
print("  summary:", final["summary"]["summary"])'

echo "== CSV export (first lines)"
curl -fsS "$API/datasets/vulnerabilities?limit=3" | head -n 4
