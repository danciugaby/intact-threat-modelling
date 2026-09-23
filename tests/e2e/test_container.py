"""End-to-end tests against the running container (docker-compose.e2e.yml).

    E2E_BASE_URL=http://localhost:5000 pytest -m e2e tests/e2e
"""

import os
import time

import pytest
import requests

pytestmark = pytest.mark.e2e
BASE = os.getenv("E2E_BASE_URL", "http://localhost:5000")
CPE = "cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"


def _get(path, **kw):
    return requests.get(BASE + path, timeout=60, **kw)


def _post(path, **kw):
    return requests.post(BASE + path, timeout=120, **kw)


def test_health_and_headers():
    r = _get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.json()["cwe_version"]  # real MITRE catalogue downloaded at build time
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in r.headers  # CORS off by default


def test_docs_served():
    assert _get("/api/openapi.yaml").status_code == 200
    assert _get("/api/docs").status_code == 200


def test_device_analysis_and_persistence():
    r = _post("/analysis", json={"device_data": {"cpeName": CPE, "deviceName": "e2e router"}, "pilot": "health"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vulnerabilities"][0]["risk"]["priority"] == "P1"
    assert body["vulnerabilities"][0]["threats"][0]["mitigations"]  # real CWE data
    assert _get(f"/threat-models/by-id/{body['id']}").json()["name"] == "e2e router"
    csv = _get("/datasets/vulnerabilities").text
    assert csv.startswith("CVE ID,")


def test_validation_errors():
    assert _post("/analysis", json={"device_data": {"cpe": "nope"}}).status_code == 400
    assert _post("/analysis", data="not json").status_code == 400


@pytest.mark.parametrize("pilot", ["health", "telecom", "transport", "nuclear", "smart_city"])
def test_topology_async_per_pilot(pilot):
    r = _get(f"/topologies/{pilot}/analysis", params={"pilot": pilot, "limit": 2, "async": "true"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    deadline = time.time() + 180
    while time.time() < deadline:
        job = _get(f"/jobs/{job_id}").json()
        if job["status"] in ("done", "failed"):
            break
        time.sleep(1)
    assert job["status"] == "done", job
    final = job["result"]["results"][-1]
    assert final["entry_points"], final
    assert final["attack_paths"], final
    assert job["result"]["pilot"] == pilot


def test_unknown_topology_is_404():
    assert _get("/topologies/does-not-exist/analysis").status_code == 404
