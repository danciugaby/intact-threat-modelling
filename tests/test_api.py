import csv
import io
import json
import time
from unittest import mock

import jwt
import pytest
import responses
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import FakeGroq

CPE = "cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"


@pytest.fixture
def client(make_app):
    return make_app().test_client()


def test_root_and_health(client):
    assert client.get("/").data == b"Server is running!"
    h = client.get("/health").get_json()
    assert h["status"] == "ok" and h["cwe_version"] == "test-4.13" and h["llm"] == "disabled"


def test_analysis_legacy_cpeName_payload(client):
    r = client.post("/analysis", json={"device_data": {"cpeName": CPE, "deviceName": "Edge router"}})
    assert r.status_code == 200
    body = r.get_json()
    # legacy fields
    assert body["name"] == "Edge router" and body["cpe"] == CPE
    v = body["vulnerabilities"][0]
    for key in ("id", "name", "description", "cvss_vector", "cpes", "threats"):
        assert key in v
    t = v["threats"][0]
    assert {a["key"] for a in t["attributes"]} == {"capec", "mitigations"}
    assert "BENCHAMRK_COMPUTE_TIME" in body and "BENCHMARK_COMPUTE_TIME" in body
    # new fields
    assert v["id"] == "CVE-2023-20198" and v["risk"]["priority"] == "P1"
    assert body["metadata"]["search_method"] == "cpe"
    assert body["summary"]["known_exploited"][:2] == ["CVE-2023-20198", "CVE-2023-20273"]
    assert body["id"] >= 1  # persisted (the original never saved)


def test_analysis_limit_and_pilot(client):
    r = client.post("/analysis", json={"device_data": {"cpe": CPE}, "pilot": "nuclear", "limit": 2})
    body = r.get_json()
    assert len(body["vulnerabilities"]) == 2
    assert body["pilot"]["key"] == "nuclear"
    assert "IEC 62645" in body["summary"]["regulatory_references"]
    assert body["summary"]["not_analysed"] == 3


def test_unmapped_cve_is_kept(client):
    body = client.post("/analysis", json={"device_data": {"cpe": CPE}, "limit": 5}).get_json()
    v = next(v for v in body["vulnerabilities"] if v["id"] == "CVE-2024-00001")
    assert v["threats"][0]["cwe_id"] is None and v["threats"][0]["scenarios"]


def test_keyword_search_warns(client):
    body = client.post("/analysis", json={"device_data": {"deviceName": "Philips MRI"}}).get_json()
    assert body["metadata"]["search_method"] == "keyword" and "warning" in body["metadata"]


@pytest.mark.parametrize("payload,status", [
    ({}, 400),
    ({"device_data": {}}, 400),
    ({"device_data": {"cpe": "garbage"}}, 400),
    ({"device_data": {"cpe": CPE}, "pilot": "mars"}, 400),
])
def test_analysis_validation(client, payload, status):
    assert client.post("/analysis", json=payload).status_code == status


def test_async_job(client):
    r = client.post("/analysis?async=true", json={"device_data": {"cpe": CPE}})
    assert r.status_code == 202
    job_id = r.get_json()["job_id"]
    for _ in range(50):
        j = client.get(f"/jobs/{job_id}").get_json()
        if j["status"] in ("done", "failed"):
            break
        time.sleep(0.1)
    assert j["status"] == "done", j
    assert j["result"]["vulnerabilities"]


def test_listing_and_exports(client):
    client.post("/analysis", json={"device_data": {"cpe": CPE}, "pilot": "health"})
    lst = client.get("/threat-models?pilot=health").get_json()
    assert len(lst) == 1 and lst[0]["pilot"]["key"] == "health"
    one = client.get(f"/threat-models/by-id/{lst[0]['id']}").get_json()
    assert one["id"] == lst[0]["id"]
    rows = list(csv.reader(io.StringIO(client.get("/datasets/vulnerabilities").data.decode())))
    assert rows[0][0] == "CVE ID" and len(rows) == 6
    threats = client.get("/datasets/threats").data.decode()
    assert "ATT&CK Techniques" in threats
    assert client.get("/datasets/threat-models?limit=1").status_code == 200


def test_llm_scenarios_flow_through(make_app):
    def reply(kwargs):
        data = json.loads(kwargs["messages"][1]["content"].split("DATA:\n", 1)[1])
        cwe = data["weaknesses"][0]["cwe_id"] if data["weaknesses"] else None
        return json.dumps({"scenarios": [{"title": f"Scenario for {data['vulnerability']['id']}",
                                          "steps": ["x"], "cwe_ids": [cwe] if cwe else []}]})
    fake = FakeGroq(reply)
    c = make_app(llm_client=fake).test_client()
    body = c.post("/analysis", json={"device_data": {"cpe": CPE}, "limit": 3}).get_json()
    assert len(fake.chat.completions.calls) == 3  # one call per CVE, not per CWE
    t = body["vulnerabilities"][0]["threats"][0]
    assert t["scenarios"][0]["title"] == "Scenario for CVE-2023-20198"
    assert "Scenario for CVE-2023-20198" in t["description"]


# ------------------------------------------------------------------ Risk Assessment
RA = "https://ra.test"


@responses.activate
def test_topology_endpoint(make_app):
    app = make_app(RISK_ASSESSMENT_GET_TOPOLOGY_URL=f"{RA}/topologies/{{topology_id}}/assets",
                   RISK_ASSESSMENT_GET_ASSET_URL=f"{RA}/assets/{{asset_id}}",
                   RISK_ASSESSMENT_TOKEN="t0k")
    responses.add(responses.GET, f"{RA}/topologies/T1/assets", json={"content": [{"id": 1}, {"id": 2}, {"id": 3}]})
    responses.add(responses.GET, f"{RA}/assets/1", json={
        "id": 1, "name": "Edge router", "cpe23name": CPE,
        "attributes": [{"key": "internet_facing", "value": "true"}],
        "relationships": [{"relatedAsset": {"id": 2, "name": "Core switch"}, "relationshipType": {"id": "CONNECTED_TO"}}]})
    responses.add(responses.GET, f"{RA}/assets/2", json={
        "id": 2, "name": "Core switch", "attributes": [{"key": "CPE", "value": CPE}], "relationships": []})
    responses.add(responses.GET, f"{RA}/assets/3", status=500, body="boom secret stack")
    r = app.test_client().get("/threat-models/T1?pilot=telecom&limit=3")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert responses.calls[0].request.headers["Authorization"] == "Bearer t0k"
    res = body["results"]
    assert res[0]["asset_id"] == "1" and res[0]["pilot"]["key"] == "telecom"
    assert res[2]["error"] == "Failed to fetch asset"
    final = res[-1]
    assert isinstance(final["topology_analysis"], list) and final["topology_analysis"]
    assert final["attack_paths"][0]["assets"][0] == "Edge router (1)"
    assert final["summary"]["generated_by"] == "deterministic"
    assert "boom" not in r.data.decode()


@responses.activate
def test_asset_endpoint_and_upstream_errors(make_app):
    app = make_app(RISK_ASSESSMENT_GET_ASSET_URL=f"{RA}/assets")
    responses.add(responses.GET, f"{RA}/assets/7", json={"id": 7, "name": "Analyser",
                                                         "attributes": [{"key": "CPE", "value": CPE}]})
    responses.add(responses.GET, f"{RA}/assets/8", status=404)
    c = app.test_client()
    body = c.get("/analysis/asset/7?pilot=PUC2").get_json()
    assert body["asset_id"] == "7" and body["pilot"]["key"] == "health"
    assert c.get("/analysis/asset/8").status_code == 404


def test_topology_not_configured(client):
    assert client.get("/threat-models/abc").status_code == 503


# ------------------------------------------------------------------ auth
@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _token(key, **claims):
    base = {"iss": "https://kc.test/realms/intact", "exp": int(time.time()) + 300, "azp": "threat-modelling",
            "realm_access": {"roles": ["tm-user"]}}
    base.update(claims)
    return jwt.encode(base, key, algorithm="RS256")


def test_auth_enforced(make_app, rsa_key):
    app = make_app(AUTH_ENABLED=True, KEYCLOAK_SERVER_URL="https://kc.test", KEYCLOAK_REALM="intact",
                   KEYCLOAK_CLIENT_ID="threat-modelling", KEYCLOAK_REQUIRED_ROLE="tm-user")
    c = app.test_client()
    signing = type("K", (), {"key": rsa_key.public_key()})
    jwks = mock.Mock()
    jwks.get_signing_key_from_jwt.return_value = signing
    with mock.patch("app.auth._jwks", return_value=jwks):
        assert c.get("/threat-models").status_code == 401
        assert c.get("/threat-models", headers={"Authorization": "Bearer junk"}).status_code == 401
        good = {"Authorization": f"Bearer {_token(rsa_key)}"}
        assert c.get("/threat-models", headers=good).status_code == 200
        wrong_role = {"Authorization": f"Bearer {_token(rsa_key, realm_access={'roles': []})}"}
        assert c.get("/threat-models", headers=wrong_role).status_code == 403
        wrong_iss = {"Authorization": f"Bearer {_token(rsa_key, iss='https://evil')}"}
        assert c.get("/threat-models", headers=wrong_iss).status_code == 401
        expired = {"Authorization": f"Bearer {_token(rsa_key, exp=int(time.time()) - 10)}"}
        assert c.get("/threat-models", headers=expired).status_code == 401
    # health stays open for orchestrator probes
    assert c.get("/health").status_code == 200


def test_csv_formula_injection_neutralised():
    from app.models import _csv
    out = _csv(["a"], [("=HYPERLINK(\"http://x\")",)])
    assert "'=HYPERLINK" in out


def test_openapi_served(client):
    r = client.get("/api/openapi.yaml")
    assert r.status_code == 200 and b"INTACT Threat Modelling API" in r.data


def test_kafka_handler(make_app):
    import kafka_worker
    app = make_app()
    res = kafka_worker.handle(app, {"type": "device", "pilot": "transport",
                                    "device_data": {"cpeName": CPE, "deviceName": "OTA gateway"}})
    assert res["pilot"]["key"] == "transport" and "UNECE R156 (SUMS)" in res["summary"]["regulatory_references"]
    with pytest.raises(ValueError):
        kafka_worker.handle(app, {"type": "nope"})


def test_bad_limit_is_400(client):
    assert client.post("/analysis", json={"device_data": {"cpe": CPE}, "limit": "lots"}).status_code == 400
