"""Tests for the November 2026 review fixes: CVE selection, scoring, topology model,
Risk Assessment integration, async jobs, per-pilot access, Kafka worker and LLM redaction."""
import json
import time
from datetime import datetime, timedelta, timezone
from unittest import mock

import jwt
import pytest
import responses
from cryptography.hazmat.primitives.asymmetric import rsa

from app.engine import topology as topo
from app.engine.llm import ScenarioGenerator, cpe_product
from app.engine.nvd import CveRecord, CvssMetric, NvdClient
from app.engine.pilots import get_pilot
from app.engine.risk import exploitability_proxy, score_cve
from app.risk_assessment import RiskAssessmentClient
from conftest import FakeGroq

CPE = "cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"
RA = "https://ra.test/api"


# ------------------------------------------------------------------ NVD selection
def _item(i, rejected=False):
    base = datetime(2000, 1, 1)
    return {"cve": {"id": f"CVE-T-{i}", "published": (base + timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "vulnStatus": "Rejected" if rejected else "Analyzed",
                    "descriptions": [{"lang": "en", "value": "x"}]}}


class _Resp:
    status_code = 200

    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class _NvdSession:
    """Serves ``total`` CVEs oldest first; the hasKev query returns CVE-T-3 and CVE-T-7."""

    def __init__(self, total, rejected=()):
        self.total, self.rejected, self.calls = total, set(rejected), []

    def get(self, url, params=None, **_):
        self.calls.append((url, dict(params)))
        if "hasKev" in url:
            items = [_item(3), _item(7)]
            return _Resp({"totalResults": 2, "vulnerabilities": items[params["startIndex"]:]})
        s, n = params["startIndex"], params["resultsPerPage"]
        return _Resp({"totalResults": self.total,
                      "vulnerabilities": [_item(i, i in self.rejected) for i in range(s, min(s + n, self.total))]})


def test_nvd_keeps_newest_window_plus_kev_when_truncated():
    sess = _NvdSession(5000)
    res = NvdClient("http://nvd", api_key="k", max_results=1000, session=sess, rate_limit=10_000) \
        .search_by_keyword("linux")
    ids = {c.id for c in res}
    assert res.truncated and res.total == 5000
    assert "CVE-T-4999" in ids and "CVE-T-4000" in ids and "CVE-T-3999" not in ids  # newest 1000
    assert {"CVE-T-3", "CVE-T-7"} <= ids  # old but known-exploited
    assert len(res) == 1002
    assert any("hasKev" in url for url, _ in sess.calls)


def test_nvd_paging_counts_rejected_records():
    sess = _NvdSession(4500, rejected=range(0, 2000))
    res = NvdClient("http://nvd", max_results=5000, session=sess, rate_limit=10_000).search_by_keyword("x")
    assert not res.truncated and len(res) == 2500
    assert [p["startIndex"] for _, p in sess.calls] == [0, 2000, 4000]


def test_modeler_warns_when_nvd_result_truncated(make_app):
    from app.engine.nvd import CveList, parse_cve

    app = make_app()
    tm = app.extensions["threat_modeler"]
    page = tm.nvd.page
    with mock.patch.object(tm.nvd, "search_by_cpe",
                           return_value=CveList.of([parse_cve(v) for v in page["vulnerabilities"]], 9000, True)):
        model = tm.get_threat_model({"cpe": CPE})
    assert model["metadata"]["nvd_total_results"] == 9000
    assert "newest" in model["metadata"]["warning"]
    assert model["exploitability_by_vector"]


# ------------------------------------------------------------------ scoring
def _cve(*metrics):
    return CveRecord(id="CVE-X", published=datetime.now(timezone.utc), description="", cvss=list(metrics))


V31 = CvssMetric("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", exploitability=3.9)
V40 = CvssMetric("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "CRITICAL")


def test_cvss_v4_does_not_lower_the_exploit_proxy():
    pilot = get_pilot("health")
    only_v31 = score_cve(_cve(V31), pilot)
    with_v4 = score_cve(_cve(V40, V31), pilot)
    assert with_v4["components"]["exploit"] == only_v31["components"]["exploit"] == 0.5
    assert exploitability_proxy(_cve(V40)) == pytest.approx(1.0, abs=0.01)
    hard = CvssMetric("4.0", "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.0, "MEDIUM")
    assert exploitability_proxy(_cve(hard)) < 0.1


def test_cvss_v2_exploitability_is_rescaled():
    v2 = CvssMetric("2.0", "AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8, "MEDIUM", exploitability=8.6)
    assert exploitability_proxy(_cve(v2)) == pytest.approx(0.86)


# ------------------------------------------------------------------ topology model
def _v(id, av="network", score=80, kev=False):
    return {"id": id, "attack_vector": av, "score": score, "known_exploited": kev, "epss_percentile": 0.5}


def _graph(switch_attrs=None, switch_assessed=True):
    return {
        "web": {"name": "web", "attributes": {"internet_facing": "true"}, "vulnerabilities": [_v("CVE-W")],
                "relationships": [{"target_id": "sw", "type": "CONNECTED_TO"}]},
        "sw": {"name": "switch", "attributes": switch_attrs or {}, "vulnerabilities": [], "assessed": switch_assessed,
               "relationships": [{"target_id": "plc", "type": "CONNECTED_TO"}]},
        "plc": {"name": "plc", "attributes": {"criticality": "high"}, "vulnerabilities": [_v("CVE-P")],
                "relationships": [{"target_id": "sensor", "type": "MANAGES"}]},
        "sensor": {"name": "sensor", "attributes": {"safety_critical": "true"}, "vulnerabilities": [],
                   "assessed": False, "relationships": []},
    }


def test_analysed_asset_without_usable_cve_blocks_the_path():
    assert topo.analyze(_graph())["attack_paths"] == []


def test_asset_without_vulnerability_data_is_reachable_but_flagged():
    r = topo.analyze(_graph(switch_assessed=False))
    (p,) = r["attack_paths"]
    assert p["target_id"] == "sw" and p["steps"][-1]["kind"] == "unassessed"
    assert p["outcome"].startswith("reachable") and "switch (sw)" in r["unassessed_assets"]


def test_transit_asset_relays_and_control_relationship_propagates_impact():
    r = topo.analyze(_graph({"asset_type": "switch"}, switch_assessed=False))
    by_target = {p["target_id"]: p for p in r["attack_paths"]}
    assert [s["kind"] for s in by_target["sensor"]["steps"]] == ["transit", "exploit", "impact"]
    assert by_target["sensor"]["target_impact"] == 1.0  # safety_critical
    assert by_target["plc"]["target_impact"] == 0.75  # criticality=high
    assert "sw" not in by_target  # transit assets are not targets
    reach = {x["asset_id"]: x for x in r["reachable_assets"]}
    assert reach["sensor"]["safety_critical"] and reach["sensor"]["outcome"] == "affected via MANAGES"
    chokes = [c["asset_id"] for c in r["choke_points"]]
    assert "web" not in chokes and chokes[0] == "sw"


def test_depends_on_propagates_impact_backwards():
    assets = {
        "edge": {"name": "edge", "attributes": {"exposed": "yes"}, "vulnerabilities": [_v("CVE-E")],
                 "relationships": [{"target_id": "db", "type": "CONNECTED_TO"}]},
        "db": {"name": "db", "vulnerabilities": [_v("CVE-D")], "relationships": []},
        "app": {"name": "app", "vulnerabilities": [_v("CVE-L", av="local")],
                "relationships": [{"target_id": "db", "type": "DEPENDS_ON"}]},
    }
    by_target = {p["target_id"]: p for p in topo.analyze(assets)["attack_paths"]}
    assert by_target["app"]["steps"][-1]["kind"] == "impact"  # db compromised => app affected


def test_exploit_summary_beyond_top_limit_enables_lateral_step():
    assets = {
        "a": {"name": "a", "attributes": {"exposed": "true"}, "vulnerabilities": [_v("CVE-A")],
              "relationships": [{"target_id": "b", "type": "CONNECTED_TO"}]},
        "b": {"name": "b", "vulnerabilities": [_v("CVE-B-LOCAL", av="local")],
              "exploit_summary": {"network": _v("CVE-B-NET", score=40)}, "relationships": []},
    }
    (p,) = topo.analyze(assets)["attack_paths"]
    assert p["steps"][0]["vulnerability_id"] == "CVE-B-NET"


def test_relationship_type_spelling_is_normalised():
    assert topo.channel_for("connected-to") == ("network", True)
    assert topo.channel_for("Runs On") == ("local", True)


# ------------------------------------------------------------------ Risk Assessment integration
def test_ra_topology_accepts_bare_list_and_metadata():
    ra = RiskAssessmentClient({"RISK_ASSESSMENT_GET_TOPOLOGY_URL": f"{RA}/t/{{topology_id}}"})
    with mock.patch.object(ra, "_get", return_value=[{"id": 1}, "2"]):
        assert ra.get_topology_info("x") == ([{"id": 1}, {"id": "2"}], {})
    with mock.patch.object(ra, "_get", return_value={"id": "x", "pilot": "nuclear", "content": [{"id": "a"}]}):
        assert ra.get_topology_info("x") == ([{"id": "a"}], {"id": "x", "pilot": "nuclear"})


@responses.activate
def test_topology_pilot_comes_from_risk_assessment(make_app):
    app = make_app(RISK_ASSESSMENT_GET_TOPOLOGY_URL=f"{RA}/topologies/{{topology_id}}/assets",
                   RISK_ASSESSMENT_GET_ASSET_URL=f"{RA}/assets/{{asset_id}}")
    responses.add(responses.GET, f"{RA}/topologies/N1/assets",
                  json={"id": "N1", "pilot": "PUC4", "content": [{"id": "gw"}, {"id": "s"}]})
    responses.add(responses.GET, f"{RA}/assets/gw", json={
        "id": "gw", "name": "Gateway", "cpe23name": CPE, "attributes": [{"key": "exposed", "value": True}],
        "relationships": [{"relatedAsset": {"id": "s"}, "relationshipType": "CONNECTED_TO"}]})
    responses.add(responses.GET, f"{RA}/assets/s", json={
        "id": "s", "name": "Sensor", "attributes": [{"key": "safety_critical", "value": True}], "relationships": []})
    body = app.test_client().get("/topologies/N1/analysis").get_json()
    assert body["pilot"] == "nuclear"
    final = body["results"][-1]
    assert final["unassessed_assets"] == ["Sensor (s)"]
    assert any(x["asset_id"] == "s" and x["safety_critical"] for x in final["reachable_assets"])


def test_offset_is_not_capped_at_1000(make_app):
    from app.models import ThreatModelRecord

    c = make_app().test_client()
    with mock.patch.object(ThreatModelRecord, "page", return_value=[]) as page:
        assert c.get("/threat-models?offset=5000").status_code == 200
    assert page.call_args.kwargs["offset"] == 5000


# ------------------------------------------------------------------ async jobs
def test_job_queue_is_capped(make_app):
    app = make_app(JOB_MAX_PENDING=1)
    c = app.test_client()
    runner = app.extensions["job_runner"]
    gate = mock.MagicMock()
    with mock.patch.object(runner.pool, "submit", gate):  # nothing runs, so the job stays pending
        assert c.post("/analysis?async=true", json={"device_data": {"cpe": CPE}}).status_code == 202
        r = c.post("/analysis?async=true", json={"device_data": {"cpe": CPE}})
    assert r.status_code == 429 and r.headers["Retry-After"]


def test_stale_job_is_reported_failed(make_app):
    from app.models import Job, db

    app = make_app(JOB_TIMEOUT_SECONDS=60)
    with app.app_context():
        job = Job(kind="device", request={}, status="running",
                  created_at=datetime.now(timezone.utc) - timedelta(hours=2))
        db.session.add(job)
        db.session.commit()
        job_id = job.id
    body = app.test_client().get(f"/jobs/{job_id}").get_json()
    assert body["status"] == "failed" and "restarted" in body["error"]


# ------------------------------------------------------------------ per-pilot access
@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _auth(key, roles):
    claims = {"iss": "https://kc.test/realms/intact", "exp": int(time.time()) + 300, "azp": "tm",
              "realm_access": {"roles": roles}}
    return {"Authorization": "Bearer " + jwt.encode(claims, key, algorithm="RS256")}


def test_pilot_roles_restrict_analysis_and_stored_data(make_app, rsa_key):
    app = make_app(AUTH_ENABLED=True, KEYCLOAK_SERVER_URL="https://kc.test", KEYCLOAK_REALM="intact",
                   KEYCLOAK_CLIENT_ID="tm", PILOT_ROLE_PREFIX="pilot:")
    c = app.test_client()
    jwks = mock.Mock()
    jwks.get_signing_key_from_jwt.return_value = type("K", (), {"key": rsa_key.public_key()})
    health, admin = _auth(rsa_key, ["pilot:health"]), _auth(rsa_key, ["pilot:all"])
    with mock.patch("app.auth._jwks", return_value=jwks):
        assert c.post("/analysis", json={"device_data": {"cpe": CPE}, "pilot": "nuclear"}, headers=health).status_code == 403
        own = c.post("/analysis", json={"device_data": {"cpe": CPE}, "pilot": "PUC2"}, headers=health)
        assert own.status_code == 200
        other = c.post("/analysis", json={"device_data": {"cpe": CPE}, "pilot": "nuclear"}, headers=admin).get_json()
        listed = {m["pilot"]["key"] for m in c.get("/threat-models", headers=health).get_json()}
        assert listed == {"health"}
        assert c.get(f"/threat-models/by-id/{other['id']}", headers=health).status_code == 404
        assert c.get(f"/threat-models/by-id/{other['id']}", headers=admin).status_code == 200
        csv_rows = c.get("/datasets/threat-models", headers=health).data.decode().strip().splitlines()
        assert len(csv_rows) == 2 and "nuclear" not in csv_rows[1]
        job = c.post("/analysis?async=true", json={"device_data": {"cpe": CPE}, "pilot": "nuclear"},
                     headers=admin).get_json()
        assert c.get(f"/jobs/{job['job_id']}", headers=health).status_code == 404


# ------------------------------------------------------------------ Kafka worker
class _Msg:
    def __init__(self, value, key=b"k"):
        self._v, self._k = value, key

    def value(self):
        return self._v

    def key(self):
        return self._k

    def error(self):
        return None

    def topic(self):
        return "req"

    def partition(self):
        return 0

    def offset(self):
        return 42


def _run_worker(kafka_worker, app, msgs, producer):
    consumer = mock.Mock()

    def poll(_):
        if msgs:
            return msgs.pop(0)
        kafka_worker.RUNNING = False
        return None

    consumer.poll.side_effect = poll
    kafka_worker.RUNNING = True
    with (mock.patch.object(kafka_worker, "create_app", return_value=app),
          mock.patch.object(kafka_worker, "Consumer", return_value=consumer),
          mock.patch.object(kafka_worker, "Producer", return_value=producer),
          mock.patch.object(kafka_worker.signal, "signal"),
          mock.patch.object(kafka_worker.time, "sleep")):
        kafka_worker.consume()
    return consumer


def test_kafka_retries_transient_failures(make_app):
    import kafka_worker
    from app.engine.http import UpstreamError

    app = make_app(KAFKA_MAX_ATTEMPTS=3)
    producer = mock.Mock()
    producer.flush.return_value = 0
    real = kafka_worker.handle
    calls = {"n": 0}

    def flaky(a, payload):
        calls["n"] += 1
        if calls["n"] < 3:
            raise UpstreamError("NVD down")
        return real(a, payload)

    with mock.patch.object(kafka_worker, "handle", side_effect=flaky):
        consumer = _run_worker(kafka_worker, app, [_Msg(json.dumps({"device_data": {"cpe": CPE}}).encode())], producer)
    out = json.loads(producer.produce.call_args.kwargs["value"])
    assert out["status"] == "done" and out["attempts"] == 3
    assert consumer.commit.call_count == 1


def test_kafka_does_not_commit_undelivered_results(make_app):
    import kafka_worker

    producer = mock.Mock()
    producer.flush.return_value = 1  # still queued: not delivered
    consumer = _run_worker(kafka_worker, make_app(), [_Msg(b"not json")], producer)
    consumer.commit.assert_not_called()
    assert consumer.seek.call_args.args[0].offset == 42


def test_kafka_client_config_supports_sasl():
    import kafka_worker

    conf = kafka_worker.client_config({"KAFKA_BOOTSTRAP_SERVERS": "b:9093", "KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
                                       "KAFKA_SASL_MECHANISM": "SCRAM-SHA-512", "KAFKA_SASL_USERNAME": "u",
                                       "KAFKA_SASL_PASSWORD": "p"}, **{"group.id": "g"})
    assert conf == {"bootstrap.servers": "b:9093", "security.protocol": "SASL_SSL", "sasl.mechanism": "SCRAM-SHA-512",
                    "sasl.username": "u", "sasl.password": "p", "group.id": "g"}


# ------------------------------------------------------------------ LLM redaction
def test_redaction_keeps_asset_identity_out_of_llm_prompts(make_app):
    groq = FakeGroq(json.dumps({"scenarios": [{"title": "t"}], "summary": "s"}))
    app = make_app(llm_client=groq)
    tm = app.extensions["threat_modeler"]
    tm.llm.redact = True
    tm.get_threat_model({"cpe": CPE, "deviceName": "Reactor-7 radiation gateway", "location": "Hall B"}, limit=1)
    tm.analyze_topology({"g": {"name": "Reactor-7 radiation gateway", "attributes": {"exposed": "true"},
                               "relationships": [], "threat_model": None}})
    sent = " ".join(m["content"] for call in groq.chat.completions.calls for m in call["messages"])
    assert "Reactor-7" not in sent and "Hall B" not in sent
    assert "cisco ios xe 16.12.4" in sent
    assert cpe_product("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*") == "apache http server"


def test_no_redaction_by_default():
    assert ScenarioGenerator(provider="none").redact is False
