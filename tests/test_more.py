"""Additional unit tests: data-source clients, failure paths, contract checks, Kafka loop."""

import json
import os
import time
from unittest import mock

import pytest
import responses
import yaml

from app.engine import topology as topo
from app.engine.exploitability import EpssClient, KevFeed
from app.engine.http import RateLimiter, TTLCache, UpstreamError, get_json
from app.engine.nvd import filter_by_age, parse_cve
from app.engine.pilots import get_pilot, list_pilots
from app.engine.risk import score_cve
from app.risk_assessment import RiskAssessmentClient, RiskAssessmentError

KEV = "https://kev.test/feed.json"
EPSS = "https://epss.test/v1/epss"
CPE = "cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ http helpers
def test_ttl_cache_expiry_and_eviction():
    c = TTLCache(ttl_seconds=0.05, max_items=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)  # evicts one entry
    assert len([k for k in "abc" if c.get(k) is not None]) == 2
    time.sleep(0.06)
    assert c.get("c") is None


def test_rate_limiter_blocks_when_full():
    rl = RateLimiter(max_calls=2, period=0.2)
    start = time.monotonic()
    for _ in range(3):
        rl.acquire()
    assert time.monotonic() - start >= 0.15


@responses.activate
def test_get_json_404_and_non_retryable():
    import requests

    responses.add(responses.GET, "https://x.test/404", status=404)
    responses.add(responses.GET, "https://x.test/400", status=400)
    s = requests.Session()
    assert get_json(s, "https://x.test/404") is None
    with pytest.raises(UpstreamError):
        get_json(s, "https://x.test/400")
    assert len(responses.calls) == 2  # 400 is not retried


@responses.activate
def test_get_json_retries_network_errors():
    import requests

    responses.add(responses.GET, "https://x.test/a", body=requests.ConnectionError("boom"))
    responses.add(responses.GET, "https://x.test/a", json={"ok": True})
    with mock.patch("app.engine.http.time.sleep"):
        assert get_json(requests.Session(), "https://x.test/a") == {"ok": True}


# ------------------------------------------------------------------ KEV / EPSS
@responses.activate
def test_kev_feed_lookup_and_cache():
    responses.add(
        responses.GET,
        KEV,
        json={
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-20198",
                    "dateAdded": "2023-10-16",
                    "dueDate": "2023-10-20",
                    "requiredAction": "Patch",
                    "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ]
        },
    )
    feed = KevFeed(KEV)
    assert feed.lookup("CVE-2023-20198")["name"].startswith("Cisco")
    assert feed.lookup("CVE-0000-0000") is None
    assert feed.available is True and len(responses.calls) == 1


@responses.activate
def test_kev_feed_unavailable_fails_soft():
    responses.add(responses.GET, KEV, status=503)
    feed = KevFeed(KEV)
    with mock.patch("app.engine.http.time.sleep"):
        assert feed.lookup("CVE-2023-20198") is None
    assert feed.available is False


@responses.activate
def test_epss_batches_and_caches():
    responses.add(
        responses.GET,
        EPSS,
        json={
            "data": [
                {"cve": "CVE-1", "epss": "0.9", "percentile": "0.99"},
                {"cve": "CVE-2", "epss": "bad"},
            ]
        },
    )
    client = EpssClient(EPSS)
    assert client.scores(["CVE-1", "CVE-2"]) == {"CVE-1": (0.9, 0.99)}
    assert client.scores(["CVE-1"]) == {"CVE-1": (0.9, 0.99)}
    assert len(responses.calls) == 1
    assert "cve=CVE-1%2CCVE-2" in responses.calls[0].request.url


@responses.activate
def test_epss_unavailable_fails_soft():
    responses.add(responses.GET, EPSS, status=500)
    client = EpssClient(EPSS)
    with mock.patch("app.engine.http.time.sleep"):
        assert client.scores(["CVE-1"]) == {}
    assert client.available is False


def test_epss_and_kev_feed_into_ranking(make_app, nvd_page):
    """KEV/EPSS signals flow through ThreatModeler._enrich into the risk score."""
    app = make_app()
    tm = app.extensions["threat_modeler"]
    tm.kev = mock.Mock(available=True)
    tm.kev.lookup.side_effect = lambda cid: {"name": "KEV name", "known_ransomware_use": "Known"} if cid == "CVE-2023-44487" else None
    tm.epss = mock.Mock(available=True)
    tm.epss.scores.return_value = {"CVE-2023-20097": (0.5, 0.97)}
    with app.app_context():
        m = tm.get_threat_model({"cpe": CPE}, limit=5)
    by_id = {v["id"]: v for v in m["vulnerabilities"]}
    assert by_id["CVE-2023-44487"]["risk"]["known_exploited"] is True
    assert by_id["CVE-2023-44487"]["name"] == "KEV name"
    assert by_id["CVE-2023-20097"]["risk"]["epss_percentile"] == 0.97
    assert m["metadata"]["sources"]["kev"] == "ok" and m["metadata"]["sources"]["epss"] == "ok"


# ------------------------------------------------------------------ risk / nvd edges
def test_score_without_cvss_or_signals():
    cve = parse_cve({"cve": {"id": "CVE-X", "published": "2025-01-01T00:00:00", "descriptions": []}})
    r = score_cve(cve, get_pilot("generic"))
    assert r["cvss"] is None and r["attack_vector"] is None
    assert r["components"]["severity"] == 0.5 and r["priority"] in ("P3", "P4")


def test_cvss_v2_vectors_are_understood():
    item = {
        "cve": {
            "id": "CVE-OLD",
            "published": "2010-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "old"}],
            "metrics": {
                "cvssMetricV2": [
                    {
                        "type": "Primary",
                        "baseSeverity": "HIGH",
                        "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 10.0},
                    }
                ]
            },
        }
    }
    r = score_cve(parse_cve(item), get_pilot("nuclear"))
    assert r["attack_vector"] == "network" and r["cia_impact"] == {"C": 1.0, "I": 1.0, "A": 1.0}
    assert r["safety_relevant"] is True


def test_filter_by_age(nvd_page):
    cves = [parse_cve(v) for v in nvd_page["vulnerabilities"]]
    assert filter_by_age(cves, 0) == cves
    assert filter_by_age(cves, 1) == []  # fixtures are from 2023/2024


def test_list_pilots_is_complete():
    keys = {p["key"] for p in list_pilots()}
    assert keys == {"telecom", "health", "transport", "nuclear", "smart_city", "generic"}
    for p in list_pilots():
        assert abs(sum(p["cia_weights"].values()) - 1) < 1e-6, p["key"]


# ------------------------------------------------------------------ topology edges
def test_topology_cycles_and_budget():
    # fully connected ring: DFS must terminate and respect max_paths
    assets = {
        str(i): {
            "name": f"N{i}",
            "attributes": {"exposed": "true"} if i == 0 else {},
            "vulnerabilities": [{"id": f"CVE-{i}", "attack_vector": "network", "score": 70}],
            "relationships": [{"target_id": str(j), "type": "CONNECTED_TO"} for j in range(8) if j != i],
        }
        for i in range(8)
    }
    r = topo.analyze(assets, max_depth=6, max_paths=10)
    assert len(r["attack_paths"]) == 10
    for p in r["attack_paths"]:
        assert len(p["assets"]) == len(set(p["assets"]))  # simple paths only


def test_topology_unknown_relationship_is_directed_network():
    assert topo.channel_for("SOMETHING_NEW") == ("network", False)
    assert topo.channel_for(None) == ("network", False)
    assert topo.channel_for("hosts") == ("local", True)


# ------------------------------------------------------------------ Risk Assessment client
def test_ra_url_templates_are_escaped():
    url = RiskAssessmentClient._fill("https://ra/assets/{asset_id}", asset_id="../x y")
    assert url == "https://ra/assets/..%2Fx%20y"
    assert RiskAssessmentClient._fill("https://ra/assets/", asset_id=5) == "https://ra/assets/5"


@responses.activate
def test_ra_client_errors():
    import requests

    responses.add(responses.GET, "https://ra.test/assets/1", body=requests.ConnectionError("down"))
    ra = RiskAssessmentClient({"RISK_ASSESSMENT_GET_ASSET_URL": "https://ra.test/assets/{asset_id}"})
    with pytest.raises(RiskAssessmentError) as e:
        ra.get_asset("1")
    assert e.value.status == 502
    with pytest.raises(RiskAssessmentError) as e:
        RiskAssessmentClient({}).get_topology("t")
    assert e.value.status == 503


def test_ra_asset_mapping():
    device, attrs = RiskAssessmentClient.asset_to_device(
        {"name": "PACS", "attributes": [{"key": "cpe", "value": CPE}, {"key": "internet_facing", "value": "true"}, "junk"]}
    )
    assert device == {"deviceName": "PACS", "cpe": CPE} and attrs["internet_facing"] == "true"
    rels = RiskAssessmentClient.relationships(
        {"relationships": [{"relatedAsset": {"id": 3}, "relationshipType": "HOSTS"}, {"relatedAsset": {}}]}
    )
    assert rels == [{"target_id": "3", "target_name": None, "type": "HOSTS"}]


# ------------------------------------------------------------------ jobs / services failure paths
def test_async_job_failure_is_recorded(make_app):
    app = make_app()
    c = app.test_client()
    tm = app.extensions["threat_modeler"]
    with mock.patch.object(tm.nvd, "search_by_cpe", side_effect=UpstreamError("nvd down")):
        job_id = c.post("/analysis?async=true", json={"device_data": {"cpe": CPE}}).get_json()["job_id"]
        for _ in range(50):
            j = c.get(f"/jobs/{job_id}").get_json()
            if j["status"] in ("done", "failed"):
                break
            time.sleep(0.05)
    assert j["status"] == "failed" and "nvd down" in j["error"]
    assert c.get("/jobs/does-not-exist").status_code == 404


def test_sync_upstream_failure_is_502(make_app):
    app = make_app()
    with mock.patch.object(app.extensions["threat_modeler"].nvd, "search_by_cpe", side_effect=UpstreamError("x")):
        r = app.test_client().post("/analysis", json={"device_data": {"cpe": CPE}})
    assert r.status_code == 502 and "NVD" in r.get_json()["error"]


def test_persistence_can_be_disabled(make_app):
    c = make_app(PERSIST_RESULTS=False).test_client()
    body = c.post("/analysis", json={"device_data": {"cpe": CPE}}).get_json()
    assert "id" not in body
    assert c.get("/threat-models").get_json() == []


def test_unknown_route_is_json_404(make_app):
    r = make_app().test_client().get("/nope")
    assert r.status_code == 404 and r.get_json() == {"error": "not found"}


# ------------------------------------------------------------------ API contract
def test_every_route_is_documented_in_openapi(make_app):
    """Fails when an endpoint is added without updating app/static/openapi.yaml."""
    with open(os.path.join(ROOT, "app", "static", "openapi.yaml")) as f:
        spec = yaml.safe_load(f)
    from openapi_spec_validator import validate

    validate(spec)
    documented = {p.replace("{", "<").replace("}", ">") for p in spec["paths"]}
    app = make_app()
    undocumented = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.rule in ("/", "/api/docs", "/api/openapi.yaml"):
            continue
        path = rule.rule.replace("<int:", "<")
        if not any(_same(path, d) for d in documented):
            undocumented.append(rule.rule)
    assert not undocumented, f"not in openapi.yaml: {undocumented}"


def _same(a, b):
    pa, pb = a.strip("/").split("/"), b.strip("/").split("/")
    return len(pa) == len(pb) and all(x == y or (x.startswith("<") and y.startswith("<")) for x, y in zip(pa, pb, strict=True))


def test_example_response_matches_current_shape():
    with open(os.path.join(ROOT, "examples", "response-fixture-health-no-llm.json")) as f:
        ex = json.load(f)
    for key in ("name", "cpe", "pilot", "vulnerabilities", "summary", "metadata"):
        assert key in ex
    v = ex["vulnerabilities"][0]
    assert {"id", "risk", "threats", "cvss_vector"} <= set(v)


# ------------------------------------------------------------------ Kafka worker loop
class _Msg:
    def __init__(self, value, key=b"k1", error=None):
        self._v, self._k, self._e = value, key, error

    def value(self):
        return self._v

    def key(self):
        return self._k

    def error(self):
        return self._e


def test_kafka_consume_publishes_results_and_dlq(make_app):
    import kafka_worker

    app = make_app()
    msgs = [
        None,
        _Msg(json.dumps({"request_id": "r1", "device_data": {"cpe": CPE}}).encode()),
        _Msg(b"not json", key=b"r2"),
    ]
    consumer = mock.Mock()

    def poll(_timeout):
        if msgs:
            return msgs.pop(0)
        kafka_worker.RUNNING = False
        return None

    consumer.poll.side_effect = poll
    producer = mock.Mock()
    kafka_worker.RUNNING = True
    with (
        mock.patch.object(kafka_worker, "create_app", return_value=app),
        mock.patch.object(kafka_worker, "Consumer", return_value=consumer),
        mock.patch.object(kafka_worker, "Producer", return_value=producer),
        mock.patch.object(kafka_worker.signal, "signal"),
    ):
        kafka_worker.consume()
    topics = [c.args[0] for c in producer.produce.call_args_list]
    assert topics == [app.config["KAFKA_RESULT_TOPIC"], app.config["KAFKA_DLQ_TOPIC"]]
    ok = json.loads(producer.produce.call_args_list[0].kwargs["value"])
    assert ok["request_id"] == "r1" and ok["status"] == "done" and ok["result"]["vulnerabilities"]
    bad = json.loads(producer.produce.call_args_list[1].kwargs["value"])
    assert bad["request_id"] == "r2" and bad["status"] == "failed"
    assert consumer.commit.call_count == 2 and consumer.close.called


def test_nvd_rate_limit_override():
    from app.engine.nvd import NvdClient

    assert NvdClient("u").limiter.max_calls == 5
    assert NvdClient("u", api_key="k").limiter.max_calls == 45
    assert NvdClient("u", rate_limit=1000).limiter.max_calls == 1000
