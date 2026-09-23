import json
from unittest import mock

import pytest
import responses

from app.engine import topology as topo
from app.engine.http import UpstreamError
from app.engine.llm import ScenarioGenerator, clean
from app.engine.modeler import InvalidInput, normalize_device
from app.engine.nvd import NvdClient, is_valid_cpe, parse_cve
from app.engine.pilots import get_pilot
from app.engine.risk import score_cve

from conftest import FakeGroq

NVD = "https://nvd.test/rest/json/cves/2.0"


# ------------------------------------------------------------------ NVD parsing
def test_parse_cve_fields(nvd_page):
    c = parse_cve(nvd_page["vulnerabilities"][0])
    assert c.id == "CVE-2023-20198"
    assert c.description.startswith("Cisco IOS XE")  # English, not descriptions[0]
    assert c.cwe_ids == [420]
    assert c.kev and c.kev["date_added"] == "2023-10-16"
    assert c.primary_cvss.base_score == 10.0
    assert c.cpes == ["cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"]


def test_parse_cve_ignores_placeholder_cwes_and_prefers_v4(nvd_page):
    c = parse_cve(nvd_page["vulnerabilities"][3])
    assert c.cwe_ids == [77]
    v4 = parse_cve(nvd_page["vulnerabilities"][4])
    assert v4.cwe_ids == [] and v4.primary_cvss.version == "4.0"


def test_cpe_validation():
    assert is_valid_cpe("cpe:2.3:o:nordicsemi:nrf52840_firmware:-:*:*:*:*:*:*:*")
    assert not is_valid_cpe("cisco ios")
    assert not is_valid_cpe("cpe:2.3:o:cisco")


@responses.activate
def test_nvd_client_paginates_and_caches(nvd_page):
    p1 = dict(nvd_page, totalResults=5, vulnerabilities=nvd_page["vulnerabilities"][:3])
    p2 = dict(nvd_page, totalResults=5, vulnerabilities=nvd_page["vulnerabilities"][3:])
    responses.add(responses.GET, NVD, json=p1)
    responses.add(responses.GET, NVD, json=p2)
    client = NvdClient(NVD)
    client.limiter.acquire = lambda: None
    out = client.search_by_cpe("cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*")
    assert len(out) == 5
    assert "cpeName=" in responses.calls[0].request.url
    assert "startIndex=3" in responses.calls[1].request.url
    client.search_by_cpe("cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*")
    assert len(responses.calls) == 2  # cached


@responses.activate
def test_nvd_wildcard_version_uses_virtual_match(nvd_page):
    responses.add(responses.GET, NVD, json=nvd_page)
    client = NvdClient(NVD)
    client.limiter.acquire = lambda: None
    client.search_by_cpe("cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*")
    assert "virtualMatchString=" in responses.calls[0].request.url


@responses.activate
def test_nvd_cpename_falls_back_to_virtual_match(nvd_page):
    responses.add(responses.GET, NVD, json=dict(nvd_page, totalResults=0, vulnerabilities=[]))
    responses.add(responses.GET, NVD, json=nvd_page)
    client = NvdClient(NVD)
    client.limiter.acquire = lambda: None
    assert len(client.search_by_cpe("cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*")) == 5
    assert "virtualMatchString=" in responses.calls[1].request.url


@responses.activate
def test_nvd_retries_are_bounded():
    """The old code looped forever when NVD returned nothing / rate-limited."""
    responses.add(responses.GET, NVD, status=503)
    client = NvdClient(NVD)
    client.limiter.acquire = lambda: None
    with mock.patch("app.engine.http.time.sleep"), pytest.raises(UpstreamError):
        client.search_by_keyword("anything")
    assert len(responses.calls) == 3


# ------------------------------------------------------------------ catalogues
def test_cwe_keeps_structured_mitigations(cwe_catalog):
    w = cwe_catalog.get(787)
    # the original newline filter dropped every multi-paragraph (XHTML) mitigation
    assert len(w["mitigations"]) == 2
    assert w["mitigations"][1]["description"] == ("Run or compile the software using features that provide "
                                                  "automatic protection. Stack canaries ASLR")
    assert cwe_catalog.get(78)["mitigations"][1]["strategy"] == "Input Validation"
    assert cwe_catalog.get(78)["capec_ids"] == [108, 15, 43, 6, 88]


def test_capec_catalog(capec_catalog):
    d = capec_catalog.describe(88)
    assert d["name"] == "OS Command Injection"
    assert d["attack_techniques"] == [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
    assert capec_catalog.describe(999)["name"] is None
    assert 1 not in capec_catalog.patterns  # deprecated skipped


# ------------------------------------------------------------------ risk
def test_kev_outranks_newer_unexploited(nvd_page):
    pilot = get_pilot("generic")
    cves = [parse_cve(v) for v in nvd_page["vulnerabilities"]]
    ranked = sorted(cves, key=lambda c: -score_cve(c, pilot)["score"])
    assert [c.id for c in ranked[:2]] == ["CVE-2023-20198", "CVE-2023-20273"]
    assert ranked[-1].id != "CVE-2023-20198"
    assert score_cve(cves[0], pilot)["priority"] == "P1"


def test_pilot_weighting_changes_impact(nvd_page):
    dos = parse_cve(nvd_page["vulnerabilities"][2])  # availability-only
    tel = score_cve(dos, get_pilot("telecom"))
    health = score_cve(dos, get_pilot("health"))
    assert tel["components"]["impact"] > health["components"]["impact"]
    assert tel["attack_vector"] == "network"


def test_safety_flag_only_for_safety_critical(nvd_page):
    rce = parse_cve(nvd_page["vulnerabilities"][1])
    assert score_cve(rce, get_pilot("nuclear"))["safety_relevant"] is True
    assert score_cve(rce, get_pilot("telecom"))["safety_relevant"] is False


def test_pilot_aliases():
    assert get_pilot("PUC2").key == "health"
    assert get_pilot("smart-city").key == "smart_city"
    assert get_pilot("unknown") is None


# ------------------------------------------------------------------ input
def test_normalize_device_accepts_legacy_keys():
    d = normalize_device({"cpeName": "cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*", "deviceName": "R1"})
    assert d["cpe"].startswith("cpe:2.3:o:cisco")
    assert normalize_device({"cpe23name": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"})["cpe"]
    with pytest.raises(InvalidInput):
        normalize_device({"cpe": "not a cpe"})
    with pytest.raises(InvalidInput):
        normalize_device({})


def test_clean_strips_control_chars():
    assert clean("abc\x00\x1b[31m" + "x" * 1000, 10) == "abc  [31mx"


# ------------------------------------------------------------------ LLM
def _llm_inputs(nvd_page, cwe_catalog, capec_catalog):
    cve = parse_cve(nvd_page["vulnerabilities"][1])
    pilot = get_pilot("health")
    risk = score_cve(cve, pilot)
    weaknesses = [cwe_catalog.get(78)]
    capecs = [capec_catalog.describe(c) for c in weaknesses[0]["capec_ids"]]
    return {"device": {"deviceName": "PACS router"}, "pilot": pilot, "cve": cve, "risk": risk,
            "weaknesses": weaknesses, "capecs": capecs}


def test_llm_output_is_grounded(nvd_page, cwe_catalog, capec_catalog):
    reply = json.dumps({"scenarios": [{
        "title": "Root shell on PACS edge router", "steps": ["a", "b", "c"], "likelihood": "HIGH",
        "cwe_ids": ["CWE-78", 9999], "attack_techniques": ["T1059", "T9999"],
        "impact": {"safety": "delayed imaging"}}]})
    fake = FakeGroq(reply)
    gen = ScenarioGenerator(model="m", client=fake, scenarios_per_cve=3)
    out = gen.scenarios(**_llm_inputs(nvd_page, cwe_catalog, capec_catalog))
    assert out[0]["cwe_ids"] == [78]
    assert out[0]["attack_techniques"] == ["T1059"]  # invented technique dropped
    assert out[0]["likelihood"] == "high"
    call = fake.chat.completions.calls[0]
    assert call["response_format"] == {"type": "json_object"}
    user = call["messages"][1]["content"]
    assert "Health 4.0" in user and "CVE-2023-20273" in user


def test_llm_bad_output_falls_back(nvd_page, cwe_catalog, capec_catalog):
    gen = ScenarioGenerator(model="m", client=FakeGroq("I cannot help with that"), max_retries=1)
    out = gen.scenarios(**_llm_inputs(nvd_page, cwe_catalog, capec_catalog))
    assert out and out[0]["generated_by"] == "deterministic"
    assert out[0]["mitigations"]


def test_llm_disabled_is_deterministic(nvd_page, cwe_catalog, capec_catalog):
    gen = ScenarioGenerator(provider="none")
    assert not gen.enabled
    out = gen.scenarios(**_llm_inputs(nvd_page, cwe_catalog, capec_catalog))
    assert out[0]["cwe_ids"] == [78]
    assert "T1059" in out[0]["attack_techniques"]


def test_groq_requires_key():
    with pytest.raises(ValueError):
        ScenarioGenerator(provider="groq", model="m", api_key=None)


# ------------------------------------------------------------------ topology
def _v(id, av, score=80, kev=False):
    return {"id": id, "attack_vector": av, "score": score, "known_exploited": kev, "epss_percentile": None}


def test_topology_paths_respect_attack_vectors():
    assets = {
        "fw": {"name": "Firewall", "attributes": {"internet_facing": "true"},
               "vulnerabilities": [_v("CVE-FW", "network", 95, kev=True)],
               "relationships": [{"target_id": "pacs", "type": "CONNECTED_TO"}]},
        "pacs": {"name": "PACS", "vulnerabilities": [_v("CVE-PACS", "network", 70)],
                 "relationships": [{"target_id": "vm", "type": "HOSTS"},
                                   {"target_id": "wiki", "type": "DOCUMENTS"}]},
        "vm": {"name": "Imaging VM", "vulnerabilities": [_v("CVE-LPE", "local", 78)], "relationships": []},
        "mri": {"name": "MRI", "vulnerabilities": [_v("CVE-MRI-L", "local", 90)],
                "relationships": [{"target_id": "pacs", "type": "SENDS_DATA_TO"}]},
        "wiki": {"name": "Wiki", "vulnerabilities": [_v("CVE-WIKI", "network", 60)], "relationships": []},
    }
    r = topo.analyze(assets, max_depth=4, max_paths=50)
    assert [e["asset_id"] for e in r["entry_points"]] == ["fw"]
    assert r["entry_point_assumption"] is None
    chains = {tuple(p["assets"]) for p in r["attack_paths"]}
    # network hop to PACS, then local (co-hosted) hop to the VM
    assert ("Firewall (fw)", "PACS (pacs)", "Imaging VM (vm)") in chains
    # MRI only has a local vuln and is linked by a directed network edge MRI->PACS: not reachable
    assert not any("MRI (mri)" in p for p in chains)
    # DOCUMENTS is security-neutral
    assert not any("Wiki (wiki)" in p for p in chains)
    assert r["choke_points"][0]["asset"] == "Firewall (fw)"
    legacy = r["lateral_moves"][0]
    assert set(legacy) >= {"asset_id", "vulnerability_id", "threat_id"}


def test_topology_without_exposure_flags_assumption():
    assets = {"a": {"name": "A", "vulnerabilities": [_v("CVE-A", "network")],
                    "relationships": [{"target_id": "b", "type": "CONNECTED_TO"}]},
              "b": {"name": "B", "vulnerabilities": [_v("CVE-B", "physical")], "relationships": []}}
    r = topo.analyze(assets)
    assert r["entry_point_assumption"]
    assert r["attack_paths"] == []  # AV:P never enables lateral movement
