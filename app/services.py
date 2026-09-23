"""Use-cases shared by the REST API, background jobs and the Kafka worker."""
import logging
from datetime import datetime

from flask import current_app

from .models import ThreatModelRecord, db
from .risk_assessment import RiskAssessmentClient, RiskAssessmentError

log = logging.getLogger(__name__)


def modeler():
    return current_app.extensions["threat_modeler"]


def _persist(model, asset_id=None):
    if not current_app.config.get("PERSIST_RESULTS", True):
        return model
    try:
        rec = ThreatModelRecord.save(model, asset_id=asset_id)
        model["id"] = rec.id
    except Exception:  # persistence must never lose the analysis result
        db.session.rollback()
        log.exception("Failed to persist threat model")
    return model


def analyze_device(device_data, pilot=None, limit=None):
    start = datetime.now()
    model = modeler().get_threat_model(device_data, pilot=pilot, limit=limit)
    model["BENCHMARK_COMPUTE_TIME"] = (datetime.now() - start).total_seconds()
    model["BENCHAMRK_COMPUTE_TIME"] = model["BENCHMARK_COMPUTE_TIME"]  # legacy misspelt key
    return _persist(model)


def analyze_asset(asset_id, pilot=None, limit=None):
    ra = RiskAssessmentClient(current_app.config)
    asset = ra.get_asset(asset_id)
    device, _attrs = ra.asset_to_device(asset)
    if not device.get("cpe") and not device.get("deviceName"):
        raise RiskAssessmentError("asset has neither a CPE nor a name", 422)
    start = datetime.now()
    model = modeler().get_threat_model(device, pilot=pilot or _attrs.get("pilot"), limit=limit)
    model["asset_id"] = asset_id
    model["BENCHMARK_COMPUTE_TIME"] = (datetime.now() - start).total_seconds()
    model["BENCHAMRK_COMPUTE_TIME"] = model["BENCHMARK_COMPUTE_TIME"]
    return _persist(model, asset_id=str(asset_id))


def analyze_topology(topology_id, pilot=None, limit=None):
    ra = RiskAssessmentClient(current_app.config)
    entries = ra.get_topology(topology_id)
    if not entries:
        raise RiskAssessmentError("Topology empty or not found", 404)

    tm = modeler()
    pilot_profile = tm.resolve_pilot(pilot)
    results, assets = [], {}
    device_time = 0.0
    for entry in entries:
        asset_id = entry.get("id")
        if asset_id is None:
            continue
        asset_id = str(asset_id)
        try:
            asset = ra.get_asset(asset_id)
        except RiskAssessmentError as exc:
            results.append({"asset_id": asset_id, "error": "Failed to fetch asset", "status_code": exc.status})
            continue
        device, attrs = ra.asset_to_device(asset)
        node = {"name": asset.get("name") or asset_id, "attributes": attrs,
                "relationships": ra.relationships(asset), "threat_model": None}
        assets[asset_id] = node
        if not device.get("cpe"):
            # Kept in the graph (it can still relay an attack) but not analysed:
            # keyword search on free-text asset names is too noisy for a topology.
            results.append({"asset_id": asset_id, "name": node["name"],
                            "warning": "Asset has no CPE; not analysed for vulnerabilities"})
            continue
        start = datetime.now()
        try:
            model = tm.get_threat_model(device, pilot=pilot_profile.key, limit=limit)
        except Exception as exc:
            log.exception("Threat model failed for asset %s", asset_id)
            results.append({"asset_id": asset_id, "name": node["name"], "error": str(exc)[:300]})
            continue
        dur = (datetime.now() - start).total_seconds()
        device_time += dur
        model.update({"asset_id": asset_id, "BENCHMARK_COMPUTE_TIME": dur, "BENCHAMRK_COMPUTE_TIME": dur})
        _persist(model, asset_id=asset_id)
        node["threat_model"] = model
        results.append(model)

    t0 = datetime.now()
    analysis = tm.analyze_topology(assets, pilot=pilot_profile.key)
    topo_time = (datetime.now() - t0).total_seconds()
    results.append({
        # legacy key: list of single-hop moves {asset_id, vulnerability_id, threat_id}
        "topology_analysis": analysis["lateral_moves"] or "No feasable attacks found",
        "attack_paths": analysis["attack_paths"],
        "entry_points": analysis["entry_points"],
        "entry_point_assumption": analysis["entry_point_assumption"],
        "choke_points": analysis["choke_points"],
        "summary": analysis.get("summary"),
        "topology_analysis_time": topo_time,
        "device_compute_time": device_time,
        "total_compute_time": device_time + topo_time,
    })
    return {"topology_id": topology_id, "pilot": pilot_profile.key, "results": results}
