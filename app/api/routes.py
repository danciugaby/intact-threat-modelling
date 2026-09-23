"""REST API. Legacy endpoints and response shapes are preserved; new ones are additive."""
import logging

from flask import Blueprint, Response, current_app, jsonify, request

from ..auth import login_required
from ..engine.http import UpstreamError
from ..engine.modeler import InvalidInput
from ..engine.pilots import list_pilots
from ..models import (Job, ThreatModelRecord, db, export_threat_models, export_threats,
                      export_vulnerabilities)
from ..risk_assessment import RiskAssessmentError
from .. import services

log = logging.getLogger(__name__)
bp = Blueprint("api", __name__)


# ---------------------------------------------------------------- helpers
def _int_arg(name, default=None, lo=0, hi=1000):
    val = request.args.get(name, default=default, type=int)
    if val is None:
        return None
    return max(lo, min(hi, val))


def _wants_async():
    return request.args.get("async", "false").lower() in {"1", "true", "yes"}


def _run(kind, payload, fn, *args, **kwargs):
    """Run synchronously, or as a background job when ?async=true."""
    if _wants_async():
        job_id = current_app.extensions["job_runner"].submit(kind, payload, fn, *args, **kwargs)
        return jsonify({"job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}), 202
    return jsonify(fn(*args, **kwargs)), 200


@bp.errorhandler(InvalidInput)
def _invalid(exc):
    return jsonify({"error": str(exc)}), 400


@bp.errorhandler(UpstreamError)
def _upstream(exc):
    log.warning("Upstream data source failure: %s", exc)
    return jsonify({"error": "A vulnerability data source (NVD) is unavailable; retry later"}), 502


@bp.errorhandler(RiskAssessmentError)
def _ra(exc):
    return jsonify({"error": str(exc)}), exc.status


# ---------------------------------------------------------------- endpoints
@bp.get("/")
def index():
    return "Server is running!"


@bp.get("/health")
def health():
    tm = current_app.extensions["threat_modeler"]
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    body = {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "cwe_version": tm.cwe.version,
        "capec_loaded": bool(tm.capec.patterns),
        "llm": current_app.config.get("LLM_PROVIDER") if tm.llm.enabled else "disabled",
        "nvd_api_key": bool(current_app.config.get("NVD_API_KEY")),
        "risk_assessment_configured": bool(current_app.config.get("RISK_ASSESSMENT_GET_ASSET_URL")),
        "auth_enabled": bool(current_app.config.get("AUTH_ENABLED")),
    }
    return jsonify(body), 200 if db_ok else 503


@bp.get("/pilots")
@login_required
def pilots():
    return jsonify(list_pilots())


@bp.post("/analysis")
@login_required
def analysis():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("device_data"), dict):
        raise InvalidInput("Body must be JSON with a 'device_data' object")
    pilot = body.get("pilot") or request.args.get("pilot")
    limit = body.get("limit") or _int_arg("limit", lo=1, hi=50)
    # validate synchronously so async callers get a 400 immediately
    from ..engine.modeler import normalize_device
    normalize_device(body["device_data"])
    services.modeler().resolve_pilot(pilot or body["device_data"].get("pilot"))
    return _run("device", body, services.analyze_device, body["device_data"], pilot, limit)


@bp.get("/analysis/asset/<asset_id>")
@login_required
def analysis_asset(asset_id):
    pilot = request.args.get("pilot")
    return _run("asset", {"asset_id": asset_id, "pilot": pilot}, services.analyze_asset, asset_id, pilot,
                _int_arg("limit", lo=1, hi=50))


@bp.get("/threat-models/<topology_id>")
@bp.get("/topologies/<topology_id>/analysis")
@login_required
def analysis_topology(topology_id):
    pilot = request.args.get("pilot")
    services.modeler().resolve_pilot(pilot)
    return _run("topology", {"topology_id": topology_id, "pilot": pilot}, services.analyze_topology,
                topology_id, pilot, _int_arg("limit", lo=1, hi=50))


@bp.get("/threat-models")
@login_required
def threat_models():
    rows = ThreatModelRecord.page(limit=_int_arg("limit", 50, 1, 500), offset=_int_arg("offset", 0),
                                  pilot=request.args.get("pilot"))
    return jsonify([r.to_dict() for r in rows])


@bp.get("/threat-models/by-id/<int:model_id>")
@login_required
def threat_model_by_id(model_id):
    rec = db.session.get(ThreatModelRecord, model_id)
    if not rec:
        return jsonify({"error": "not found"}), 404
    return jsonify(rec.to_dict())


@bp.get("/jobs/<job_id>")
@login_required
def job_status(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job.to_dict())


def _csv_response(content, filename):
    resp = Response(content, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@bp.get("/datasets/threat-models")
@login_required
def datasets_threat_models():
    return _csv_response(export_threat_models(_int_arg("limit", None, 1, 100000), _int_arg("offset")),
                         "threat_model_export.csv")


@bp.get("/datasets/vulnerabilities")
@login_required
def datasets_vulnerabilities():
    return _csv_response(export_vulnerabilities(_int_arg("limit", None, 1, 100000), _int_arg("offset")),
                         "vulnerabilities_export.csv")


@bp.get("/datasets/threats")
@login_required
def datasets_threats():
    return _csv_response(export_threats(_int_arg("limit", None, 1, 100000), _int_arg("offset")),
                         "threat_export.csv")
