"""REST API. Legacy endpoints and response shapes are preserved; new ones are additive."""
import logging

from flask import Blueprint, Response, current_app, jsonify, request

from ..auth import PilotForbidden, allowed_pilots, check_pilot, login_required
from ..engine.http import UpstreamError
from ..engine.modeler import InvalidInput
from ..engine.pilots import get_pilot, list_pilots
from ..jobs import JobQueueFull, expire_if_stale
from ..models import (Job, ThreatModelRecord, db, export_threat_models, export_threats,
                      export_vulnerabilities)
from ..risk_assessment import RiskAssessmentError
from .. import services

log = logging.getLogger(__name__)
bp = Blueprint("api", __name__)
MAX_OFFSET = 10 ** 9


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


@bp.errorhandler(PilotForbidden)
def _forbidden(exc):
    return jsonify({"error": str(exc)}), 403


@bp.errorhandler(JobQueueFull)
def _busy(exc):
    return jsonify({"error": str(exc)}), 429, {"Retry-After": "60"}


def _visible(pilot_key, allowed):
    return allowed is None or pilot_key in allowed


def _pilot_key(value):
    """Canonical pilot key for a name or alias (unknown values are returned unchanged)."""
    if not value:
        return value
    profile = get_pilot(value)
    return profile.key if profile else value


def _record_pilot(doc):
    p = (doc or {}).get("pilot")
    return p.get("key") if isinstance(p, dict) else p


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
        "cwe_weaknesses": len(tm.cwe.weaknesses),
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
    allowed = allowed_pilots()
    key = services.modeler().resolve_pilot(pilot or body["device_data"].get("pilot")
                                            or body["device_data"].get("sector")).key
    check_pilot(key, allowed)
    return _run("device", dict(body, pilot=key), services.analyze_device, body["device_data"], pilot, limit,
                allowed_pilots=allowed)


@bp.get("/analysis/asset/<asset_id>")
@login_required
def analysis_asset(asset_id):
    pilot = request.args.get("pilot")
    allowed = allowed_pilots()
    if pilot:
        check_pilot(services.modeler().resolve_pilot(pilot).key, allowed)
    return _run("asset", {"asset_id": asset_id, "pilot": pilot}, services.analyze_asset, asset_id, pilot,
                _int_arg("limit", lo=1, hi=50), allowed_pilots=allowed)


@bp.get("/threat-models/<topology_id>")
@bp.get("/topologies/<topology_id>/analysis")
@login_required
def analysis_topology(topology_id):
    pilot = request.args.get("pilot")
    allowed = allowed_pilots()
    if pilot:
        check_pilot(services.modeler().resolve_pilot(pilot).key, allowed)
    return _run("topology", {"topology_id": topology_id, "pilot": pilot}, services.analyze_topology,
                topology_id, pilot, _int_arg("limit", lo=1, hi=50), allowed_pilots=allowed)


@bp.get("/threat-models")
@login_required
def threat_models():
    pilot = _pilot_key(request.args.get("pilot"))
    rows = ThreatModelRecord.page(limit=_int_arg("limit", 50, 1, 500), offset=_int_arg("offset", 0, 0, MAX_OFFSET),
                                  pilot=pilot, pilots=allowed_pilots())
    return jsonify([r.to_dict() for r in rows])


@bp.get("/threat-models/by-id/<int:model_id>")
@login_required
def threat_model_by_id(model_id):
    rec = db.session.get(ThreatModelRecord, model_id)
    if not rec or not _visible(rec.pilot, allowed_pilots()):
        return jsonify({"error": "not found"}), 404
    return jsonify(rec.to_dict())


@bp.get("/jobs/<job_id>")
@login_required
def job_status(job_id):
    job = db.session.get(Job, job_id)
    allowed = allowed_pilots()
    if job and allowed is not None:
        resolved = {_pilot_key(k) for k in (_record_pilot(job.request), _record_pilot(job.result)) if k}
        if not resolved or not resolved <= allowed:
            job = None
    if not job:
        return jsonify({"error": "not found"}), 404
    expire_if_stale(job, current_app.config.get("JOB_TIMEOUT_SECONDS", 3600))
    return jsonify(job.to_dict())


def _csv_response(content, filename):
    resp = Response(content, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@bp.get("/datasets/threat-models")
@login_required
def datasets_threat_models():
    return _csv_response(export_threat_models(_int_arg("limit", None, 1, 100000), _int_arg("offset", 0, 0, MAX_OFFSET),
                                 allowed_pilots()),
                         "threat_model_export.csv")


@bp.get("/datasets/vulnerabilities")
@login_required
def datasets_vulnerabilities():
    return _csv_response(export_vulnerabilities(_int_arg("limit", None, 1, 100000), _int_arg("offset", 0, 0, MAX_OFFSET),
                                 allowed_pilots()),
                         "vulnerabilities_export.csv")


@bp.get("/datasets/threats")
@login_required
def datasets_threats():
    return _csv_response(export_threats(_int_arg("limit", None, 1, 100000), _int_arg("offset", 0, 0, MAX_OFFSET),
                                 allowed_pilots()),
                         "threat_export.csv")
