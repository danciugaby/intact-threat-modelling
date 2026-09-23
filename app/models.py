"""Persistence: threat models (normalised for CSV export + full JSON document) and jobs."""
import csv
import uuid
from datetime import datetime, timezone
from io import StringIO

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _now():
    return datetime.now(timezone.utc)


class ThreatModelRecord(db.Model):
    __tablename__ = "threat_model"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cpe = db.Column(db.String(512), nullable=True, index=True)
    pilot = db.Column(db.String(32), nullable=True, index=True)
    asset_id = db.Column(db.String(128), nullable=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now, index=True)
    document = db.Column(db.JSON, nullable=False)
    vulnerabilities = db.relationship("VulnerabilityRecord", back_populates="threat_model",
                                      cascade="all, delete-orphan")

    @staticmethod
    def save(model, asset_id=None):
        rec = ThreatModelRecord(name=(model.get("name") or "unknown")[:255], cpe=model.get("cpe"),
                                pilot=(model.get("pilot") or {}).get("key"), asset_id=asset_id,
                                document=model)
        db.session.add(rec)
        for v in model.get("vulnerabilities", []):
            risk = v.get("risk") or {}
            vr = VulnerabilityRecord(
                cve_id=v["id"], name=(v.get("name") or v["id"])[:255], description=v.get("description") or "",
                cvss_vector=",".join(v.get("cvss_vector") or []), risk_score=risk.get("score"),
                priority=risk.get("priority"), known_exploited=bool(risk.get("known_exploited")),
                epss=risk.get("epss"), threat_model=rec)
            db.session.add(vr)
            for t in v.get("threats", []):
                db.session.add(ThreatRecord(
                    name=(t.get("name") or "")[:255], cwe_id=t.get("cwe_id"), description=t.get("description"),
                    capec_ids=",".join(str(c["id"]) for c in t.get("capec", [])),
                    attack_techniques=",".join(t.get("attack_techniques", [])), vulnerability=vr))
        db.session.commit()
        return rec

    def to_dict(self):
        doc = dict(self.document or {})
        doc["id"] = self.id
        doc.setdefault("created_at", self.created_at.isoformat() if self.created_at else None)
        return doc

    @staticmethod
    def page(limit=None, offset=None, pilot=None):
        q = ThreatModelRecord.query.order_by(ThreatModelRecord.id.desc())
        if pilot:
            q = q.filter_by(pilot=pilot)
        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)
        return q.all()


class VulnerabilityRecord(db.Model):
    __tablename__ = "vulnerability"
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(32), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    cvss_vector = db.Column(db.Text)
    risk_score = db.Column(db.Float)
    priority = db.Column(db.String(4))
    known_exploited = db.Column(db.Boolean, default=False)
    epss = db.Column(db.Float)
    threat_model_id = db.Column(db.Integer, db.ForeignKey("threat_model.id"), nullable=False)
    threat_model = db.relationship("ThreatModelRecord", back_populates="vulnerabilities")
    threats = db.relationship("ThreatRecord", back_populates="vulnerability", cascade="all, delete-orphan")


class ThreatRecord(db.Model):
    __tablename__ = "threat"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cwe_id = db.Column(db.Integer)
    description = db.Column(db.Text)
    capec_ids = db.Column(db.Text)
    attack_techniques = db.Column(db.Text)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=False)
    vulnerability = db.relationship("VulnerabilityRecord", back_populates="threats")


class Job(db.Model):
    __tablename__ = "job"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kind = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="queued")  # queued|running|done|failed
    request = db.Column(db.JSON)
    result = db.Column(db.JSON)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    finished_at = db.Column(db.DateTime(timezone=True))

    def to_dict(self, include_result=True):
        d = {"job_id": self.id, "kind": self.kind, "status": self.status,
             "created_at": self.created_at.isoformat() if self.created_at else None,
             "finished_at": self.finished_at.isoformat() if self.finished_at else None}
        if self.error:
            d["error"] = self.error
        if include_result and self.status == "done":
            d["result"] = self.result
        return d


def _csv(header, rows):
    out = StringIO()
    w = csv.writer(out)
    w.writerow(header)
    for r in rows:
        # neutralise spreadsheet formula injection from upstream text
        w.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in r])
    return out.getvalue()


def _paged(query, limit, offset):
    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)
    return query.all()


def export_threat_models(limit=None, offset=None):
    rows = _paged(ThreatModelRecord.query.order_by(ThreatModelRecord.id), limit, offset)
    return _csv(["ID", "Name", "CPE", "Pilot", "Asset ID", "Created"],
                [(r.id, r.name, r.cpe, r.pilot, r.asset_id, r.created_at) for r in rows])


def export_vulnerabilities(limit=None, offset=None):
    rows = _paged(VulnerabilityRecord.query.order_by(VulnerabilityRecord.id), limit, offset)
    return _csv(["CVE ID", "Name", "Description", "CVSS Vector", "Risk Score", "Priority", "Known Exploited",
                 "EPSS", "Threat Model ID"],
                [(r.cve_id, r.name, r.description, r.cvss_vector, r.risk_score, r.priority, r.known_exploited,
                  r.epss, r.threat_model_id) for r in rows])


def export_threats(limit=None, offset=None):
    rows = _paged(ThreatRecord.query.order_by(ThreatRecord.id), limit, offset)
    return _csv(["ID", "Name", "CWE", "Description", "CAPEC IDs", "ATT&CK Techniques", "Vulnerability ID"],
                [(r.id, r.name, r.cwe_id, r.description, r.capec_ids, r.attack_techniques, r.vulnerability_id)
                 for r in rows])
