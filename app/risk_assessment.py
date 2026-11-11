"""Client for the INTACT Risk Assessment service (asset & topology source)."""
import logging

import requests

log = logging.getLogger(__name__)


class RiskAssessmentError(RuntimeError):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


class RiskAssessmentClient:
    def __init__(self, cfg, session=None):
        self.topology_url = cfg.get("RISK_ASSESSMENT_GET_TOPOLOGY_URL")
        self.asset_url = cfg.get("RISK_ASSESSMENT_GET_ASSET_URL")
        self.token = cfg.get("RISK_ASSESSMENT_TOKEN")
        self.timeout = cfg.get("HTTP_TIMEOUT", 20)
        self.session = session or requests.Session()

    @property
    def configured(self):
        return bool(self.topology_url and self.asset_url)

    def _get(self, url):
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise RiskAssessmentError(f"Risk Assessment service unreachable: {exc.__class__.__name__}")
        if resp.status_code == 404:
            raise RiskAssessmentError("not found", 404)
        if resp.status_code != 200:
            # don't echo upstream bodies to API clients
            log.warning("Risk Assessment %s -> %s: %s", url, resp.status_code, resp.text[:500])
            raise RiskAssessmentError(f"Risk Assessment service returned HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError:
            raise RiskAssessmentError("Risk Assessment service returned invalid JSON")

    @staticmethod
    def _fill(template, **values):
        url = template
        for k, v in values.items():
            safe = requests.utils.quote(str(v), safe="")
            if "{" + k + "}" in url:
                url = url.replace("{" + k + "}", safe)
            else:
                url = url.rstrip("/") + "/" + safe
        return url

    def get_asset(self, asset_id):
        if not self.asset_url:
            raise RiskAssessmentError("RISK_ASSESSMENT_GET_ASSET_URL is not configured", 503)
        return self._get(self._fill(self.asset_url, asset_id=asset_id))

    def get_topology(self, topology_id):
        return self.get_topology_info(topology_id)[0]

    def get_topology_info(self, topology_id):
        """Return (asset entries, metadata). Accepts ``{"content": [...], "pilot": ...}``,
        ``{"assets": [...]}`` or a bare list of ``{"id": ...}`` entries / ids."""
        if not self.topology_url:
            raise RiskAssessmentError("RISK_ASSESSMENT_GET_TOPOLOGY_URL is not configured", 503)
        data = self._get(self._fill(self.topology_url, topology_id=topology_id))
        meta = {}
        if isinstance(data, dict):
            meta = {k: data.get(k) for k in ("id", "name", "pilot") if data.get(k) is not None}
            entries = data.get("content", data.get("assets", []))
        elif isinstance(data, list):
            entries = data
        else:
            entries = []
        entries = [e if isinstance(e, dict) else {"id": e} for e in entries or [] if e is not None]
        return entries, meta

    @staticmethod
    def asset_to_device(asset):
        """Map a Risk Assessment asset to a device_data dict."""
        attrs = {}
        for a in asset.get("attributes", []) or []:
            if isinstance(a, dict) and a.get("key") is not None:
                attrs[str(a["key"])] = a.get("value")
        cpe = asset.get("cpe23name") or attrs.get("CPE") or attrs.get("cpe")
        device = {"deviceName": asset.get("name"), "cpe": cpe,
                  "description": asset.get("description") or attrs.get("description")}
        return {k: v for k, v in device.items() if v}, attrs

    @staticmethod
    def relationships(asset):
        out = []
        for rel in asset.get("relationships", []) or []:
            related = rel.get("relatedAsset") or {}
            rtype = rel.get("relationshipType")
            rtype = rtype.get("id") if isinstance(rtype, dict) else rtype
            if related.get("id") is not None:
                out.append({"target_id": str(related["id"]), "target_name": related.get("name"),
                            "type": rtype or "CONNECTED_TO"})
        return out
