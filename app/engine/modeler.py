"""Threat model orchestration: device -> CVEs -> risk ranking -> CWE/CAPEC/ATT&CK
mapping -> scenarios, plus topology analysis.

Output keeps the fields the original service returned (``name``, ``cpe``,
``vulnerabilities[].id/name/description/cvss_vector/cpes/threats[].id/name/description/
attributes``) so existing consumers (e.g. the INTACT Risk Assessment service) keep
working; new information is added alongside."""
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .catalogs import CapecCatalog, CweCatalog
from .exploitability import EpssClient, KevFeed
from .llm import ScenarioGenerator, clean
from .nvd import NvdClient, filter_by_age, is_valid_cpe
from .pilots import PILOTS, get_pilot
from .risk import score_cve
from . import topology as topo

log = logging.getLogger(__name__)

EPSS_PRERANK = 200  # only fetch EPSS for the top-N CVEs by CVSS/KEV


class InvalidInput(ValueError):
    """The request payload can't be turned into a device description."""


def normalize_device(raw):
    """Accept every field name the old API/Kafka/Risk-Assessment payloads used."""
    if not isinstance(raw, dict):
        raise InvalidInput("device_data must be an object")
    cpe = raw.get("cpe") or raw.get("cpeName") or raw.get("cpe23name") or raw.get("cpe23Name")
    name = raw.get("deviceName") or raw.get("name")
    if not cpe and not name:
        raise InvalidInput("device_data needs a 'cpe' (or 'cpeName') or a 'deviceName'")
    if cpe:
        cpe = str(cpe).strip()
        if not is_valid_cpe(cpe):
            raise InvalidInput(f"'{cpe[:120]}' is not a valid CPE 2.3 string")
    device = {
        "deviceName": clean(name, 200) if name else None,
        "cpe": cpe,
        "description": clean(raw.get("description"), 1000),
        "role": clean(raw.get("role"), 200),
        "location": clean(raw.get("location"), 200),
        "exposure": clean(raw.get("exposure"), 100),
    }
    return {k: v for k, v in device.items() if v}


class ThreatModeler:
    def __init__(self, cfg, *, nvd=None, kev=None, epss=None, llm=None, cwe=None, capec=None):
        """``cfg`` is a mapping with the keys defined in ``app.config.Config``."""
        self.cfg = cfg
        self.cwe = cwe or CweCatalog(cfg["CWEC_FILE_PATH"])
        self.capec = capec or CapecCatalog(cfg.get("CAPEC_FILE_PATH"))
        self.nvd = nvd or NvdClient(cfg["NVD_API_URL"], cfg.get("NVD_API_KEY"), cfg.get("NVD_TIMEOUT", 30),
                                    cfg.get("NVD_CACHE_TTL", 21600), cfg.get("NVD_MAX_RESULTS", 2000))
        self.kev = kev if kev is not None else (KevFeed(cfg["KEV_FEED_URL"], cfg.get("HTTP_TIMEOUT", 20))
                                                 if cfg.get("KEV_ENABLED") else None)
        self.epss = epss if epss is not None else (EpssClient(cfg["EPSS_API_URL"], cfg.get("HTTP_TIMEOUT", 20))
                                                    if cfg.get("EPSS_ENABLED") else None)
        self.llm = llm or ScenarioGenerator(
            provider=cfg.get("LLM_PROVIDER", "groq"), model=cfg.get("LLM_MODEL_NAME"),
            api_key=cfg.get("GROQ_API_KEY"), temperature=cfg.get("LLM_TEMPERATURE", 0.3),
            timeout=cfg.get("LLM_TIMEOUT", 60), max_retries=cfg.get("LLM_MAX_RETRIES", 2),
            scenarios_per_cve=cfg.get("SCENARIOS_PER_CVE", 3),
        )
        self.pool = ThreadPoolExecutor(max_workers=max(1, cfg.get("LLM_MAX_CONCURRENCY", 4)),
                                       thread_name_prefix="llm")

    # ------------------------------------------------------------------ public
    def resolve_pilot(self, key):
        pilot = get_pilot(key or self.cfg.get("DEFAULT_PILOT", "generic"))
        if pilot is None:
            raise InvalidInput(f"Unknown pilot '{key}'. Known: {', '.join(PILOTS)}")
        return pilot

    def get_threat_model(self, raw_device, pilot=None, limit=None):
        started = datetime.now(timezone.utc)
        timings = {}
        device = normalize_device(raw_device)
        pilot = self.resolve_pilot(pilot or raw_device.get("pilot") or raw_device.get("sector"))
        try:
            limit = max(1, min(int(limit or self.cfg.get("THREAT_MODEL_LIMIT", 5)), 50))
        except (TypeError, ValueError):
            raise InvalidInput("'limit' must be an integer")

        # 1. threat landscape
        t0 = datetime.now()
        if device.get("cpe"):
            cves, method = self.nvd.search_by_cpe(device["cpe"]), "cpe"
        else:
            cves, method = self.nvd.search_by_keyword(device["deviceName"]), "keyword"
        cves = filter_by_age(cves, self.cfg.get("CVE_MAX_AGE_YEARS", 0))
        total_found = len(cves)
        timings["threat_landscape"] = (datetime.now() - t0).total_seconds()

        # 2. exploitation signals + ranking
        t0 = datetime.now()
        signals = self._enrich(cves)
        scored = [(c, score_cve(c, pilot)) for c in cves]
        scored.sort(key=lambda cr: (-cr[1]["score"], -cr[0].published.timestamp()))
        selected = scored[:limit]
        timings["risk_ranking"] = (datetime.now() - t0).total_seconds()

        # 3. mapping + scenarios (LLM calls in parallel, one per CVE)
        t0 = datetime.now()
        futures = [self.pool.submit(self._build_vulnerability, device, pilot, c, r) for c, r in selected]
        vulnerabilities = [f.result() for f in futures]
        timings["mapping_and_scenarios"] = (datetime.now() - t0).total_seconds()

        model = {
            "name": device.get("deviceName") or device.get("cpe"),
            "cpe": device.get("cpe"),
            "pilot": {"key": pilot.key, "name": pilot.name, "safety_critical": pilot.safety_critical},
            "device": device,
            "vulnerabilities": vulnerabilities,
            "summary": self._summary(vulnerabilities, pilot, total_found),
            "metadata": {
                "generated_at": started.isoformat(),
                "search_method": method,
                "cves_found": total_found,
                "cves_selected": len(vulnerabilities),
                "selection": "risk-ranked (CVSS, KEV, EPSS, pilot C/I/A weighting, attack vector)",
                "sources": {
                    "nvd": "NVD CVE API 2.0",
                    "cwe_version": self.cwe.version,
                    "capec_version": self.capec.version,
                    "kev": signals["kev"],
                    "epss": signals["epss"],
                },
                "llm": {"provider": self.cfg.get("LLM_PROVIDER"), "model": self.cfg.get("LLM_MODEL_NAME")}
                if self.llm.enabled else {"provider": "none"},
                "timings_seconds": timings,
            },
        }
        if method == "keyword":
            model["metadata"]["warning"] = ("No CPE supplied: CVEs were found by keyword search on the device "
                                            "name and may include unrelated products. Supply a CPE for accuracy.")
        return model

    def analyze_topology(self, assets, pilot=None):
        """``assets``: {asset_id: {"name", "attributes", "relationships":[{target_id,type}],
        "threat_model": <output of get_threat_model> or None}}"""
        pilot = self.resolve_pilot(pilot)
        graph = {}
        for aid, a in assets.items():
            vulns = []
            for v in (a.get("threat_model") or {}).get("vulnerabilities", []):
                r = v.get("risk", {})
                vulns.append({
                    "id": v["id"], "attack_vector": r.get("attack_vector"), "score": r.get("score", 0),
                    "known_exploited": r.get("known_exploited"), "epss_percentile": r.get("epss_percentile"),
                })
            graph[aid] = {"name": a.get("name"), "attributes": a.get("attributes") or {},
                          "relationships": a.get("relationships") or [], "vulnerabilities": vulns}
        analysis = topo.analyze(graph, self.cfg.get("TOPOLOGY_MAX_PATH_DEPTH", 4),
                                self.cfg.get("TOPOLOGY_MAX_PATHS", 25))
        if self.cfg.get("TOPOLOGY_LLM_SUMMARY", True):
            analysis["summary"] = self.llm.topology_summary(pilot, analysis)
        return analysis

    # ----------------------------------------------------------------- internals
    def _enrich(self, cves):
        kev_state = "disabled"
        if self.kev is not None:
            for c in cves:
                entry = self.kev.lookup(c.id)
                if entry:
                    c.kev = {**(c.kev or {}), **{k: v for k, v in entry.items() if v}}
            kev_state = "ok" if self.kev.available is not False else "unavailable (NVD KEV fields used)"
        epss_state = "disabled"
        if self.epss is not None and cves:
            pre = sorted(cves, key=lambda c: (bool(c.kev), c.primary_cvss.base_score if c.primary_cvss else 0),
                         reverse=True)[:EPSS_PRERANK]
            scores = self.epss.scores([c.id for c in pre])
            for c in pre:
                if c.id in scores:
                    c.epss, c.epss_percentile = scores[c.id]
            epss_state = "ok" if self.epss.available is not False else "unavailable"
        return {"kev": kev_state, "epss": epss_state}

    def _build_vulnerability(self, device, pilot, cve, risk):
        weaknesses = []
        for cid in cve.cwe_ids:
            w = self.cwe.get(cid)
            weaknesses.append(w or {"id": cid, "name": f"CWE-{cid}", "capec_ids": [], "mitigations": [],
                                    "consequences": []})
        capec_ids = sorted({c for w in weaknesses for c in w.get("capec_ids", [])})
        capecs = [self.capec.describe(c) for c in capec_ids]

        scenarios = self.llm.scenarios(device, pilot, cve, risk, weaknesses, capecs)

        threats = []
        groups = weaknesses or [None]
        for idx, w in enumerate(groups):
            if w is None:
                w_scen = scenarios
                name, cwe_id, w_capecs, mitigations = "Unclassified weakness (no CWE mapping in NVD)", None, [], []
            else:
                w_scen = [s for s in scenarios if w["id"] in s.get("cwe_ids", [])]
                if idx == 0:  # scenarios without a matching CWE go to the first weakness
                    w_scen += [s for s in scenarios if not set(s.get("cwe_ids", [])) & {x["id"] for x in weaknesses}]
                name, cwe_id = w["name"], w["id"]
                w_capecs = [c for c in capecs if c["id"] in w.get("capec_ids", [])]
                mitigations = w.get("mitigations", [])
            threats.append({
                "id": idx,
                "name": name,
                "cwe_id": cwe_id,
                # legacy text field: readable rendering of the structured scenarios
                "description": "\n\n".join(_render(s) for s in w_scen),
                "scenarios": w_scen,
                "capec": w_capecs,
                "attack_techniques": sorted({t["id"] for c in w_capecs for t in c.get("attack_techniques", [])}),
                "mitigations": mitigations,
                "attributes": [
                    {"key": "capec", "value": [str(c["id"]) for c in w_capecs]},
                    {"key": "mitigations", "value": [m["description"] for m in mitigations]},
                ],
            })

        return {
            "id": cve.id,
            "name": cve.title,
            "description": cve.description,
            "published": cve.published.date().isoformat(),
            "cvss_vector": [m.vector for m in cve.cvss],
            "cpes": cve.cpes[:25],
            "cwe_ids": cve.cwe_ids,
            "risk": risk,
            "references": cve.references,
            "threats": threats,
        }

    @staticmethod
    def _summary(vulns, pilot, total_found):
        by_priority = {p: 0 for p in ("P1", "P2", "P3", "P4")}
        for v in vulns:
            by_priority[v["risk"]["priority"]] += 1
        top = vulns[0] if vulns else None
        return {
            "by_priority": by_priority,
            "known_exploited": [v["id"] for v in vulns if v["risk"]["known_exploited"]],
            "safety_relevant": [v["id"] for v in vulns if v["risk"]["safety_relevant"]],
            "highest_risk": {"id": top["id"], "score": top["risk"]["score"], "priority": top["risk"]["priority"]}
            if top else None,
            "not_analysed": max(0, total_found - len(vulns)),
            "regulatory_references": list(pilot.standards),
        }


def _render(s):
    parts = [s.get("title", "")]
    if s.get("entry_point"):
        parts.append(f"Entry point: {s['entry_point']}")
    if s.get("steps"):
        parts.append("Steps: " + " -> ".join(s["steps"]))
    imp = s.get("impact") or {}
    imp_txt = "; ".join(f"{k}: {v}" for k, v in imp.items() if v)
    if imp_txt:
        parts.append(f"Impact: {imp_txt}")
    return "\n".join(p for p in parts if p)
