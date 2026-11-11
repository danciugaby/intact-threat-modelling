"""MITRE CWE and CAPEC catalogues, parsed once into in-memory indexes.

The old code ran an XPath ``findall`` over the full 14 MB CWE tree for every lookup and
dropped any mitigation whose text contained a newline (i.e. every structured one).
Here each catalogue is parsed once and full text (including XHTML paragraphs and lists)
is kept."""
import logging
import os
import re
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

# Namespaces seen so far: CWE schema 7 (CWE 4.x) is http://cwe.mitre.org/cwe-7, schema 8
# (CWE 5.0, Oct 2026) uses a new one, CAPEC is http://capec.mitre.org/capec-3. Elements are
# matched by local name so a namespace change does not silently empty the catalogue.


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _kids(elem, *names):
    """Children reached by following ``names`` (local names), e.g. ("Potential_Mitigations", "Mitigation")."""
    nodes = [elem]
    for name in names:
        nodes = [c for n in nodes for c in n if _local(c.tag) == name]
    return nodes


def _kid(elem, *names):
    found = _kids(elem, *names)
    return found[0] if found else None


def _kid_text(elem, *names):
    k = _kid(elem, *names)
    if k is None or not (k.text or "").strip():
        return None
    return k.text.strip()


def _num(value):
    """79, "79" or "CWE-79" -> 79; anything else -> None."""
    m = re.search(r"\d+", str(value or ""))
    return int(m.group()) if m else None


def _text(elem):
    """Flatten an element (possibly containing XHTML) into readable text."""
    if elem is None:
        return ""
    return re.sub(r"\s+", " ", " ".join(t.strip() for t in elem.itertext() if t.strip())).strip()


class CweCatalog:
    def __init__(self, path):
        self.path = path
        self.version = None
        self.weaknesses = {}
        self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            raise FileNotFoundError(
                f"CWE catalogue not found at {self.path!r}. Run `python scripts/update_data.py` "
                "or set CWEC_FILE_PATH.")
        root = ET.parse(self.path).getroot()
        self.version = root.get("Version")
        self.namespace = root.tag[1:].split("}")[0] if root.tag.startswith("{") else None
        for w in root.iter():
            if _local(w.tag) != "Weakness":
                continue
            wid = _num(w.get("ID"))
            if wid is None:
                continue
            mitigations = []
            for m in _kids(w, "Potential_Mitigations", "Mitigation"):
                desc = _text(_kid(m, "Description"))
                if not desc:
                    continue
                mitigations.append({
                    "id": m.get("Mitigation_ID"),
                    "phases": [p.text.strip() for p in _kids(m, "Phase") + _kids(m, "Custom_Phase")
                               if p.text and p.text.strip()],
                    "strategy": _kid_text(m, "Strategy"),
                    "effectiveness": _kid_text(m, "Effectiveness"),
                    "description": desc,
                })
            consequences = []
            for c in _kids(w, "Common_Consequences", "Consequence"):
                consequences.append({
                    "scope": [x.text.strip() for x in _kids(c, "Scope") if x.text and x.text.strip()],
                    "impact": [x.text.strip() for x in _kids(c, "Impact") if x.text and x.text.strip()],
                })
            capec_ids = [_num(p.get("CAPEC_ID")) for p in _kids(w, "Related_Attack_Patterns", "Related_Attack_Pattern")]
            self.weaknesses[wid] = {
                "id": wid,
                "name": w.get("Name"),
                "abstraction": w.get("Abstraction"),
                "status": w.get("Status"),
                "description": _text(_kid(w, "Description")),
                "likelihood": _kid_text(w, "Likelihood_Of_Exploit"),
                "capec_ids": [n for n in capec_ids if n is not None],
                "mitigations": mitigations,
                "consequences": consequences,
            }
        if not self.weaknesses:
            log.error("CWE catalogue %s (version %s, namespace %s) contains no weaknesses this parser "
                      "understands; CWE names, mitigations and CAPEC/ATT&CK mappings will be missing",
                      self.path, self.version, self.namespace)
        else:
            log.info("Loaded CWE %s (%d weaknesses, %d with mitigations, %d with CAPEC links)", self.version,
                     len(self.weaknesses), sum(1 for w in self.weaknesses.values() if w["mitigations"]),
                     sum(1 for w in self.weaknesses.values() if w["capec_ids"]))

    def get(self, cwe_id):
        n = _num(cwe_id)
        return self.weaknesses.get(n) if n is not None else None


class CapecCatalog:
    """Optional: gives CAPEC names, severity and MITRE ATT&CK technique mappings.
    If the file is absent, CAPEC ids are still returned (from CWE) without detail."""

    def __init__(self, path):
        self.path = path
        self.version = None
        self.patterns = {}
        if path and os.path.exists(path):
            self._load()
        else:
            log.warning("CAPEC catalogue not found at %s; CAPEC names/ATT&CK mappings disabled "
                        "(run scripts/update_data.py)", path)

    def _load(self):
        root = ET.parse(self.path).getroot()
        self.version = root.get("Version")
        for ap in root.iter():
            if _local(ap.tag) != "Attack_Pattern":
                continue
            cid = _num(ap.get("ID"))
            if cid is None or (ap.get("Status") or "").lower() == "deprecated":
                continue
            techniques = []
            for tm in _kids(ap, "Taxonomy_Mappings", "Taxonomy_Mapping"):
                entry = _kid_text(tm, "Entry_ID") if tm.get("Taxonomy_Name") == "ATTACK" else None
                if entry:
                    techniques.append({"id": entry if entry.startswith("T") else f"T{entry}",
                                       "name": _kid_text(tm, "Entry_Name") or ""})
            self.patterns[cid] = {
                "id": cid,
                "name": ap.get("Name"),
                "severity": _kid_text(ap, "Typical_Severity"),
                "likelihood": _kid_text(ap, "Likelihood_Of_Attack"),
                "attack_techniques": techniques,
            }
        log.info("Loaded CAPEC %s (%d patterns)", self.version, len(self.patterns))

    def describe(self, capec_id):
        p = self.patterns.get(int(capec_id))
        if p:
            return dict(p)
        return {"id": int(capec_id), "name": None, "severity": None, "likelihood": None,
                "attack_techniques": []}
