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

CWE_NS = "{http://cwe.mitre.org/cwe-7}"
CAPEC_NS = "{http://capec.mitre.org/capec-3}"


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
        for w in root.iter(f"{CWE_NS}Weakness"):
            try:
                wid = int(w.get("ID"))
            except (TypeError, ValueError):
                continue
            mitigations = []
            for m in w.iterfind(f"{CWE_NS}Potential_Mitigations/{CWE_NS}Mitigation"):
                desc = _text(m.find(f"{CWE_NS}Description"))
                if not desc:
                    continue
                mitigations.append({
                    "id": m.get("Mitigation_ID"),
                    "phases": [p.text for p in m.iterfind(f"{CWE_NS}Phase") if p.text],
                    "strategy": (m.findtext(f"{CWE_NS}Strategy") or None),
                    "effectiveness": (m.findtext(f"{CWE_NS}Effectiveness") or None),
                    "description": desc,
                })
            consequences = []
            for c in w.iterfind(f"{CWE_NS}Common_Consequences/{CWE_NS}Consequence"):
                consequences.append({
                    "scope": [s.text for s in c.iterfind(f"{CWE_NS}Scope") if s.text],
                    "impact": [i.text for i in c.iterfind(f"{CWE_NS}Impact") if i.text],
                })
            self.weaknesses[wid] = {
                "id": wid,
                "name": w.get("Name"),
                "abstraction": w.get("Abstraction"),
                "status": w.get("Status"),
                "description": _text(w.find(f"{CWE_NS}Description")),
                "likelihood": w.findtext(f"{CWE_NS}Likelihood_Of_Exploit"),
                "capec_ids": [
                    int(p.get("CAPEC_ID"))
                    for p in w.iterfind(f"{CWE_NS}Related_Attack_Patterns/{CWE_NS}Related_Attack_Pattern")
                    if (p.get("CAPEC_ID") or "").isdigit()
                ],
                "mitigations": mitigations,
                "consequences": consequences,
            }
        log.info("Loaded CWE %s (%d weaknesses)", self.version, len(self.weaknesses))

    def get(self, cwe_id):
        return self.weaknesses.get(int(cwe_id))


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
        for ap in root.iter(f"{CAPEC_NS}Attack_Pattern"):
            try:
                cid = int(ap.get("ID"))
            except (TypeError, ValueError):
                continue
            if (ap.get("Status") or "").lower() == "deprecated":
                continue
            techniques = []
            for tm in ap.iterfind(f"{CAPEC_NS}Taxonomy_Mappings/{CAPEC_NS}Taxonomy_Mapping"):
                if tm.get("Taxonomy_Name") == "ATTACK":
                    entry = (tm.findtext(f"{CAPEC_NS}Entry_ID") or "").strip()
                    if entry:
                        techniques.append({
                            "id": entry if entry.startswith("T") else f"T{entry}",
                            "name": (tm.findtext(f"{CAPEC_NS}Entry_Name") or "").strip(),
                        })
            self.patterns[cid] = {
                "id": cid,
                "name": ap.get("Name"),
                "severity": ap.findtext(f"{CAPEC_NS}Typical_Severity"),
                "likelihood": ap.findtext(f"{CAPEC_NS}Likelihood_Of_Attack"),
                "attack_techniques": techniques,
            }
        log.info("Loaded CAPEC %s (%d patterns)", self.version, len(self.patterns))

    def describe(self, capec_id):
        p = self.patterns.get(int(capec_id))
        if p:
            return dict(p)
        return {"id": int(capec_id), "name": None, "severity": None, "likelihood": None,
                "attack_techniques": []}
