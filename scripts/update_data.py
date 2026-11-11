"""Download the latest MITRE CWE and CAPEC catalogues into ./data.

    python scripts/update_data.py [--dest data]

Afterwards set CWEC_FILE_PATH to the printed CWE file (CAPEC is picked up as
data/capec_latest.xml by default)."""
import argparse
import io
import os
import sys
import zipfile

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from app.engine.catalogs import CapecCatalog, CweCatalog  # noqa: E402

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=os.path.join(os.path.dirname(__file__), "..", "data"))
    dest = ap.parse_args().dest
    os.makedirs(dest, exist_ok=True)

    r = requests.get(CWE_URL, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = next(n for n in z.namelist() if n.endswith(".xml"))
        z.extract(name, dest)
    cwe_path = os.path.join(dest, name)
    latest = os.path.join(dest, "cwec_latest.xml")
    os.replace(cwe_path, latest)
    print(f"CWE   -> {latest} ({name})")

    r = requests.get(CAPEC_URL, timeout=120)
    r.raise_for_status()
    with open(os.path.join(dest, "capec_latest.xml"), "wb") as f:
        f.write(r.content)
    print(f"CAPEC -> {os.path.join(dest, 'capec_latest.xml')}")
    # Refuse a catalogue the engine cannot read (e.g. a new MITRE schema), so the image build
    # fails loudly instead of shipping threat models without CWE names and mitigations.
    cwe = CweCatalog(latest)
    capec = CapecCatalog(os.path.join(dest, "capec_latest.xml"))
    print(f"Parsed CWE {cwe.version}: {len(cwe.weaknesses)} weaknesses "
          f"({sum(1 for w in cwe.weaknesses.values() if w['mitigations'])} with mitigations); "
          f"CAPEC {capec.version}: {len(capec.patterns)} patterns")
    if len(cwe.weaknesses) < 100 or not capec.patterns:
        print("ERROR: the downloaded catalogues could not be parsed; update app/engine/catalogs.py", file=sys.stderr)
        return 1
    print("Set CWEC_FILE_PATH=data/cwec_latest.xml to use the refreshed CWE catalogue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
