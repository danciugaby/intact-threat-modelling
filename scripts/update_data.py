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
    print("Set CWEC_FILE_PATH=data/cwec_latest.xml to use the refreshed CWE catalogue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
