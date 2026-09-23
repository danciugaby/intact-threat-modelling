"""Mock upstream services for the sandbox and the end-to-end tests.

Serves:
  * an INTACT Risk Assessment API with one demo topology per pilot
      GET /ra/topologies/<pilot>/assets     -> {"content": [{"id": ...}, ...]}
      GET /ra/assets/<asset_id>             -> asset with attributes + relationships
  * an offline NVD CVE API 2.0 stand-in (recorded fixture), used when OFFLINE=1
      GET /nvd/rest/json/cves/2.0
  * GET /health

Run:  python sandbox/mock_services.py [--port 5100]
"""

import argparse
import json
import os

from flask import Flask, abort, jsonify

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def create_mock_app():
    app = Flask("mock_services")
    with open(os.path.join(HERE, "topologies.json")) as f:
        topologies = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    assets = {a["id"]: a for topo in topologies.values() for a in topo}
    with open(os.path.join(ROOT, "tests", "fixtures", "nvd_cisco_ios_xe.json")) as f:
        nvd_fixture = json.load(f)

    def render_asset(a):
        out = {
            "id": a["id"],
            "name": a["name"],
            "attributes": a.get("attributes", []),
            "relationships": [
                {
                    "relatedAsset": {"id": r["to"], "name": assets[r["to"]]["name"]},
                    "relationshipType": {"id": r["type"]},
                }
                for r in a.get("relationships", [])
            ],
        }
        if a.get("cpe23name"):
            out["cpe23name"] = a["cpe23name"]
        return out

    @app.get("/health")
    def health():
        return {"status": "ok", "topologies": sorted(topologies)}

    @app.get("/ra/topologies/<topology_id>/assets")
    def topology(topology_id):
        if topology_id not in topologies:
            abort(404)
        return jsonify({"content": [{"id": a["id"]} for a in topologies[topology_id]]})

    @app.get("/ra/assets/<asset_id>")
    def asset(asset_id):
        if asset_id not in assets:
            abort(404)
        return jsonify(render_asset(assets[asset_id]))

    @app.get("/nvd/rest/json/cves/2.0")
    def nvd():
        return jsonify(nvd_fixture)

    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.getenv("MOCK_PORT", "5100")))
    args = ap.parse_args()
    create_mock_app().run(host=args.host, port=args.port)
