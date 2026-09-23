"""INTACT Threat Modelling service - application factory."""
import logging
import os

from flask import Flask, jsonify, send_from_directory

from .config import Config
from .models import db


def create_app(config_object=Config, threat_modeler=None):
    app = Flask(__name__)
    app.config.from_object(config_object)
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    db.init_app(app)
    with app.app_context():
        db.create_all()

    if app.config.get("CORS_ORIGINS"):
        from flask_cors import CORS

        CORS(app, origins=app.config["CORS_ORIGINS"], supports_credentials=False)

    if threat_modeler is None:
        from .engine.modeler import ThreatModeler

        threat_modeler = ThreatModeler(app.config)
    app.extensions["threat_modeler"] = threat_modeler

    from .jobs import JobRunner

    app.extensions["job_runner"] = JobRunner(app, app.config.get("JOB_WORKERS", 2))

    from .api.routes import bp

    app.register_blueprint(bp)

    static_dir = os.path.join(os.path.dirname(__file__), "static")

    @app.get("/api/openapi.yaml")
    def openapi_spec():
        return send_from_directory(static_dir, "openapi.yaml", mimetype="application/yaml")

    @app.get("/api/docs")
    def api_docs():
        return send_from_directory(static_dir, "docs.html")

    @app.errorhandler(404)
    def _404(_):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(500)
    def _500(_):
        return jsonify({"error": "internal server error"}), 500

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    if not app.config.get("AUTH_ENABLED"):
        app.logger.warning("AUTH_ENABLED is false: the API is unauthenticated. Enable Keycloak for any "
                           "shared deployment.")
    return app
