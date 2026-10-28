import logging
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

from app.analysis.routes import analysis_api
from app.config import Config
from app.db import close_db, init_db_command
from app.detection.cli import run_detections_command
from app.incidents.cli import group_incidents_command
from app.incidents.routes import incidents_api
from app.ingestion.cli import ingest_logs_command
from app.routes import api, web
from app.threat_intel.routes import phase5_api
from app.remediation.cli import approve_remediation_command, remove_remediation_command
from app.remediation.routes import remediation_api


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    app.instance_path = str(Path(app.instance_path))
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    if not app.config.get("SECRET_KEY"):
        if os.environ.get("SENTINELX_ENV", "development").lower() == "production":
            raise RuntimeError("SENTINELX_SECRET_KEY must be set in production.")
        app.config["SECRET_KEY"] = secrets.token_hex(32)

    app.teardown_appcontext(close_db)
    app.register_blueprint(web)
    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(incidents_api)
    app.register_blueprint(phase5_api)
    app.register_blueprint(remediation_api)
    app.register_blueprint(analysis_api)
    app.cli.add_command(init_db_command)
    app.cli.add_command(ingest_logs_command)
    app.cli.add_command(run_detections_command)
    app.cli.add_command(group_incidents_command)
    app.cli.add_command(approve_remediation_command)
    app.cli.add_command(remove_remediation_command)

    @app.errorhandler(404)
    def not_found(error):
        if request.path == "/api" or request.path.startswith("/api/"):
            return jsonify(error={"code": "not_found", "message": "Resource not found."}), 404
        return error

    @app.errorhandler(sqlite3.Error)
    def database_error(error):
        app.logger.exception("Database operation failed: %s", error)
        return jsonify(error={"code": "database_unavailable", "message": "The database is temporarily unavailable."}), 503

    @app.errorhandler(500)
    def internal_error(_error):
        if request.path == "/api" or request.path.startswith("/api/"):
            return jsonify(error={"code": "internal_error", "message": "The request could not be completed."}), 500
        return "The request could not be completed.", 500

    @app.errorhandler(413)
    def request_too_large(_error):
        if request.path == "/api/ingest":
            return jsonify(error={"code": "file_too_large", "message": "Upload exceeds the configured file-size limit."}), 413
        return "Request exceeds the configured size limit.", 413

    if os.environ.get("SENTINELX_ENV", "development").lower() == "production":
        app.config["DEBUG"] = False
    if app.config["DEBUG"]:
        app.logger.setLevel(logging.DEBUG)

    return app
