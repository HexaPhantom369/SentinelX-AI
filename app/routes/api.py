from datetime import datetime, timezone
import sqlite3

from flask import Blueprint, current_app, jsonify, request

from app.db import get_db
from app.detection import run_detections
from app.detection.engine import DetectionConfigurationError, DetectionDataError
from app.ingestion import ingest_log_file


api = Blueprint("api", __name__)


def _query_integer(name, default, minimum, maximum):
    value = request.args.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if minimum <= parsed <= maximum else None


@api.get("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
    except sqlite3.Error as error:
        current_app.logger.exception("Health check could not reach the database: %s", error)
        return jsonify(error={"code": "database_unavailable", "message": "The database is temporarily unavailable."}), 503

    return jsonify(
        data={
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@api.get("/dashboard")
def dashboard():
    connection = get_db()
    stats = {
        "security_events": connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0],
        "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "critical_alerts": connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' "
            "AND status IN ('New', 'Investigating', 'Escalated')"
        ).fetchone()[0],
        "high_alerts": connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'high' "
            "AND status IN ('New', 'Investigating', 'Escalated')"
        ).fetchone()[0],
        "open_incidents": connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('New', 'Investigating', 'Contained')"
        ).fetchone()[0],
        "enabled_rules": connection.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE enabled = 1"
        ).fetchone()[0],
    }
    latest_job = connection.execute(
        "SELECT status, finished_at, records_received, records_imported, records_rejected, records_duplicate "
        "FROM ingestion_jobs "
        "ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    latest_alerts = connection.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
        "r.rule_id, r.name AS rule_name, r.mitre_technique_id, r.mitre_technique_name, "
        "r.mitre_rationale, COUNT(ae.event_id) AS evidence_count "
        "FROM alerts a LEFT JOIN detection_rules r ON r.rule_id = a.rule_id "
        "LEFT JOIN alert_events ae ON ae.alert_id = a.id "
        "GROUP BY a.id "
        "ORDER BY a.triggered_at DESC LIMIT 10"
    ).fetchall()
    latest_events = connection.execute(
        "SELECT id, observed_at, event_type, outcome, username, source_ip, host_name "
        "FROM security_events ORDER BY observed_at DESC, ingested_at DESC LIMIT 10"
    ).fetchall()

    ingestion = (
        {
            "status": latest_job["status"],
            "finished_at": latest_job["finished_at"],
            "records_imported": latest_job["records_imported"],
            "records_received": latest_job["records_received"],
            "records_rejected": latest_job["records_rejected"],
            "records_duplicate": latest_job["records_duplicate"],
        }
        if latest_job
        else {
            "status": "not_configured",
            "finished_at": None,
            "records_imported": 0,
            "records_received": 0,
            "records_rejected": 0,
            "records_duplicate": 0,
        }
    )
    return jsonify(
        data={
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
            "ingestion": ingestion,
            "ai_analysis": {"status": "not_configured"},
            "recent_alerts": [dict(alert) for alert in latest_alerts],
            "recent_events": [dict(event) for event in latest_events],
        }
    )


@api.get("/events")
def events():
    limit = _query_integer("limit", 50, 1, 100)
    offset = _query_integer("offset", 0, 0, 1000000)
    if limit is None or offset is None:
        return jsonify(error={"code": "invalid_pagination", "message": "limit must be 1–100 and offset 0–1000000."}), 400
    rows = get_db().execute(
        "SELECT id, observed_at, event_type, outcome, username, source_ip, host_name "
        "FROM security_events ORDER BY observed_at DESC, ingested_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return jsonify(data={"events": [dict(row) for row in rows], "limit": limit, "offset": offset})


@api.post("/ingest")
def ingest():
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify(error={"code": "missing_file", "message": "Choose a JSON or CSV file to ingest."}), 400
    if not uploaded.filename:
        return jsonify(error={"code": "missing_filename", "message": "The uploaded file must have a filename."}), 400

    result = ingest_log_file(
        get_db(),
        uploaded.filename,
        uploaded.stream.read(current_app.config["MAX_CONTENT_LENGTH"] + 1),
        current_app.config["MAX_CONTENT_LENGTH"],
    )
    status_code = {"completed": 201, "partial": 207, "failed": 422}[result["status"]]
    return jsonify(data=result), status_code


@api.get("/detections/rules")
def detection_rules():
    rows = get_db().execute(
        "SELECT rule_id, name, description, severity, mitre_technique_id, "
        "mitre_technique_name, mitre_rationale, recommended_steps_json, config_json, enabled "
        "FROM detection_rules ORDER BY rule_id"
    ).fetchall()
    return jsonify(data={"rules": [dict(row) for row in rows]})


@api.post("/detections/run")
@api.post("/detection/run")
def evaluate_detections():
    try:
        result = run_detections(get_db())
    except DetectionConfigurationError as error:
        current_app.logger.warning("Detection run blocked by invalid rule configuration: %s", error)
        return jsonify(error={"code": "invalid_rule_configuration", "message": str(error)}), 422
    except DetectionDataError as error:
        current_app.logger.warning("Detection run blocked by invalid stored event data: %s", error)
        return jsonify(error={"code": "invalid_event_data", "message": str(error)}), 422
    return jsonify(data=result), 200
