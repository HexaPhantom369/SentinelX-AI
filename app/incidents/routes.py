from datetime import datetime, timezone
import json
import sqlite3

from app.audit import append_audit_entry

from flask import Blueprint, current_app, jsonify, request

from app.db import get_db
from app.incidents.service import group_alerts_into_incidents
from app.remediation import advise_remediation
from app.remediation.advisor import AdvisoryTargetError
from app.remediation.process_policy import eligible_process


incidents_api = Blueprint("incidents_api", __name__)
INCIDENT_STATUSES = {"New", "Investigating", "Contained", "Resolved"}
ALLOWED_TRANSITIONS = {
    "New": {"Investigating", "Contained", "Resolved"},
    "Investigating": {"New", "Contained", "Resolved"},
    "Contained": {"Investigating", "Resolved"},
    "Resolved": {"Investigating"},
}


def _insert_audit(connection, action, entity_type, entity_id, details):
    append_audit_entry(
        connection,
        action,
        entity_type,
        entity_id,
        details,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@incidents_api.post("/api/incidents/group")
def group_incidents():
    try:
        result = group_alerts_into_incidents(get_db())
    except sqlite3.Error as error:
        current_app.logger.exception("Incident grouping failed: %s", error)
        raise
    return jsonify(data=result), 200


@incidents_api.get("/api/incidents")
def list_incidents():
    rows = get_db().execute(
        "SELECT i.id, i.title, i.severity, i.status, i.findings, i.created_at, i.updated_at, "
        "COUNT(DISTINCT ia.alert_id) AS alert_count, COUNT(DISTINCT ae.event_id) AS evidence_count "
        "FROM incidents i "
        "LEFT JOIN incident_alerts ia ON ia.incident_id = i.id "
        "LEFT JOIN alert_events ae ON ae.alert_id = ia.alert_id "
        "GROUP BY i.id ORDER BY i.updated_at DESC LIMIT 100"
    ).fetchall()
    return jsonify(data={"incidents": [dict(row) for row in rows]})


@incidents_api.get("/api/incidents/<incident_id>")
def incident_detail(incident_id):
    connection = get_db()
    incident = connection.execute(
        "SELECT id, title, severity, status, findings, created_at, updated_at "
        "FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()
    if incident is None:
        return jsonify(error={"code": "incident_not_found", "message": "Incident was not found."}), 404

    alert_rows = connection.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
        "r.rule_id, r.mitre_technique_id, r.mitre_technique_name "
        "FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
        "LEFT JOIN detection_rules r ON r.rule_id = a.rule_id "
        "WHERE ia.incident_id = ? ORDER BY a.triggered_at, a.id",
        (incident_id,),
    ).fetchall()
    note_rows = connection.execute(
        "SELECT id, body, classification, created_at FROM investigation_notes "
        "WHERE incident_id = ? ORDER BY created_at, id",
        (incident_id,),
    ).fetchall()
    event_rows = connection.execute(
        "SELECT DISTINCT e.id, e.observed_at, e.event_type, e.outcome, e.username, "
        "e.source_ip, e.host_name, e.process_id, e.process_name, "
        "e.parent_process_name, e.file_hash, e.indicator_tags_json "
        "FROM incident_alerts ia "
        "JOIN alert_events ae ON ae.alert_id = ia.alert_id "
        "JOIN security_events e ON e.id = ae.event_id "
        "WHERE ia.incident_id = ? ORDER BY e.observed_at, e.id",
        (incident_id,),
    ).fetchall()
    timeline = []
    for event in event_rows:
        event_data = dict(event)
        if (
            event_data["event_type"] == "windows_process_creation_4688"
            and eligible_process(event_data["process_id"], event_data["process_name"])
        ):
            try:
                tags = json.loads(event_data.pop("indicator_tags_json") or "[]")
            except json.JSONDecodeError:
                tags = []
            event_data["process_action_available"] = isinstance(tags, list) and bool(tags)
        else:
            event_data.pop("indicator_tags_json", None)
            event_data["process_action_available"] = False
        timeline.append(
            {
                "timestamp": event["observed_at"],
                "type": "event",
                "classification": "observed_fact",
                "data": event_data,
            }
        )
    timeline.extend(
        {
            "timestamp": alert["triggered_at"],
            "type": "alert",
            "classification": "detection_finding",
            "data": dict(alert),
        }
        for alert in alert_rows
    )
    timeline.extend(
        {
            "timestamp": note["created_at"],
            "type": "note",
            "classification": note["classification"],
            "data": dict(note),
        }
        for note in note_rows
    )
    timeline.sort(key=lambda item: (item["timestamp"], item["type"]))
    return jsonify(
        data={
            "incident": dict(incident),
            "alerts": [dict(alert) for alert in alert_rows],
            "notes": [dict(note) for note in note_rows],
            "timeline": timeline,
        }
    )


@incidents_api.patch("/api/incidents/<incident_id>")
def update_incident(incident_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"status"}:
        return jsonify(error={"code": "invalid_request", "message": "Provide only a valid incident status."}), 400
    status = payload.get("status")
    if status not in INCIDENT_STATUSES:
        return jsonify(
            error={
                "code": "invalid_status",
                "message": f"status must be one of: {', '.join(sorted(INCIDENT_STATUSES))}.",
            }
        ), 400

    connection = get_db()
    incident = connection.execute(
        "SELECT status FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()
    if incident is None:
        return jsonify(error={"code": "incident_not_found", "message": "Incident was not found."}), 404
    previous_status = incident["status"]
    if status == previous_status:
        return jsonify(data={"id": incident_id, "status": status, "changed": False})
    if status not in ALLOWED_TRANSITIONS[previous_status]:
        return jsonify(
            error={
                "code": "invalid_transition",
                "message": f"Cannot transition an incident from {previous_status} to {status}.",
            }
        ), 409

    now = datetime.now(timezone.utc).isoformat()
    try:
        connection.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, incident_id),
        )
        _insert_audit(
            connection,
            "incident.status_changed",
            "incident",
            incident_id,
            {"from": previous_status, "to": status},
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise
    return jsonify(data={"id": incident_id, "status": status, "changed": True})


@incidents_api.post("/api/alerts/<alert_id>/ai-solve")
def advise_alert(alert_id):
    try:
        result = advise_remediation(get_db(), "alert", alert_id)
    except AdvisoryTargetError as error:
        return jsonify(error={"code": "advisory_unavailable", "message": str(error)}), 422
    return jsonify(data=result), 200


@incidents_api.get("/api/alerts/<alert_id>/remediation")
def alert_remediation_history(alert_id):
    connection = get_db()
    if connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        return jsonify(error={"code": "alert_not_found", "message": "Alert was not found."}), 404
    rows = connection.execute(
        "SELECT id, action_type, status, title, rationale, target_json, "
        "mitre_technique_id, mitre_technique_name, requires_human_approval, created_at, "
        "execution_status, execution_at, execution_details, firewall_removed_at, "
        "firewall_removal_status "
        "FROM remediation_actions WHERE alert_id = ? ORDER BY created_at DESC",
        (alert_id,),
    ).fetchall()
    return jsonify(data={"recommendations": [dict(row) for row in rows]})


@incidents_api.post("/api/incidents/<incident_id>/ai-solve")
def advise_incident(incident_id):
    try:
        result = advise_remediation(get_db(), "incident", incident_id)
    except AdvisoryTargetError as error:
        return jsonify(error={"code": "advisory_unavailable", "message": str(error)}), 422
    return jsonify(data=result), 200


@incidents_api.get("/api/incidents/<incident_id>/remediation")
def incident_remediation_history(incident_id):
    connection = get_db()
    if connection.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
        return jsonify(error={"code": "incident_not_found", "message": "Incident was not found."}), 404
    rows = connection.execute(
        "SELECT id, action_type, status, title, rationale, target_json, "
        "mitre_technique_id, mitre_technique_name, requires_human_approval, created_at, "
        "execution_status, execution_at, execution_details, firewall_removed_at, "
        "firewall_removal_status "
        "FROM remediation_actions WHERE incident_id = ? ORDER BY created_at DESC",
        (incident_id,),
    ).fetchall()
    return jsonify(data={"recommendations": [dict(row) for row in rows]})
