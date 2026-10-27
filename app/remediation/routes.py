import ipaddress
import json
import sqlite3
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request

from app.audit import append_audit_entry
from app.db import get_db
from app.remediation import advise_remediation
from app.remediation.advisor import AdvisoryTargetError
from app.remediation.executor import (
    RemediationExecutionError,
    approve_firewall_block,
    remove_firewall_block,
)


remediation_api = Blueprint("remediation_api", __name__)


def _require_local_ui_intent():
    try:
        if not ipaddress.ip_address(request.remote_addr).is_loopback:
            return jsonify(error={"code": "loopback_required", "message": "Web-based firewall actions are restricted to local loopback requests."}), 403
    except (TypeError, ValueError):
        return jsonify(error={"code": "loopback_required", "message": "Web-based firewall actions are restricted to local loopback requests."}), 403

    if request.headers.get("X-SentinelX-Request") != "1":
        return jsonify(error={"code": "request_intent_required", "message": "Send the SentinelX UI intent header for this state-changing request."}), 403
    origin = request.headers.get("Origin")
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc.casefold() != request.host.casefold() or parsed.scheme not in {"http", "https"}:
            return jsonify(error={"code": "cross_origin_request", "message": "Cross-origin state-changing requests are not accepted."}), 403
    return None


def _error_response(code, message, status):
    return jsonify(error={"code": code, "message": message}), status


@remediation_api.get("/api/remediation")
def remediation_recommendations():
    rows = get_db().execute(
        "SELECT r.id, r.alert_id, r.incident_id, r.action_type, r.status, r.title, "
        "r.rationale, r.target_json, r.mitre_technique_id, r.mitre_technique_name, "
        "r.requires_human_approval, r.created_at, r.execution_status, "
        "r.firewall_removal_status, r.firewall_removed_at, "
        "COALESCE(a.title, i.title) AS subject_title "
        "FROM remediation_actions r "
        "LEFT JOIN alerts a ON a.id = r.alert_id "
        "LEFT JOIN incidents i ON i.id = r.incident_id "
        "WHERE r.action_type = 'block_source_ip' "
        "ORDER BY r.created_at DESC LIMIT 100"
    ).fetchall()
    recommendations = []
    for row in rows:
        item = dict(row)
        try:
            target = json.loads(item.pop("target_json"))
        except (json.JSONDecodeError, TypeError):
            current_app.logger.error("Invalid target data for remediation action %s.", item["id"])
            return _error_response(
                "invalid_recommendation_data",
                "A stored firewall recommendation has invalid target data; inspect the local database.",
                500,
            )
        if not isinstance(target, dict):
            current_app.logger.error("Invalid target data for remediation action %s.", item["id"])
            return _error_response(
                "invalid_recommendation_data",
                "A stored firewall recommendation has invalid target data; inspect the local database.",
                500,
            )
        item["target"] = target
        item["subject_type"] = "alert" if item["alert_id"] else "incident"
        item["subject_id"] = item["alert_id"] or item["incident_id"]
        recommendations.append(item)
    return jsonify(data={"recommendations": recommendations})


@remediation_api.post("/api/remediation/run-advisor")
def run_remediation_advisor():
    rejected = _require_local_ui_intent()
    if rejected:
        return rejected
    payload = request.get_json(silent=True)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"subject_type", "subject_id"}
        or not isinstance(payload.get("subject_type"), str)
        or payload["subject_type"] not in {"alert", "incident"}
        or not isinstance(payload.get("subject_id"), str)
        or not payload["subject_id"].strip()
    ):
        return _error_response(
            "invalid_request",
            "Provide subject_type (alert or incident) and a non-empty subject_id.",
            400,
        )
    try:
        result = advise_remediation(
            get_db(), payload["subject_type"], payload["subject_id"].strip()
        )
    except AdvisoryTargetError as error:
        return _error_response("advisory_unavailable", str(error), 422)
    return jsonify(data=result), 200


def _execute_firewall_action(action_id, operation):
    rejected = _require_local_ui_intent()
    if rejected:
        return rejected
    payload = request.get_json(silent=True)
    confirm_ip = payload.get("confirm_ip") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"confirm_ip"}
        or not isinstance(confirm_ip, str)
        or not confirm_ip.strip()
    ):
        return _error_response(
            "invalid_confirmation",
            "Type the exact recommendation IP in confirm_ip to approve this action.",
            400,
        )
    try:
        ipaddress.ip_address(confirm_ip)
    except ValueError:
        return _error_response("invalid_confirmation", "confirm_ip must be a valid IP address.", 400)

    try:
        action = (
            approve_firewall_block if operation == "approve" else remove_firewall_block
        )(get_db(), action_id, confirm_ip, True)
    except RemediationExecutionError as error:
        connection = get_db()
        if connection.execute(
            "SELECT 1 FROM remediation_actions WHERE id = ?", (action_id,)
        ).fetchone():
            append_audit_entry(
                connection,
                f"remediation.firewall_{operation}_rejected",
                "remediation_action",
                action_id,
                {"reason": str(error), "human_approval_attempted": True},
            )
            connection.commit()
        status = 404 if "not found" in str(error).casefold() else 409
        return _error_response("remediation_action_rejected", str(error), status)
    except sqlite3.Error:
        get_db().rollback()
        current_app.logger.exception("Firewall remediation %s failed for %s.", operation, action_id)
        raise
    return jsonify(data=action), 200


@remediation_api.post("/api/remediation/approve/<action_id>")
def approve_remediation(action_id):
    return _execute_firewall_action(action_id, "approve")


@remediation_api.post("/api/remediation/remove/<action_id>")
def remove_remediation(action_id):
    return _execute_firewall_action(action_id, "remove")
