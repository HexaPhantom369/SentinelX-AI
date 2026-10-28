from datetime import datetime, timezone
import ipaddress
import json
import logging
import sqlite3
import uuid

from app.audit import append_audit_entry
from app.remediation.process_policy import eligible_process

logger = logging.getLogger(__name__)

class AdvisoryTargetError(ValueError):
    """An alert or incident does not exist or has no evidence to assess."""


def _mitre_mappings(alerts):
    result = []
    seen = set()
    for alert in alerts:
        if not alert["mitre_technique_id"]:
            continue
        technique_id = alert["mitre_technique_id"]
        if technique_id in seen:
            continue
        seen.add(technique_id)
        result.append(
            {
                "technique_id": technique_id,
                "technique_name": alert["mitre_technique_name"],
                "rationale": alert["mitre_rationale"],
                "rule_id": alert["rule_id"],
            }
        )
    return result


def _recommendations(events, mitre_mappings):
    recommendations = []
    source_ips = sorted({event["source_ip"] for event in events if event["source_ip"]})
    global_ips = []
    for source_ip in source_ips:
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise AdvisoryTargetError(
                f"Stored event contains an invalid source IP address: {source_ip}."
            ) from error
        if address.is_global:
            global_ips.append(source_ip)

    for source_ip in global_ips[:10]:
        recommendations.append(
            {
                "action_type": "block_source_ip",
                "title": f"Review firewall blocking for {source_ip}",
                "target": {"source_ip": source_ip},
                "rationale": (
                    f"Source IP {source_ip} appears in the linked event evidence. "
                    "Verify it is not an approved VPN, proxy, shared NAT, or trusted service "
                    "before considering a temporary, scoped firewall block."
                ),
                "available": True,
                "requires_human_approval": True,
                "execution_available": False,
                "mitre_mappings": mitre_mappings,
            }
        )

    process_targets = {}
    for event in events:
        pid = eligible_process(event.get("process_id"), event.get("process_name"))
        name = event.get("process_name")
        try:
            tags = json.loads(event.get("indicator_tags_json") or "[]")
        except json.JSONDecodeError as error:
            raise AdvisoryTargetError("Stored process indicator metadata is invalid.") from error
        if (
            pid is None
            or event.get("event_type") != "windows_process_creation_4688"
            or not isinstance(tags, list)
            or not tags
        ):
            continue
        process_targets.setdefault((str(pid), name), event)
    for (pid, name), event in list(process_targets.items())[:10]:
        recommendations.append(
            {
                "action_type": "terminate_process",
                "title": f"Review process {name} (PID {pid})",
                "target": {
                    "process_id": pid,
                    "process_name": name,
                    "event_id": event["id"],
                    "observed_at": event["observed_at"],
                },
                "rationale": (
                    "This process identity is linked to a locally classified suspicious "
                    "endpoint event. Verify the live process and business impact; termination "
                    "requires an elevated Windows service and exact-PID human confirmation."
                ),
                "available": True,
                "requires_human_approval": True,
                "execution_available": True,
                "mitre_mappings": mitre_mappings,
            }
        )
    if not process_targets:
        recommendations.append(
            {
                "action_type": "terminate_process",
                "title": "No eligible suspicious process identity",
                "target": {"process_id": None, "process_name": None},
                "rationale": (
                    "No linked suspicious event includes a valid non-critical PID and process "
                    "name. Process termination is unavailable without that endpoint evidence."
                ),
                "available": False,
                "requires_human_approval": True,
                "execution_available": False,
                "mitre_mappings": mitre_mappings,
            }
        )
    if not global_ips:
        recommendations.append(
            {
                "action_type": "investigate",
                "title": "Review authentication source evidence",
                "target": {},
                "rationale": (
                    "No globally routable source IP was found in the linked evidence, so "
                    "firewall blocking is not recommended. Check internal identity and "
                    "network context instead."
                ),
                "available": True,
                "requires_human_approval": False,
                "execution_available": False,
                "mitre_mappings": mitre_mappings,
            }
        )
    return recommendations


def _load_alert(connection, alert_id):
    alert = connection.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
        "r.rule_id, r.mitre_technique_id, r.mitre_technique_name, r.mitre_rationale "
        "FROM alerts a LEFT JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.id = ?",
        (alert_id,),
    ).fetchone()
    if alert is None:
        raise AdvisoryTargetError("Alert was not found.")
    events = connection.execute(
        "SELECT e.id, e.observed_at, e.event_type, e.outcome, e.username, "
        "e.source_ip, e.host_name, e.process_id, e.process_name, e.indicator_tags_json "
        "FROM alert_events ae JOIN security_events e ON e.id = ae.event_id "
        "WHERE ae.alert_id = ? ORDER BY e.observed_at, e.id",
        (alert_id,),
    ).fetchall()
    return dict(alert), [dict(event) for event in events]


def _load_incident(connection, incident_id):
    incident = connection.execute(
        "SELECT id, title, severity, status, findings, created_at, updated_at "
        "FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()
    if incident is None:
        raise AdvisoryTargetError("Incident was not found.")
    alert_rows = connection.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
        "r.rule_id, r.mitre_technique_id, r.mitre_technique_name, r.mitre_rationale "
        "FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
        "LEFT JOIN detection_rules r ON r.rule_id = a.rule_id "
        "WHERE ia.incident_id = ? ORDER BY a.triggered_at, a.id",
        (incident_id,),
    ).fetchall()
    alerts = [dict(row) for row in alert_rows]
    events_by_id = {}
    for alert in alerts:
        rows = connection.execute(
            "SELECT e.id, e.observed_at, e.event_type, e.outcome, e.username, "
            "e.source_ip, e.host_name, e.process_id, e.process_name, e.indicator_tags_json "
            "FROM alert_events ae JOIN security_events e ON e.id = ae.event_id "
            "WHERE ae.alert_id = ?",
            (alert["id"],),
        ).fetchall()
        for row in rows:
            events_by_id[row["id"]] = dict(row)
    return dict(incident), alerts, list(events_by_id.values())


def _audit_advisory(connection, subject_type, subject_id, recommendations, evidence_count, mitre_mappings):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    for recommendation in recommendations:
        recommendation_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO remediation_actions "
            "(id, alert_id, incident_id, action_type, status, title, rationale, "
            "target_json, mitre_technique_id, mitre_technique_name, "
            "requires_human_approval, created_at) "
            "VALUES (?, ?, ?, ?, 'recommendation_only', ?, ?, ?, ?, ?, ?, ?)",
            (
                recommendation_id,
                subject_id if subject_type == "alert" else None,
                subject_id if subject_type == "incident" else None,
                recommendation["action_type"],
                recommendation["title"],
                recommendation["rationale"],
                json.dumps(
                    {
                        **recommendation["target"],
                        "available": recommendation["available"],
                        "execution_available": recommendation["execution_available"],
                    },
                    sort_keys=True,
                ),
                recommendation["mitre_mappings"][0]["technique_id"]
                if recommendation["mitre_mappings"]
                else None,
                recommendation["mitre_mappings"][0]["technique_name"]
                if recommendation["mitre_mappings"]
                else None,
                int(recommendation["requires_human_approval"]),
                now,
            ),
        )
        recommendation["recommendation_id"] = recommendation_id
    details = {
        "advisor": "deterministic_evidence_advisor",
        "run_id": run_id,
        "recommendation_count": len(recommendations),
        "action_types": [item["action_type"] for item in recommendations],
        "evidence_count": evidence_count,
        "mitre_mappings": mitre_mappings,
        "execution_performed": False,
        "human_approval_required_for_disruptive_actions": True,
    }
    append_audit_entry(
        connection,
        "ai_solve.recommendations_generated",
        subject_type,
        subject_id,
        details,
        created_at=now,
    )
    return run_id


def advise_remediation(connection: sqlite3.Connection, subject_type: str, subject_id: str):
    """Return deterministic, evidence-based advice; never execute operating-system actions."""
    if subject_type == "alert":
        alert, events = _load_alert(connection, subject_id)
        alerts = [alert]
    elif subject_type == "incident":
        _incident, alerts, events = _load_incident(connection, subject_id)
    else:
        raise AdvisoryTargetError("Unsupported advisory target.")
    if not events:
        raise AdvisoryTargetError(
            "The alert or incident has no linked event evidence; no remediation advice was generated."
        )

    mitre_mappings = _mitre_mappings(alerts)
    recommendations = _recommendations(events, mitre_mappings)
    observed_facts = {
        "alert_ids": [alert["id"] for alert in alerts],
        "event_count": len(events),
        "event_types": sorted({event["event_type"] for event in events}),
        "outcomes": sorted({event["outcome"] for event in events}),
        "source_ips": sorted({event["source_ip"] for event in events if event["source_ip"]}),
        "usernames": sorted({event["username"] for event in events if event["username"]}),
        "host_names": sorted({event["host_name"] for event in events if event["host_name"]}),
        "processes": [
            {"process_id": event["process_id"], "process_name": event["process_name"]}
            for event in events if event["process_id"] and event["process_name"]
        ],
    }
    try:
        run_id = _audit_advisory(
            connection,
            subject_type,
            subject_id,
            recommendations,
            len(events),
            mitre_mappings,
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        logger.exception("AI Solve advisory could not be written to the audit trail.")
        raise

    return {
        "run_id": run_id,
        "advisor": "deterministic_evidence_advisor",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "observed_facts": observed_facts,
        "mitre_mappings": mitre_mappings,
        "recommendations": recommendations,
        "limitations": [
            "This is a deterministic, evidence-based advisor; no external AI model was called.",
            "Recommendations are not executed. There is no endpoint agent or authenticated approval workflow in this phase.",
            "Process termination is unavailable because linked events contain no process identity.",
            "A source IP may be shared, trusted, or expected; verify context before considering firewall changes.",
        ],
        "execution_performed": False,
    }
