from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
import uuid

from app.audit import append_audit_entry


SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
CORRELATION_WINDOW_SECONDS = 30 * 60


def _event_time(value):
    timestamp = value
    parsed = datetime.fromisoformat(
        timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _alerts(connection):
    rows = connection.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.triggered_at, a.rule_id, "
        "GROUP_CONCAT(DISTINCT e.id) AS event_ids "
        "FROM alerts a LEFT JOIN alert_events ae ON ae.alert_id = a.id "
        "LEFT JOIN security_events e ON e.id = ae.event_id "
        "GROUP BY a.id ORDER BY a.triggered_at, a.id"
    ).fetchall()
    result = []
    for row in rows:
        alert = dict(row)
        events = connection.execute(
            "SELECT e.id, e.observed_at, e.event_type, e.outcome, e.username, "
            "e.source_ip, e.host_name "
            "FROM alert_events ae JOIN security_events e ON e.id = ae.event_id "
            "WHERE ae.alert_id = ? ORDER BY e.observed_at, e.id",
            (alert["id"],),
        ).fetchall()
        alert["events"] = [dict(event) for event in events]
        alert["event_ids_set"] = {event["id"] for event in events}
        alert["times"] = [_event_time(event["observed_at"]) for event in events]
        alert["source_accounts"] = {
            (event["source_ip"], event["username"])
            for event in events
            if event["source_ip"] and event["username"]
        }
        alert["host_sources"] = {
            (event["host_name"], event["source_ip"])
            for event in events
            if event["host_name"] and event["source_ip"]
        }
        result.append(alert)
    return result


def _related(left, right):
    if left["event_ids_set"].intersection(right["event_ids_set"]):
        return True
    if not left["times"] or not right["times"]:
        return False
    left_start, left_end = min(left["times"]), max(left["times"])
    right_start, right_end = min(right["times"]), max(right["times"])
    interval_gap = max(
        0,
        (right_start - left_end).total_seconds(),
        (left_start - right_end).total_seconds(),
    )
    if interval_gap > CORRELATION_WINDOW_SECONDS:
        return False
    return bool(
        left["source_accounts"].intersection(right["source_accounts"])
        or left["host_sources"].intersection(right["host_sources"])
    )


def _components(alerts):
    by_id = {alert["id"]: alert for alert in alerts}
    neighbors = defaultdict(set)
    for index, left in enumerate(alerts):
        for right in alerts[index + 1 :]:
            if _related(left, right):
                neighbors[left["id"]].add(right["id"])
                neighbors[right["id"]].add(left["id"])

    seen = set()
    components = []
    for alert_id in by_id:
        if alert_id in seen:
            continue
        pending = [alert_id]
        seen.add(alert_id)
        component = []
        while pending:
            current = pending.pop()
            component.append(by_id[current])
            for neighbor in neighbors[current] - seen:
                seen.add(neighbor)
                pending.append(neighbor)
        components.append(sorted(component, key=lambda alert: alert["id"]))
    return components


def _correlation_rationale(alerts):
    evidence_ids = set().union(*(alert["event_ids_set"] for alert in alerts))
    shared_sources = set.intersection(
        *(alert["source_accounts"] for alert in alerts)
    ) if len(alerts) > 1 and all(alert["source_accounts"] for alert in alerts) else set()
    shared_host_sources = set.intersection(
        *(alert["host_sources"] for alert in alerts)
    ) if len(alerts) > 1 and all(alert["host_sources"] for alert in alerts) else set()
    if len(alerts) == 1:
        return "Single alert grouped as an incident; no related alert was present."
    if shared_sources:
        source_ip, username = sorted(shared_sources)[0]
        return (
            f"{len(alerts)} alerts share source IP {source_ip} and account {username}; "
            f"their evidence timestamps are within {CORRELATION_WINDOW_SECONDS // 60} minutes."
        )
    if shared_host_sources:
        host_name, source_ip = sorted(shared_host_sources)[0]
        return (
            f"{len(alerts)} alerts share host {host_name} and source IP {source_ip}; "
            f"their evidence timestamps are within {CORRELATION_WINDOW_SECONDS // 60} minutes."
        )
    return (
        f"{len(alerts)} alerts share {len(evidence_ids)} supporting event(s). "
        "Shared evidence provides the correlation."
    )


def group_alerts_into_incidents(connection: sqlite3.Connection):
    """Group related alerts by shared event or same source/account within 30 minutes."""
    alerts = _alerts(connection)
    components = _components(alerts)
    created = 0
    updated = 0
    unchanged = 0
    linked_alerts = 0
    now = datetime.now(timezone.utc).isoformat()

    try:
        for component in components:
            alert_ids = [alert["id"] for alert in component]
            placeholders = ",".join("?" for _ in alert_ids)
            linked_incidents = connection.execute(
                f"SELECT DISTINCT incident_id FROM incident_alerts "
                f"WHERE alert_id IN ({placeholders})",
                alert_ids,
            ).fetchall()

            if len(linked_incidents) > 1:
                unchanged += 1
                continue

            rationale = _correlation_rationale(component)
            severity = max(
                (alert["severity"] for alert in component),
                key=lambda value: SEVERITY_ORDER[value],
            )
            alert_names = list(dict.fromkeys(alert["title"] for alert in component))
            title = "Correlated activity: " + " · ".join(alert_names)
            event_ids = sorted(
                set().union(*(alert["event_ids_set"] for alert in component))
            )
            findings = json.dumps(
                {
                    "classification": "observed_facts",
                    "correlation": rationale,
                    "alert_ids": alert_ids,
                    "event_ids": event_ids,
                    "limitations": "Correlation is deterministic and indicates related evidence, not a confirmed incident cause.",
                },
                sort_keys=True,
            )
            if linked_incidents:
                incident_id = linked_incidents[0]["incident_id"]
                incident = connection.execute(
                    "SELECT id, title, severity, findings FROM incidents WHERE id = ?",
                    (incident_id,),
                ).fetchone()
                if incident is None:
                    raise sqlite3.IntegrityError(
                        f"Incident link references missing incident {incident_id}."
                    )
                existing_ids = {
                    row["alert_id"]
                    for row in connection.execute(
                        "SELECT alert_id FROM incident_alerts WHERE incident_id = ?",
                        (incident_id,),
                    ).fetchall()
                }
                additions = [alert_id for alert_id in alert_ids if alert_id not in existing_ids]
                if additions:
                    connection.executemany(
                        "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                        [(incident_id, alert_id) for alert_id in additions],
                    )
                    connection.execute(
                        "UPDATE incidents SET title = ?, findings = ?, updated_at = ? WHERE id = ?",
                        (title[:512], findings, now, incident_id),
                    )
                    updated += 1
                    linked_alerts += len(additions)
                else:
                    unchanged += 1
                if SEVERITY_ORDER[severity] > SEVERITY_ORDER[incident["severity"]]:
                    connection.execute(
                        "UPDATE incidents SET severity = ?, updated_at = ? WHERE id = ?",
                        (severity, now, incident_id),
                    )
                continue

            correlation_key = hashlib.sha256(
                "|".join(alert_ids).encode("utf-8")
            ).hexdigest()
            incident_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO incidents "
                "(id, title, severity, status, findings, correlation_key, created_at, updated_at) "
                "VALUES (?, ?, ?, 'New', ?, ?, ?, ?)",
                (incident_id, title[:512], severity, findings, correlation_key, now, now),
            )
            connection.executemany(
                "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                [(incident_id, alert_id) for alert_id in alert_ids],
            )
            append_audit_entry(
                connection,
                "incident.created_from_alerts",
                "incident",
                incident_id,
                {"alert_ids": alert_ids, "correlation": rationale},
            )
            created += 1
            linked_alerts += len(alert_ids)
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise

    return {
        "incidents_created": created,
        "incidents_updated": updated,
        "groups_unchanged": unchanged,
        "alerts_linked": linked_alerts,
        "alerts_considered": len(alerts),
        "completed_at": now,
    }
