import json


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}
RISK_SCORES = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "informational": 10,
}
TACTICS = {
    "T1110": "Credential Access",
    "T1046": "Discovery",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1027": "Defense Evasion",
    "T1003": "Credential Access",
    "T1490": "Impact",
    "T1204.002": "Execution",
    "T1078": "Initial Access",
    "T1548": "Privilege Escalation",
}
INDICATOR_EXPLANATIONS = {
    "encoded_command": "The endpoint collector locally marked an encoded command pattern. Encoded commands can be legitimate; inspect the signed script and parent process.",
    "download_cradle": "The endpoint collector locally marked a script download-and-execute pattern. Verify the destination and software deployment context.",
    "credential_access_signature": "The endpoint collector locally marked a credential-access tool or command signature. Confirm whether an approved security assessment was running.",
    "shadow_copy_deletion": "A script or process matched a shadow-copy deletion pattern that could reduce recovery options. Confirm immediately with the host owner.",
    "suspicious_process": "The endpoint collector marked a process pattern for review. Validate the process name, parent, account, and change records.",
}


class AnalysisTargetError(ValueError):
    """The requested analysis target is absent or has no linked evidence."""


def _load_subject(connection, subject_type, subject_id):
    if subject_type == "alert":
        alerts = connection.execute(
            "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
            "r.rule_id, r.name AS rule_name, r.mitre_technique_id, "
            "r.mitre_technique_name, r.mitre_rationale, r.recommended_steps_json "
            "FROM alerts a LEFT JOIN detection_rules r ON r.rule_id = a.rule_id "
            "WHERE a.id = ?",
            (subject_id,),
        ).fetchall()
        if not alerts:
            raise AnalysisTargetError("Alert was not found.")
        event_filter = "ae.alert_id = ?"
        parameters = (subject_id,)
        subject_title = alerts[0]["title"]
    elif subject_type == "incident":
        incident = connection.execute(
            "SELECT id, title FROM incidents WHERE id = ?", (subject_id,)
        ).fetchone()
        if not incident:
            raise AnalysisTargetError("Incident was not found.")
        alerts = connection.execute(
            "SELECT a.id, a.title, a.severity, a.status, a.explanation, a.triggered_at, "
            "r.rule_id, r.name AS rule_name, r.mitre_technique_id, "
            "r.mitre_technique_name, r.mitre_rationale, r.recommended_steps_json "
            "FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
            "LEFT JOIN detection_rules r ON r.rule_id = a.rule_id "
            "WHERE ia.incident_id = ? ORDER BY a.triggered_at, a.id",
            (subject_id,),
        ).fetchall()
        event_filter = "ae.alert_id IN (SELECT alert_id FROM incident_alerts WHERE incident_id = ?)"
        parameters = (subject_id,)
        subject_title = incident["title"]
    else:
        raise AnalysisTargetError("subject_type must be alert or incident.")

    events = connection.execute(
        "SELECT DISTINCT e.id, e.observed_at, e.event_type, e.outcome, e.username, "
        "e.source_ip, e.host_name, e.process_id, e.process_name, "
        "e.parent_process_name, e.destination_port, e.file_hash, e.indicator_tags_json "
        "FROM alert_events ae JOIN security_events e ON e.id = ae.event_id "
        f"WHERE {event_filter} ORDER BY e.observed_at, e.id",
        parameters,
    ).fetchall()
    if not events:
        raise AnalysisTargetError("The subject has no linked event evidence to analyze.")
    return subject_title, [dict(item) for item in alerts], [dict(item) for item in events]


def analyze_subject(connection, subject_type, subject_id):
    """Build a local, deterministic threat summary without sending telemetry externally."""
    subject_title, alerts, events = _load_subject(connection, subject_type, subject_id)
    severity = max(
        (alert["severity"] for alert in alerts),
        key=lambda item: SEVERITY_ORDER.get(item, 0),
        default="medium",
    )
    tags = set()
    for event in events:
        try:
            parsed_tags = json.loads(event.get("indicator_tags_json") or "[]")
        except json.JSONDecodeError as error:
            raise AnalysisTargetError("Stored host indicator metadata is invalid.") from error
        if not isinstance(parsed_tags, list) or not all(isinstance(tag, str) for tag in parsed_tags):
            raise AnalysisTargetError("Stored host indicator metadata is invalid.")
        tags.update(parsed_tags)

    explanations = [INDICATOR_EXPLANATIONS[tag] for tag in sorted(tags) if tag in INDICATOR_EXPLANATIONS]
    if any(event["event_type"] == "windows_firewall_blocked_5157" for event in events):
        explanations.append(
            "Windows Filtering Platform logged blocked connections. A burst across several ports can indicate reconnaissance, but can also come from approved scanners."
        )
    if any(event["event_type"] == "windows_file_reputation_suspicious" for event in events):
        explanations.append(
            "The file hash exceeded the configured external reputation threshold. Reputation results require local verification and can be incorrect."
        )
    if not explanations:
        explanations = [
            alert["explanation"] for alert in alerts if alert.get("explanation")
        ] or ["The linked events matched a configured SentinelX detection rule."]

    techniques = []
    seen = set()
    for alert in alerts:
        technique_id = alert.get("mitre_technique_id")
        if technique_id and technique_id not in seen:
            seen.add(technique_id)
            techniques.append(
                {
                    "technique_id": technique_id,
                    "technique_name": alert.get("mitre_technique_name"),
                    "tactic": TACTICS.get(technique_id, "Review"),
                }
            )
    if "shadow_copy_deletion" in tags and "T1490" not in seen:
        techniques.append(
            {"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"}
        )
    if tags & {"encoded_command", "download_cradle"} and "T1059.001" not in seen:
        techniques.append(
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"}
        )

    recommended_steps = []
    for alert in alerts:
        try:
            steps = json.loads(alert.get("recommended_steps_json") or "[]")
        except json.JSONDecodeError as error:
            raise AnalysisTargetError("Stored detection guidance is invalid.") from error
        if isinstance(steps, list):
            recommended_steps.extend(step for step in steps if isinstance(step, str))
    if not recommended_steps:
        recommended_steps = [
            "Verify the host, user, event time, and process context with the system owner.",
            "Preserve relevant endpoint and security logs before making changes.",
            "Use only approved response procedures and confirm business impact with an authorized operator.",
        ]

    evidence = {
        "event_count": len(events),
        "alert_count": len(alerts),
        "source_ips": sorted({event["source_ip"] for event in events if event["source_ip"]}),
        "hosts": sorted({event["host_name"] for event in events if event["host_name"]}),
        "process_names": sorted({event["process_name"] for event in events if event["process_name"]}),
        "parent_process_names": sorted({event["parent_process_name"] for event in events if event["parent_process_name"]}),
        "file_hashes": sorted({event["file_hash"] for event in events if event["file_hash"]}),
        "indicators": sorted(tags),
        "events": [
            {
                "event_id": event["id"],
                "observed_at": event["observed_at"],
                "event_type": event["event_type"],
                "outcome": event["outcome"],
                "username": event["username"],
                "source_ip": event["source_ip"],
                "host": event["host_name"],
                "process_id": event["process_id"],
                "process_name": event["process_name"],
                "parent_process_name": event["parent_process_name"],
                "file_sha256": event["file_hash"],
            }
            for event in events[:30]
        ],
    }
    return {
        "engine": "local_deterministic_evidence_analysis",
        "model_called": False,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_title": subject_title,
        "plain_language_explanation": " ".join(dict.fromkeys(explanations)),
        "risk": {
            "severity": severity,
            "score": RISK_SCORES.get(severity, 55),
            "basis": "Severity is derived from linked deterministic alerts and host-local indicators, not an autonomous model judgment.",
        },
        "mitre_attack": techniques,
        "recommended_actions": list(dict.fromkeys(recommended_steps))[:8],
        "evidence": evidence,
        "telemetry_disclosure": "Raw command lines, script bodies, and file contents are not stored or sent to an AI service. Process and identity metadata is disclosed to Gemini only after an explicit AI Solve action.",
    }
