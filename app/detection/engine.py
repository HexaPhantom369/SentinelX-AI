from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import sqlite3
import uuid


logger = logging.getLogger(__name__)

RULE_DEFINITIONS = (
    {
        "rule_id": "R001",
        "name": "Repeated authentication failures",
        "description": "Detects repeated failed authentication from one source within a time window.",
        "severity": "high",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_rationale": "Repeated failed authentication attempts are consistent with brute-force behavior, but do not prove an attack.",
        "thresholds": {"attempts": 5, "window_minutes": 10},
        "recommended_steps": [
            "Review the supporting authentication events and verify the source and account context.",
            "Check whether the affected user recognizes the activity.",
            "Correlate with endpoint or identity-provider logs before escalation.",
        ],
    },
    {
        "rule_id": "R002",
        "name": "Successful logins from multiple sources",
        "description": "Flags one account with successful authentication from multiple source IPs in a short period.",
        "severity": "medium",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "mitre_rationale": "Multiple successful source addresses may warrant review for valid-account misuse; the pattern may also reflect VPNs, NAT, or normal travel.",
        "thresholds": {"distinct_sources": 2, "window_minutes": 15},
        "recommended_steps": [
            "Confirm whether the source addresses are expected VPN, proxy, or NAT egress points.",
            "Check the account owner and authentication context with the identity provider.",
        ],
    },
    {
        "rule_id": "R003",
        "name": "Successful login after repeated failures",
        "description": "Detects a success after repeated failures for the same account and source within a time window.",
        "severity": "high",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_rationale": "A successful authentication following repeated failures can be consistent with a brute-force sequence, but the events alone do not establish compromise.",
        "thresholds": {"failures": 3, "window_minutes": 15},
        "recommended_steps": [
            "Review the linked failures and successful login together.",
            "Verify the login with the account owner and inspect independent identity logs.",
        ],
    },
    {
        "rule_id": "R004",
        "name": "High authentication frequency",
        "description": "Flags a high volume of authentication events from one source in a short time window.",
        "severity": "medium",
        "mitre_technique_id": None,
        "mitre_technique_name": None,
        "mitre_rationale": None,
        "thresholds": {"events": 10, "window_minutes": 5},
        "recommended_steps": [
            "Check whether the source is an expected authentication gateway or automated service.",
            "Review the event mix and related accounts before deciding whether to escalate.",
        ],
    },
    {
        "rule_id": "R005",
        "name": "Multiple accounts from one source",
        "description": "Detects failed authentication against multiple accounts from one source within a time window.",
        "severity": "high",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_rationale": "Repeated failures targeting distinct accounts from one source are consistent with password-spraying behavior; they are not proof of malicious intent.",
        "thresholds": {"distinct_accounts": 3, "window_minutes": 10},
        "recommended_steps": [
            "Review the targeted accounts and confirm whether the source belongs to an approved system.",
            "Correlate with identity-provider controls and other relevant authentication evidence.",
        ],
    },
    {
        "rule_id": "R006",
        "name": "Explicit privilege escalation event",
        "description": "Highlights events explicitly labeled as a privilege escalation.",
        "severity": "medium",
        "mitre_technique_id": "T1548",
        "mitre_technique_name": "Abuse Elevation Control Mechanism",
        "mitre_rationale": "Only explicit event-type labels indicating privilege escalation are mapped; a generic sudo or administrator login is not sufficient evidence.",
        "thresholds": {},
        "recommended_steps": [
            "Verify the actor, target account, host, and authorization for the recorded privilege change.",
            "Review surrounding system and identity events; this detection is not a finding of unauthorized activity.",
        ],
    },
    {
        "rule_id": "R007",
        "name": "Blocked multi-port connection burst",
        "description": "Detects a short burst of blocked firewall connections to multiple destination ports from one source.",
        "severity": "high",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_rationale": "A concentrated multi-port burst may reflect service discovery or scanning; legitimate monitoring and misconfigured clients can produce similar events.",
        "thresholds": {"events": 10, "distinct_ports": 5, "window_minutes": 2},
        "recommended_steps": [
            "Check the source IP against approved scanners, VPNs, and monitoring systems.",
            "Review the blocked destination ports and correlate with firewall and endpoint records.",
            "Do not block shared or trusted infrastructure without an operator's impact review.",
        ],
    },
    {
        "rule_id": "R008",
        "name": "Potential shadow-copy destruction command",
        "description": "Highlights locally classified script or process telemetry matching a shadow-copy deletion indicator.",
        "severity": "critical",
        "mitre_technique_id": "T1490",
        "mitre_technique_name": "Inhibit System Recovery",
        "mitre_rationale": "A local indicator match for shadow-copy deletion is consistent with recovery-inhibition behavior; verify the process and administrative context before response.",
        "thresholds": {},
        "recommended_steps": [
            "Verify the host, user, process name, and change-management context immediately.",
            "Preserve endpoint and security logs; coordinate response with the host owner.",
            "Use authorized endpoint controls only after confirming the process and operational impact.",
        ],
    },
    {
        "rule_id": "R009",
        "name": "Suspicious script or process indicator",
        "description": "Highlights locally classified encoded, download-cradle, or credential-access telemetry.",
        "severity": "high",
        "mitre_technique_id": "T1059.001",
        "mitre_technique_name": "PowerShell",
        "mitre_rationale": "The local collector observed a high-risk command pattern; legitimate administration tools may use similar behavior and the raw command is intentionally not stored.",
        "thresholds": {},
        "recommended_steps": [
            "Review the process name, parent process, host, user, and event time with the endpoint owner.",
            "Inspect approved software and change records before classifying the activity.",
            "Escalate through the organization's authorized endpoint-response process if corroborated.",
        ],
    },
    {
        "rule_id": "R010",
        "name": "File hash reported suspicious",
        "description": "Highlights a newly observed file hash that crossed the configured VirusTotal reputation threshold.",
        "severity": "high",
        "mitre_technique_id": "T1204.002",
        "mitre_technique_name": "Malicious File",
        "mitre_rationale": "A multi-engine reputation result is an investigative signal, not proof; verify the file and host context before response.",
        "thresholds": {},
        "recommended_steps": [
            "Verify the file hash and owning host with the endpoint operator.",
            "Review reputation detections and trusted software distribution records.",
            "Do not delete or quarantine the file automatically; follow the authorized endpoint process.",
        ],
    },
)

AUTHENTICATION_TERMS = {"auth", "authentication", "authenticate", "login", "logon", "ssh", "signin"}
PRIVILEGE_EVENT_TERMS = (
    "privilege_escalation",
    "privilege escalation",
)
CONFIG_LIMITS = {
    "attempts": (2, 10000),
    "failures": (2, 10000),
    "events": (2, 10000),
    "distinct_sources": (2, 1000),
    "distinct_accounts": (2, 1000),
    "distinct_ports": (2, 65535),
    "window_minutes": (1, 1440),
}


class DetectionConfigurationError(ValueError):
    """A persisted detection rule has invalid threshold configuration."""


class DetectionDataError(ValueError):
    """Stored event data cannot be safely evaluated."""


def _is_authentication(event):
    event_type = re.sub(r"([a-z])([A-Z])", r"\1 \2", event["event_type"])
    tokens = set(re.findall(r"[a-z0-9]+", event_type.casefold()))
    return not tokens.isdisjoint(AUTHENTICATION_TERMS)


def _event_time(event):
    if "_parsed_time" in event:
        return event["_parsed_time"]
    value = event["observed_at"]
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise DetectionDataError(
            f"Stored event {event['id']} has an invalid timestamp."
        ) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_config(rule_id, raw_config):
    try:
        config = json.loads(raw_config)
    except (json.JSONDecodeError, TypeError) as error:
        raise DetectionConfigurationError(f"{rule_id} has invalid JSON configuration.") from error
    if not isinstance(config, dict):
        raise DetectionConfigurationError(f"{rule_id} configuration must be an object.")

    definition = next(item for item in RULE_DEFINITIONS if item["rule_id"] == rule_id)
    defaults = definition["thresholds"]
    if set(config) != set(defaults):
        raise DetectionConfigurationError(
            f"{rule_id} configuration must contain exactly: {', '.join(defaults)}."
        )
    for key, value in config.items():
        minimum, maximum = CONFIG_LIMITS[key]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise DetectionConfigurationError(
                f"{rule_id} {key} must be a whole number from {minimum} to {maximum}."
            )
    return config


def _window_matches(events, key_function, window_minutes, qualifies):
    """Return non-overlapping time windows; evidence is sorted for stable fingerprints."""
    grouped = defaultdict(list)
    for event in events:
        key = key_function(event)
        if key:
            grouped[key].append(event)

    matches = []
    window_seconds = window_minutes * 60
    for key, grouped_events in grouped.items():
        grouped_events.sort(key=lambda event: (_event_time(event), event["id"]))
        timestamps = [_event_time(event) for event in grouped_events]
        start_index = 0
        end_index = 0
        while start_index < len(grouped_events):
            anchor = timestamps[start_index]
            end_index = max(end_index, start_index)
            while end_index < len(grouped_events):
                if (timestamps[end_index] - anchor).total_seconds() > window_seconds:
                    break
                end_index += 1
            window = grouped_events[start_index:end_index]
            if qualifies(window):
                matches.append(
                    {
                        "key": str(key),
                        "anchor_id": grouped_events[start_index]["id"],
                        "events": window,
                    }
                )
                start_index = end_index
            else:
                start_index += 1
    return matches


def _make_match(rule, key, anchor_id, events, explanation):
    fingerprint_value = f"{rule['rule_id']}|{key}|{anchor_id}"
    fingerprint = hashlib.sha256(fingerprint_value.encode("utf-8")).hexdigest()
    return {
        "rule": rule,
        "fingerprint": fingerprint,
        "events": events,
        "explanation": explanation,
        "triggered_at": max(events, key=_event_time)["observed_at"],
    }


def _run_rule(rule, config, events):
    rule_id = rule["rule_id"]
    if rule_id == "R007":
        blocked = [
            event for event in events
            if event["event_type"] == "windows_firewall_blocked_5157"
            and event["source_ip"]
            and event.get("destination_port")
        ]
        matches = _window_matches(
            blocked,
            lambda event: event["source_ip"],
            config["window_minutes"],
            lambda group: len(group) >= config["events"]
            and len({event["destination_port"] for event in group}) >= config["distinct_ports"],
        )
        return [
            _make_match(
                rule,
                match["key"],
                match["anchor_id"],
                match["events"],
                f"Observed {len(match['events'])} blocked connections from {match['key']} to {len({event['destination_port'] for event in match['events']})} destination ports within {config['window_minutes']} minutes. This may indicate scanning but can also be expected monitoring.",
            )
            for match in matches
        ]

    if rule_id in {"R008", "R009"}:
        target_tag = "shadow_copy_deletion" if rule_id == "R008" else None
        other_tags = {
            "encoded_command",
            "download_cradle",
            "credential_access_signature",
            "suspicious_process",
        }
        matches = []
        for event in events:
            try:
                tags = json.loads(event.get("indicator_tags_json") or "[]")
            except json.JSONDecodeError as error:
                raise DetectionDataError(
                    f"Stored event {event['id']} has invalid indicator metadata."
                ) from error
            if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
                raise DetectionDataError(
                    f"Stored event {event['id']} has invalid indicator metadata."
                )
            is_match = target_tag in tags if target_tag else not other_tags.isdisjoint(tags)
            if is_match:
                matches.append(
                    _make_match(
                        rule,
                        event.get("host_name") or event["id"],
                        event["id"],
                        [event],
                        f"Local host telemetry marked indicator(s) {', '.join(sorted(set(tags) & ({target_tag} if target_tag else other_tags)))} on {event.get('process_name') or event['event_type']}. The command content is not retained; verify this event in the authorized endpoint logs.",
                    )
                )
        return matches

    if rule_id == "R010":
        return [
            _make_match(
                rule,
                event.get("host_name") or event["id"],
                event["id"],
                [event],
                f"File hash {event.get('file_hash') or 'not recorded'} received a suspicious reputation result. Validate the hash and endpoint context; reputation alone does not confirm malware.",
            )
            for event in events
            if event["event_type"] == "windows_file_reputation_suspicious"
        ]

    if rule_id == "R006":
        matches = []
        for event in events:
            event_type = event["event_type"].casefold()
            if any(term in event_type for term in PRIVILEGE_EVENT_TERMS):
                matches.append(
                    _make_match(
                        rule,
                        event.get("host_name") or event["id"],
                        event["id"],
                        [event],
                        f"Observed event type '{event['event_type']}' explicitly labels a privilege escalation. This is an indicator for review, not confirmation of unauthorized activity.",
                    )
                )
        return matches

    window_minutes = config["window_minutes"]
    auth_events = [event for event in events if _is_authentication(event)]

    if rule_id == "R001":
        failures = [event for event in auth_events if event["outcome"] == "failure"]
        matches = _window_matches(
            failures,
            lambda event: event["source_ip"] or event["username"],
            window_minutes,
            lambda group: len(group) >= config["attempts"],
        )
        return [
            _make_match(
                rule,
                match["key"],
                match["anchor_id"],
                match["events"],
                f"Observed {len(match['events'])} failed authentication events from source/account '{match['key']}' within {window_minutes} minutes. This may indicate repeated guessing; it is not proof of an attack.",
            )
            for match in matches
        ]

    if rule_id == "R002":
        successes = [event for event in auth_events if event["outcome"] == "success" and event["username"]]
        matches = _window_matches(
            successes,
            lambda event: event["username"],
            window_minutes,
            lambda group: len({event["source_ip"] for event in group if event["source_ip"]})
            >= config["distinct_sources"],
        )
        return [
            _make_match(
                rule,
                match["key"],
                match["anchor_id"],
                match["events"],
                f"Observed successful authentication for account '{match['key']}' from {len({event['source_ip'] for event in match['events'] if event['source_ip']})} source IPs within {window_minutes} minutes. VPN, proxy, or NAT use may explain this pattern.",
            )
            for match in matches
        ]

    if rule_id == "R003":
        keyed = defaultdict(list)
        for event in auth_events:
            if event["source_ip"] and event["username"]:
                keyed[(event["source_ip"], event["username"])].append(event)
        matches = []
        for (source_ip, username), group in keyed.items():
            group.sort(key=lambda event: (_event_time(event), event["id"]))
            pending_failures = deque()
            for event in group:
                event_time = _event_time(event)
                while pending_failures and (event_time - _event_time(pending_failures[0])).total_seconds() > window_minutes * 60:
                    pending_failures.popleft()
                if event["outcome"] == "success" and len(pending_failures) >= config["failures"]:
                    failures = list(pending_failures)
                    evidence = failures + [event]
                    matches.append(
                        _make_match(
                            rule,
                            f"{source_ip}|{username}",
                            failures[0]["id"],
                            evidence,
                            f"Observed {len(failures)} authentication failures followed by a success for account '{username}' from {source_ip} within {window_minutes} minutes. This sequence warrants review but does not confirm compromise.",
                        )
                    )
                    pending_failures = []
                elif event["outcome"] == "failure":
                    pending_failures.append(event)
        return matches

    if rule_id == "R004":
        sourced_events = [event for event in auth_events if event["source_ip"]]
        matches = _window_matches(
            sourced_events,
            lambda event: event["source_ip"],
            window_minutes,
            lambda group: len(group) >= config["events"],
        )
        return [
            _make_match(
                rule,
                match["key"],
                match["anchor_id"],
                match["events"],
                f"Observed {len(match['events'])} authentication events from {match['key']} within {window_minutes} minutes, exceeding the configured frequency threshold of {config['events']}.",
            )
            for match in matches
        ]

    if rule_id == "R005":
        failures = [
            event for event in auth_events
            if event["outcome"] == "failure" and event["source_ip"] and event["username"]
        ]
        matches = _window_matches(
            failures,
            lambda event: event["source_ip"],
            window_minutes,
            lambda group: len({event["username"] for event in group})
            >= config["distinct_accounts"],
        )
        return [
            _make_match(
                rule,
                match["key"],
                match["anchor_id"],
                match["events"],
                f"Observed failed authentication against {len({event['username'] for event in match['events']})} accounts from {match['key']} within {window_minutes} minutes. This is consistent with password-spraying behavior, but is not proof of malicious activity.",
            )
            for match in matches
        ]

    raise DetectionConfigurationError(f"No detection implementation is registered for {rule_id}.")


def seed_detection_rules(connection: sqlite3.Connection):
    for rule in RULE_DEFINITIONS:
        connection.execute(
            "INSERT OR IGNORE INTO detection_rules "
            "(rule_id, name, description, severity, mitre_technique_id, "
            "mitre_technique_name, mitre_rationale, recommended_steps_json, config_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule["rule_id"],
                rule["name"],
                rule["description"],
                rule["severity"],
                rule["mitre_technique_id"],
                rule["mitre_technique_name"],
                rule["mitre_rationale"],
                json.dumps(rule["recommended_steps"]),
                json.dumps(rule["thresholds"]),
            ),
        )


def run_detections(connection: sqlite3.Connection):
    """Evaluate enabled baseline rules and persist deduplicated, evidence-linked alerts."""
    seed_detection_rules(connection)
    rule_rows = connection.execute(
        "SELECT rule_id, name, description, severity, mitre_technique_id, "
        "mitre_technique_name, mitre_rationale, recommended_steps_json, config_json "
        "FROM detection_rules WHERE enabled = 1 ORDER BY rule_id"
    ).fetchall()
    rules = [dict(row) for row in rule_rows]
    configs = {rule["rule_id"]: _validate_config(rule["rule_id"], rule["config_json"]) for rule in rules}
    event_rows = connection.execute(
        "SELECT id, observed_at, event_type, outcome, username, source_ip, host_name, "
        "destination_port, file_hash, process_id, process_name, parent_process_name, "
        "indicator_tags_json "
        "FROM security_events ORDER BY observed_at, id"
    ).fetchall()
    events = [dict(row) for row in event_rows]
    for event in events:
        event["_parsed_time"] = _event_time(event)
    matches = []
    for rule in rules:
        matches.extend(_run_rule(rule, configs[rule["rule_id"]], events))

    now = datetime.now(timezone.utc).isoformat()
    created_alerts = 0
    try:
        for match in matches:
            rule = match["rule"]
            alert_id = str(uuid.uuid4())
            cursor = connection.execute(
                "INSERT OR IGNORE INTO alerts "
                "(id, rule_id, title, severity, explanation, triggered_at, fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    alert_id,
                    rule["rule_id"],
                    rule["name"],
                    rule["severity"],
                    match["explanation"],
                    match["triggered_at"] or now,
                    match["fingerprint"],
                ),
            )
            if cursor.rowcount:
                created_alerts += 1
            saved_alert = connection.execute(
                "SELECT id FROM alerts WHERE fingerprint = ?",
                (match["fingerprint"],),
            ).fetchone()
            connection.executemany(
                "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                [(saved_alert["id"], event["id"]) for event in match["events"]],
            )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        logger.exception("Detection run failed while writing alert records.")
        raise

    return {
        "rules_evaluated": len(rules),
        "events_evaluated": len(events),
        "matches_found": len(matches),
        "alerts_created": created_alerts,
        "alerts_existing": len(matches) - created_alerts,
        "completed_at": now,
    }
