from datetime import datetime, timedelta, timezone
import hmac
import ipaddress
import json
import re
import sqlite3
import uuid
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request

from app.audit import append_audit_entry, verify_audit_chain
from app.detection import run_detections
from app.db import get_db
from app.ingestion.service import ingest_log_file
from app.remediation.quarantine import validate_candidate_path
from app.remediation.executor import RemediationExecutionError
from app.threat_intel.providers import (
    PROVIDER_NAMES,
    ThreatIntelError,
    create_provider,
    validate_public_ip,
)
from app.threat_intel.service import enrich_observed_ips


phase5_api = Blueprint("phase5_api", __name__)
SUPPORTED_PROVIDERS = {"disabled", *PROVIDER_NAMES}
AGENT_EVENT_TYPES = {
    "windows_security_logon_4624_success",
    "windows_security_logon_4625_failure",
    "windows_firewall_blocked_5157",
    "windows_script_block_4104",
    "windows_process_creation_4688",
}


def _provider_configured(provider):
    if provider == "mock":
        return True
    if provider == "abuseipdb":
        return bool(current_app.config.get("ABUSEIPDB_API_KEY"))
    if provider == "virustotal":
        return bool(current_app.config.get("VIRUSTOTAL_API_KEY"))
    return False


def _integration_settings(connection):
    return connection.execute(
        "SELECT provider, enabled, updated_at FROM integration_settings "
        "WHERE name = 'threat_intel'"
    ).fetchone()


def _loopback_request():
    try:
        return ipaddress.ip_address(request.remote_addr).is_loopback
    except (TypeError, ValueError):
        return False


def _require_ui_intent():
    if request.headers.get("X-SentinelX-Request") != "1":
        return jsonify(
            error={
                "code": "request_intent_required",
                "message": "Send the SentinelX UI intent header for this state-changing request.",
            }
        ), 403
    origin = request.headers.get("Origin")
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc.casefold() != request.host.casefold() or parsed.scheme not in {"http", "https"}:
            return jsonify(
                error={
                    "code": "cross_origin_request",
                    "message": "Cross-origin state-changing requests are not accepted.",
                }
            ), 403
    return None


@phase5_api.get("/api/threat-intel")
def threat_intel_history():
    rows = get_db().execute(
        "SELECT id, indicator_value, provider, status, reputation_score, summary_json, "
        "error_summary, looked_up_at FROM threat_intel_lookups "
        "ORDER BY looked_up_at DESC LIMIT 100"
    ).fetchall()
    history = []
    for row in rows:
        item = dict(row)
        raw_summary = item.pop("summary_json")
        try:
            item["summary"] = json.loads(raw_summary)
        except json.JSONDecodeError:
            item["summary"] = {"unparseable_summary": raw_summary}
        history.append(item)
    return jsonify(data={"lookups": history})


@phase5_api.post("/api/threat-intel/enrich")
def enrich_threat_intel():
    rejected = _require_ui_intent()
    if rejected:
        return rejected
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {"subject_type", "subject_id"}:
        return jsonify(error={"code": "invalid_request", "message": "Provide subject_type and subject_id, or omit both to use active alert evidence."}), 400
    subject_type = payload.get("subject_type")
    subject_id = payload.get("subject_id")
    if subject_type is None:
        if subject_id is not None:
            return jsonify(error={"code": "invalid_request", "message": "subject_type and subject_id must be provided together."}), 400
    elif (
        not isinstance(subject_type, str)
        or subject_type not in {"alert", "incident"}
        or not isinstance(subject_id, str)
        or not subject_id.strip()
    ):
        return jsonify(error={"code": "invalid_request", "message": "Use a non-empty alert or incident identifier."}), 400
    settings = _integration_settings(get_db())
    if not settings["enabled"] or settings["provider"] == "disabled":
        return jsonify(error={"code": "integration_disabled", "message": "Enable a threat intelligence provider in Settings first."}), 409
    if not _provider_configured(settings["provider"]):
        return jsonify(error={"code": "provider_not_configured", "message": "Configure the selected provider API key in the local environment first."}), 409
    connection = get_db()
    if subject_type == "alert" and connection.execute(
        "SELECT 1 FROM alerts WHERE id = ?", (subject_id,)
    ).fetchone() is None:
        return jsonify(error={"code": "alert_not_found", "message": "Alert was not found."}), 404
    if subject_type == "incident" and connection.execute(
        "SELECT 1 FROM incidents WHERE id = ?", (subject_id,)
    ).fetchone() is None:
        return jsonify(error={"code": "incident_not_found", "message": "Incident was not found."}), 404
    try:
        result = enrich_observed_ips(
            get_db(),
            settings["provider"],
            current_app.config,
            subject_type,
            subject_id,
        )
    except ThreatIntelError as error:
        return jsonify(error={"code": "threat_intel_error", "message": str(error)}), 400
    return jsonify(data=result)


@phase5_api.get("/api/settings")
def get_settings():
    connection = get_db()
    row = _integration_settings(connection)
    token_configured = bool(current_app.config.get("AGENT_TOKEN"))
    return jsonify(
        data={
            "threat_intel": {
                "provider": row["provider"],
                "enabled": bool(row["enabled"]),
                "configured": _provider_configured(row["provider"]),
                "providers": [
                    {"id": "disabled", "name": "Disabled", "configured": True},
                    {"id": "mock", "name": "Mock (no external requests)", "configured": True},
                    {
                        "id": "abuseipdb",
                        "name": "AbuseIPDB",
                        "configured": _provider_configured("abuseipdb"),
                    },
                    {
                        "id": "virustotal",
                        "name": "VirusTotal",
                        "configured": _provider_configured("virustotal"),
                    },
                ],
                "api_key_environment_variables": {
                    "abuseipdb": "SENTINELX_ABUSEIPDB_API_KEY",
                    "virustotal": "SENTINELX_VIRUSTOTAL_API_KEY",
                },
            },
            "host_monitor": {
                "agent_token_configured": token_configured,
                "endpoint": "/api/host-monitor/windows-events",
                "transport": "loopback-only HTTP with bearer token",
                "file_hash_lookups_enabled": bool(
                    current_app.config.get("ENABLE_FILE_HASH_LOOKUPS")
                ),
                "file_hash_provider_configured": bool(
                    current_app.config.get("VIRUSTOTAL_API_KEY")
                ),
            },
            "active_defense": {
                "execution_mode": "local human-approved dashboard and CLI actions",
                "dashboard_execution_available": True,
                "platform": "Windows Firewall, process termination, and file quarantine",
                "human_approval_required": True,
            },
            "ai_triage": {
                "provider": "Google Gemini",
                "configured": bool(current_app.config.get("GEMINI_API_KEY")),
                "external_telemetry_only_on_explicit_ai_solve": True,
            },
        }
    )


@phase5_api.put("/api/settings/threat-intel")
def update_threat_intel_settings():
    rejected = _require_ui_intent()
    if rejected:
        return rejected
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"provider", "enabled"}:
        return jsonify(error={"code": "invalid_request", "message": "Provide provider and enabled fields only."}), 400
    provider = payload["provider"]
    enabled = payload["enabled"]
    if not isinstance(provider, str) or provider not in SUPPORTED_PROVIDERS or not isinstance(enabled, bool):
        return jsonify(error={"code": "invalid_settings", "message": "Choose a supported provider and a boolean enabled value."}), 400
    if provider == "disabled" and enabled:
        return jsonify(error={"code": "invalid_settings", "message": "The disabled provider cannot be enabled."}), 400
    if enabled and not _provider_configured(provider):
        return jsonify(error={"code": "provider_not_configured", "message": "Configure the selected API key in the local environment first."}), 409

    connection = get_db()
    now = datetime.now(timezone.utc).isoformat()
    prior = _integration_settings(connection)
    try:
        connection.execute(
            "UPDATE integration_settings SET provider = ?, enabled = ?, updated_at = ? "
            "WHERE name = 'threat_intel'",
            (provider, int(enabled), now),
        )
        append_audit_entry(
            connection,
            "settings.threat_intel_updated",
            "integration",
            "threat_intel",
            {
                "from_provider": prior["provider"],
                "from_enabled": bool(prior["enabled"]),
                "to_provider": provider,
                "to_enabled": enabled,
            },
            created_at=now,
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise
    return jsonify(data={"provider": provider, "enabled": enabled, "updated_at": now})


@phase5_api.post("/api/settings/threat-intel/test")
def test_threat_intel_provider():
    rejected = _require_ui_intent()
    if rejected:
        return rejected
    settings = _integration_settings(get_db())
    provider_name = settings["provider"]
    if provider_name == "disabled" or not settings["enabled"]:
        return jsonify(error={"code": "integration_disabled", "message": "Enable a provider before testing its connection."}), 409
    if not _provider_configured(provider_name):
        return jsonify(error={"code": "provider_not_configured", "message": "Configure the selected provider API key in the local environment first."}), 409
    try:
        provider = create_provider(provider_name, current_app.config)
        result = provider.lookup("8.8.8.8")
    except ThreatIntelError as error:
        return jsonify(error={"code": "provider_test_failed", "message": str(error)}), 502
    connection = get_db()
    now = datetime.now(timezone.utc).isoformat()
    append_audit_entry(
        connection,
        "threat_intel.provider_tested",
        "integration",
        "threat_intel",
        {"provider": provider_name, "test_indicator": "8.8.8.8", "status": "completed"},
        created_at=now,
    )
    connection.commit()
    return jsonify(
        data={
            "provider": provider_name,
            "status": "connected",
            "test_indicator": "8.8.8.8",
            "score": result["score"],
            "message": "Provider returned a valid reputation response.",
        }
    )


@phase5_api.post("/api/host-monitor/windows-events")
def ingest_windows_security_events():
    token = current_app.config.get("AGENT_TOKEN")
    if not token:
        return jsonify(error={"code": "agent_not_configured", "message": "Set SENTINELX_AGENT_TOKEN before starting the host monitor."}), 503
    if not _loopback_request():
        return jsonify(error={"code": "loopback_required", "message": "The Windows event agent endpoint accepts loopback connections only."}), 403
    authorization = request.headers.get("Authorization", "")
    supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not hmac.compare_digest(supplied, token):
        return jsonify(error={"code": "invalid_agent_token", "message": "The host monitor bearer token is invalid."}), 401
    payload = request.get_json(silent=True)
    records = payload.get("events") if isinstance(payload, dict) else None
    if (
        not isinstance(records, list)
        or not records
        or len(records) > 100
        or any(
            not isinstance(record, dict)
            or not isinstance(record.get("event_type"), str)
            or record.get("event_type") not in AGENT_EVENT_TYPES
            or set(record) - {
                "timestamp", "observed_at", "event_type", "outcome", "username",
                "source_ip", "host_name", "host_event_record_id", "process_id",
                "process_name", "parent_process_name", "destination_port",
                "file_hash", "indicator_tags",
            }
            for record in records
        )
    ):
        return jsonify(error={"code": "invalid_agent_payload", "message": "Provide 1 to 100 supported Windows security events using approved normalized fields only. Raw command lines and script content are not accepted."}), 400
    content = json.dumps({"events": records}, separators=(",", ":")).encode("utf-8")
    result = ingest_log_file(
        get_db(),
        "windows-security-events.json",
        content,
        current_app.config["MAX_CONTENT_LENGTH"],
    )
    append_audit_entry(
        get_db(),
        "host_monitor.windows_events_ingested",
        "host_monitor",
        None,
        {
            "received": result["records_received"],
            "imported": result["records_imported"],
            "duplicates": result["records_duplicate"],
            "rejected": result["records_rejected"],
            "status": result["status"],
        },
    )
    get_db().commit()
    if result["records_imported"]:
        result["detection"] = run_detections(get_db())
    return jsonify(data=result), 201 if result["status"] == "completed" else 207 if result["status"] == "partial" else 422


@phase5_api.post("/api/host-monitor/file-hash")
def check_host_file_hash():
    token = current_app.config.get("AGENT_TOKEN")
    if not token:
        return jsonify(error={"code": "agent_not_configured", "message": "Set SENTINELX_AGENT_TOKEN before starting the host monitor."}), 503
    if not _loopback_request():
        return jsonify(error={"code": "loopback_required", "message": "The file reputation endpoint accepts loopback connections only."}), 403
    authorization = request.headers.get("Authorization", "")
    supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not hmac.compare_digest(supplied, token):
        return jsonify(error={"code": "invalid_agent_token", "message": "The host monitor bearer token is invalid."}), 401
    if not current_app.config.get("ENABLE_FILE_HASH_LOOKUPS"):
        return jsonify(error={"code": "file_hash_lookups_disabled", "message": "Set SENTINELX_ENABLE_FILE_HASH_LOOKUPS=1 to explicitly enable external file-hash lookups."}), 409
    if not current_app.config.get("VIRUSTOTAL_API_KEY"):
        return jsonify(error={"code": "provider_not_configured", "message": "Set SENTINELX_VIRUSTOTAL_API_KEY before enabling file reputation checks."}), 409

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) not in ({"sha256"}, {"sha256", "file_path"}):
        return jsonify(error={"code": "invalid_request", "message": "Provide a SHA-256 digest and, optionally, a local watched-file path; file contents are never accepted."}), 400
    sha256 = payload.get("sha256")
    if not isinstance(sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return jsonify(error={"code": "invalid_hash", "message": "sha256 must be a 64-character hexadecimal digest."}), 400
    sha256 = sha256.lower()
    file_path = payload.get("file_path")
    candidate_path = None
    if file_path is not None:
        try:
            candidate_path = validate_candidate_path(file_path, sha256)
        except RemediationExecutionError as error:
            return jsonify(error={"code": "invalid_file_candidate", "message": str(error)}), 400
    connection = get_db()
    now = datetime.now(timezone.utc)
    cached = connection.execute(
        "SELECT reputation_score, summary_json, looked_up_at FROM threat_intel_lookups "
        "WHERE indicator_value = ? AND provider = 'virustotal_file' AND status = 'completed' "
        "ORDER BY looked_up_at DESC LIMIT 1",
        (sha256,),
    ).fetchone()
    cached_at = None
    if cached:
        try:
            cached_at = datetime.fromisoformat(cached["looked_up_at"].replace("Z", "+00:00"))
        except ValueError:
            cached_at = None
    if cached and cached_at and now - cached_at < timedelta(hours=24):
        result = {
            "score": cached["reputation_score"],
            "summary": json.loads(cached["summary_json"]),
            "cached": True,
        }
        lookup_timestamp = cached["looked_up_at"]
    else:
        requests_today = connection.execute(
            "SELECT COUNT(*) FROM threat_intel_lookups "
            "WHERE provider = 'virustotal_file' AND looked_up_at >= ?",
            ((now - timedelta(days=1)).isoformat(),),
        ).fetchone()[0]
        if requests_today >= 50:
            return jsonify(error={"code": "file_lookup_limit", "message": "The local file reputation limit of 50 new hashes per 24 hours has been reached."}), 429
        try:
            provider = create_provider("virustotal", current_app.config)
            result = provider.lookup_file_hash(sha256)
        except ThreatIntelError as error:
            connection.execute(
                "INSERT INTO threat_intel_lookups "
                "(id, indicator_value, provider, status, summary_json, error_summary, looked_up_at) "
                "VALUES (?, ?, 'virustotal_file', 'failed', '{}', ?, ?)",
                (str(uuid.uuid4()), sha256, str(error)[:500], now.isoformat()),
            )
            append_audit_entry(
                connection,
                "threat_intel.file_hash_lookup_failed",
                "file_hash",
                sha256,
                {"provider": "virustotal_file", "error": str(error)},
                created_at=now.isoformat(),
            )
            connection.commit()
            return jsonify(error={"code": "file_lookup_failed", "message": str(error)}), 502
        connection.execute(
            "INSERT INTO threat_intel_lookups "
            "(id, indicator_value, provider, status, reputation_score, summary_json, looked_up_at) "
            "VALUES (?, ?, 'virustotal_file', 'completed', ?, ?, ?)",
            (
                str(uuid.uuid4()),
                sha256,
                result["score"],
                json.dumps(result["summary"], sort_keys=True),
                now.isoformat(),
            ),
        )
        result["cached"] = False
        lookup_timestamp = now.isoformat()

    malicious = result["summary"].get("malicious_engines", 0)
    suspicious = result["summary"].get("suspicious_engines", 0)
    is_suspicious = (
        isinstance(malicious, int)
        and not isinstance(malicious, bool)
        and isinstance(suspicious, int)
        and not isinstance(suspicious, bool)
        and malicious + suspicious >= 5
    )
    observed_at = lookup_timestamp
    event_type = (
        "windows_file_reputation_suspicious"
        if is_suspicious
        else "windows_file_reputation_checked"
    )
    ingest_result = ingest_log_file(
        connection,
        "windows-file-hash-reputation.json",
        json.dumps(
            {
                "events": [{
                    "timestamp": observed_at,
                    "event_type": event_type,
                    "outcome": "failure" if is_suspicious else "unknown",
                    "file_hash": sha256,
                }]
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        current_app.config["MAX_CONTENT_LENGTH"],
    )
    append_audit_entry(
        connection,
        "threat_intel.file_hash_suspicious" if is_suspicious else "threat_intel.file_hash_checked",
        "file_hash",
        sha256,
        {
            "provider": "virustotal_file",
            "score": result["score"],
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "external_hash_disclosure": not result["cached"],
        },
        created_at=observed_at,
    )
    if is_suspicious and candidate_path is not None:
        connection.execute(
            "INSERT INTO host_file_candidates "
            "(file_hash, original_path, status, reputation_score, observed_at) "
            "VALUES (?, ?, 'suspicious', ?, ?) "
            "ON CONFLICT(file_hash) DO UPDATE SET "
            "original_path = CASE WHEN host_file_candidates.status = 'quarantined' "
            "THEN host_file_candidates.original_path ELSE excluded.original_path END, "
            "status = CASE WHEN host_file_candidates.status = 'quarantined' "
            "THEN host_file_candidates.status ELSE 'suspicious' END, "
            "reputation_score = excluded.reputation_score, observed_at = excluded.observed_at",
            (sha256, str(candidate_path), result["score"], observed_at),
        )
    connection.commit()
    detection = run_detections(connection) if ingest_result["records_imported"] else None
    return jsonify(
        data={
            "sha256": sha256,
            "provider": "virustotal_file",
            "cached": result["cached"],
            "score": result["score"],
            "summary": result["summary"],
            "suspicious": is_suspicious,
            "file_contents_uploaded": False,
            "local_path_recorded": bool(is_suspicious and candidate_path is not None),
            "ingestion": ingest_result,
            "detection": detection,
        }
    ), 200


@phase5_api.get("/api/audit")
def audit_history():
    connection = get_db()
    verification = verify_audit_chain(connection)
    rows = connection.execute(
        "SELECT id, actor_user_id, action, entity_type, entity_id, details_json, "
        "created_at, previous_hash, record_hash FROM audit_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    entries = []
    for row in rows:
        item = dict(row)
        raw_details = item.pop("details_json")
        try:
            item["details"] = json.loads(raw_details)
        except json.JSONDecodeError:
            item["details"] = {"unparseable_details": raw_details}
        item["chain_valid"] = item["id"] not in verification["invalid_records"]
        entries.append(item)
    return jsonify(data={"verification": verification, "entries": entries})


@phase5_api.get("/api/audit/verify")
@phase5_api.post("/api/audit/verify")
def verify_audit_history():
    if request.method == "POST":
        rejected = _require_ui_intent()
        if rejected:
            return rejected
    return jsonify(data=verify_audit_chain(get_db()))
