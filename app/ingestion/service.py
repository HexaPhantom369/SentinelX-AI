import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import PurePath, PureWindowsPath
import re
import sqlite3
import uuid

from werkzeug.utils import secure_filename


MAX_REPORTED_ERRORS = 20
EVENT_FIELDS = {
    "observed_at": ("observed_at", "timestamp", "time", "@timestamp"),
    "event_type": ("event_type", "type", "event"),
    "outcome": ("outcome", "result", "status"),
    "username": ("username", "user", "account"),
    "source_ip": ("source_ip", "src_ip", "ip_address", "ip"),
    "host_name": ("host_name", "hostname", "host", "computer"),
    "host_event_record_id": ("host_event_record_id",),
    "process_id": ("process_id", "pid"),
    "process_name": ("process_name", "image_name"),
    "parent_process_name": ("parent_process_name", "parent_image_name"),
    "destination_port": ("destination_port", "dest_port", "destinationport"),
    "file_hash": ("file_hash", "sha256", "sha_256"),
    "indicator_tags": ("indicator_tags", "threat_indicators"),
}
ALLOWED_INDICATOR_TAGS = {
    "encoded_command",
    "download_cradle",
    "credential_access_signature",
    "shadow_copy_deletion",
    "suspicious_process",
}
OUTCOME_VALUES = {
    "success": "success",
    "successful": "success",
    "allowed": "success",
    "accepted": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "denied": "failure",
    "blocked": "failure",
    "unknown": "unknown",
}


class IngestionValidationError(ValueError):
    """A whole-file error that prevents records from being parsed."""


def _safe_filename(filename):
    name = PureWindowsPath(filename or "").name
    name = PurePath(name).name
    return secure_filename(name)[:255] or "unnamed-upload"


def _decode_file(filename, content, max_bytes):
    safe_name = _safe_filename(filename)
    if not safe_name.lower().endswith((".json", ".csv")):
        raise IngestionValidationError("Only .json and .csv log files are supported.")
    if not isinstance(content, bytes):
        raise IngestionValidationError("The uploaded file could not be read.")
    if len(content) > max_bytes:
        raise IngestionValidationError(f"File exceeds the {max_bytes}-byte upload limit.")
    if not content.strip():
        raise IngestionValidationError("The uploaded file is empty.")
    try:
        return safe_name, content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise IngestionValidationError("Files must use UTF-8 or UTF-8 with BOM encoding.") from error


def _reject_json_constant(value):
    raise ValueError(f"Invalid JSON numeric constant: {value}")


def _parse_json(text):
    try:
        payload = json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as error:
        raise IngestionValidationError(f"Invalid JSON: {error}") from error

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and "events" in payload:
        records = payload["events"]
        if not isinstance(records, list):
            raise IngestionValidationError("The JSON 'events' property must be an array.")
    elif isinstance(payload, dict):
        records = [payload]
    else:
        raise IngestionValidationError("JSON must contain an event object or an array of events.")
    if not records:
        raise IngestionValidationError("The JSON file must contain at least one event.")
    return records


def _parse_csv(text):
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        headers = reader.fieldnames
        if not headers or any(not header or not header.strip() for header in headers):
            raise IngestionValidationError("CSV must include a non-empty header row.")
        normalized_headers = [header.strip() for header in headers]
        if len({header.casefold() for header in normalized_headers}) != len(normalized_headers):
            raise IngestionValidationError("CSV header names must be unique.")
        reader.fieldnames = normalized_headers
        rows = list(reader)
    except csv.Error as error:
        raise IngestionValidationError(f"Invalid CSV: {error}") from error

    if not rows:
        raise IngestionValidationError("CSV must contain a header and at least one data row.")
    return rows


def _as_text(value, field, max_length, required=False):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required.")
    if len(value) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters.")
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise ValueError(f"{field} contains unsupported control characters.")
    return value or None


def _read_alias(record, field):
    aliases = EVENT_FIELDS[field]
    values = {key.casefold(): value for key, value in record.items() if isinstance(key, str)}
    for alias in aliases:
        if alias.casefold() in values:
            return values[alias.casefold()]
    return None


def _normalize_timestamp(value):
    timestamp = _as_text(value, "observed_at", 64, required=True)
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00" if timestamp.endswith(("Z", "z")) else timestamp)
    except ValueError as error:
        raise ValueError("observed_at must be a valid ISO 8601 timestamp.") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalize_event(record):
    if not isinstance(record, dict):
        raise ValueError("Each event must be a JSON object or CSV row.")
    if None in record and record[None]:
        raise ValueError("CSV row contains more fields than its header.")

    observed_at = _normalize_timestamp(_read_alias(record, "observed_at"))
    event_type = _as_text(_read_alias(record, "event_type"), "event_type", 128, required=True)
    outcome_value = _as_text(_read_alias(record, "outcome"), "outcome", 64)
    outcome_key = (outcome_value or "unknown").casefold()
    if outcome_key not in OUTCOME_VALUES:
        raise ValueError("outcome must be success, failure, or unknown (or a supported equivalent).")
    username = _as_text(_read_alias(record, "username"), "username", 256)
    source_ip = _as_text(_read_alias(record, "source_ip"), "source_ip", 45)
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError as error:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address.") from error
    host_name = _as_text(_read_alias(record, "host_name"), "host_name", 255)
    host_event_record_id = _as_text(
        _read_alias(record, "host_event_record_id"), "host_event_record_id", 64
    )
    if host_event_record_id and not re.fullmatch(r"[0-9]{1,20}", host_event_record_id):
        raise ValueError("host_event_record_id must contain decimal digits only.")
    process_id = _as_text(_read_alias(record, "process_id"), "process_id", 32)
    if process_id and not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})", process_id):
        raise ValueError("process_id must be decimal digits or a hexadecimal Windows identifier.")
    process_name = _as_text(_read_alias(record, "process_name"), "process_name", 255)
    if process_name:
        process_name = PureWindowsPath(process_name).name
        process_name = PurePath(process_name).name
    parent_process_name = _as_text(
        _read_alias(record, "parent_process_name"), "parent_process_name", 255
    )
    if parent_process_name:
        parent_process_name = PureWindowsPath(parent_process_name).name
        parent_process_name = PurePath(parent_process_name).name
    raw_port = _read_alias(record, "destination_port")
    destination_port = None
    if raw_port not in (None, ""):
        if isinstance(raw_port, bool) or not str(raw_port).strip().isdigit():
            raise ValueError("destination_port must be a whole number from 1 to 65535.")
        destination_port = int(raw_port)
        if not 1 <= destination_port <= 65535:
            raise ValueError("destination_port must be a whole number from 1 to 65535.")
    file_hash = _as_text(_read_alias(record, "file_hash"), "file_hash", 64)
    if file_hash:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", file_hash):
            raise ValueError("file_hash must be a SHA-256 hexadecimal digest.")
        file_hash = file_hash.lower()
    raw_tags = _read_alias(record, "indicator_tags")
    if raw_tags is None:
        indicator_tags = []
    elif isinstance(raw_tags, list) and all(isinstance(item, str) for item in raw_tags):
        indicator_tags = sorted({item.strip().casefold() for item in raw_tags if item.strip()})
    elif isinstance(raw_tags, str):
        indicator_tags = sorted({item.strip().casefold() for item in raw_tags.split(",") if item.strip()})
    else:
        raise ValueError("indicator_tags must be a list of supported strings.")
    if len(indicator_tags) > len(ALLOWED_INDICATOR_TAGS) or not set(indicator_tags) <= ALLOWED_INDICATOR_TAGS:
        raise ValueError("indicator_tags contains an unsupported or excessive indicator.")

    normalized = {
        "observed_at": observed_at,
        "event_type": event_type,
        "outcome": OUTCOME_VALUES[outcome_key],
        "username": username,
        "source_ip": source_ip,
        "host_name": host_name,
        "host_event_record_id": host_event_record_id,
        "process_id": process_id,
        "process_name": process_name,
        "parent_process_name": parent_process_name,
        "destination_port": destination_port,
        "file_hash": file_hash,
        "indicator_tags": indicator_tags,
    }
    identity = {
        key: value
        for key, value in normalized.items()
        if key not in {"host_event_record_id", "process_id", "process_name", "parent_process_name", "destination_port", "file_hash", "indicator_tags"}
    }
    for key in ("host_event_record_id", "process_id", "process_name", "parent_process_name", "destination_port", "file_hash"):
        if normalized[key] is not None:
            identity[key] = normalized[key]
    if indicator_tags:
        identity["indicator_tags"] = indicator_tags
    stable_content = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    normalized["id"] = hashlib.sha256(stable_content.encode("utf-8")).hexdigest()
    return normalized


def _record_failed_job(connection, filename, started_at, error_message, received=0):
    finished_at = datetime.now(timezone.utc).isoformat()
    job_id = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO ingestion_jobs "
        "(id, source_filename, status, started_at, finished_at, records_received, "
        "records_imported, records_rejected, records_duplicate, error_summary) "
        "VALUES (?, ?, 'failed', ?, ?, ?, 0, ?, 0, ?)",
        (job_id, filename, started_at, finished_at, received, received, error_message[:1000]),
    )
    connection.commit()
    return {
        "id": job_id,
        "source_filename": filename,
        "status": "failed",
        "records_received": received,
        "records_imported": 0,
        "records_rejected": received,
        "records_duplicate": 0,
        "errors": [error_message[:500]],
    }


def ingest_log_file(connection: sqlite3.Connection, filename: str, content: bytes, max_bytes: int):
    """Validate and normalize supported event fields, storing no raw log payload."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        safe_name, text = _decode_file(filename, content, max_bytes)
        records = _parse_json(text) if safe_name.lower().endswith(".json") else _parse_csv(text)
    except IngestionValidationError as error:
        return _record_failed_job(connection, _safe_filename(filename), started_at, str(error))

    errors = []
    normalized_events = []
    records_rejected = 0
    for index, record in enumerate(records, start=1):
        try:
            normalized_events.append(_normalize_event(record))
        except ValueError as error:
            records_rejected += 1
            if len(errors) < MAX_REPORTED_ERRORS:
                errors.append({"record": index, "message": str(error)})

    records_received = len(records)
    job_id = str(uuid.uuid4())
    finished_at = datetime.now(timezone.utc).isoformat()
    connection.execute(
        "INSERT INTO ingestion_jobs "
        "(id, source_filename, status, started_at, finished_at, records_received, "
        "records_imported, records_rejected, records_duplicate, error_summary) "
        "VALUES (?, ?, 'failed', ?, ?, ?, 0, ?, 0, ?)",
        (
            job_id,
            safe_name,
            started_at,
            finished_at,
            records_received,
            records_rejected,
            "; ".join(error["message"] for error in errors)[:1000] or None,
        ),
    )

    records_imported = 0
    records_duplicate = 0
    try:
        for event in normalized_events:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO security_events "
                "(id, observed_at, event_type, outcome, username, source_ip, host_name, "
                "host_event_record_id, process_id, process_name, parent_process_name, "
                "destination_port, file_hash, indicator_tags_json, ingestion_job_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event["id"],
                    event["observed_at"],
                    event["event_type"],
                    event["outcome"],
                    event["username"],
                    event["source_ip"],
                    event["host_name"],
                    event["host_event_record_id"],
                    event["process_id"],
                    event["process_name"],
                    event["parent_process_name"],
                    event["destination_port"],
                    event["file_hash"],
                    json.dumps(event["indicator_tags"], separators=(",", ":")),
                    job_id,
                ),
            )
            if cursor.rowcount:
                records_imported += 1
            else:
                records_duplicate += 1
        status = (
            "failed"
            if records_rejected and not records_imported and not records_duplicate
            else "partial"
            if records_rejected
            else "completed"
        )
        connection.execute(
            "UPDATE ingestion_jobs SET status = ?, records_imported = ?, "
            "records_duplicate = ?, error_summary = ? WHERE id = ?",
            (
                status,
                records_imported,
                records_duplicate,
                "; ".join(error["message"] for error in errors)[:1000] or None,
                job_id,
            ),
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise

    return {
        "id": job_id,
        "source_filename": safe_name,
        "status": status,
        "records_received": records_received,
        "records_imported": records_imported,
        "records_rejected": records_rejected,
        "records_duplicate": records_duplicate,
        "errors": errors,
    }
