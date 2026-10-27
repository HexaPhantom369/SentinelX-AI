import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import PurePath, PureWindowsPath
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

    normalized = {
        "observed_at": observed_at,
        "event_type": event_type,
        "outcome": OUTCOME_VALUES[outcome_key],
        "username": username,
        "source_ip": source_ip,
        "host_name": host_name,
    }
    stable_content = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
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
                "(id, observed_at, event_type, outcome, username, source_ip, host_name, ingestion_job_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event["id"],
                    event["observed_at"],
                    event["event_type"],
                    event["outcome"],
                    event["username"],
                    event["source_ip"],
                    event["host_name"],
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
