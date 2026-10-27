import sqlite3
from pathlib import Path

import click
from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id TEXT PRIMARY KEY,
    source_filename TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'failed')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    records_received INTEGER NOT NULL DEFAULT 0 CHECK (records_received >= 0),
    records_imported INTEGER NOT NULL DEFAULT 0 CHECK (records_imported >= 0),
    records_rejected INTEGER NOT NULL DEFAULT 0 CHECK (records_rejected >= 0),
    records_duplicate INTEGER NOT NULL DEFAULT 0 CHECK (records_duplicate >= 0),
    error_summary TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    observed_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'unknown' CHECK (outcome IN ('success', 'failure', 'unknown')),
    username TEXT,
    source_ip TEXT,
    host_name TEXT,
    ingestion_job_id TEXT REFERENCES ingestion_jobs(id) ON DELETE SET NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    mitre_rationale TEXT,
    recommended_steps_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT REFERENCES detection_rules(rule_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New', 'Investigating', 'Escalated', 'Resolved', 'False Positive')),
    explanation TEXT NOT NULL,
    triggered_at TEXT NOT NULL,
    fingerprint TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New', 'Investigating', 'Contained', 'Resolved')),
    findings TEXT,
    correlation_key TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
    author_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    body TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'analyst_observation'
        CHECK (classification IN ('analyst_observation', 'ai_recommendation')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (incident_id IS NOT NULL OR alert_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS threat_intelligence_indicators (
    id TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'file_hash')),
    indicator_value TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen_at TEXT,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (indicator_type, indicator_value, source)
);

CREATE TABLE IF NOT EXISTS model_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    dataset_name TEXT NOT NULL,
    metrics_json TEXT NOT NULL DEFAULT '{}',
    limitations TEXT NOT NULL,
    evaluated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id TEXT PRIMARY KEY,
    alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
    incident_id TEXT REFERENCES incidents(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (action_type IN ('block_source_ip', 'terminate_process', 'investigate')),
    status TEXT NOT NULL DEFAULT 'recommendation_only'
        CHECK (status IN ('recommendation_only', 'dismissed')),
    title TEXT NOT NULL,
    rationale TEXT NOT NULL,
    target_json TEXT NOT NULL DEFAULT '{}',
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    requires_human_approval INTEGER NOT NULL DEFAULT 1 CHECK (requires_human_approval IN (0, 1)),
    execution_status TEXT NOT NULL DEFAULT 'not_requested'
        CHECK (execution_status IN ('not_requested', 'executing', 'executed', 'failed')),
    execution_at TEXT,
    execution_details TEXT,
    firewall_removed_at TEXT,
    firewall_removal_status TEXT NOT NULL DEFAULT 'not_requested'
        CHECK (firewall_removal_status IN ('not_requested', 'removing', 'removed', 'failed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((alert_id IS NOT NULL AND incident_id IS NULL) OR
           (alert_id IS NULL AND incident_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS threat_intel_lookups (
    id TEXT PRIMARY KEY,
    indicator_value TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
    reputation_score INTEGER CHECK (reputation_score BETWEEN 0 AND 100),
    summary_json TEXT NOT NULL DEFAULT '{}',
    error_summary TEXT,
    looked_up_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator
    ON threat_intel_lookups(indicator_value, looked_up_at);

CREATE TABLE IF NOT EXISTS integration_settings (
    name TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('disabled', 'mock', 'abuseipdb', 'virustotal')),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS audit_chain_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_record_id INTEGER NOT NULL,
    last_record_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_observed_at ON security_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_username ON security_events(username);
CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_alert ON remediation_actions(alert_id);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_incident ON remediation_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_lookups_date ON threat_intel_lookups(looked_up_at);
"""


def get_db():
    if "db" not in g:
        database = Path(current_app.config["DATABASE"])
        database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = get_db()
    connection.executescript(SCHEMA)
    ingestion_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(ingestion_jobs)")
    }
    if "records_duplicate" not in ingestion_columns:
        connection.execute(
            "ALTER TABLE ingestion_jobs ADD COLUMN records_duplicate "
            "INTEGER NOT NULL DEFAULT 0 CHECK (records_duplicate >= 0)"
        )
    rule_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(detection_rules)")
    }
    for column, definition in (
        ("mitre_technique_id", "TEXT"),
        ("mitre_technique_name", "TEXT"),
        ("mitre_rationale", "TEXT"),
        ("recommended_steps_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        if column not in rule_columns:
            connection.execute(f"ALTER TABLE detection_rules ADD COLUMN {column} {definition}")
    alert_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
    }
    if "fingerprint" not in alert_columns:
        connection.execute("ALTER TABLE alerts ADD COLUMN fingerprint TEXT")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint)"
    )
    connection.execute(
        "INSERT OR IGNORE INTO integration_settings (name, provider, enabled) "
        "VALUES ('threat_intel', 'disabled', 0)"
    )
    audit_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(audit_logs)")
    }
    for column in ("previous_hash", "record_hash"):
        if column not in audit_columns:
            connection.execute(f"ALTER TABLE audit_logs ADD COLUMN {column} TEXT")
    remediation_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(remediation_actions)")
    }
    for column, definition in (
        ("execution_status", "TEXT NOT NULL DEFAULT 'not_requested'"),
        ("execution_at", "TEXT"),
        ("execution_details", "TEXT"),
        ("firewall_removed_at", "TEXT"),
        (
            "firewall_removal_status",
            "TEXT NOT NULL DEFAULT 'not_requested' "
            "CHECK (firewall_removal_status IN ('not_requested', 'removing', 'removed', 'failed'))",
        ),
    ):
        if column not in remediation_columns:
            connection.execute(
                f"ALTER TABLE remediation_actions ADD COLUMN {column} {definition}"
            )
    incident_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(incidents)")
    }
    incident_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
    ).fetchone()["sql"]
    if "correlation_key" not in incident_columns or "'New'" not in incident_sql:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE incidents_v4 ("
                "id TEXT PRIMARY KEY, "
                "title TEXT NOT NULL, "
                "severity TEXT NOT NULL CHECK (severity IN "
                "('critical', 'high', 'medium', 'low', 'informational')), "
                "status TEXT NOT NULL DEFAULT 'New' CHECK (status IN "
                "('New', 'Investigating', 'Contained', 'Resolved')), "
                "findings TEXT, "
                "correlation_key TEXT UNIQUE, "
                "created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), "
                "updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))"
            )
            connection.execute(
                "INSERT INTO incidents_v4 "
                "(id, title, severity, status, findings, created_at, updated_at) "
                "SELECT id, title, severity, "
                "CASE WHEN status = 'Open' THEN 'New' "
                "WHEN status = 'Closed' THEN 'Resolved' ELSE status END, "
                "findings, created_at, updated_at FROM incidents"
            )
            connection.execute("DROP TABLE incidents")
            connection.execute("ALTER TABLE incidents_v4 RENAME TO incidents")
            connection.execute("COMMIT")
        except sqlite3.Error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    from app.detection.engine import seed_detection_rules

    seed_detection_rules(connection)
    from app.audit import backfill_audit_chain

    backfill_audit_chain(connection)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    connection.execute("PRAGMA user_version = 5")
    connection.commit()


@click.command("init-db")
def init_db_command():
    """Create or upgrade SentinelX tables and load built-in rules without dropping data."""
    init_db()
    click.echo("Initialized SentinelX database (schema version 5).")
