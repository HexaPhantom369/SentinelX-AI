import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import create_app
from app.db import init_db


class SentinelXDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-key",
                "DATABASE": str(self.database),
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    @contextmanager
    def connect_db(self):
        connection = sqlite3.connect(self.database)
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def ingest(self, events):
        response = self.client.post(
            "/api/ingest",
            data={
                "file": (
                    io.BytesIO(json.dumps(events).encode()),
                    "detection-test.json",
                )
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201, response.json)

    def auth_event(self, minute, *, event_type="ssh_authentication", outcome="failure",
                   username="analyst", source_ip="192.0.2.55"):
        observed = datetime(2026, 3, 1, tzinfo=timezone.utc) + timedelta(minutes=minute)
        return {
            "timestamp": observed.isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "outcome": outcome,
            "username": username,
            "source_ip": source_ip,
            "host_name": "test-endpoint",
        }

    def run_rules(self):
        response = self.client.post("/api/detections/run")
        self.assertEqual(response.status_code, 200, response.json)
        return response.json["data"]

    def alerts(self):
        with self.connect_db() as connection:
            rows = connection.execute(
                "SELECT a.id, a.rule_id, a.title, a.severity, a.explanation, "
                "a.fingerprint, r.mitre_technique_id, r.mitre_technique_name "
                "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id "
                "ORDER BY a.rule_id"
            ).fetchall()
        return [dict(zip(
            ("id", "rule_id", "title", "severity", "explanation", "fingerprint",
             "mitre_technique_id", "mitre_technique_name"),
            row,
        )) for row in rows]

    def test_repeated_ssh_failures_create_r001_alert_with_event_evidence(self):
        self.ingest([self.auth_event(i) for i in range(5)])
        result = self.run_rules()
        alerts = self.alerts()
        self.assertEqual(result["rules_evaluated"], 6)
        self.assertEqual([alert["rule_id"] for alert in alerts], ["R001"])
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertIn("not proof of an attack", alerts[0]["explanation"])
        self.assertEqual(alerts[0]["mitre_technique_id"], "T1110")
        with self.connect_db() as connection:
            evidence = connection.execute(
                "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (alerts[0]["id"],)
            ).fetchone()[0]
        self.assertEqual(evidence, 5)

    def test_authorization_events_are_not_mistaken_for_authentication(self):
        events = [
            self.auth_event(i, event_type="authorization_change", username=f"user-{i}")
            for i in range(5)
        ]
        self.ingest(events)
        self.run_rules()
        self.assertEqual(self.alerts(), [])

    def test_successful_login_after_failures_creates_r003_alert(self):
        events = [self.auth_event(i, username="alice") for i in range(3)]
        events.append(self.auth_event(3, username="alice", outcome="success"))
        self.ingest(events)
        self.run_rules()
        alert = next(alert for alert in self.alerts() if alert["rule_id"] == "R003")
        self.assertEqual(alert["mitre_technique_id"], "T1110")
        with self.connect_db() as connection:
            evidence = connection.execute(
                "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (alert["id"],)
            ).fetchone()[0]
        self.assertEqual(evidence, 4)

    def test_success_before_failures_does_not_match_r003(self):
        events = [
            self.auth_event(0, username="alice", outcome="success"),
            self.auth_event(1, username="alice"),
            self.auth_event(2, username="alice"),
            self.auth_event(3, username="alice"),
        ]
        self.ingest(events)
        self.run_rules()
        self.assertNotIn("R003", {alert["rule_id"] for alert in self.alerts()})

    def test_successful_logins_from_multiple_sources_create_r002_alert(self):
        self.ingest(
            [
                self.auth_event(0, event_type="interactive_login", outcome="success", username="alice", source_ip="192.0.2.1"),
                self.auth_event(2, event_type="interactive_login", outcome="success", username="alice", source_ip="198.51.100.2"),
            ]
        )
        self.run_rules()
        alert = next(alert for alert in self.alerts() if alert["rule_id"] == "R002")
        self.assertEqual(alert["mitre_technique_id"], "T1078")
        self.assertIn("VPN, proxy, or NAT", alert["explanation"])

    def test_high_authentication_frequency_creates_r004_alert_without_mapping(self):
        events = [
            self.auth_event(i / 2, event_type="authentication", outcome="success", username=f"user-{i}")
            for i in range(10)
        ]
        self.ingest(events)
        self.run_rules()
        alert = next(alert for alert in self.alerts() if alert["rule_id"] == "R004")
        self.assertIsNone(alert["mitre_technique_id"])

    def test_failures_against_multiple_accounts_create_r005_alert(self):
        events = [
            self.auth_event(i, username=f"user-{i}", source_ip="203.0.113.8")
            for i in range(3)
        ]
        self.ingest(events)
        self.run_rules()
        alert = next(alert for alert in self.alerts() if alert["rule_id"] == "R005")
        self.assertEqual(alert["mitre_technique_id"], "T1110")
        self.assertIn("not proof of malicious activity", alert["explanation"])

    def test_explicit_privilege_escalation_creates_r006_alert(self):
        self.ingest(
            [
                self.auth_event(
                    1,
                    event_type="privilege_escalation",
                    outcome="success",
                    username="operator",
                )
            ]
        )
        self.run_rules()
        alert = next(alert for alert in self.alerts() if alert["rule_id"] == "R006")
        self.assertEqual(alert["mitre_technique_id"], "T1548")
        self.assertIn("not confirmation", alert["explanation"])

    def test_generic_sudo_event_does_not_match_privilege_escalation_rule(self):
        self.ingest(
            [
                self.auth_event(
                    1,
                    event_type="sudo_command",
                    outcome="success",
                    username="operator",
                )
            ]
        )
        self.run_rules()
        self.assertNotIn("R006", {alert["rule_id"] for alert in self.alerts()})

    def test_detection_reruns_do_not_duplicate_alerts_or_evidence(self):
        self.ingest([self.auth_event(i) for i in range(5)])
        first = self.run_rules()
        second = self.run_rules()
        self.assertEqual(first["alerts_created"], 1)
        self.assertEqual(second["matches_found"], 1)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(second["alerts_existing"], 1)
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0], 5)

    def test_threshold_configuration_and_disabled_rules_are_honored(self):
        self.ingest([self.auth_event(i) for i in range(2)])
        with self.connect_db() as connection:
            connection.execute(
                "UPDATE detection_rules SET config_json = ? WHERE rule_id = 'R001'",
                (json.dumps({"attempts": 2, "window_minutes": 10}),),
            )
            connection.execute("UPDATE detection_rules SET enabled = 0 WHERE rule_id = 'R004'")
        result = self.run_rules()
        self.assertEqual(result["rules_evaluated"], 5)
        self.assertEqual([alert["rule_id"] for alert in self.alerts()], ["R001"])

    def test_invalid_rule_configuration_returns_explicit_api_error(self):
        with self.connect_db() as connection:
            connection.execute(
                "UPDATE detection_rules SET config_json = ? WHERE rule_id = 'R001'",
                ('{"attempts":1,"window_minutes":10}',),
            )
        response = self.client.post("/api/detections/run")
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json["error"]["code"], "invalid_rule_configuration")
        self.assertEqual(self.alerts(), [])

    def test_invalid_legacy_event_timestamp_returns_explicit_data_error(self):
        with self.connect_db() as connection:
            connection.execute(
                "INSERT INTO security_events "
                "(id, observed_at, event_type, outcome) VALUES (?, ?, ?, ?)",
                ("legacy-event", "not-a-time", "ssh_authentication", "failure"),
            )
        response = self.client.post("/api/detections/run")
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json["error"]["code"], "invalid_event_data")
        self.assertEqual(self.alerts(), [])

    def test_cli_detection_command_runs_rules_and_reports_results(self):
        self.ingest([self.auth_event(i) for i in range(5)])
        with self.app.app_context():
            result = self.app.test_cli_runner().invoke(args=["run-detections"])
        self.assertEqual(result.exit_code, 0, f"{result.output}\n{result.exception!r}")
        self.assertIn("1 new alerts", result.output)
        self.assertEqual(len(self.alerts()), 1)

    def test_dashboard_alerts_include_mapping_and_rule_metadata(self):
        self.ingest([self.auth_event(i) for i in range(5)])
        self.run_rules()
        response = self.client.get("/api/dashboard")
        alert = response.json["data"]["recent_alerts"][0]
        self.assertEqual(alert["rule_id"], "R001")
        self.assertEqual(alert["mitre_technique_id"], "T1110")
        self.assertEqual(alert["evidence_count"], 5)
        page = self.client.get("/")
        self.assertIn(b"MITRE ATT&amp;CK", page.data)
        self.assertIn(b"Run detection rules", page.data)

    def test_detection_rules_endpoint_exposes_thresholds_and_mappings(self):
        response = self.client.get("/api/detections/rules")
        self.assertEqual(response.status_code, 200)
        rules = response.json["data"]["rules"]
        self.assertEqual(len(rules), 6)
        repeated_failures = next(rule for rule in rules if rule["rule_id"] == "R001")
        self.assertEqual(json.loads(repeated_failures["config_json"]), {"attempts": 5, "window_minutes": 10})
        self.assertEqual(repeated_failures["mitre_technique_id"], "T1110")
        high_frequency = next(rule for rule in rules if rule["rule_id"] == "R004")
        self.assertIsNone(high_frequency["mitre_technique_id"])

    def test_v2_database_migration_adds_rule_metadata_and_alert_fingerprints(self):
        legacy_database = Path(self.temp_dir.name) / "legacy-v2.db"
        connection = sqlite3.connect(legacy_database)
        connection.executescript(
            """
            CREATE TABLE detection_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY,
                rule_id TEXT REFERENCES detection_rules(rule_id),
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                explanation TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO detection_rules
                (rule_id, name, description, severity, created_at, updated_at)
                VALUES ('OLD1', 'Existing rule', 'Preserve this rule', 'low', 't', 't');
            INSERT INTO alerts
                (id, rule_id, title, severity, explanation, triggered_at, created_at)
                VALUES ('old-alert', 'OLD1', 'Existing alert', 'low', 'Keep evidence', 't', 't');
            PRAGMA user_version = 2;
            """
        )
        connection.close()

        self.app.config["DATABASE"] = str(legacy_database)
        with self.app.app_context():
            init_db()

        connection = sqlite3.connect(legacy_database)
        try:
            rule_columns = {row[1] for row in connection.execute("PRAGMA table_info(detection_rules)")}
            alert_columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")}
            old_rule = connection.execute(
                "SELECT name, description FROM detection_rules WHERE rule_id = 'OLD1'"
            ).fetchone()
            old_alert = connection.execute(
                "SELECT title, explanation, fingerprint FROM alerts WHERE id = 'old-alert'"
            ).fetchone()
            rule_count = connection.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        finally:
            connection.close()
        self.assertTrue({"mitre_technique_id", "recommended_steps_json"} <= rule_columns)
        self.assertIn("fingerprint", alert_columns)
        self.assertEqual(old_rule, ("Existing rule", "Preserve this rule"))
        self.assertEqual(old_alert, ("Existing alert", "Keep evidence", None))
        self.assertEqual(rule_count, 7)
        self.assertEqual(version, 5)


if __name__ == "__main__":
    unittest.main()
