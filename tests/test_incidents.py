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


class SentinelXIncidentTests(unittest.TestCase):
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

    def create_alerts(self, source_ip="8.8.8.8"):
        events = []
        for minute in range(5):
            observed = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(minutes=minute)
            events.append(
                {
                    "timestamp": observed.isoformat().replace("+00:00", "Z"),
                    "event_type": "ssh_authentication",
                    "outcome": "failure",
                    "username": "incident-user",
                    "source_ip": source_ip,
                    "host_name": "lab-endpoint",
                }
            )
        observed = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(minutes=5)
        events.append(
            {
                "timestamp": observed.isoformat().replace("+00:00", "Z"),
                "event_type": "ssh_authentication",
                "outcome": "success",
                "username": "incident-user",
                "source_ip": source_ip,
                "host_name": "lab-endpoint",
            }
        )
        response = self.client.post(
            "/api/ingest",
            data={"file": (io.BytesIO(json.dumps(events).encode()), "incident.json")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201, response.json)
        detections = self.client.post("/api/detections/run")
        self.assertEqual(detections.status_code, 200, detections.json)
        return self.client.get("/api/dashboard").json["data"]["recent_alerts"]

    def group(self):
        response = self.client.post("/api/incidents/group")
        self.assertEqual(response.status_code, 200, response.json)
        return response.json["data"]

    def test_related_alerts_group_into_incident_with_supporting_timeline(self):
        alerts = self.create_alerts()
        self.assertEqual({alert["rule_id"] for alert in alerts}, {"R001", "R003"})
        result = self.group()
        self.assertEqual(result["incidents_created"], 1)
        self.assertEqual(result["alerts_linked"], 2)

        incidents = self.client.get("/api/incidents").json["data"]["incidents"]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "New")
        self.assertEqual(incidents[0]["severity"], "high")
        self.assertEqual(incidents[0]["alert_count"], 2)
        self.assertEqual(incidents[0]["evidence_count"], 6)
        detail = self.client.get(f"/api/incidents/{incidents[0]['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.json["data"]["alerts"]), 2)
        self.assertEqual(len([item for item in detail.json["data"]["timeline"] if item["type"] == "event"]), 6)
        self.assertEqual(json.loads(detail.json["data"]["incident"]["findings"])["classification"], "observed_facts")

    def test_incident_grouping_is_idempotent_and_audited(self):
        self.create_alerts()
        first = self.group()
        second = self.group()
        self.assertEqual(first["incidents_created"], 1)
        self.assertEqual(second["incidents_created"], 0)
        self.assertEqual(second["groups_unchanged"], 1)
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE action = 'incident.created_from_alerts'"
                ).fetchone()[0],
                1,
            )

    def test_incident_lifecycle_validates_transitions_and_audits_changes(self):
        self.create_alerts()
        self.group()
        incident_id = self.client.get("/api/incidents").json["data"]["incidents"][0]["id"]

        transition = self.client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "Investigating"},
        )
        self.assertEqual(transition.status_code, 200)
        self.assertTrue(transition.json["data"]["changed"])
        self.assertEqual(
            self.client.patch(
                f"/api/incidents/{incident_id}",
                json={"status": "Contained"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/incidents/{incident_id}",
                json={"status": "Resolved"},
            ).json["data"]["status"],
            "Resolved",
        )
        self.assertEqual(
            self.client.patch(
                f"/api/incidents/{incident_id}",
                json={"status": "Contained"},
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/incidents/{incident_id}",
                json={"status": "Closed"},
            ).status_code,
            400,
        )
        with self.connect_db() as connection:
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE action = 'incident.status_changed'"
            ).fetchone()[0]
        self.assertEqual(audit_count, 3)

    def test_alert_ai_solve_stores_advisory_and_audit_without_execution(self):
        alerts = self.create_alerts()
        alert = next(alert for alert in alerts if alert["rule_id"] == "R001")
        response = self.client.post(f"/api/alerts/{alert['id']}/ai-solve")
        self.assertEqual(response.status_code, 200, response.json)
        advisory = response.json["data"]
        self.assertEqual(advisory["advisor"], "deterministic_evidence_advisor")
        self.assertFalse(advisory["execution_performed"])
        self.assertEqual(advisory["observed_facts"]["event_count"], 5)
        self.assertEqual(advisory["mitre_mappings"][0]["technique_id"], "T1110")
        block = next(item for item in advisory["recommendations"] if item["action_type"] == "block_source_ip")
        self.assertEqual(block["target"]["source_ip"], "8.8.8.8")
        self.assertTrue(block["requires_human_approval"])
        self.assertFalse(block["execution_available"])
        terminate = next(item for item in advisory["recommendations"] if item["action_type"] == "terminate_process")
        self.assertFalse(terminate["available"])
        self.assertIsNone(terminate["target"]["process_id"])

        history = self.client.get(f"/api/alerts/{alert['id']}/remediation")
        self.assertEqual(history.status_code, 200)
        self.assertTrue(all(item["status"] == "recommendation_only" for item in history.json["data"]["recommendations"]))
        with self.connect_db() as connection:
            audit = connection.execute(
                "SELECT action, details_json FROM audit_logs "
                "WHERE action = 'ai_solve.recommendations_generated'"
            ).fetchone()
            execution_count = connection.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%executed%'"
            ).fetchone()[0]
        self.assertEqual(audit[0], "ai_solve.recommendations_generated")
        self.assertFalse(json.loads(audit[1])["execution_performed"])
        self.assertEqual(execution_count, 0)

    def test_incident_ai_solve_uses_linked_evidence_and_writes_audit(self):
        self.create_alerts()
        self.group()
        incident_id = self.client.get("/api/incidents").json["data"]["incidents"][0]["id"]
        response = self.client.post(f"/api/incidents/{incident_id}/ai-solve")
        self.assertEqual(response.status_code, 200, response.json)
        advisory = response.json["data"]
        self.assertEqual(len(advisory["observed_facts"]["alert_ids"]), 2)
        self.assertEqual(advisory["observed_facts"]["event_count"], 6)
        self.assertEqual({mapping["technique_id"] for mapping in advisory["mitre_mappings"]}, {"T1110"})
        with self.connect_db() as connection:
            action_count = connection.execute(
                "SELECT COUNT(*) FROM remediation_actions WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()[0]
        self.assertEqual(action_count, len(advisory["recommendations"]))

    def test_missing_target_or_unlinked_evidence_returns_clear_error(self):
        self.assertEqual(self.client.post("/api/alerts/no-such-alert/ai-solve").status_code, 422)
        with self.connect_db() as connection:
            connection.execute(
                "INSERT INTO alerts (id, title, severity, explanation, triggered_at) "
                "VALUES ('no-evidence', 'No evidence', 'low', 'No data', '2026-01-01T00:00:00Z')"
            )
        response = self.client.post("/api/alerts/no-evidence/ai-solve")
        self.assertEqual(response.status_code, 422)
        self.assertIn("no linked event evidence", response.json["error"]["message"])
        self.assertEqual(
            self.client.get("/api/incidents/no-such-incident").status_code,
            404,
        )

    def test_cli_groups_correlated_alerts(self):
        self.create_alerts()
        with self.app.app_context():
            result = self.app.test_cli_runner().invoke(args=["group-incidents"])
        self.assertEqual(result.exit_code, 0, f"{result.output}\n{result.exception!r}")
        self.assertIn("1 incidents created", result.output)

    def test_v3_incident_migration_preserves_links_and_maps_legacy_states(self):
        legacy_database = Path(self.temp_dir.name) / "legacy-v3.db"
        connection = sqlite3.connect(legacy_database)
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY, rule_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New', explanation TEXT NOT NULL,
                triggered_at TEXT NOT NULL, fingerprint TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open', 'Investigating', 'Contained', 'Resolved', 'Closed')),
                findings TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE incident_alerts (
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                PRIMARY KEY (incident_id, alert_id)
            );
            INSERT INTO alerts (id, title, severity, explanation, triggered_at, created_at)
                VALUES ('legacy-alert', 'Legacy alert', 'high', 'Evidence', 't', 't');
            INSERT INTO incidents
                (id, title, severity, status, findings, created_at, updated_at)
                VALUES ('legacy-open', 'Legacy open', 'high', 'Open', 'facts', 't', 't');
            INSERT INTO incidents
                (id, title, severity, status, findings, created_at, updated_at)
                VALUES ('legacy-closed', 'Legacy closed', 'low', 'Closed', 'facts', 't', 't');
            INSERT INTO incident_alerts (incident_id, alert_id)
                VALUES ('legacy-open', 'legacy-alert');
            PRAGMA user_version = 3;
            """
        )
        connection.close()
        self.app.config["DATABASE"] = str(legacy_database)
        with self.app.app_context():
            init_db()
        connection = sqlite3.connect(legacy_database)
        try:
            statuses = connection.execute(
                "SELECT id, status FROM incidents ORDER BY id"
            ).fetchall()
            links = connection.execute("SELECT COUNT(*) FROM incident_alerts").fetchone()[0]
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(statuses, [("legacy-closed", "Resolved"), ("legacy-open", "New")])
        self.assertEqual(links, 1)
        self.assertEqual(foreign_key_errors, [])
        self.assertEqual(version, 7)


if __name__ == "__main__":
    unittest.main()
