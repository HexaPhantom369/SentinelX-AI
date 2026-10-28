import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.db import init_db


class SentinelXAppTests(unittest.TestCase):
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

    def test_homepage_renders_phase_one_workspace(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"security operations center", response.data.lower())
        self.assertIn(b"No security events yet", response.data)
        self.assertIn(b'id="incidents-view"', response.data)
        self.assertIn(b'id="advisor-dialog"', response.data)
        self.assertIn(b"Google Gemini", response.data)
        self.assertIn(b"human-approved quarantine", response.data)

    def test_health_endpoint_reports_database_connection(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["status"], "ok")
        self.assertEqual(response.json["data"]["database"], "connected")

    def test_dashboard_starts_with_real_zero_counts(self):
        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["data"]["stats"],
            {
                "security_events": 0,
                "alerts": 0,
                "critical_alerts": 0,
                "high_alerts": 0,
                "open_incidents": 0,
                "enabled_rules": 10,
            },
        )
        self.assertEqual(response.json["data"]["ingestion"]["status"], "not_configured")
        self.assertEqual(response.json["data"]["ai_analysis"]["status"], "not_configured")

    def test_dashboard_counts_database_records_and_filters_closed_items(self):
        with self.app.app_context():
            connection = sqlite3.connect(self.database)
            connection.execute(
                "INSERT INTO security_events (id, observed_at, event_type) "
                "VALUES ('event-1', '2026-01-01T00:00:00Z', 'authentication')"
            )
            connection.executemany(
                "INSERT INTO alerts (id, title, severity, status, explanation, triggered_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    ("alert-1", "Critical alert", "critical", "New", "Evidence", "2026-01-01T00:00:00Z"),
                    ("alert-2", "Resolved high alert", "high", "Resolved", "Evidence", "2026-01-02T00:00:00Z"),
                ],
            )
            connection.execute(
                "INSERT INTO incidents (id, title, severity, status) "
                "VALUES ('incident-1', 'Open case', 'high', 'New')"
            )
            connection.commit()
            connection.close()

        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["data"]["stats"],
            {
                "security_events": 1,
                "alerts": 2,
                "critical_alerts": 1,
                "high_alerts": 0,
                "open_incidents": 1,
                "enabled_rules": 10,
            },
        )
        self.assertEqual(len(response.json["data"]["recent_alerts"]), 2)

    def test_database_initialization_is_idempotent_and_preserves_data(self):
        with self.app.app_context():
            connection = sqlite3.connect(self.database)
            connection.execute(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES ('user-1', 'analyst', 'test-hash')"
            )
            connection.commit()
            connection.close()
            init_db()
            connection = sqlite3.connect(self.database)
            users = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.close()
            connection = sqlite3.connect(self.database)
            rules = connection.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            connection.close()
        self.assertEqual(users, 1)
        self.assertEqual(schema_version, 7)
        self.assertEqual(rules, 10)

    def test_api_not_found_uses_json_error_response(self):
        response = self.client.get("/api/not-a-route")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
