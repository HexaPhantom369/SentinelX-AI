import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import create_app
from app.db import init_db
from app.remediation.executor import approve_firewall_block, remove_firewall_block


class SentinelXPhaseSixTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "test.sqlite"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "phase-six-test-key",
                "DATABASE": str(self.database),
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    @property
    def ui_headers(self):
        return {
            "X-SentinelX-Request": "1",
            "Origin": "http://localhost",
        }

    def create_recommendation(self):
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "INSERT INTO security_events "
                "(id, observed_at, event_type, outcome, username, source_ip, host_name) "
                "VALUES ('event-phase6', '2026-10-27T10:00:00Z', "
                "'ssh_authentication', 'failure', 'analyst', '8.8.8.8', 'workstation')"
            )
            connection.execute(
                "INSERT INTO alerts "
                "(id, rule_id, title, severity, explanation, triggered_at) "
                "VALUES ('alert-phase6', 'R001', 'Suspicious authentication', 'high', "
                "'Repeated failures', '2026-10-27T10:00:00Z')"
            )
            connection.execute(
                "INSERT INTO alert_events (alert_id, event_id) "
                "VALUES ('alert-phase6', 'event-phase6')"
            )
            connection.execute(
                "INSERT INTO remediation_actions "
                "(id, alert_id, action_type, title, rationale, target_json, "
                "mitre_technique_id, mitre_technique_name, requires_human_approval) "
                "VALUES ('action-phase6', 'alert-phase6', 'block_source_ip', "
                "'Review firewall block', 'Observed in linked evidence', ?, "
                "'T1110', 'Brute Force', 1)",
                (
                    json.dumps(
                        {
                            "source_ip": "8.8.8.8",
                            "available": True,
                            "execution_available": False,
                        }
                    ),
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def test_advisor_endpoint_persists_recommendations_for_the_dashboard(self):
        self.create_recommendation()
        invalid = self.client.post(
            "/api/remediation/run-advisor",
            json={"subject_type": ["alert"], "subject_id": "alert-phase6"},
            headers=self.ui_headers,
        )
        self.assertEqual(invalid.status_code, 400)
        response = self.client.post(
            "/api/remediation/run-advisor",
            json={"subject_type": "alert", "subject_id": "alert-phase6"},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertFalse(response.json["data"]["execution_performed"])
        recommendations = self.client.get("/api/remediation").json["data"]["recommendations"]
        firewall = next(item for item in recommendations if item["id"] != "action-phase6")
        self.assertEqual(firewall["subject_id"], "alert-phase6")
        self.assertEqual(firewall["target"]["source_ip"], "8.8.8.8")
        self.assertEqual(firewall["mitre_technique_id"], "T1110")

    def test_browser_firewall_approval_and_rollback_are_audited(self):
        self.create_recommendation()
        commands = []

        def fake_runner(command, **_kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=0, stdout="Ok.", stderr="")

        def approve(connection, action_id, typed_ip, approved):
            return approve_firewall_block(
                connection,
                action_id,
                typed_ip,
                approved,
                runner=fake_runner,
                admin_check=lambda: True,
            )

        def remove(connection, action_id, typed_ip, approved):
            return remove_firewall_block(
                connection,
                action_id,
                typed_ip,
                approved,
                runner=fake_runner,
                admin_check=lambda: True,
            )

        with (
            patch("app.remediation.routes.approve_firewall_block", side_effect=approve),
            patch("app.remediation.routes.remove_firewall_block", side_effect=remove),
            patch("app.remediation.executor.platform.system", return_value="Windows"),
            patch("app.remediation.executor.os.path.isfile", return_value=True),
            patch.dict("os.environ", {"SystemRoot": r"C:\Windows"}),
        ):
            approved = self.client.post(
                "/api/remediation/approve/action-phase6",
                json={"confirm_ip": "8.8.8.8"},
                headers=self.ui_headers,
            )
            self.assertEqual(approved.status_code, 200, approved.json)
            self.assertEqual(approved.json["data"]["status"], "completed")
            active = self.client.get("/api/remediation").json["data"]["recommendations"]
            self.assertEqual(active[0]["execution_status"], "executed")

            removed = self.client.post(
                "/api/remediation/remove/action-phase6",
                json={"confirm_ip": "8.8.8.8"},
                headers=self.ui_headers,
            )
            self.assertEqual(removed.status_code, 200, removed.json)
            self.assertEqual(removed.json["data"]["status"], "completed")

        self.assertEqual(len(commands), 2)
        self.assertIn("add", commands[0])
        self.assertIn("delete", commands[1])
        connection = sqlite3.connect(self.database)
        try:
            actions = [
                row[0]
                for row in connection.execute(
                    "SELECT action FROM audit_logs ORDER BY id"
                )
            ]
            self.assertEqual(
                connection.execute(
                    "SELECT execution_status, firewall_removal_status "
                    "FROM remediation_actions WHERE id = 'action-phase6'"
                ).fetchone(),
                ("executed", "removed"),
            )
        finally:
            connection.close()
        self.assertIn("remediation.firewall_add_completed", actions)
        self.assertIn("remediation.firewall_delete_completed", actions)
        self.assertTrue(self.client.get("/api/audit/verify").json["data"]["valid"])

    def test_firewall_api_rejects_missing_intent_and_invalid_confirmation(self):
        self.create_recommendation()
        self.assertEqual(
            self.client.post(
                "/api/remediation/approve/action-phase6",
                json={"confirm_ip": "8.8.8.8"},
            ).status_code,
            403,
        )
        invalid = self.client.post(
            "/api/remediation/approve/action-phase6",
            json={"confirm_ip": "not-an-ip"},
            headers=self.ui_headers,
        )
        self.assertEqual(invalid.status_code, 400)
        mismatch = self.client.post(
            "/api/remediation/approve/action-phase6",
            json={"confirm_ip": "8.8.4.4"},
            headers=self.ui_headers,
        )
        self.assertEqual(mismatch.status_code, 409)
        connection = sqlite3.connect(self.database)
        try:
            status = connection.execute(
                "SELECT execution_status FROM remediation_actions "
                "WHERE id = 'action-phase6'"
            ).fetchone()[0]
            self.assertEqual(status, "not_requested")
        finally:
            connection.close()
        history = self.client.get("/api/audit").json["data"]
        self.assertTrue(history["verification"]["valid"])
        self.assertEqual(
            history["entries"][0]["action"],
            "remediation.firewall_approve_rejected",
        )
        cross_origin = self.client.post(
            "/api/remediation/approve/action-phase6",
            json={"confirm_ip": "8.8.8.8"},
            headers={**self.ui_headers, "Origin": "https://untrusted.example"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        remote = self.client.post(
            "/api/remediation/approve/action-phase6",
            json={"confirm_ip": "8.8.8.8"},
            headers=self.ui_headers,
            environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
        )
        self.assertEqual(remote.status_code, 403)

    def test_compatibility_detection_route_and_audit_verification_get(self):
        detections = self.client.post("/api/detection/run")
        self.assertEqual(detections.status_code, 200, detections.json)
        self.assertEqual(detections.json["data"]["events_evaluated"], 0)
        audit = self.client.get("/api/audit/verify")
        self.assertEqual(audit.status_code, 200, audit.json)
        self.assertTrue(audit.json["data"]["valid"])

    def test_dashboard_contains_web_approval_and_audit_controls(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Active defense", response.data)
        self.assertIn(b"Audit Chain: Verifying", response.data)
        self.assertIn(b"remediation-confirm-ip", response.data)
        script = self.client.get("/static/js/dashboard.js")
        try:
            self.assertIn(b"Approve Block", script.data)
            self.assertIn(b"Rollback Rule", script.data)
            self.assertIn(b"Cryptographically Verified", script.data)
        finally:
            script.close()
