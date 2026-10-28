import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.audit import verify_audit_chain
from app.db import init_db
from app.remediation.executor import (
    RemediationExecutionError,
    approve_firewall_block,
    remove_firewall_block,
)
from app.threat_intel.providers import (
    AbuseIPDBProvider,
    ThreatIntelError,
    VirusTotalProvider,
)


class SentinelXPhaseFiveTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-key",
                "DATABASE": str(self.database),
                "AGENT_TOKEN": "local-test-token",
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    @property
    def ui_headers(self):
        return {"X-SentinelX-Request": "1"}

    @property
    def agent_headers(self):
        return {"Authorization": f"Bearer {self.app.config['AGENT_TOKEN']}"}

    @contextmanager
    def connect_db(self):
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def configure_mock_provider(self):
        return self.client.put(
            "/api/settings/threat-intel",
            json={"provider": "mock", "enabled": True},
            headers=self.ui_headers,
        )

    def create_evidence_alert(self, source_ip="8.8.8.8"):
        with self.connect_db() as connection:
            connection.execute(
                "INSERT INTO security_events "
                "(id, observed_at, event_type, outcome, username, source_ip, host_name) "
                "VALUES ('event-ip', '2026-03-01T10:00:00Z', 'authentication', "
                "'failure', 'analyst', ?, 'host-a')",
                (source_ip,),
            )
            connection.execute(
                "INSERT INTO alerts "
                "(id, title, severity, explanation, triggered_at) "
                "VALUES ('alert-ip', 'Suspicious login', 'high', 'Evidence', "
                "'2026-03-01T10:00:00Z')"
            )
            connection.execute(
                "INSERT INTO alert_events (alert_id, event_id) VALUES ('alert-ip', 'event-ip')"
            )

    def create_firewall_recommendation(self, source_ip="8.8.8.8"):
        with self.connect_db() as connection:
            connection.execute(
                "INSERT INTO remediation_actions "
                "(id, alert_id, action_type, title, rationale, target_json, "
                "requires_human_approval) "
                "VALUES ('recommendation-1', 'alert-ip', 'block_source_ip', "
                "'Review IP', 'Observed evidence', ?, 1)",
                (json.dumps({
                    "source_ip": source_ip,
                    "available": True,
                    "execution_available": False,
                }),),
            )

    def test_settings_provider_selection_is_validated_and_audited(self):
        self.assertEqual(self.client.get("/api/settings").json["data"]["threat_intel"]["provider"], "disabled")
        self.assertEqual(
            self.client.put(
                "/api/settings/threat-intel",
                json={"provider": "mock", "enabled": True},
                headers=self.ui_headers,
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(
                "/api/settings/threat-intel",
                json={"provider": "unknown", "enabled": True},
                headers=self.ui_headers,
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.put(
                "/api/settings/threat-intel",
                json={"provider": "abuseipdb", "enabled": True},
                headers=self.ui_headers,
            ).status_code,
            409,
        )
        history = self.client.get("/api/audit").json["data"]
        self.assertTrue(history["verification"]["valid"])
        self.assertEqual(history["entries"][0]["action"], "settings.threat_intel_updated")

    def test_ui_state_changes_require_same_origin_intent_and_provider_test_is_audited(self):
        self.configure_mock_provider()
        self.assertEqual(self.client.post("/api/settings/threat-intel/test").status_code, 403)
        cross_origin = self.client.post(
            "/api/settings/threat-intel/test",
            headers={**self.ui_headers, "Origin": "https://untrusted.example"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        response = self.client.post(
            "/api/settings/threat-intel/test",
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["data"]["test_indicator"], "8.8.8.8")
        entries = self.client.get("/api/audit").json["data"]["entries"]
        self.assertEqual(entries[0]["action"], "threat_intel.provider_tested")

    def test_threat_intel_enriches_only_observed_public_ips_and_caches_results(self):
        self.create_evidence_alert()
        self.assertEqual(self.configure_mock_provider().status_code, 200)
        response = self.client.post(
            "/api/threat-intel/enrich",
            json={"subject_type": "alert", "subject_id": "alert-ip"},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["data"]["results"][0]["indicator"], "8.8.8.8")
        self.assertEqual(response.json["data"]["results"][0]["score"], 0)
        self.assertIn("shared with the selected provider", response.json["data"]["disclosure"])
        cached = self.client.post(
            "/api/threat-intel/enrich",
            json={"subject_type": "alert", "subject_id": "alert-ip"},
            headers=self.ui_headers,
        )
        self.assertEqual(cached.json["data"]["results"][0]["status"], "cached")
        self.assertEqual(len(self.client.get("/api/threat-intel").json["data"]["lookups"]), 1)

    def test_threat_intel_subject_selector_requires_a_valid_type_and_identifier_pair(self):
        self.configure_mock_provider()
        invalid_requests = [
            {"subject_type": "alert"},
            {"subject_id": "alert-ip"},
            {"subject_type": "other", "subject_id": "alert-ip"},
            {"subject_type": "alert", "subject_id": " "},
        ]
        for payload in invalid_requests:
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/api/threat-intel/enrich",
                    json=payload,
                    headers=self.ui_headers,
                )
                self.assertEqual(response.status_code, 400, response.json)

    def test_non_public_observed_ip_is_never_sent_to_provider(self):
        self.create_evidence_alert("192.168.1.12")
        self.configure_mock_provider()
        response = self.client.post(
            "/api/threat-intel/enrich",
            json={"subject_type": "alert", "subject_id": "alert-ip"},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["results"], [])
        self.assertEqual(len(response.json["data"]["skipped"]), 1)
        self.assertIn("globally routable", response.json["data"]["skipped"][0]["reason"])

    def test_provider_adapters_validate_api_responses(self):
        abuse = AbuseIPDBProvider("secret", request_json=lambda _request: {
            "data": {"abuseConfidenceScore": 82, "totalReports": 12, "countryCode": "US"}
        })
        self.assertEqual(abuse.lookup("8.8.8.8")["score"], 82)
        with self.assertRaises(ThreatIntelError):
            AbuseIPDBProvider("secret", request_json=lambda _request: {"data": {}}).lookup("8.8.8.8")

        virus_total = VirusTotalProvider("secret", request_json=lambda _request: {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2, "suspicious": 1, "harmless": 7,
                        "undetected": 0, "timeout": 0,
                    },
                    "reputation": -3,
                }
            }
        })
        self.assertEqual(virus_total.lookup("8.8.8.8")["score"], 30)

    def test_agent_endpoint_requires_token_and_ingests_only_supported_events(self):
        payload = {
            "events": [
                {
                    "timestamp": f"2026-10-27T10:0{minute}:00Z",
                    "event_type": "windows_security_logon_4625_failure",
                    "outcome": "failure",
                    "username": "demo-user",
                    "source_ip": "203.0.113.7",
                    "host_name": "workstation",
                }
                for minute in range(5)
            ]
        }
        self.assertEqual(self.client.post("/api/host-monitor/windows-events", json=payload).status_code, 401)
        response = self.client.post(
            "/api/host-monitor/windows-events",
            json=payload,
            headers={"Authorization": "Bearer local-test-token"},
        )
        self.assertEqual(response.status_code, 201, response.json)
        self.assertEqual(response.json["data"]["records_imported"], 5)
        detections = self.client.post("/api/detections/run")
        self.assertEqual(detections.status_code, 200, detections.json)
        self.assertGreaterEqual(detections.json["data"]["matches_found"], 1)
        duplicate = self.client.post(
            "/api/host-monitor/windows-events",
            json=payload,
            headers={"Authorization": "Bearer local-test-token"},
        )
        self.assertEqual(duplicate.json["data"]["records_duplicate"], 5)
        successful = {
            "events": [{
                "timestamp": "2026-10-27T10:05:00Z",
                "event_type": "windows_security_logon_4624_success",
                "outcome": "success",
                "username": "demo-user",
                "source_ip": "203.0.113.7",
                "host_name": "workstation",
            }]
        }
        success_response = self.client.post(
            "/api/host-monitor/windows-events",
            json=successful,
            headers=self.agent_headers,
        )
        self.assertEqual(success_response.status_code, 201, success_response.json)
        self.assertEqual(success_response.json["data"]["records_imported"], 1)
        detections = self.client.post("/api/detections/run")
        self.assertEqual(detections.status_code, 200, detections.json)
        self.assertGreaterEqual(detections.json["data"]["matches_found"], 1)
        rejected = self.client.post(
            "/api/host-monitor/windows-events",
            json={"events": [{**payload["events"][0], "event_type": "arbitrary"}]},
            headers={"Authorization": "Bearer local-test-token"},
        )
        self.assertEqual(rejected.status_code, 400)
        remote = self.client.post(
            "/api/host-monitor/windows-events",
            json=payload,
            headers={"Authorization": "Bearer local-test-token"},
            environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
        )
        self.assertEqual(remote.status_code, 403)
        with self.connect_db() as connection:
            event = connection.execute(
                "SELECT event_type, outcome, username FROM security_events"
            ).fetchone()
            self.assertEqual(tuple(event), ("windows_security_logon_4625_failure", "failure", "demo-user"))

    def test_audit_chain_detects_record_tampering(self):
        self.configure_mock_provider()
        self.assertTrue(self.client.post("/api/audit/verify", headers=self.ui_headers).json["data"]["valid"])
        with self.connect_db() as connection:
            connection.execute("UPDATE audit_logs SET action = 'tampered' WHERE id = 1")
        verification = self.client.post("/api/audit/verify", headers=self.ui_headers).json["data"]
        self.assertFalse(verification["valid"])
        self.assertIn(1, verification["invalid_records"])

    def test_firewall_executor_requires_explicit_approval_and_exact_public_target(self):
        self.create_evidence_alert()
        self.create_firewall_recommendation()
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        calls = []

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs))
            return type("Result", (), {"returncode": 0, "stdout": "Ok.", "stderr": ""})()

        try:
            with patch("app.remediation.executor.platform.system", return_value="Windows"):
                with self.assertRaises(RemediationExecutionError):
                    approve_firewall_block(
                        connection, "recommendation-1", "8.8.8.8", False,
                        runner=fake_runner, admin_check=lambda: True,
                    )
                with self.assertRaises(RemediationExecutionError):
                    approve_firewall_block(
                        connection, "recommendation-1", "8.8.4.4", True,
                        runner=fake_runner, admin_check=lambda: True,
                    )
                self.assertEqual(calls, [])
                result = approve_firewall_block(
                    connection, "recommendation-1", "8.8.8.8", True,
                    runner=fake_runner, admin_check=lambda: True,
                )
                self.assertEqual(result["status"], "completed")
                command, kwargs = calls[0]
                self.assertTrue(command[0].lower().endswith("netsh.exe"))
                self.assertIn("remoteip=8.8.8.8", command)
                self.assertFalse(kwargs.get("shell", False))
                with self.assertRaises(RemediationExecutionError):
                    approve_firewall_block(
                        connection, "recommendation-1", "8.8.8.8", True,
                        runner=fake_runner, admin_check=lambda: True,
                    )
                removed = remove_firewall_block(
                    connection, "recommendation-1", "8.8.8.8", True,
                    runner=fake_runner, admin_check=lambda: True,
                )
                self.assertEqual(removed["status"], "completed")
                self.assertIn("delete", calls[1][0])
                with connection:
                    action = connection.execute(
                        "SELECT execution_status, firewall_removal_status, execution_details "
                        "FROM remediation_actions WHERE id = 'recommendation-1'"
                    ).fetchone()
                    audit = connection.execute(
                        "SELECT COUNT(*) FROM audit_logs WHERE entity_id = 'recommendation-1'"
                    ).fetchone()[0]
                self.assertEqual(action["execution_status"], "executed")
                self.assertEqual(action["firewall_removal_status"], "removed")
                self.assertEqual(len(json.loads(action["execution_details"])["history"]), 4)
                self.assertGreaterEqual(audit, 4)
        finally:
            connection.close()

    def test_firewall_executor_rejects_private_targets(self):
        self.create_evidence_alert("192.168.1.2")
        self.create_firewall_recommendation("192.168.1.2")
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        with patch("app.remediation.executor.platform.system", return_value="Windows"):
            with self.assertRaisesRegex(RemediationExecutionError, "globally routable"):
                approve_firewall_block(
                    connection, "recommendation-1", "192.168.1.2", True,
                    runner=lambda *_args, **_kwargs: self.fail("OS command must not run"),
                    admin_check=lambda: True,
                )
        connection.close()

    def test_firewall_cli_decline_never_calls_os_and_records_denial(self):
        self.create_evidence_alert()
        self.create_firewall_recommendation()
        with self.app.app_context():
            result = self.app.test_cli_runner().invoke(
                args=["approve-remediation", "recommendation-1"],
                input="8.8.8.8\nn\n",
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Approval declined", result.output)
        with self.connect_db() as connection:
            action = connection.execute(
                "SELECT execution_status FROM remediation_actions WHERE id = 'recommendation-1'"
            ).fetchone()
            audit = connection.execute(
                "SELECT action FROM audit_logs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertEqual(action["execution_status"], "not_requested")
            self.assertEqual(audit["action"], "remediation.firewall_approval_denied")
            self.assertTrue(verify_audit_chain(connection)["valid"])

    def test_v4_audit_history_is_backfilled_during_v5_migration(self):
        legacy = Path(self.temp_dir.name) / "legacy-v4.db"
        connection = sqlite3.connect(legacy)
        connection.executescript(
            """
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id TEXT, action TEXT NOT NULL,
                entity_type TEXT NOT NULL, entity_id TEXT, details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY, rule_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL, explanation TEXT NOT NULL, triggered_at TEXT NOT NULL,
                fingerprint TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('New', 'Investigating', 'Contained', 'Resolved')),
                findings TEXT, correlation_key TEXT UNIQUE,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE remediation_actions (
                id TEXT PRIMARY KEY,
                alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
                incident_id TEXT REFERENCES incidents(id) ON DELETE CASCADE,
                action_type TEXT NOT NULL CHECK (action_type IN ('block_source_ip', 'terminate_process', 'investigate')),
                status TEXT NOT NULL DEFAULT 'recommendation_only'
                    CHECK (status IN ('recommendation_only', 'dismissed')),
                title TEXT NOT NULL, rationale TEXT NOT NULL, target_json TEXT NOT NULL DEFAULT '{}',
                mitre_technique_id TEXT, mitre_technique_name TEXT,
                requires_human_approval INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                CHECK ((alert_id IS NOT NULL AND incident_id IS NULL) OR
                       (alert_id IS NULL AND incident_id IS NOT NULL))
            );
            INSERT INTO alerts (id, title, severity, status, explanation, triggered_at, created_at)
                VALUES ('legacy-alert', 'Legacy alert', 'high', 'New', 'Evidence', 't', 't');
            INSERT INTO remediation_actions
                (id, alert_id, action_type, title, rationale, target_json, created_at)
                VALUES ('legacy-action', 'legacy-alert', 'investigate', 'Review', 'Evidence', '{}', 't');
            INSERT INTO audit_logs (action, entity_type, details_json, created_at)
                VALUES ('legacy.action', 'test', '{"ok":true}', '2026-10-01T00:00:00Z');
            PRAGMA user_version = 4;
            """
        )
        connection.close()
        self.app.config["DATABASE"] = str(legacy)
        with self.app.app_context():
            init_db()
            from app.db import get_db

            result = verify_audit_chain(get_db())
            version = get_db().execute("PRAGMA user_version").fetchone()[0]
            action = get_db().execute(
                "SELECT execution_status, firewall_removal_status "
                "FROM remediation_actions WHERE id = 'legacy-action'"
            ).fetchone()
            foreign_key_errors = get_db().execute("PRAGMA foreign_key_check").fetchall()
        self.assertTrue(result["valid"])
        self.assertEqual(version, 7)
        self.assertEqual(tuple(action), ("not_requested", "not_requested"))
        self.assertEqual(foreign_key_errors, [])


if __name__ == "__main__":
    unittest.main()
