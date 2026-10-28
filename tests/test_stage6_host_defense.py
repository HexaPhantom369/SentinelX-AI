import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.db import init_db
from app.threat_intel.providers import ThreatIntelError, VirusTotalProvider


class StageSixHostDefenseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "host-defense.sqlite"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "stage-six-test",
                "DATABASE": str(self.database),
                "AGENT_TOKEN": "local-host-test-token",
                "ENABLE_FILE_HASH_LOOKUPS": False,
                "VIRUSTOTAL_API_KEY": None,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    @property
    def agent_headers(self):
        return {"Authorization": "Bearer local-host-test-token"}

    @property
    def ui_headers(self):
        return {"X-SentinelX-Request": "1", "Origin": "http://localhost"}

    def test_windows_telemetry_ingestion_detects_port_scan_and_suspicious_script(self):
        records = [
            {
                "timestamp": f"2026-10-28T10:00:{minute:02d}Z",
                "event_type": "windows_firewall_blocked_5157",
                "outcome": "failure",
                "source_ip": "8.8.8.8",
                "destination_port": 1000 + minute,
                "host_event_record_id": str(100 + minute),
                "host_name": "workstation",
            }
            for minute in range(10)
        ]
        records.append(
            {
                "timestamp": "2026-10-28T10:11:00Z",
                "event_type": "windows_script_block_4104",
                "outcome": "failure",
                "host_event_record_id": "111",
                "host_name": "workstation",
                "process_name": "powershell.exe",
                "indicator_tags": ["shadow_copy_deletion", "encoded_command"],
            }
        )
        response = self.client.post(
            "/api/host-monitor/windows-events",
            json={"events": records},
            headers=self.agent_headers,
        )
        self.assertEqual(response.status_code, 201, response.json)
        self.assertEqual(response.json["data"]["records_imported"], 11)
        alerts = self.client.get("/api/dashboard").json["data"]["recent_alerts"]
        rule_ids = {alert["rule_id"] for alert in alerts}
        self.assertIn("R007", rule_ids)
        self.assertIn("R008", rule_ids)
        self.assertIn("R009", rule_ids)

        rejected_raw = self.client.post(
            "/api/host-monitor/windows-events",
            json={
                "events": [{
                    "timestamp": "2026-10-28T10:12:00Z",
                    "event_type": "windows_process_creation_4688",
                    "command_line": "sensitive raw command",
                }]
            },
            headers=self.agent_headers,
        )
        self.assertEqual(rejected_raw.status_code, 400)
        connection = sqlite3.connect(self.database)
        try:
            data = " ".join(
                str(value)
                for row in connection.execute("SELECT * FROM security_events")
                for value in row
            )
        finally:
            connection.close()
        self.assertNotIn("sensitive raw command", data)

    def test_analysis_endpoint_returns_local_plain_language_assessment(self):
        self.client.post(
            "/api/host-monitor/windows-events",
            headers=self.agent_headers,
            json={
                "events": [{
                    "timestamp": "2026-10-28T10:00:00Z",
                    "event_type": "windows_process_creation_4688",
                    "outcome": "failure",
                    "host_event_record_id": "1",
                    "host_name": "workstation",
                    "process_id": "1234",
                    "process_name": "powershell.exe",
                    "indicator_tags": ["shadow_copy_deletion"],
                }]
            },
        )
        alert = next(
            item for item in self.client.get("/api/dashboard").json["data"]["recent_alerts"]
            if item["rule_id"] == "R008"
        )
        response = self.client.post(
            f"/api/analysis/alert/{alert['id']}",
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200, response.json)
        analysis = response.json["data"]
        self.assertEqual(analysis["engine"], "local_deterministic_evidence_analysis")
        self.assertFalse(analysis["model_called"])
        self.assertEqual(analysis["risk"]["severity"], "critical")
        self.assertIn("shadow-copy", analysis["plain_language_explanation"])
        self.assertEqual(analysis["mitre_attack"][0]["technique_id"], "T1490")
        self.assertIn("powershell.exe", analysis["evidence"]["process_names"])

    def test_file_hash_lookup_requires_explicit_opt_in_and_only_sends_sha256(self):
        sha256 = "a" * 64
        disabled = self.client.post(
            "/api/host-monitor/file-hash",
            headers=self.agent_headers,
            json={"sha256": sha256},
        )
        self.assertEqual(disabled.status_code, 409)

        self.app.config["ENABLE_FILE_HASH_LOOKUPS"] = True
        self.app.config["VIRUSTOTAL_API_KEY"] = "test-key-not-real"
        provider = type(
            "MockHashProvider",
            (),
            {
                "lookup_file_hash": lambda _self, value: {
                    "score": 40,
                    "summary": {
                        "status": "analyzed",
                        "malicious_engines": 5,
                        "suspicious_engines": 1,
                        "total_engines": 15,
                        "community_reputation": -3,
                    },
                }
            },
        )()
        with patch("app.threat_intel.routes.create_provider", return_value=provider) as create:
            response = self.client.post(
                "/api/host-monitor/file-hash",
                headers=self.agent_headers,
                json={"sha256": sha256},
            )
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(response.json["data"]["suspicious"])
            self.assertFalse(response.json["data"]["file_contents_uploaded"])
            create.assert_called_once()

        alert_rules = {
            item["rule_id"]
            for item in self.client.get("/api/dashboard").json["data"]["recent_alerts"]
        }
        self.assertIn("R010", alert_rules)
        connection = sqlite3.connect(self.database)
        try:
            found = connection.execute(
                "SELECT COUNT(*) FROM threat_intel_lookups WHERE indicator_value = ?",
                (sha256,),
            ).fetchone()[0]
            row = connection.execute(
                "SELECT file_hash FROM security_events WHERE event_type = 'windows_file_reputation_suspicious'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(found, 1)
        self.assertEqual(row[0], sha256)

        invalid = self.client.post(
            "/api/host-monitor/file-hash",
            headers=self.agent_headers,
            json={"sha256": sha256, "path": "C:\\Users\\someone\\file.exe"},
        )
        self.assertEqual(invalid.status_code, 400)

    def test_virustotal_file_hash_adapter_validates_reputation_shape(self):
        provider = VirusTotalProvider(
            "test-key",
            request_json=lambda _request: {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 2,
                            "harmless": 5,
                            "undetected": 0,
                            "timeout": 0,
                        },
                        "reputation": -3,
                    }
                }
            },
        )
        result = provider.lookup_file_hash("a" * 64)
        self.assertEqual(result["score"], 50)
        with self.assertRaises(ThreatIntelError):
            VirusTotalProvider("test-key", request_json=lambda _request: {}).lookup_file_hash("a" * 64)
