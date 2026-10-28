from datetime import datetime, timezone
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.db import init_db
from app.analysis.gemini import triage_with_gemini
from app.remediation.quarantine import quarantine_host_file


class StageSevenResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "stage-seven.sqlite"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "stage-seven-test",
                "DATABASE": str(self.database),
                "AGENT_TOKEN": "stage-seven-agent",
                "GEMINI_API_KEY": None,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    @property
    def agent_headers(self):
        return {"Authorization": f"Bearer {self.app.config['AGENT_TOKEN']}"}

    @property
    def ui_headers(self):
        return {"X-SentinelX-Request": "1"}

    def create_suspicious_process_alert(self, process_id="12345", process_name="powershell.exe"):
        response = self.client.post(
            "/api/host-monitor/windows-events",
            headers=self.agent_headers,
            json={
                "events": [{
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "windows_process_creation_4688",
                    "outcome": "failure",
                    "username": "demo-user",
                    "host_name": "demo-host",
                    "host_event_record_id": "987654321",
                    "process_id": process_id,
                    "process_name": process_name,
                    "indicator_tags": ["encoded_command"],
                }]
            },
        )
        self.assertEqual(response.status_code, 201, response.json)
        alert = next(
            item for item in self.client.get("/api/dashboard").json["data"]["recent_alerts"]
            if item["rule_id"] == "R009"
        )
        return alert

    def create_process_recommendation(self, alert_id):
        response = self.client.post(
            "/api/remediation/run-advisor",
            headers=self.ui_headers,
            json={"subject_type": "alert", "subject_id": alert_id},
        )
        self.assertEqual(response.status_code, 200, response.json)
        return next(
            item for item in response.json["data"]["recommendations"]
            if item["action_type"] == "terminate_process"
        )

    def test_process_termination_requires_exact_pid_and_writes_audit(self):
        alert = self.create_suspicious_process_alert()
        recommendation = self.create_process_recommendation(alert["id"])
        target = recommendation["target"]
        self.assertEqual(target["process_id"], "12345")
        self.assertEqual(target["process_name"], "powershell.exe")

        rejected = self.client.post(
            f"/api/remediation/approve-kill/{recommendation['recommendation_id']}",
            headers=self.ui_headers,
            json={"confirm_pid": "12346"},
        )
        self.assertEqual(rejected.status_code, 409)

        windows_root = self.root / "Windows"
        powershell = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.touch()
        with patch.dict("os.environ", {"SystemRoot": str(windows_root)}), \
                patch("app.remediation.executor.platform.system", return_value="Windows"), \
                patch("app.remediation.executor._windows_admin", return_value=True), \
                patch("app.remediation.executor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as runner:
            response = self.client.post(
                f"/api/remediation/approve-kill/{recommendation['recommendation_id']}",
                headers=self.ui_headers,
                json={"confirm_pid": "12345"},
            )

        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["data"]["status"], "completed")
        command = runner.call_args.args[0]
        self.assertTrue(any(item.endswith("Invoke-SentinelXProcessAction.ps1") for item in command))
        self.assertEqual(command[command.index("-ProcessId") + 1], "12345")
        connection = sqlite3.connect(self.database)
        try:
            status = connection.execute(
                "SELECT execution_status FROM remediation_actions WHERE id = ?",
                (recommendation["recommendation_id"],),
            ).fetchone()[0]
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE action = 'remediation.process_termination_completed'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(status, "executed")
        self.assertEqual(audit_count, 1)

    def test_core_windows_process_never_gets_a_termination_recommendation(self):
        alert = self.create_suspicious_process_alert("555", "lsass.exe")
        recommendation = self.create_process_recommendation(alert["id"])
        self.assertFalse(recommendation["available"])
        self.assertFalse(recommendation["execution_available"])
        self.assertIsNone(recommendation["target"]["process_id"])

    def test_gemini_prompt_is_structured_and_excludes_raw_commands(self):
        analysis = {
            "subject_type": "incident",
            "subject_title": "Suspicious PowerShell",
            "risk": {"severity": "high"},
            "mitre_attack": [],
            "evidence": {
                "events": [{
                    "event_id": "event-1",
                    "event_type": "windows_process_creation_4688",
                    "username": "demo-user",
                    "source_ip": "198.51.100.77",
                    "process_id": "12345",
                    "process_name": "powershell.exe",
                }],
                "indicators": ["encoded_command"],
            },
        }
        response_body = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "threat_summary": "A suspicious encoded command ran.",
                            "severity": "high",
                            "mitre_attack": [{
                                "technique_id": "T1059.001",
                                "technique_name": "PowerShell",
                                "tactic": "Execution",
                            }],
                            "mitigation_advice": ["Verify the process with the host owner."],
                        })
                    }]
                }
            }]
        }
        captured = {}

        def fake_request(url, api_key, payload):
            captured.update({"url": url, "api_key": api_key, "payload": payload})
            return response_body

        triage = triage_with_gemini(analysis, "test-key", request_json=fake_request)
        prompt = captured["payload"]["contents"][0]["parts"][0]["text"]
        self.assertEqual(triage["severity"], "high")
        self.assertIn("12345", prompt)
        self.assertNotIn("command_line", prompt)
        self.assertNotIn("raw command", prompt.casefold())

    def test_analysis_endpoint_falls_back_locally_without_gemini_key(self):
        alert = self.create_suspicious_process_alert()
        response = self.client.post(
            f"/api/analysis/alert/{alert['id']}",
            headers=self.ui_headers,
            json={"external_ai": True},
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertFalse(response.json["data"]["model_called"])
        self.assertIn("GEMINI_API_KEY", response.json["data"]["ai_fallback_reason"])

    def test_analysis_endpoint_uses_gemini_only_for_explicit_request(self):
        alert = self.create_suspicious_process_alert()
        triage = {
            "threat_summary": "An encoded PowerShell command was detected.",
            "severity": "high",
            "mitre_attack": [],
            "mitigation_advice": ["Verify the process with the host owner."],
            "model": "gemini-2.5-flash",
            "provider": "Google Gemini",
            "telemetry_disclosed": True,
            "review_required": True,
        }
        self.app.config["GEMINI_API_KEY"] = "test-key"
        with patch("app.analysis.routes.triage_with_gemini", return_value=triage) as gemini:
            response = self.client.post(
                f"/api/analysis/alert/{alert['id']}",
                headers=self.ui_headers,
                json={"external_ai": True},
            )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(response.json["data"]["model_called"])
        self.assertEqual(response.json["data"]["generative_analysis"]["severity"], "high")
        gemini.assert_called_once()

    def test_analysis_does_not_send_to_gemini_without_explicit_opt_in(self):
        alert = self.create_suspicious_process_alert()
        self.app.config["GEMINI_API_KEY"] = "test-key"
        with patch("app.analysis.routes.triage_with_gemini") as gemini:
            response = self.client.post(
                f"/api/analysis/alert/{alert['id']}",
                headers=self.ui_headers,
                json={},
            )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertFalse(response.json["data"]["model_called"])
        gemini.assert_not_called()

    def test_suspicious_virus_total_result_retains_only_local_candidate_path(self):
        downloads = self.root / "Downloads"
        downloads.mkdir()
        candidate = downloads / "sample.exe"
        candidate.write_bytes(b"synthetic suspicious file bytes")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        self.app.config["ENABLE_FILE_HASH_LOOKUPS"] = True
        self.app.config["VIRUSTOTAL_API_KEY"] = "test-key"
        provider = type(
            "MockHashProvider",
            (),
            {
                "lookup_file_hash": lambda _self, value: {
                    "score": 90,
                    "summary": {
                        "malicious_engines": 5,
                        "suspicious_engines": 0,
                        "total_engines": 10,
                    },
                }
            },
        )()
        with patch("app.remediation.quarantine._allowed_roots", return_value={downloads.resolve()}), \
                patch("app.threat_intel.routes.create_provider", return_value=provider) as create:
            response = self.client.post(
                "/api/host-monitor/file-hash",
                headers=self.agent_headers,
                json={"sha256": digest, "file_path": str(candidate)},
            )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(response.json["data"]["local_path_recorded"])
        create.assert_called_once()
        connection = sqlite3.connect(self.database)
        try:
            stored = connection.execute(
                "SELECT original_path, status FROM host_file_candidates WHERE file_hash = ?",
                (digest,),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(stored, (str(candidate.resolve()), "suspicious"))
        active = self.client.get("/api/remediation").json["data"]
        self.assertEqual(active["files"][0]["file_name"], "sample.exe")

    def test_file_quarantine_moves_hash_verified_file_and_revokes_execute(self):
        downloads = self.root / "Downloads"
        downloads.mkdir()
        source = downloads / "sample.exe"
        source.write_bytes(b"synthetic suspicious file bytes")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        instance = self.root / "instance"
        instance.mkdir()
        windows_root = self.root / "Windows"
        icacls = windows_root / "System32" / "icacls.exe"
        icacls.parent.mkdir(parents=True)
        icacls.touch()

        with self.app.app_context():
            connection = sqlite3.connect(self.database)
            connection.row_factory = sqlite3.Row
            connection.execute(
                "INSERT INTO host_file_candidates "
                "(file_hash, original_path, status, reputation_score, observed_at) "
                "VALUES (?, ?, 'suspicious', 90, ?)",
                (digest, str(source), datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
            with patch.dict("os.environ", {"SystemRoot": str(windows_root)}), \
                    patch("app.remediation.quarantine._allowed_roots", return_value={downloads.resolve()}), \
                    patch("app.remediation.quarantine.platform.system", return_value="Windows"), \
                    patch("app.remediation.quarantine._windows_admin", return_value=True), \
                    patch("app.remediation.quarantine.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as runner:
                result = quarantine_host_file(connection, digest, digest, str(instance))
            destination = instance / "quarantine" / f"{digest}.locked"
            self.assertEqual(result["status"], "quarantined")
            self.assertFalse(source.exists())
            self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), digest)
            self.assertIn("*S-1-1-0:(X)", runner.call_args.args[0])
            status = connection.execute(
                "SELECT status FROM host_file_candidates WHERE file_hash = ?",
                (digest,),
            ).fetchone()[0]
            self.assertEqual(status, "quarantined")
            connection.close()


if __name__ == "__main__":
    unittest.main()
