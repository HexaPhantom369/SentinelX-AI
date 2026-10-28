import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from app import create_app
from app.db import init_db


class SentinelXIngestionTests(unittest.TestCase):
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

    def upload(self, filename, content):
        return self.client.post(
            "/api/ingest",
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    def test_json_import_normalizes_fields_and_returns_database_events(self):
        response = self.upload(
            "auth.json",
            json.dumps(
                [
                    {
                        "timestamp": "2026-02-03T04:05:06+02:00",
                        "type": "authentication",
                        "result": "failed",
                        "user": " analyst ",
                        "ip": "192.0.2.10",
                        "host": "lab-win",
                        "password": "must not be stored",
                    }
                ]
            ).encode(),
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["data"]["records_imported"], 1)
        self.assertEqual(response.json["data"]["records_rejected"], 0)
        events = self.client.get("/api/events").json["data"]["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["observed_at"], "2026-02-03T02:05:06.000000Z")
        self.assertEqual(events[0]["outcome"], "failure")
        self.assertEqual(events[0]["source_ip"], "192.0.2.10")
        self.assertNotIn("password", events[0])
        dashboard = self.client.get("/api/dashboard").json["data"]
        self.assertEqual(dashboard["stats"]["security_events"], 1)
        self.assertEqual(dashboard["recent_events"][0]["event_type"], "authentication")
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ingestion_jobs WHERE status = 'completed'").fetchone()[0],
                1,
            )
            stored_values = " ".join(str(value) for row in connection.execute("SELECT * FROM security_events") for value in row)
            self.assertNotIn("must not be stored", stored_values)

    def test_csv_import_normalizes_supported_header_aliases(self):
        response = self.upload(
            "linux.csv",
            b"timestamp,event_type,outcome,username,source_ip,host_name\n"
            b"2026-02-03T04:05:06Z,ssh_login,success,admin,2001:db8::1,linux-lab\n",
        )
        self.assertEqual(response.status_code, 201)
        event = self.client.get("/api/events").json["data"]["events"][0]
        self.assertEqual(event["event_type"], "ssh_login")
        self.assertEqual(event["source_ip"], "2001:db8::1")
        self.assertEqual(event["host_name"], "linux-lab")

    def test_mixed_valid_and_invalid_rows_are_reported_and_valid_rows_kept(self):
        response = self.upload(
            "mixed.json",
            json.dumps(
                [
                    {"timestamp": "2026-01-01T00:00:00Z", "event_type": "login", "source_ip": "192.0.2.1"},
                    {"timestamp": "not-a-time", "event_type": "login"},
                    {"timestamp": "2026-01-01T00:00:00Z", "event_type": "login", "source_ip": "999.1.1.1"},
                ]
            ).encode(),
        )
        self.assertEqual(response.status_code, 207)
        self.assertEqual(response.json["data"]["status"], "partial")
        self.assertEqual(response.json["data"]["records_received"], 3)
        self.assertEqual(response.json["data"]["records_imported"], 1)
        self.assertEqual(response.json["data"]["records_rejected"], 2)
        self.assertEqual(len(self.client.get("/api/events").json["data"]["events"]), 1)

    def test_invalid_records_create_failed_job_without_events(self):
        response = self.upload(
            "invalid.json",
            b'[{"timestamp":"bad","event_type":"login"}]',
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json["data"]["status"], "failed")
        self.assertEqual(response.json["data"]["records_rejected"], 1)
        self.assertEqual(len(response.json["data"]["errors"]), 1)
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT status FROM ingestion_jobs").fetchone()[0], "failed")

    def test_malformed_json_and_unsupported_file_are_recorded_as_failed_jobs(self):
        malformed = self.upload("broken.json", b"{")
        unsupported = self.upload("notes.txt", b"not a log")
        self.assertEqual(malformed.status_code, 422)
        self.assertEqual(unsupported.status_code, 422)
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ingestion_jobs").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 0)

    def test_csv_row_with_more_values_than_header_is_rejected(self):
        response = self.upload(
            "extra.csv",
            b"timestamp,event_type\n2026-01-01T00:00:00Z,login,unexpected\n",
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json["data"]["records_rejected"], 1)
        self.assertIn("more fields", response.json["data"]["errors"][0]["message"])

    def test_duplicate_events_are_not_inserted_again(self):
        event = json.dumps(
            {"timestamp": "2026-01-01T00:00:00Z", "event_type": "login", "username": "analyst"}
        ).encode()
        first = self.upload("one.json", event)
        second = self.upload("two.json", event)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.json["data"]["records_imported"], 0)
        self.assertEqual(second.json["data"]["records_duplicate"], 1)
        with self.connect_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ingestion_jobs").fetchone()[0], 2)

    def test_missing_upload_and_invalid_pagination_return_client_errors(self):
        missing = self.client.post("/api/ingest")
        pagination = self.client.get("/api/events?limit=1000")
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json["error"]["code"], "missing_file")
        self.assertEqual(pagination.status_code, 400)
        self.assertEqual(pagination.json["error"]["code"], "invalid_pagination")

    def test_oversized_file_is_rejected(self):
        self.app.config["MAX_CONTENT_LENGTH"] = 128
        response = self.upload("large.json", b" " * 256)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"]["code"], "file_too_large")

    def test_schema_upgrade_preserves_existing_ingestion_jobs(self):
        with self.connect_db() as connection:
            connection.execute("DROP TABLE ingestion_jobs")
            connection.execute(
                "CREATE TABLE ingestion_jobs ("
                "id TEXT PRIMARY KEY, source_filename TEXT NOT NULL, "
                "status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, "
                "records_received INTEGER NOT NULL DEFAULT 0, "
                "records_imported INTEGER NOT NULL DEFAULT 0, "
                "records_rejected INTEGER NOT NULL DEFAULT 0, error_summary TEXT)"
            )
            connection.execute(
                "INSERT INTO ingestion_jobs (id, source_filename, status, started_at) "
                "VALUES ('old-job', 'old.csv', 'completed', '2026-01-01T00:00:00Z')"
            )
            connection.execute("PRAGMA user_version = 1")
        with self.app.app_context():
            init_db()
        with self.connect_db() as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(ingestion_jobs)")}
            row = connection.execute(
                "SELECT id, records_duplicate FROM ingestion_jobs WHERE id = 'old-job'"
            ).fetchone()
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertIn("records_duplicate", columns)
        self.assertEqual(row, ("old-job", 0))
        self.assertEqual(version, 7)

    def test_cli_import_uses_same_ingestion_service(self):
        sample_path = Path(self.temp_dir.name) / "sample.json"
        sample_path.write_text(
            '{"timestamp":"2026-01-01T00:00:00Z","event_type":"login"}',
            encoding="utf-8",
        )
        with self.app.app_context():
            result = self.app.test_cli_runner().invoke(
                args=["ingest-logs", str(sample_path)],
            )
        self.assertEqual(result.exit_code, 0, f"{result.output}\n{result.exception!r}")
        self.assertIn("imported 1", result.output)
        self.assertEqual(self.client.get("/api/events").json["data"]["events"][0]["event_type"], "login")


if __name__ == "__main__":
    unittest.main()
