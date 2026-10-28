# SentinelX

SentinelX is a defensive security monitoring and investigation platform built in deliberate, testable phases. It includes validated log ingestion, evidence-linked detections and incidents, optional threat intelligence, Windows telemetry, human-approved Windows Firewall/process/file actions, deterministic local analysis, and optional explicitly invoked Gemini triage.

## Quickstart

1. `git clone <repository-url> SentinelX-AI`
2. Right-click `start_sentinelx.bat` and choose **Run as administrator**.
3. SentinelX opens at <http://127.0.0.1:5000>; keep the console window open while using it.

For a safe synthetic end-to-end demonstration, set the server's `SENTINELX_AGENT_TOKEN` in the current PowerShell session, then run `.\simulate_attack.ps1` in another PowerShell window using the same token. It creates synthetic failed-logon and blocked-port records and a harmless short-lived encoded PowerShell child; it does not attempt real logons or send network traffic.

## Current architecture

```text
Browser
  ├── Responsive HTML/CSS/JavaScript dashboard and JSON/CSV upload
  ├── /api/health, /api/dashboard, /api/events, /api/ingest
  ├── /api/detections/*, /api/incidents/*, /api/alerts/*/ai-solve
  ├── /api/threat-intel/*, /api/settings/*, /api/host-monitor/*
  ├── /api/remediation/*, /api/audit/verify, /api/detection/run
        └── Flask application factory and route blueprints
              ├── Shared JSON/CSV validation and normalization service
              ├── Deterministic detection rules and evidence-linked alerts
              ├── Evidence-based incident grouping and lifecycle
              ├── Recommendation-only remediation advisor with audit records
              ├── Pluggable threat-intelligence providers and reputation cache
              ├── Windows Security 4624/4625/5157/4104/4688 loopback event collector
              ├── Local file hashing and explicitly opt-in VirusTotal hash reputation
              ├── Local deterministic evidence analysis and high-risk dashboard warnings
              ├── Optional explicit Gemini triage with sanitized evidence only
              ├── Human-approved Windows Firewall and process executors
              ├── Hash-verified local file quarantine with execution denied
              └── Hash-linked audit history with verification
              └── SQLite database in instance/sentinelx.db
Local operator
  ├── flask ingest-logs PATH (same validation service)
  └── flask run-detections (same detection engine as API)
  └── flask group-incidents (same grouping service as API)
  ├── flask approve-remediation ID (interactive, elevated Windows CLI)
  └── flask remove-remediation ID (interactive reverse operation)
```

- `app/__init__.py` creates the Flask application, registers route blueprints, and configures safe local defaults.
- `app/config.py` reads environment-based settings.
- `app/db.py` owns SQLite connections and idempotent schema initialization.
- `app/routes/` separates browser pages from JSON API endpoints.
- `app/ingestion/service.py` validates the supported event fields, normalizes timestamps/IPs/outcomes, detects duplicate events, and records ingestion history.
- `app/ingestion/cli.py` exposes the same ingestion service to a local operator.
- `app/detection/engine.py` implements ten deterministic baseline rules, configurable JSON thresholds, justified ATT&CK metadata, idempotent alert creation, and links every alert to its supporting event IDs.
- `app/detection/cli.py` exposes the detection engine as a Flask CLI command.
- `app/incidents/service.py` correlates alerts using shared event evidence or matching source/account or host/source context within 30 minutes.
- `app/incidents/routes.py` provides incident grouping, detail/timeline, lifecycle, and recommendation APIs.
- `app/remediation/advisor.py` creates evidence-linked firewall and suspicious-process recommendations, with explicit human-approval flags.
- `app/remediation/executor.py` validates exact public-IP approvals and suspicious PID/name/event evidence before invoking fixed Windows commands without a shell. Process termination rechecks the live name and start time, and blocks core Windows and SentinelX server PIDs.
- `app/remediation/Invoke-SentinelXProcessAction.ps1` contains the fixed, parameter-validated `Stop-Process -Id <PID> -Force` action and refuses protected names or PID reuse.
- `app/remediation/quarantine.py` accepts only hash-matching monitored files under Downloads/Temp, moves them to an admin/SYSTEM-only quarantine directory as `<sha256>.locked`, denies execute permission, and audits completion or failure.
- `app/remediation/routes.py` provides local browser advisor, typed-target approval, rollback, quarantine, and recommendation-list endpoints.
- `app/threat_intel/providers.py` implements mock, AbuseIPDB, and VirusTotal adapters with fixed HTTPS endpoints, bounded requests, validated response shapes, and no redirect following.
- `app/threat_intel/routes.py` supports an opt-in VirusTotal endpoint that discloses only file hashes externally, caps new lookups at 50 per 24 hours, and stores a local watched-file path only when its reputation is suspicious.
- `app/analysis/service.py` creates a deterministic local fallback. `app/analysis/gemini.py` optionally sends sanitized event, user, IP, and process metadata to Gemini only after an operator invokes AI Solve; raw command lines, script bodies, and file contents are never stored or sent.
- `app/host_monitor/Watch-SentinelXSecurityLog.ps1` reads Windows Security Event IDs 4624, 4625, 5157, 4104, and 4688 and posts selected normalized fields and fixed local indicator tags to a loopback-only bearer-token endpoint. Raw command lines and script blocks are not uploaded.
- `app/host_monitor/Watch-SentinelXFiles.ps1` hashes recent files in Downloads and temporary folders locally, sends only SHA-256 externally, and provides a local file path to SentinelX only for possible human-approved quarantine.
- `app/audit.py` appends a SHA-256 hash chain for application audit events and verifies record links and the stored chain head.
- `app/templates/` and `app/static/` contain the accessible responsive dashboard.
- `datasets/synthetic/` contains clearly synthetic Windows and Linux authentication examples.
- `tests/` uses Python's standard-library `unittest`; no test framework dependency is required.

The SQLite schema includes related, constrained tables for users, ingestion jobs, events, rules, alerts, incidents, investigation notes, audit records, remediation recommendations and execution state, suspicious local file candidates, threat-intelligence lookups, and model evaluations. Schema version 7 adds the quarantine-candidate table while preserving earlier records and audit history.

## Windows setup

For the guided Windows bootstrap, right-click `start_sentinelx.bat` and choose **Run as administrator**. It checks Python 3.10+, creates `.venv` when needed, installs the pinned requirement ranges, initializes/upgrades `instance\sentinelx.sqlite`, opens the local dashboard, and starts the server on loopback. If the earlier `instance\sentinelx.db` exists, it makes a consistent SQLite backup into the new path first and leaves the original intact. Keep the console window open. The browser approval flow runs the service elevated, so use it only on a trusted local machine.

Alternatively, run these commands in PowerShell:

```powershell
Set-Location D:\Bikash\github\SentinelX-AI
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks virtual-environment activation, use this for the current terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Generate a local secret and create or upgrade the database:

```powershell
$env:SENTINELX_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
flask --app run.py init-db
```

`init-db` creates missing tables and indexes, upgrades earlier schemas to version 7, and preserves existing records. It does not drop or replace the database. The default database is `instance\sentinelx.db`. To keep it elsewhere, set `SENTINELX_DATABASE` to an absolute path before initializing.

Start the local application:

```powershell
python run.py
```

Open <http://127.0.0.1:5000>. The default server binds to loopback only. The secret above is per PowerShell session; create and persist a protected secret for subsequent sessions. `.env` is ignored by Git. In production mode (`SENTINELX_ENV=production`), a configured `SENTINELX_SECRET_KEY` is required and secure session cookies are enabled.

## API

- `GET /api/health` checks that the application can query SQLite.
- `GET /api/dashboard` returns counts queried from SQLite, recent recorded events and alerts, latest ingestion status, and AI-analysis configuration status.
- `GET /api/events?limit=50&offset=0` lists normalized events, newest first (`limit` 1–100).
- `POST /api/ingest` accepts a multipart file field named `file`; supported formats are `.json` and `.csv`, up to 2 MiB.
- `GET /api/detections/rules` lists enabled and disabled rules, thresholds, and ATT&CK mapping rationale.
- `POST /api/detections/run` (or `/api/detection/run`) evaluates enabled rules against the stored event set and persists deduplicated alerts with evidence links.
- `POST /api/incidents/group` correlates alerts and creates or updates incidents; repeated runs are idempotent.
- `GET /api/incidents` lists incidents with linked-alert and evidence counts.
- `GET /api/incidents/<id>` returns incident, linked alerts, evidence timeline, and investigation notes.
- `PATCH /api/incidents/<id>` changes lifecycle state using validated transitions: New ↔ Investigating as permitted, New/Investigating → Contained or Resolved, Contained → Investigating or Resolved, and Resolved → Investigating.
- `POST /api/alerts/<id>/ai-solve` and `POST /api/incidents/<id>/ai-solve` generate and persist evidence-based recommendations. `GET /api/alerts/<id>/remediation` and `GET /api/incidents/<id>/remediation` list persisted recommendation history.
- `POST /api/remediation/run-advisor` generates evidence-based advice; `GET /api/remediation` lists firewall recommendations and their execution state.
- `POST /api/remediation/approve/<action-id>` and `/api/remediation/remove/<action-id>` require `{"confirm_ip":"<exact-target>"}`, loopback, and same-origin UI intent; they execute/rollback only the corresponding SentinelX Windows Firewall rule.
- `POST /api/remediation/approve-kill/<action-id>` requires `{"confirm_pid":"<exact-decimal-pid>"}` and validates linked suspicious 4688 evidence, exact PID/name, protected-process exclusions, and local administrator status before running the fixed PowerShell script.
- `POST /api/remediation/quarantine/<sha256>` requires `{"confirm_sha256":"<exact-digest>"}` and rechecks the file under a monitored Downloads/Temp folder before moving and denying execute permission.
- `GET /api/remediation` lists pending firewall/process recommendations and suspicious local file candidates (only file names, not paths).
- `GET /api/settings` reports configured integration state without returning secrets.
- `PUT /api/settings/threat-intel` selects and enables/disables a supported provider. Dashboard mutations require the `X-SentinelX-Request: 1` same-origin intent header.
- `POST /api/settings/threat-intel/test` performs an explicit provider test lookup of `8.8.8.8`; the dashboard confirms this disclosure first.
- `POST /api/threat-intel/enrich` looks up source IPs linked to one alert/incident or active alert evidence. Only globally routable addresses are sent; successful results are cached for 24 hours.
- `GET /api/threat-intel` lists recent lookup results.
- `POST /api/host-monitor/windows-events` accepts 1–100 approved Windows security telemetry records, from loopback with the configured bearer token.
- `POST /api/host-monitor/file-hash` accepts a SHA-256 digest and optional local watched-file path from the loopback bearer-token agent; VirusTotal receives only the hash, file contents are never accepted, and the path is retained only for suspicious results.
- `POST /api/analysis/<alert|incident>/<id>` returns deterministic local analysis by default. AI Solve may send sanitized telemetry to Gemini with `{"external_ai":true}` only when the operator explicitly invokes the button and `GEMINI_API_KEY` is configured; without a key or on provider failure it returns local analysis.
- `GET /api/audit` returns recent audit history plus full-chain verification; `GET /api/audit/verify` rechecks every record and `POST` remains available for dashboard compatibility.

Threat-intelligence lookups are disabled by default. Choose `mock`, `abuseipdb`, or `virustotal` in Settings. Real providers require `SENTINELX_ABUSEIPDB_API_KEY` or `SENTINELX_VIRUSTOTAL_API_KEY` to be set in the local environment before enabling. The UI never accepts, stores, or reveals provider keys. External IP lookups are user-initiated and disclose eligible public source IPs to the configured provider; private/reserved IPs are skipped.

## Live Windows Security monitoring

Set a high-entropy shared token in the SentinelX server environment before restarting the app:

```powershell
$env:SENTINELX_AGENT_TOKEN = (python -c "import secrets; print(secrets.token_urlsafe(32))")
```

In another PowerShell process on the same Windows host, set that exact token and start the collector:

```powershell
$env:SENTINELX_AGENT_TOKEN = "<same-token>"
.\app\host_monitor\Watch-SentinelXSecurityLog.ps1
```

The script defaults to `http://127.0.0.1:5000` and reads Security Event IDs 4624 (successful logon), 4625 (failed logon), 5157 (blocked connection), 4104 (PowerShell script block), and 4688 (process creation). It sends normalized account/IP/host/time/port/process metadata and allow-listed indicator tags. Script and command content are inspected locally to classify a few detection patterns and are never uploaded or stored. The collector polls with an overlap so repeated events are deduplicated; set `SENTINELX_API_BASE` only to an HTTP loopback address. Windows may require granting the operator access to the Security log. The server rejects non-loopback clients and requests without the bearer token; do not bind this development server to an external interface.

The optional file watcher polls Downloads and temporary folders for recent executable/script files, hashes eligible files locally, and sends only the SHA-256 digest. VirusTotal file checks are disabled by default. To enable them, set both environment variables in the SentinelX server process before restarting it:

```powershell
$env:SENTINELX_ENABLE_FILE_HASH_LOOKUPS = "1"
$env:SENTINELX_VIRUSTOTAL_API_KEY = "<your local VirusTotal API key>"
```

In the collector PowerShell process, set the same `SENTINELX_AGENT_TOKEN` used by the server, then run `.\app\host_monitor\Watch-SentinelXFiles.ps1`. The server limits new file-hash lookups to 50 per rolling 24-hour window and caches completed results for 24 hours. VirusTotal receives the hash only; local paths and file contents are not uploaded. The watcher may read/hash files locally, so review the paths and retention policies before enabling it.

High and critical alerts are surfaced in the dashboard warning banner, refreshed every 15 seconds; browser notifications are optional and require granting notification permission. Automatic incident analysis is generated locally and deterministically from linked evidence. The explicitly selected AI Solve action may use Gemini when configured; all analysis and recommendations require human validation.

## Human-approved Windows Firewall actions

AI Solve remains recommendation-only until a human approves an eligible public source IP recommendation. Review its evidence, ATT&CK mapping, and impact in the dashboard's Active Defense panel; click **Approve Block**, then type the exact IP into the confirmation dialog. The Windows Firewall service must run elevated (the one-click launcher requests elevation):

```powershell
flask --app run.py approve-remediation <recommendation-id>
```

The dashboard checks the recommendation state and linked evidence, requires a globally routable IP, and invokes the fixed Windows `netsh.exe` path with argument-list execution (no shell) only after typed-IP confirmation. It creates only an inbound, source-IP-scoped rule with a SentinelX-owned unique name. Failed attempts, approval, command result, and rollback are chained into the audit log. The matching **Rollback Rule** button requires the same typed-IP confirmation. The equivalent CLI commands remain available:

```powershell
flask --app run.py remove-remediation <recommendation-id>
```

Do not block an address unless its ownership and impact are understood; firewall changes may disrupt remote access. Browser firewall controls are restricted to local loopback and same-origin UI-intent requests, but SentinelX has no user authentication or roles yet. Running the application elevated gives the process administrator privileges; use it only on a trusted local machine and never expose the server to a network. No process-kill action is available. The audit hash chain is tamper-evident, not tamper-proof against an administrator who can rewrite both the database and its chain head.

Successful responses use a `data` object; request-level errors use an `error` object. Ingestion returns HTTP 201 for completed, 207 for partially imported, and 422 for failed files/records. Each response includes received, imported, rejected, and duplicate counts plus up to 20 row errors. Uploads are not persisted in application storage or the database; the web framework may temporarily spool larger multipart uploads to system temporary storage while processing a request.

JSON may be a single event object, an array of event objects, or an object with an `events` array. Each event must include `timestamp` (or `observed_at`) and `event_type` (or `type`). Optional aliases include `outcome`/`result`, `username`/`user`, `source_ip`/`ip`, and `host_name`/`hostname`. Timestamps must be ISO 8601; timestamps without a timezone are treated as UTC. Outcomes normalize to `success`, `failure`, or `unknown`; IPv4/IPv6 values are validated. Unknown fields such as passwords are ignored and never stored.

CSV uses a header row with the same fields and aliases, for example:

```csv
timestamp,event_type,outcome,username,source_ip,host_name
2026-01-15T10:00:00Z,linux_ssh_authentication,failure,demo-admin,198.51.100.23,sentinelx-linux-demo
```

The event identity is a SHA-256 digest of the normalized supported fields. Re-importing the same normalized event does not create a second event; the new ingestion job records it as a duplicate. Invalid rows are counted and reported while valid rows from the same file are retained. Files that cannot be parsed are recorded as failed ingestion jobs.

## Import logs

Use the dashboard upload section at <http://127.0.0.1:5000> or the CLI. With the virtual environment active and current directory set to `D:\Bikash\github\SentinelX-AI`:

```powershell
flask --app run.py ingest-logs .\datasets\synthetic\windows-auth.json
flask --app run.py ingest-logs .\datasets\synthetic\linux-auth.csv
flask --app run.py run-detections
```

The sample data is synthetic and intentionally includes repeated failed SSH/authentication attempts followed by a success. The import command reports received, imported, rejected, and duplicate counts; the detection command then evaluates the new records and creates explainable sample alerts. Run either import more than once to see duplicate protection. For an API import from PowerShell:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/ingest -Method Post `
  -Form @{ file = Get-Item .\datasets\synthetic\windows-auth.json }
```

The dashboard reloads event and ingestion counts after a browser upload. The Security Events panel shows the latest ten stored records; `/api/events` supports paging for further inspection.

## Detection rules

Run the enabled rules against imported events from PowerShell or the Alerts panel:

```powershell
flask --app run.py run-detections
```

With a fresh database and both synthetic files imported, the detection command reports 10 enabled rules evaluated against 11 events and creates 3 sample alerts.

The JSON API alternative is:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/detections/run -Method Post
```

The command and API share the same engine. Each run reports rules/events evaluated, matches, newly created alerts, and previously recorded matches. Re-running a rule against the same evidence does not create duplicate alerts. Alert evidence is linked through the `alert_events` table. The dashboard shows severity, rule ID/name, evidence event count, and the applicable ATT&CK technique (or “Not mapped”).

## Incidents and AI Solve

Group alerts into evidence-supported incident cases from the dashboard or command line:

```powershell
flask --app run.py group-incidents
```

The grouping service links alerts only when they share supporting event IDs or matching source/account or host/source context within 30 minutes; time proximity alone is not sufficient. Grouping is repeatable, preserves incident state, and records incident creation in the audit log. Incidents expose a timeline of linked events and alerts and support `New`, `Investigating`, `Contained`, and `Resolved` states. Invalid transitions are rejected and successful state changes are audited.

Use **AI Solve · Gemini triage** on an alert or incident to generate persisted defensive recommendations and request triage. If `GEMINI_API_KEY` is configured, the explicit click discloses up to 30 linked event summaries, including usernames, IPs, process IDs/names, and event times to Google Gemini. Raw command lines and script bodies are not available to the model because SentinelX does not collect or store them; file contents are never sent. Provider failure falls back to local deterministic analysis, with a reason returned to the dashboard. Verify model output; do not treat it as confirmation.

The Active Defense panel can show **Approve Kill** only for linked suspicious process-creation evidence with a valid PID/name. The operator must type the exact decimal PID. Windows PowerShell rechecks that the PID still refers to the same executable and that its start time is consistent with the event; core Windows processes, PIDs 0–4, and the SentinelX server/parent process are rejected. This action is Windows-only, requires an elevated server, and is audited.

The file watcher sends the watched file path only to loopback SentinelX. SentinelX stores it only after a suspicious VirusTotal verdict, and the external VirusTotal provider receives only the SHA-256 digest. **Quarantine File** is enabled only for eligible files in the monitored Downloads/Temp folders; it recomputes the SHA-256, moves the file to the instance quarantine as `<sha256>.locked`, restricts directory access to SYSTEM/Administrators, denies execute permission, and records the result in the audit chain. A failed operation is surfaced; inspect the original and quarantine paths before retrying.

| Rule | Detection behavior | Default threshold | Severity | ATT&CK mapping |
|---|---|---|---|---|
| R001 | Repeated failed authentication from a source/account | 5 failures / 10 minutes | High | T1110 · Brute Force |
| R002 | Successful authentication for one account from multiple source IPs | 2 distinct sources / 15 minutes | Medium | T1078 · Valid Accounts |
| R003 | Successful authentication after failures for the same account and source | 3 failures before success / 15 minutes | High | T1110 · Brute Force |
| R004 | High authentication-event frequency from one source | 10 events / 5 minutes | Medium | Not mapped |
| R005 | Failed authentication against multiple accounts from one source | 3 accounts / 10 minutes | High | T1110 · Brute Force |
| R006 | Event explicitly labeled as privilege escalation | Explicit event type | Medium | T1548 · Abuse Elevation Control Mechanism |
| R007 | Burst of blocked firewall connections to several destination ports | 10 events, 5 ports / 2 minutes | High | T1046 · Network Service Discovery |
| R008 | Locally classified shadow-copy deletion indicator | Explicit indicator tag | Critical | T1490 · Inhibit System Recovery |
| R009 | Locally classified encoded, download-cradle, or credential-access indicator | Explicit indicator tag | High | T1059.001 · PowerShell |
| R010 | VirusTotal file hash crosses the suspicious reputation threshold | At least 5 combined malicious/suspicious engines | High | T1204.002 · Malicious File |

Rule thresholds are stored as JSON in each `detection_rules.config_json`; these values can be changed in the local SQLite database, and the evaluator validates allowed keys and bounded integer values before processing. `GET /api/detections/rules` exposes current values. Default limits are 1–1440 minutes and 2–10,000 attempts/events or 2–1,000 distinct sources/accounts.

MITRE ATT&CK technique names and IDs use the [official Enterprise ATT&CK knowledge base](https://attack.mitre.org/). Mappings are intentionally conservative: R004 is not mapped without a justified technique, R002 notes that VPN/proxy/NAT can explain the pattern, and R006 does not treat generic sudo or admin login events as escalation. These detections are investigation signals, not confirmation that an attack occurred. The UI shows each mapping's rationale as a tooltip.

## Run tests

With the virtual environment active:

```powershell
python -m unittest discover -s tests -v
```

The tests create isolated temporary SQLite databases and cover page rendering, health and dashboard APIs, data-driven counts, status filtering, idempotent initialization and schema upgrades with data preservation, JSON/CSV normalization, malformed and partially invalid files, duplicate ingestion, upload limits, all ten detection behaviors, host telemetry metadata, local evidence and Gemini triage behavior, gated hash reputation, PID validation and human-approved process execution using mocked Windows calls, hash-verified file quarantine using mocked ACL execution, threshold validation, evidence links, alert deduplication, incident grouping and lifecycle, audit-chain migration and tamper detection, and firewall approval/target restrictions.

## Security and limitations

- The development server binds to loopback. The upload and ingestion APIs do not yet require authentication; do not expose them to an untrusted network or import sensitive logs until authentication, authorization, CSRF protection, retention, and audit controls are implemented.
- Uploads are limited to 2 MiB and processed in memory. Only timestamp, event type, outcome, username, IP, and host fields are stored; unrecognized columns and raw log content are discarded.
- The CLI reads the specified local file and invokes the same validator. Keep sensitive input files outside version control and delete them according to your own retention policy.
- Reputation providers receive public source IPs only after an operator-triggered lookup. API keys belong in protected local environment configuration; rotate keys if exposed.
- The Windows agent uses a bearer token over loopback HTTP. Keep the token secret, use a high-entropy value, and do not expose the Flask development server or collector endpoint to a network.
- Firewall, process termination, and quarantine actions are Windows-only and available only after evidence validation, local operator approval, exact-target typing, and administrator checks; PowerShell/Windows executors use fixed argument lists, not shell interpolation.
- Dashboard firewall execution is available only through loopback and same-origin UI-intent requests; an exact-IP typed confirmation is required for both block and rollback. Because this local application does not yet have user authentication or roles, do not expose it to other users or networks. Running the bootstrap elevated means the local SentinelX process has administrator privileges.
- The audit chain detects changes to logged records and checks the stored head, but is not a cryptographic signature or remote immutable log. A privileged local attacker can rewrite the database and chain state.
- User login and role enforcement are not implemented. Phase 5 state-changing dashboard APIs require a same-origin UI intent header; this is not a replacement for authentication/authorization or comprehensive CSRF hardening.
- Never expose this development server to a public network. Authentication, role enforcement, CSRF controls, and production deployment hardening are later security work.
- Local secrets and SQLite database files are excluded from version control. Do not put real credentials or sensitive logs in the repository.
- Optional AI and machine-learning behavior is not claimed or simulated.

## Roadmap

1. **Foundation (complete):** application factory, SQLite schema, live overview, responsive base UI.
2. **Log ingestion (complete):** validated JSON/CSV parsing, normalized records, duplicate prevention, ingestion history, and event display.
3. **Detection (complete):** six independently tested rules, configurable thresholds, and evidence-linked alerts.
4. **Incident management (complete):** deterministic alert grouping, lifecycle tracking, evidence timelines, recommendation-only AI Solve, and audit records.
5. **Live host monitoring, threat intelligence, and active defense (complete):** Windows logon event collection, pluggable IP reputation, locally approved firewall changes, and verifiable audit chain.
6. **Web orchestration and bootstrap (complete):** one-click Windows startup, local-browser firewall approval/rollback, and live audit verification.
7. **Host defense detection and analysis (implemented):** additional Windows telemetry, local indicator classification, optional hash-only file reputation, deterministic evidence analysis, and dashboard warnings.
8. **Human-approved EDR response and optional Gemini triage (implemented):** guarded process termination, monitored-file quarantine, typed-target confirmation, audit-chain events, explicit Gemini disclosure, and safe synthetic demo.
9. **Security hardening:** authentication, authorization, comprehensive CSRF protection, retention controls, deployment hardening, and remote audit export.
10. **Optional anomaly detection:** evaluate and document any model; evidence-based assistance remains usable without external AI.

Each phase is intended to add tested functionality without claiming future features are already available.
