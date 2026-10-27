# SentinelX

SentinelX is a defensive security monitoring and investigation platform built in deliberate, testable phases. The current milestones include a Flask/SQLite foundation, validated JSON/CSV ingestion, explainable evidence-linked detections, incident management, optional threat-intelligence lookups, a token-protected Windows Security log collector, and human-approved Windows Firewall response through the local dashboard or CLI.

## Quickstart

1. `git clone <repository-url> SentinelX-AI`
2. Right-click `start_sentinelx.bat` and choose **Run as administrator**.
3. SentinelX opens at <http://127.0.0.1:5000>; keep the console window open while using it.

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
              ├── Windows Security 4624/4625 loopback event collector
              ├── Interactive local Windows Firewall executor (dashboard modal or CLI)
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
- `app/detection/engine.py` implements six deterministic baseline rules, configurable JSON thresholds, justified ATT&CK metadata, idempotent alert creation, and links every alert to its supporting event IDs.
- `app/detection/cli.py` exposes the detection engine as a Flask CLI command.
- `app/incidents/service.py` correlates alerts using shared event evidence or matching source/account or host/source context within 30 minutes.
- `app/incidents/routes.py` provides incident grouping, detail/timeline, lifecycle, and recommendation APIs.
- `app/remediation/advisor.py` creates deterministic, evidence-based recommendations and audit records. It does not execute operating-system actions or call an external AI model.
- `app/remediation/executor.py` permits only an exact, public IP linked to a pending evidence-backed recommendation; approval and execution require a local loopback request, same-origin UI intent, exact-IP typing, and an elevated Windows process.
- `app/remediation/routes.py` provides browser advisor, approve, rollback, and recommendation-list endpoints with the same executor checks and audit logging as the CLI.
- `app/threat_intel/providers.py` implements mock, AbuseIPDB, and VirusTotal adapters with fixed HTTPS endpoints, bounded requests, validated response shapes, and no redirect following.
- `app/host_monitor/Watch-SentinelXSecurityLog.ps1` reads only Windows Security Event IDs 4624 and 4625 and posts normalized fields to a loopback-only bearer-token endpoint.
- `app/audit.py` appends a SHA-256 hash chain for application audit events and verifies record links and the stored chain head.
- `app/templates/` and `app/static/` contain the accessible responsive dashboard.
- `datasets/synthetic/` contains clearly synthetic Windows and Linux authentication examples.
- `tests/` uses Python's standard-library `unittest`; no test framework dependency is required.

The SQLite schema includes related, constrained tables for users, ingestion jobs, events, rules, alerts, incidents, investigation notes, audit records, remediation recommendations and execution state, threat-intelligence lookups, and model evaluations. Schema version 5 adds IP reputation cache/settings, Windows action state, audit-chain hashes, and backfills existing audit records without removing data.

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

`init-db` creates missing tables and indexes, upgrades earlier schemas to version 5, and preserves existing records. It does not drop or replace the database. The default database is `instance\sentinelx.db`. To keep it elsewhere, set `SENTINELX_DATABASE` to an absolute path before initializing.

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
- `GET /api/settings` reports configured integration state without returning secrets.
- `PUT /api/settings/threat-intel` selects and enables/disables a supported provider. Dashboard mutations require the `X-SentinelX-Request: 1` same-origin intent header.
- `POST /api/settings/threat-intel/test` performs an explicit provider test lookup of `8.8.8.8`; the dashboard confirms this disclosure first.
- `POST /api/threat-intel/enrich` looks up source IPs linked to one alert/incident or active alert evidence. Only globally routable addresses are sent; successful results are cached for 24 hours.
- `GET /api/threat-intel` lists recent lookup results.
- `POST /api/host-monitor/windows-events` accepts 1–100 approved Windows logon event records only, from loopback with the configured bearer token.
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

The script defaults to `http://127.0.0.1:5000`, reads only Windows Security logon events 4624 (success) and 4625 (failure), sends normalized account/IP/host/time fields, and polls with a configurable overlap so repeated events are deduplicated. It does not upload raw XML. Set `SENTINELX_API_BASE` only to an HTTP loopback address. Windows may require granting the operator access to the Security log. The server rejects non-loopback clients and requests without the bearer token; do not bind this development server to an external interface.

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

With a fresh database and both synthetic files imported, the detection command reports 6 enabled rules evaluated against 11 events and creates 3 sample alerts.

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

Use **AI Solve** on an alert or incident to generate a persisted advisory from its linked event evidence. In this phase, “AI Solve” is a deterministic local advisor, not an external AI model. A source-IP firewall block is suggested only for a globally routable observed IP and is clearly marked as requiring human review; this application does not apply firewall changes. Process termination remains unavailable without verified endpoint process identity. No recommendation executes automatically. The advisor records the observed evidence summary, recommendations, ATT&CK mappings, and an audit entry. Do not treat a recommendation as confirmation of malicious activity.

| Rule | Detection behavior | Default threshold | Severity | ATT&CK mapping |
|---|---|---|---|---|
| R001 | Repeated failed authentication from a source/account | 5 failures / 10 minutes | High | T1110 · Brute Force |
| R002 | Successful authentication for one account from multiple source IPs | 2 distinct sources / 15 minutes | Medium | T1078 · Valid Accounts |
| R003 | Successful authentication after failures for the same account and source | 3 failures before success / 15 minutes | High | T1110 · Brute Force |
| R004 | High authentication-event frequency from one source | 10 events / 5 minutes | Medium | Not mapped |
| R005 | Failed authentication against multiple accounts from one source | 3 accounts / 10 minutes | High | T1110 · Brute Force |
| R006 | Event explicitly labeled as privilege escalation | Explicit event type | Medium | T1548 · Abuse Elevation Control Mechanism |

Rule thresholds are stored as JSON in each `detection_rules.config_json`; these values can be changed in the local SQLite database, and the evaluator validates allowed keys and bounded integer values before processing. `GET /api/detections/rules` exposes current values. Default limits are 1–1440 minutes and 2–10,000 attempts/events or 2–1,000 distinct sources/accounts.

MITRE ATT&CK technique names and IDs use the [official Enterprise ATT&CK knowledge base](https://attack.mitre.org/). Mappings are intentionally conservative: R004 is not mapped without a justified technique, R002 notes that VPN/proxy/NAT can explain the pattern, and R006 does not treat generic sudo or admin login events as escalation. These detections are investigation signals, not confirmation that an attack occurred. The UI shows each mapping's rationale as a tooltip.

## Run tests

With the virtual environment active:

```powershell
python -m unittest discover -s tests -v
```

The tests create isolated temporary SQLite databases and cover page rendering, health and dashboard APIs, data-driven counts, status filtering, idempotent initialization and schema upgrades with data preservation, JSON/CSV normalization, malformed and partially invalid files, duplicate ingestion, upload limits, all six detection behaviors, threshold validation, evidence links, alert deduplication, mappings, incident grouping and lifecycle, recommendation persistence and audit history, provider selection/parsing and cache behavior, token-protected event intake, legacy audit-chain migration and tamper detection, and firewall approval/target restrictions using a mocked OS command.

## Security and limitations

- The development server binds to loopback. The upload and ingestion APIs do not yet require authentication; do not expose them to an untrusted network or import sensitive logs until authentication, authorization, CSRF protection, retention, and audit controls are implemented.
- Uploads are limited to 2 MiB and processed in memory. Only timestamp, event type, outcome, username, IP, and host fields are stored; unrecognized columns and raw log content are discarded.
- The CLI reads the specified local file and invokes the same validator. Keep sensitive input files outside version control and delete them according to your own retention policy.
- Reputation providers receive public source IPs only after an operator-triggered lookup. API keys belong in protected local environment configuration; rotate keys if exposed.
- The Windows agent uses a bearer token over loopback HTTP. Keep the token secret, use a high-entropy value, and do not expose the Flask development server or collector endpoint to a network.
- Firewall execution is Windows-only and available from the dashboard or CLI only after exact-IP confirmation. The service must run elevated; the CLI independently prompts for typed-IP and explicit approval.
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
7. **Security hardening:** authentication, authorization, comprehensive CSRF protection, retention controls, deployment hardening, and remote audit export.
7. **Optional anomaly detection:** evaluate and document any model; evidence-based assistance remains usable without external AI.
8. **Endpoint expansion:** additional transparent read-only monitoring, secure event transport, and carefully policy-gated later actions.

Each phase is intended to add tested functionality without claiming future features are already available.
