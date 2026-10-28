# SentinelX-AI

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg?logo=windows)](https://microsoft.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

SentinelX-AI is an open-source, local-first **Endpoint Detection and Response (EDR)** and **Security Orchestration, Automation, and Response (SOAR)** platform for Windows hosts. It features real-time Windows security telemetry collection, deterministic threat detection mapped to MITRE ATT&CK, explicit human-in-the-loop active containment (Firewall IP isolation, PID termination, and file quarantine), and generative AI triage powered by Gemini.

---

## Key Features

- **24/7 Live Windows Telemetry:** Streams and normalizes native Windows Security and Sysmon/PowerShell logs (Event IDs `4624`, `4625`, `5157`, `4104`, `4688`).
- **Deterministic Threat Engine:** 10 out-of-the-box detection rules covering brute force, network reconnaissance, shadow copy deletion, and malicious PowerShell execution.
- **Human-Approved Active Containment:**
  - **Inbound Firewall Isolation:** Block malicious attacking IPs via native `netsh.exe` with typed verification and rollback capability.
  - **Safe Process Termination:** Terminate malicious PIDs using elevated PowerShell checks with protected system process exclusions (prevents killing `lsass`, `csrss`, `svchost`, etc.).
  - **File Quarantine:** Restrict execute permissions and isolate suspicious scripts/executables into `instance/quarantine/<sha256>.locked`.
- **AI-Powered Incident Triage:** Explains incident scope, assesses MITRE techniques, and generates blue-team mitigation advice using the Gemini API (with deterministic offline fallback).
- **Tamper-Evident Audit Ledger:** Cryptographically links all detection, analysis, and containment actions in a SHA-256 hash chain.

---

## Architecture Overview

```text
Host Telemetry Sources (Windows Event Logs & Monitored Paths)
  │
  ├── Watch-SentinelXSecurityLog.ps1 (Security Event IDs 4624, 4625, 5157, 4104, 4688)
  └── Watch-SentinelXFiles.ps1 (SHA-256 local hashing for Downloads / Temp)
        │ (Loopback HTTP + Bearer Token)
        ▼
SentinelX-AI Core Engine (Flask / Python 3.10+)
  ├── Ingestion & Normalization Service (Deduplication, ISO 8601 formatting)
  ├── Deterministic Rules Engine (R001–R010 with MITRE ATT&CK Mapping)
  ├── Incident Correlation (Temporal & contextual entity grouping)
  ├── SQLite Storage (`instance/sentinelx.sqlite` with SHA-256 Audit Chain)
  ├── Gemini Copilot / Local Fallback Triage Engine
  └── Containment Executors (netsh.exe, Stop-Process, File ACL Lockdown)
        │
        ▼
Responsive SOC Dashboard (http://127.0.0.1:5000)
  ├── Real-time Threat Warning Banners & Browser Notifications
  ├── Alerts, Incidents, & Evidence Timelines
  └── Operator-Approved Remediation Panels (Typed Confirmation)
```

---

## Quickstart (Windows 10/11)

### 1. Clone the Repository
Open PowerShell and clone the project:
```powershell
git clone https://github.com/HexaPhantom369/SentinelX-AI.git
Set-Location SentinelX-AI
```

### 2. Environment Configuration
Copy the configuration template:
```powershell
Copy-Item .env.example .env
```
Open `.env` in a text editor to set your configuration:
```env
SENTINELX_SECRET_KEY=generate_a_random_secret_here
SENTINELX_AGENT_TOKEN=choose_a_secure_token_for_telemetry
GEMINI_API_KEY=your_optional_gemini_api_key
SENTINELX_ENABLE_FILE_HASH_LOOKUPS=0
```
*(If `GEMINI_API_KEY` is not provided, SentinelX defaults to built-in deterministic offline analysis).*

### 3. Launch SentinelX Server
Right-click **`start_sentinelx.bat`** and select **Run as administrator**.

The batch script automatically:
- Validates Python 3.10+
- Creates and activates the local virtual environment (`.venv`)
- Installs dependencies from `requirements.txt`
- Initializes and migrates database schemas
- Launches the web console at [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Real-Time Host Monitoring Setup

To enable real-time detection on your machine, run the background telemetry collector in an elevated terminal.

Open an Administrator PowerShell window and execute:
```powershell
Set-Location SentinelX-AI
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Use the exact SENTINELX_AGENT_TOKEN set in your .env
$env:SENTINELX_AGENT_TOKEN = "your_chosen_token_here"

# Start the continuous security log collector
.\app\host_monitor\Watch-SentinelXSecurityLog.ps1
```

Keep this window running. The script continuously captures live security telemetry and forwards sanitized events to your local dashboard.

---

## MITRE ATT&CK Detection Matrix

SentinelX-AI inspects normalized host telemetry using 10 deterministic detection rules:

| Rule ID | Detection Behavior | Default Trigger Threshold | Severity | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- |
| **R001** | Repeated authentication failures from a source/account | 5 failures / 10 minutes | High | `T1110` · Brute Force |
| **R002** | Successful authentication across multiple source IPs | 2 distinct IPs / 15 minutes | Medium | `T1078` · Valid Accounts |
| **R003** | Successful login following repeated failed attempts | 3 failures before success / 15 min | High | `T1110` · Brute Force |
| **R004** | Abnormal authentication spike from single source | 10 events / 5 minutes | Medium | Behavioral Anomaly |
| **R005** | Credential spraying against multiple accounts | 3 accounts / 10 minutes | High | `T1110` · Brute Force |
| **R006** | Explicit local privilege escalation indicators | Explicit event type | Medium | `T1548` · Abuse Elevation Control |
| **R007** | Blocked multi-port firewall connection burst | 10 drops across 5 ports / 2 min | High | `T1046` · Network Service Discovery |
| **R008** | Shadow copy deletion or recovery inhibition | Indicator tag (`vssadmin`, `wbadmin`) | Critical | `T1490` · Inhibit System Recovery |
| **R009** | Obfuscated script, download cradle, or credential dump | Indicator tag (`encoded_command`, cradle)| High | `T1059.001` · PowerShell |
| **R010** | Monitored file hash crosses threat threshold | ≥ 5 malicious engine verdicts | High | `T1204.002` · Malicious File |

---

## Operator Containment & Response (SOAR)

SentinelX enforces a strict **Human-In-The-Loop** containment model. No destructive host action is taken without operator review.

1. **Host Firewall Blocking:**
   - Navigated via **Active Defense**.
   - Generates inbound block rules using native `netsh advfirewall`.
   - Requires typing the exact target IP to confirm block and rollback actions.
2. **Process Termination:**
   - Evaluates process creation (`4688`) evidence.
   - Requires entering the exact decimal PID.
   - Automatically prevents terminating critical operating system processes (`system`, `smss`, `csrss`, `lsass`, `svchost`, `explorer`).
3. **File Quarantine:**
   - Flags suspicious executables and scripts in watched download/temporary directories.
   - Moves target files to `instance/quarantine/<sha256>.locked` and removes execute permissions.

---

## Running the Automated Test Suite

SentinelX utilizes Python's built-in `unittest` framework to execute complete end-to-end regression tests without external testing dependencies:

```powershell
Set-Location SentinelX-AI
.\.venv\Scripts\Activate.ps1
python -m unittest discover -s tests -v
```

All 71+ unit tests validate database schema versioning, evidence linking, mock process termination boundaries, ACL quarantine operations, and AI triage flows.

---

## Security & Operational Scope

- **Local Host Security:** SentinelX binds strictly to loopback (`127.0.0.1`). Do not expose the development server to untrusted public interfaces.
- **Privacy by Design:** Raw command lines, file contents, and passwords are never transmitted externally. When Gemini AI analysis is triggered, only sanitized event metadata (timestamps, usernames, anonymized indicators) is shared.
- **Cryptographic Audit Log:** All containment operations, rule modifications, and incident transitions are recorded in a SHA-256 forward-linked audit ledger.

---

## Contributing & License

Contributions, bug reports, and rule improvements are welcome! Please submit a pull request or open an issue on GitHub.

Distributed under the **MIT License**. See `LICENSE` for more details.