from datetime import datetime, timezone
import ipaddress
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

from app.audit import append_audit_entry
from app.remediation.process_policy import (
    PROTECTED_PROCESS_NAMES,
    canonical_process_id,
    eligible_process,
)


class RemediationExecutionError(ValueError):
    """A local firewall action could not be safely approved or completed."""

def _validate_target(connection, action, typed_ip, approved, admin_check):
    if not approved:
        raise RemediationExecutionError("Human approval was not provided; no firewall command was run.")
    if action is None:
        raise RemediationExecutionError("Remediation recommendation was not found.")
    if action["action_type"] != "block_source_ip":
        raise RemediationExecutionError("Only source-IP firewall recommendations can be executed.")
    if action["status"] != "recommendation_only" or not action["requires_human_approval"]:
        raise RemediationExecutionError("Only pending, human-approved recommendations can be executed.")
    if action["execution_status"] != "not_requested":
        raise RemediationExecutionError("This recommendation already has an execution record; review it before retrying.")
    try:
        target = json.loads(action["target_json"])
        address = ipaddress.ip_address(target["source_ip"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RemediationExecutionError("The recommendation does not contain a valid IP target.") from error
    if not address.is_global:
        raise RemediationExecutionError("Only globally routable source IPs can be blocked.")
    if not target.get("available") or target.get("execution_available"):
        raise RemediationExecutionError("This recommendation is not eligible for execution.")
    if typed_ip != str(address):
        raise RemediationExecutionError("The manually confirmed IP does not exactly match the recommendation.")
    evidence = connection.execute(
        "SELECT 1 FROM security_events e "
        "LEFT JOIN alert_events ae ON ae.event_id = e.id "
        "LEFT JOIN incident_alerts ia ON ia.alert_id = ae.alert_id "
        "WHERE e.source_ip = ? AND ((? IS NOT NULL AND ae.alert_id = ?) "
        "OR (? IS NOT NULL AND ia.incident_id = ?)) LIMIT 1",
        (
            str(address),
            action["alert_id"], action["alert_id"],
            action["incident_id"], action["incident_id"],
        ),
    ).fetchone()
    if evidence is None:
        raise RemediationExecutionError("The IP is no longer linked to evidence for this recommendation.")
    if platform.system() != "Windows":
        raise RemediationExecutionError("Firewall execution is supported only on Windows.")
    if not admin_check():
        raise RemediationExecutionError("Run the local SentinelX CLI in an elevated administrator terminal.")
    rule_suffix = hashlib.sha256(action["id"].encode("utf-8")).hexdigest()[:16]
    rule_name = f"SentinelX-Block-{rule_suffix}"
    return str(address), rule_name


def _windows_admin():
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _execution_history(action, details):
    stored = action["execution_details"]
    if stored:
        try:
            previous = json.loads(stored)
        except json.JSONDecodeError as error:
            raise RemediationExecutionError(
                "Existing execution history is invalid; inspect the audit trail before continuing."
            ) from error
        history = previous.get("history") if isinstance(previous, dict) else None
        if not isinstance(history, list):
            history = [previous]
    else:
        history = []
    history.append(details)
    return json.dumps({"history": history}, sort_keys=True)


def _execute(connection, action, operation, rule_name, source_ip, runner):
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise RemediationExecutionError("Windows system directory is unavailable; no firewall command was run.")
    netsh = os.path.join(system_root, "System32", "netsh.exe")
    if not os.path.isfile(netsh):
        raise RemediationExecutionError("Windows netsh.exe was not found in the system directory.")
    if operation == "add":
        command = [
            netsh, "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={source_ip}", "profile=any", "enable=yes",
        ]
    else:
        command = [netsh, "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    action_id = action["id"]
    now = datetime.now(timezone.utc).isoformat()
    approval_details = {
        "operation": operation,
        "human_approved": True,
        "approver": os.environ.get("USERNAME") or "local-operator",
        "source_ip": source_ip,
        "rule_name": rule_name,
    }
    approved_history = _execution_history(action, approval_details)
    if operation == "add":
        cursor = connection.execute(
            "UPDATE remediation_actions SET execution_status = 'executing', execution_at = ?, "
            "execution_details = ? "
            "WHERE id = ? AND execution_status = 'not_requested'",
            (now, approved_history, action_id),
        )
        approval_action = "remediation.firewall_add_approved"
    else:
        cursor = connection.execute(
            "UPDATE remediation_actions SET firewall_removal_status = 'removing', "
            "execution_details = ? "
            "WHERE id = ? AND firewall_removal_status = 'not_requested'",
            (approved_history, action_id),
        )
        approval_action = "remediation.firewall_delete_approved"
    if cursor.rowcount != 1:
        connection.rollback()
        raise RemediationExecutionError("The remediation state changed; inspect it before trying again.")
    append_audit_entry(
        connection,
        approval_action,
        "remediation_action",
        action_id,
        approval_details,
        created_at=now,
    )
    connection.commit()
    action_with_approval = dict(action)
    action_with_approval["execution_details"] = approved_history
    try:
        result = runner(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        details = {
            "operation": operation,
            "human_approved": True,
            "command": command,
            "error": "Command failed or timed out; inspect Windows Firewall before retrying.",
        }
        execution_details = _execution_history(action_with_approval, details)
        if operation == "add":
            connection.execute(
                "UPDATE remediation_actions SET execution_status = 'failed', "
                "execution_details = ? WHERE id = ?",
                (execution_details, action_id),
            )
        else:
            connection.execute(
                "UPDATE remediation_actions SET firewall_removal_status = 'failed', "
                "execution_details = ? WHERE id = ?",
                (execution_details, action_id),
            )
        append_audit_entry(
            connection,
            f"remediation.firewall_{operation}_failed",
            "remediation_action",
            action_id,
            {"source_ip": source_ip, **details},
            created_at=now,
        )
        connection.commit()
        raise RemediationExecutionError(details["error"]) from error

    details = {
        "operation": operation,
        "human_approved": True,
        "command": command,
        "return_code": result.returncode,
        "output": (result.stdout or result.stderr or "")[:1000],
    }
    if result.returncode != 0:
        details["error"] = "Windows Firewall rejected the command; inspect the rule state."
        execution_details = _execution_history(action_with_approval, details)
        if operation == "add":
            connection.execute(
                "UPDATE remediation_actions SET execution_status = 'failed', "
                "execution_details = ? WHERE id = ?",
                (execution_details, action_id),
            )
        else:
            connection.execute(
                "UPDATE remediation_actions SET firewall_removal_status = 'failed', "
                "execution_details = ? WHERE id = ?",
                (execution_details, action_id),
            )
        append_audit_entry(
            connection,
            f"remediation.firewall_{operation}_failed",
            "remediation_action",
            action_id,
            {"source_ip": source_ip, **details},
            created_at=now,
        )
        connection.commit()
        raise RemediationExecutionError(details["error"])

    execution_details = _execution_history(action_with_approval, details)
    if operation == "add":
        connection.execute(
            "UPDATE remediation_actions SET execution_status = 'executed', "
            "execution_details = ? WHERE id = ?",
            (execution_details, action_id),
        )
    else:
        connection.execute(
            "UPDATE remediation_actions SET firewall_removed_at = ?, "
            "firewall_removal_status = 'removed', execution_details = ? WHERE id = ?",
            (now, execution_details, action_id),
        )
    append_audit_entry(
        connection,
        f"remediation.firewall_{operation}_completed",
        "remediation_action",
        action_id,
        {"source_ip": source_ip, **details},
        created_at=now,
    )
    connection.commit()
    return {"action_id": action_id, "source_ip": source_ip, "rule_name": rule_name, "status": "completed"}


def approve_firewall_block(
    connection,
    action_id,
    typed_ip,
    approved,
    *,
    runner=subprocess.run,
    admin_check=_windows_admin,
):
    action = connection.execute(
        "SELECT id, alert_id, incident_id, action_type, status, target_json, "
        "requires_human_approval, execution_status, execution_details "
        "FROM remediation_actions WHERE id = ?",
        (action_id,),
    ).fetchone()
    source_ip, rule_name = _validate_target(connection, action, typed_ip, approved, admin_check)
    return _execute(connection, action, "add", rule_name, source_ip, runner)


def remove_firewall_block(
    connection,
    action_id,
    typed_ip,
    approved,
    *,
    runner=subprocess.run,
    admin_check=_windows_admin,
):
    action = connection.execute(
        "SELECT id, alert_id, incident_id, action_type, status, target_json, "
        "requires_human_approval, execution_status, firewall_removed_at, "
        "firewall_removal_status, execution_details "
        "FROM remediation_actions WHERE id = ?",
        (action_id,),
    ).fetchone()
    if action is None:
        raise RemediationExecutionError("Remediation recommendation was not found.")
    if (
        action["execution_status"] != "executed"
        or action["firewall_removal_status"] != "not_requested"
        or action["firewall_removed_at"]
    ):
        raise RemediationExecutionError("No active SentinelX firewall rule is recorded for this recommendation.")
    action_for_validation = dict(action)
    action_for_validation["execution_status"] = "not_requested"
    action_for_validation["execution_details"] = action["execution_details"]
    source_ip, rule_name = _validate_target(
        connection, action_for_validation, typed_ip, approved, admin_check
    )
    return _execute(connection, action, "delete", rule_name, source_ip, runner)


def approve_process_termination(
    connection,
    action_id,
    typed_pid,
    approved,
    *,
    runner=None,
    admin_check=None,
):
    runner = runner or subprocess.run
    admin_check = admin_check or _windows_admin
    if not approved:
        raise RemediationExecutionError("Human approval was not provided; no process command was run.")
    action = connection.execute(
        "SELECT id, alert_id, incident_id, action_type, status, target_json, "
        "requires_human_approval, execution_status, execution_details "
        "FROM remediation_actions WHERE id = ?",
        (action_id,),
    ).fetchone()
    if action is None:
        raise RemediationExecutionError("Remediation recommendation was not found.")
    if (
        action["action_type"] != "terminate_process"
        or action["status"] != "recommendation_only"
        or not action["requires_human_approval"]
        or action["execution_status"] != "not_requested"
    ):
        raise RemediationExecutionError("Only a pending, human-approved process recommendation can be executed.")
    try:
        target = json.loads(action["target_json"])
        pid_text = target["process_id"]
        pid = int(pid_text, 10)
        process_name = target["process_name"]
        event_id = target["event_id"]
        observed_at = target["observed_at"]
        observed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RemediationExecutionError("The recommendation has invalid process evidence.") from error
    if not isinstance(process_name, str):
        raise RemediationExecutionError("The recommendation has an invalid process name.")
    process_base_name = Path(process_name).stem
    if (
        eligible_process(pid_text, process_name) is None
        or pid in {os.getpid(), os.getppid()}
        or str(pid) != pid_text
        or process_base_name.casefold() in PROTECTED_PROCESS_NAMES
        or typed_pid != pid_text
    ):
        raise RemediationExecutionError("The process target is protected, invalid, or does not exactly match the typed PID.")
    if not isinstance(event_id, str) or not event_id:
        raise RemediationExecutionError("The recommendation has no linked process event.")
    event = connection.execute(
        "SELECT e.id, e.process_id, e.process_name, e.event_type, e.observed_at, "
        "e.indicator_tags_json FROM security_events e "
        "WHERE e.id = ? AND e.event_type = 'windows_process_creation_4688' "
        "AND EXISTS ("
        "SELECT 1 FROM alert_events ae LEFT JOIN incident_alerts ia ON ia.alert_id = ae.alert_id "
        "WHERE ae.event_id = e.id AND ((? IS NOT NULL AND ae.alert_id = ?) "
        "OR (? IS NOT NULL AND ia.incident_id = ?)))",
        (event_id, action["alert_id"], action["alert_id"], action["incident_id"], action["incident_id"]),
    ).fetchone()
    if (
        event is None
        or canonical_process_id(event["process_id"]) != pid_text
        or event["process_name"] != process_name
        or event["observed_at"] != observed_at
    ):
        raise RemediationExecutionError("The process identity is no longer linked to this alert or incident.")
    try:
        tags = json.loads(event["indicator_tags_json"] or "[]")
    except json.JSONDecodeError as error:
        raise RemediationExecutionError("The process indicator evidence is invalid.") from error
    if not isinstance(tags, list) or not tags:
        raise RemediationExecutionError("The process has no suspicious indicator evidence.")
    if platform.system() != "Windows":
        raise RemediationExecutionError("Process termination is supported only on Windows.")
    if not admin_check():
        raise RemediationExecutionError("Run SentinelX in an elevated administrator session.")

    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise RemediationExecutionError("Windows system directory is unavailable; no process command was run.")
    powershell = os.path.join(
        system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    script = Path(__file__).with_name("Invoke-SentinelXProcessAction.ps1")
    if not os.path.isfile(powershell) or not script.is_file():
        raise RemediationExecutionError("The trusted PowerShell process-action files are unavailable.")

    now = datetime.now(timezone.utc).isoformat()
    approval = {
        "process_id": pid,
        "process_name": process_name,
        "event_id": event_id,
        "human_approved": True,
        "approver": os.environ.get("USERNAME") or "local-operator",
    }
    history = _execution_history(action, {"operation": "terminate_process", **approval})
    cursor = connection.execute(
        "UPDATE remediation_actions SET execution_status = 'executing', execution_at = ?, "
        "execution_details = ? WHERE id = ? AND execution_status = 'not_requested'",
        (now, history, action_id),
    )
    if cursor.rowcount != 1:
        connection.rollback()
        raise RemediationExecutionError("The remediation state changed; inspect it before trying again.")
    append_audit_entry(
        connection,
        "remediation.process_termination_approved",
        "remediation_action",
        action_id,
        approval,
        created_at=now,
    )
    connection.commit()
    command = [
        powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(script), "-ProcessId", str(pid),
        "-ExpectedName", process_name, "-ObservedAt", observed_time.isoformat(),
    ]
    try:
        result = runner(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = "PowerShell process termination failed or timed out; inspect the live process."
        output = ""
        return_code = -1
        cause = error
    else:
        return_code = result.returncode
        output = (result.stdout or result.stderr or "")[:1000]
        failure = "PowerShell rejected the process action; no successful termination was confirmed."
        cause = None

    succeeded = return_code == 0
    details = {
        "operation": "terminate_process",
        **approval,
        "return_code": return_code,
        "output": output,
    }
    if not succeeded:
        details["error"] = failure
    history = _execution_history(
        {**dict(action), "execution_details": history},
        details,
    )
    connection.execute(
        "UPDATE remediation_actions SET execution_status = ?, execution_details = ? WHERE id = ?",
        ("executed" if succeeded else "failed", history, action_id),
    )
    append_audit_entry(
        connection,
        "remediation.process_termination_completed" if succeeded else "remediation.process_termination_failed",
        "remediation_action",
        action_id,
        details,
        created_at=now,
    )
    connection.commit()
    if not succeeded:
        error = RemediationExecutionError(failure)
        if cause:
            raise error from cause
        raise error
    return {
        "action_id": action_id,
        "process_id": pid,
        "process_name": process_name,
        "status": "completed",
    }
