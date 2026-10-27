from datetime import datetime, timezone
import ipaddress
import hashlib
import json
import os
import platform
import subprocess

from app.audit import append_audit_entry


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
