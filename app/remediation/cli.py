import json

import click

from app.audit import append_audit_entry
from app.db import get_db
from app.remediation.executor import (
    RemediationExecutionError,
    approve_firewall_block,
    remove_firewall_block,
)


def _request_approval(action, operation):
    target_ip = json.loads(action["target_json"])["source_ip"]
    click.echo(f"{operation} Windows Firewall rule for observed source IP: {target_ip}")
    click.echo("This changes the local host firewall and may disrupt network access.")
    typed_ip = click.prompt("Type the exact IP to continue", default="", show_default=False)
    if typed_ip != target_ip:
        append_audit_entry(
            get_db(),
            "remediation.firewall_approval_denied",
            "remediation_action",
            action["id"],
            {"reason": "typed_ip_mismatch", "operation": operation},
        )
        get_db().commit()
        raise click.ClickException("IP confirmation did not match; no firewall command was run.")
    if not click.confirm("Do you explicitly approve this local firewall change?", default=False):
        append_audit_entry(
            get_db(),
            "remediation.firewall_approval_denied",
            "remediation_action",
            action["id"],
            {"reason": "human_declined", "operation": operation},
        )
        get_db().commit()
        raise click.ClickException("Approval declined; no firewall command was run.")
    return target_ip


@click.command("approve-remediation")
@click.argument("action_id")
def approve_remediation_command(action_id):
    """Interactively approve one evidence-linked Windows Firewall block."""
    action = get_db().execute(
        "SELECT id, action_type, target_json, execution_status FROM remediation_actions WHERE id = ?",
        (action_id,),
    ).fetchone()
    if action is None:
        raise click.ClickException("Remediation recommendation was not found.")
    typed_ip = _request_approval(action, "Add an inbound block")
    try:
        result = approve_firewall_block(get_db(), action_id, typed_ip, True)
    except RemediationExecutionError as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        f"Firewall rule added for {result['source_ip']} ({result['rule_name']}). "
        "The action and approval are recorded in the audit chain."
    )


@click.command("remove-remediation")
@click.argument("action_id")
def remove_remediation_command(action_id):
    """Interactively remove one SentinelX-managed Windows Firewall block."""
    action = get_db().execute(
        "SELECT id, action_type, target_json, execution_status, firewall_removed_at "
        "FROM remediation_actions WHERE id = ?",
        (action_id,),
    ).fetchone()
    if action is None:
        raise click.ClickException("Remediation recommendation was not found.")
    typed_ip = _request_approval(action, "Remove the SentinelX-managed inbound block for")
    try:
        result = remove_firewall_block(get_db(), action_id, typed_ip, True)
    except RemediationExecutionError as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        f"Firewall rule removed for {result['source_ip']}. "
        "The action is recorded in the audit chain."
    )
