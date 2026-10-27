import click

from app.db import get_db
from app.incidents.service import group_alerts_into_incidents


@click.command("group-incidents")
def group_incidents_command():
    """Group related alerts into incidents using shared evidence and identity context."""
    result = group_alerts_into_incidents(get_db())
    click.echo(
        f"Considered {result['alerts_considered']} alerts: "
        f"{result['incidents_created']} incidents created, "
        f"{result['incidents_updated']} updated, "
        f"{result['groups_unchanged']} unchanged; "
        f"{result['alerts_linked']} alert links."
    )
