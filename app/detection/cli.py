import click

from app.db import get_db
from app.detection.engine import (
    DetectionConfigurationError,
    DetectionDataError,
    run_detections,
)


@click.command("run-detections")
def run_detections_command():
    """Evaluate enabled detection rules against stored security events."""
    try:
        result = run_detections(get_db())
    except (DetectionConfigurationError, DetectionDataError) as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        f"Evaluated {result['rules_evaluated']} rules against {result['events_evaluated']} events: "
        f"{result['matches_found']} matches, {result['alerts_created']} new alerts, "
        f"{result['alerts_existing']} existing alerts."
    )
