from pathlib import Path

import click
from flask import current_app

from app.db import get_db
from app.ingestion.service import ingest_log_file


@click.command("ingest-logs")
@click.argument("path", type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True))
def ingest_logs_command(path):
    """Validate and import a local JSON or CSV security log file."""
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    if path.stat().st_size > max_bytes:
        raise click.ClickException(f"File exceeds the {max_bytes}-byte upload limit.")
    result = ingest_log_file(get_db(), path.name, path.read_bytes(), max_bytes)
    click.echo(
        f"{result['status']}: received {result['records_received']}, "
        f"imported {result['records_imported']}, rejected {result['records_rejected']}, "
        f"duplicates {result['records_duplicate']}."
    )
    for error in result["errors"]:
        record = f"Record {error['record']}: " if isinstance(error, dict) else ""
        message = error["message"] if isinstance(error, dict) else error
        click.echo(f"{record}{message}", err=True)
    if result["status"] == "failed":
        raise click.ClickException("The file was not ingested.")
