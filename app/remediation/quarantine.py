from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess

from app.audit import append_audit_entry
from app.remediation.executor import RemediationExecutionError, _windows_admin


ALLOWED_EXTENSIONS = {".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr"}
MAX_FILE_SIZE = 100 * 1024 * 1024


def _allowed_roots():
    profile = Path(os.environ.get("USERPROFILE") or Path.home())
    roots = [
        profile / "Downloads",
        Path(os.environ.get("TEMP") or profile / "AppData" / "Local" / "Temp"),
        Path(os.environ.get("LOCALAPPDATA") or profile / "AppData" / "Local") / "Temp",
    ]
    resolved = set()
    for root in roots:
        try:
            resolved.add(root.resolve(strict=True))
        except (OSError, RuntimeError):
            continue
    return resolved


def _beneath(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_candidate_path(file_path, expected_hash):
    if not isinstance(file_path, str) or not file_path or len(file_path) > 2048:
        raise RemediationExecutionError("Provide a valid local candidate path.")
    candidate = Path(file_path)
    try:
        if candidate.is_symlink():
            raise RemediationExecutionError("Symbolic links and reparse points cannot be quarantined.")
        resolved = candidate.resolve(strict=True)
        stat = resolved.stat()
    except (OSError, ValueError, RuntimeError) as error:
        raise RemediationExecutionError("The monitored file is not available on this host.") from error
    if not resolved.is_file() or resolved.suffix.casefold() not in ALLOWED_EXTENSIONS:
        raise RemediationExecutionError("Only monitored executable and script files can be quarantined.")
    if stat.st_size <= 0 or stat.st_size > MAX_FILE_SIZE:
        raise RemediationExecutionError("The candidate file size is outside the supported range.")
    if hasattr(stat, "st_file_attributes") and stat.st_file_attributes & 0x400:
        raise RemediationExecutionError("Windows reparse points cannot be quarantined.")
    if not any(_beneath(resolved, root) for root in _allowed_roots()):
        raise RemediationExecutionError("Quarantine is limited to the monitored Downloads and Temp folders.")
    if _sha256_file(resolved) != expected_hash:
        raise RemediationExecutionError("The current file hash does not match the suspicious reputation evidence.")
    return resolved


def quarantine_host_file(
    connection,
    file_hash,
    confirm_hash,
    instance_path,
    *,
    runner=None,
    admin_check=None,
):
    runner = runner or subprocess.run
    admin_check = admin_check or _windows_admin
    if confirm_hash != file_hash:
        raise RemediationExecutionError("Type the exact suspicious SHA-256 digest to approve quarantine.")
    row = connection.execute(
        "SELECT file_hash, original_path, status, quarantine_path FROM host_file_candidates "
        "WHERE file_hash = ?",
        (file_hash,),
    ).fetchone()
    if row is None:
        raise RemediationExecutionError("No suspicious file candidate matches this hash.")
    if row["status"] == "quarantined":
        raise RemediationExecutionError("This file is already quarantined.")
    if platform.system() != "Windows":
        raise RemediationExecutionError("File quarantine is supported only on Windows.")
    if not admin_check():
        raise RemediationExecutionError("Run SentinelX in an elevated administrator session.")
    system_root = os.environ.get("SystemRoot")
    icacls = os.path.join(system_root or "", "System32", "icacls.exe")
    if not system_root or not os.path.isfile(icacls):
        raise RemediationExecutionError("Windows icacls.exe is unavailable.")

    original = validate_candidate_path(row["original_path"], file_hash)
    instance = Path(instance_path).resolve()
    quarantine_dir = instance / "quarantine"
    if quarantine_dir.exists() and quarantine_dir.is_symlink():
        raise RemediationExecutionError("The quarantine directory cannot be a symbolic link.")
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir = quarantine_dir.resolve(strict=True)
    if quarantine_dir.parent != instance:
        raise RemediationExecutionError("The quarantine directory escaped the SentinelX instance.")
    destination = quarantine_dir / f"{file_hash}.locked"
    if destination.exists():
        raise RemediationExecutionError("A quarantine destination already exists; inspect it before proceeding.")
    directory_acl = runner(
        [
            icacls, str(quarantine_dir), "/inheritance:r",
            "/grant:r", "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if directory_acl.returncode != 0:
        raise RemediationExecutionError("Windows could not restrict access to the quarantine directory.")

    now = datetime.now(timezone.utc).isoformat()
    approval = {
        "sha256": file_hash,
        "source_name": original.name,
        "destination_name": destination.name,
        "human_approved": True,
        "approver": os.environ.get("USERNAME") or "local-operator",
    }
    try:
        shutil.copy2(original, destination)
        if _sha256_file(destination) != file_hash:
            raise RemediationExecutionError("The quarantined copy failed hash verification.")
        if _sha256_file(original) != file_hash:
            raise RemediationExecutionError("The source file changed during quarantine; it was not removed.")
        original.unlink()
        result = runner(
            [
                icacls, str(destination), "/inheritance:r",
                "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)",
                "/deny", "*S-1-1-0:(X)",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            raise RemediationExecutionError(
                "Windows could not revoke execute permission; the original file will be restored if possible."
            )
    except (OSError, subprocess.TimeoutExpired, RemediationExecutionError) as error:
        if destination.exists():
            try:
                reset = runner(
                    [icacls, str(destination), "/reset"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                if original.exists():
                    destination.unlink()
                elif reset.returncode == 0 and _sha256_file(destination) == file_hash:
                    shutil.move(str(destination), str(original))
            except (OSError, subprocess.TimeoutExpired):
                pass
        connection.execute(
            "UPDATE host_file_candidates SET status = 'failed', quarantine_path = ?, error_summary = ? "
            "WHERE file_hash = ?",
            (str(destination) if destination.exists() else None, str(error)[:500], file_hash),
        )
        append_audit_entry(
            connection,
            "remediation.file_quarantine_failed",
            "file_hash",
            file_hash,
            {
                "reason": str(error)[:500],
                "quarantine_name": destination.name if destination.exists() else None,
                **approval,
            },
            created_at=now,
        )
        connection.commit()
        raise RemediationExecutionError(
            "Quarantine failed; inspect the file location, ACLs, and audit trail."
        ) from error

    connection.execute(
        "UPDATE host_file_candidates SET status = 'quarantined', quarantine_path = ?, "
        "quarantined_at = ?, error_summary = NULL WHERE file_hash = ?",
        (str(destination), now, file_hash),
    )
    append_audit_entry(
        connection,
        "remediation.file_quarantined",
        "file_hash",
        file_hash,
        approval,
        created_at=now,
    )
    connection.commit()
    return {"sha256": file_hash, "status": "quarantined", "quarantine_name": destination.name}
