import hashlib
import json


GENESIS_HASH = "0" * 64


def _record_hash(row, previous_hash):
    payload = {
        "id": row["id"],
        "actor_user_id": row["actor_user_id"],
        "action": row["action"],
        "entity_type": row["entity_type"],
        "entity_id": row["entity_id"],
        "details_json": row["details_json"],
        "created_at": row["created_at"],
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_audit_entry(
    connection,
    action,
    entity_type,
    entity_id,
    details,
    *,
    actor_user_id=None,
    created_at=None,
):
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    connection.execute(
        "INSERT INTO audit_logs "
        "(actor_user_id, action, entity_type, entity_id, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))",
        (actor_user_id, action, entity_type, entity_id, details_json, created_at),
    )
    row = connection.execute(
        "SELECT id, actor_user_id, action, entity_type, entity_id, details_json, created_at "
        "FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    chain = connection.execute(
        "SELECT last_record_hash FROM audit_chain_state WHERE singleton = 1"
    ).fetchone()
    previous_hash = chain["last_record_hash"] if chain else GENESIS_HASH
    record_hash = _record_hash(row, previous_hash)
    connection.execute(
        "UPDATE audit_logs SET previous_hash = ?, record_hash = ? WHERE id = ?",
        (previous_hash, record_hash, row["id"]),
    )
    connection.execute(
        "INSERT INTO audit_chain_state (singleton, last_record_id, last_record_hash) "
        "VALUES (1, ?, ?) ON CONFLICT(singleton) DO UPDATE SET "
        "last_record_id = excluded.last_record_id, last_record_hash = excluded.last_record_hash",
        (row["id"], record_hash),
    )
    return row["id"], record_hash


def backfill_audit_chain(connection):
    rows = connection.execute(
        "SELECT id, actor_user_id, action, entity_type, entity_id, details_json, "
        "created_at, previous_hash, record_hash FROM audit_logs ORDER BY id"
    ).fetchall()
    has_chain_state = connection.execute(
        "SELECT 1 FROM audit_chain_state WHERE singleton = 1"
    ).fetchone()
    if not rows:
        connection.execute(
            "INSERT OR IGNORE INTO audit_chain_state "
            "(singleton, last_record_id, last_record_hash) VALUES (1, 0, ?)",
            (GENESIS_HASH,),
        )
        return
    if has_chain_state or any(row["record_hash"] for row in rows):
        return
    previous_hash = GENESIS_HASH
    for row in rows:
        record_hash = _record_hash(row, previous_hash)
        connection.execute(
            "UPDATE audit_logs SET previous_hash = ?, record_hash = ? WHERE id = ?",
            (previous_hash, record_hash, row["id"]),
        )
        previous_hash = record_hash
    connection.execute(
        "INSERT INTO audit_chain_state (singleton, last_record_id, last_record_hash) "
        "VALUES (1, ?, ?) ON CONFLICT(singleton) DO UPDATE SET "
        "last_record_id = excluded.last_record_id, last_record_hash = excluded.last_record_hash",
        (rows[-1]["id"], previous_hash),
    )


def verify_audit_chain(connection):
    rows = connection.execute(
        "SELECT id, actor_user_id, action, entity_type, entity_id, details_json, "
        "created_at, previous_hash, record_hash FROM audit_logs ORDER BY id"
    ).fetchall()
    previous_hash = GENESIS_HASH
    invalid_ids = []
    for row in rows:
        expected_hash = _record_hash(row, previous_hash)
        if row["previous_hash"] != previous_hash or row["record_hash"] != expected_hash:
            invalid_ids.append(row["id"])
        previous_hash = row["record_hash"] or ""
    head = connection.execute(
        "SELECT last_record_id, last_record_hash FROM audit_chain_state WHERE singleton = 1"
    ).fetchone()
    expected_id = rows[-1]["id"] if rows else 0
    expected_head = rows[-1]["record_hash"] if rows else GENESIS_HASH
    if head is None or head["last_record_id"] != expected_id or head["last_record_hash"] != expected_head:
        invalid_ids.append("chain_head")
    return {
        "valid": not invalid_ids,
        "records_checked": len(rows),
        "invalid_records": invalid_ids[:20],
        "verified_through_id": expected_id,
    }
