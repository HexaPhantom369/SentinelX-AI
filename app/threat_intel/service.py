from datetime import datetime, timedelta, timezone
import json
import uuid

from app.audit import append_audit_entry
from app.threat_intel.providers import ThreatIntelError, create_provider, validate_public_ip


CACHE_AGE = timedelta(hours=24)
MAX_LOOKUPS_PER_REQUEST = 20


def _evidence_ips(connection, subject_type=None, subject_id=None):
    if subject_type == "alert":
        rows = connection.execute(
            "SELECT DISTINCT e.source_ip FROM alert_events ae "
            "JOIN security_events e ON e.id = ae.event_id "
            "WHERE ae.alert_id = ? AND e.source_ip IS NOT NULL ORDER BY e.source_ip",
            (subject_id,),
        ).fetchall()
    elif subject_type == "incident":
        rows = connection.execute(
            "SELECT DISTINCT e.source_ip FROM incident_alerts ia "
            "JOIN alert_events ae ON ae.alert_id = ia.alert_id "
            "JOIN security_events e ON e.id = ae.event_id "
            "WHERE ia.incident_id = ? AND e.source_ip IS NOT NULL ORDER BY e.source_ip",
            (subject_id,),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT DISTINCT e.source_ip FROM alerts a "
            "JOIN alert_events ae ON ae.alert_id = a.id "
            "JOIN security_events e ON e.id = ae.event_id "
            "WHERE a.status IN ('New', 'Investigating', 'Escalated') "
            "AND e.source_ip IS NOT NULL ORDER BY e.source_ip LIMIT ?",
            (MAX_LOOKUPS_PER_REQUEST * 4,),
        ).fetchall()
    return [row["source_ip"] for row in rows]


def enrich_observed_ips(connection, provider_name, config, subject_type=None, subject_id=None):
    if subject_type not in (None, "alert", "incident") or (
        subject_type is None and subject_id is not None
    ) or (subject_type is not None and not subject_id):
        raise ThreatIntelError("Provide a valid alert or incident target.")
    ips = _evidence_ips(connection, subject_type, subject_id)
    provider = create_provider(provider_name, config)
    now = datetime.now(timezone.utc)
    results = []
    skipped = []
    seen = set()
    for candidate in ips:
        try:
            indicator = validate_public_ip(candidate)
        except ThreatIntelError as error:
            skipped.append({"indicator": candidate, "reason": str(error)})
            continue
        if indicator in seen:
            continue
        seen.add(indicator)
        if len(results) >= MAX_LOOKUPS_PER_REQUEST:
            skipped.append({"indicator": indicator, "reason": "Request lookup limit reached."})
            continue
        cached = connection.execute(
            "SELECT provider, status, reputation_score, summary_json, error_summary, looked_up_at "
            "FROM threat_intel_lookups WHERE indicator_value = ? AND provider = ? "
            "AND status = 'completed' ORDER BY looked_up_at DESC LIMIT 1",
            (indicator, provider_name),
        ).fetchone()
        if cached:
            try:
                cached_at = datetime.fromisoformat(cached["looked_up_at"].replace("Z", "+00:00"))
            except ValueError:
                cached_at = datetime.min.replace(tzinfo=timezone.utc)
            if now - cached_at < CACHE_AGE:
                results.append(
                    {
                        "indicator": indicator,
                        "provider": provider_name,
                        "status": "cached",
                        "score": cached["reputation_score"],
                        "summary": json.loads(cached["summary_json"]),
                        "looked_up_at": cached["looked_up_at"],
                    }
                )
                continue
        looked_up_at = now.isoformat()
        try:
            result = provider.lookup(indicator)
            status = "completed"
            score = result["score"]
            summary_json = json.dumps(result["summary"], sort_keys=True)
            error_summary = None
            results.append(
                {
                    "indicator": indicator,
                    "provider": provider_name,
                    "status": status,
                    "score": score,
                    "summary": result["summary"],
                    "looked_up_at": looked_up_at,
                }
            )
        except ThreatIntelError as error:
            status = "failed"
            score = None
            summary_json = "{}"
            error_summary = str(error)
            results.append(
                {
                    "indicator": indicator,
                    "provider": provider_name,
                    "status": status,
                    "score": None,
                    "summary": {},
                    "error": error_summary,
                    "looked_up_at": looked_up_at,
                }
            )
        connection.execute(
            "INSERT INTO threat_intel_lookups "
            "(id, indicator_value, provider, status, reputation_score, summary_json, "
            "error_summary, looked_up_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                indicator,
                provider_name,
                status,
                score,
                summary_json,
                error_summary,
                looked_up_at,
            ),
        )
    append_audit_entry(
        connection,
        "threat_intel.lookup_completed",
        "threat_intel",
        subject_id,
        {
            "provider": provider_name,
            "subject_type": subject_type or "active_alerts",
            "requested_indicators": len(seen),
            "completed": sum(item["status"] in {"completed", "cached"} for item in results),
            "failed": sum(item["status"] == "failed" for item in results),
            "skipped": len(skipped),
        },
        created_at=now.isoformat(),
    )
    connection.commit()
    return {
        "provider": provider_name,
        "results": results,
        "skipped": skipped,
        "disclosure": (
            "Globally routable source IP addresses from stored alert evidence were shared "
            "with the selected provider at your request."
        ),
    }
