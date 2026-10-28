import ipaddress
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request

from app.analysis import analyze_subject
from app.analysis.service import AnalysisTargetError
from app.analysis.gemini import GeminiTriageError, triage_with_gemini
from app.audit import append_audit_entry
from app.db import get_db


analysis_api = Blueprint("analysis_api", __name__)


def _require_local_intent():
    try:
        if not ipaddress.ip_address(request.remote_addr).is_loopback:
            return jsonify(error={"code": "loopback_required", "message": "Analysis is restricted to local requests."}), 403
    except (TypeError, ValueError):
        return jsonify(error={"code": "loopback_required", "message": "Analysis is restricted to local requests."}), 403
    if request.headers.get("X-SentinelX-Request") != "1":
        return jsonify(error={"code": "request_intent_required", "message": "Send the SentinelX UI intent header."}), 403
    origin = request.headers.get("Origin")
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc.casefold() != request.host.casefold() or parsed.scheme not in {"http", "https"}:
            return jsonify(error={"code": "cross_origin_request", "message": "Cross-origin requests are not accepted."}), 403
    return None


@analysis_api.post("/api/analysis/<subject_type>/<subject_id>")
def analyze(subject_type, subject_id):
    rejected = _require_local_intent()
    if rejected:
        return rejected
    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict) or set(payload) - {"external_ai"}:
        return jsonify(error={"code": "invalid_request", "message": "Only the optional external_ai boolean is accepted."}), 400
    external_ai = payload.get("external_ai", False)
    if not isinstance(external_ai, bool):
        return jsonify(error={"code": "invalid_request", "message": "external_ai must be a boolean."}), 400
    try:
        result = analyze_subject(get_db(), subject_type, subject_id)
    except AnalysisTargetError as error:
        return jsonify(error={"code": "analysis_unavailable", "message": str(error)}), 422
    if external_ai:
        api_key = current_app.config.get("GEMINI_API_KEY")
        if not api_key:
            result["ai_fallback_reason"] = "GEMINI_API_KEY is not configured; deterministic local analysis is shown."
        else:
            try:
                triage = triage_with_gemini(result, api_key)
            except GeminiTriageError:
                current_app.logger.warning("Gemini triage failed; using local evidence analysis.")
                result["ai_fallback_reason"] = "Gemini was unavailable or returned invalid data; deterministic local analysis is shown."
                append_audit_entry(
                    get_db(),
                    "ai_solve.gemini_fallback",
                    subject_type,
                    subject_id,
                    {"provider": "Google Gemini", "fallback": "local_deterministic"},
                )
            else:
                result["generative_analysis"] = triage
                result["engine"] = "gemini_generative_triage"
                result["model_called"] = True
                append_audit_entry(
                    get_db(),
                    "ai_solve.gemini_triage_requested",
                    subject_type,
                    subject_id,
                    {
                        "provider": "Google Gemini",
                        "model": triage["model"],
                        "event_count": result["evidence"]["event_count"],
                        "raw_command_line_shared": False,
                        "file_contents_shared": False,
                    },
                )
        get_db().commit()
    return jsonify(data=result)
