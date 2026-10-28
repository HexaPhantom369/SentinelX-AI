import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


PROVIDER_NAMES = {"mock", "abuseipdb", "virustotal"}


class ThreatIntelError(ValueError):
    """A provider is unavailable or returned an unusable response."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _request_json(request, timeout=8):
    try:
        response = build_opener(_NoRedirect).open(request, timeout=timeout)
        with response:
            payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ThreatIntelError("Threat intelligence provider returned an oversized response.")
        return json.loads(payload.decode("utf-8"))
    except HTTPError as error:
        if error.code == 429:
            raise ThreatIntelError("Threat intelligence provider rate limit reached.") from error
        if error.code in (401, 403):
            raise ThreatIntelError("Threat intelligence provider rejected its configured API key.") from error
        raise ThreatIntelError(
            f"Threat intelligence provider returned HTTP {error.code}."
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise ThreatIntelError("Threat intelligence provider could not be reached.") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ThreatIntelError("Threat intelligence provider returned invalid JSON.") from error


class MockProvider:
    name = "mock"

    def lookup(self, indicator):
        return {
            "score": 0,
            "summary": {
                "provider_mode": "mock",
                "message": "Synthetic neutral result; no external lookup was performed.",
            },
        }


class AbuseIPDBProvider:
    name = "abuseipdb"

    def __init__(self, api_key, request_json=_request_json):
        if not api_key:
            raise ThreatIntelError("Set SENTINELX_ABUSEIPDB_API_KEY before enabling AbuseIPDB.")
        self.api_key = api_key
        self.request_json = request_json

    def lookup(self, indicator):
        query = urlencode({"ipAddress": indicator, "maxAgeInDays": 90})
        request = Request(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        response = self.request_json(request)
        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, dict):
            raise ThreatIntelError("AbuseIPDB response did not contain IP reputation data.")
        score = data.get("abuseConfidenceScore")
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise ThreatIntelError("AbuseIPDB returned an invalid reputation score.")
        summary = {
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
        }
        return {"score": score, "summary": summary}


class VirusTotalProvider:
    name = "virustotal"

    def __init__(self, api_key, request_json=_request_json):
        if not api_key:
            raise ThreatIntelError("Set SENTINELX_VIRUSTOTAL_API_KEY before enabling VirusTotal.")
        self.api_key = api_key
        self.request_json = request_json

    def lookup(self, indicator):
        request = Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        response = self.request_json(request)
        try:
            attributes = response["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            values = [
                stats[key]
                for key in ("harmless", "malicious", "suspicious", "undetected", "timeout")
            ]
        except (KeyError, TypeError) as error:
            raise ThreatIntelError("VirusTotal response did not contain IP reputation data.") from error
        if (
            any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values)
        ):
            raise ThreatIntelError("VirusTotal returned invalid analysis statistics.")
        total = sum(values)
        if malicious + suspicious > total:
            raise ThreatIntelError("VirusTotal returned invalid analysis statistics.")
        score = round(100 * (malicious + suspicious) / total) if total else 0
        return {
            "score": score,
            "summary": {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "community_reputation": attributes.get("reputation"),
            },
        }

    def lookup_file_hash(self, sha256):
        request = Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        try:
            response = self.request_json(request)
        except ThreatIntelError as error:
            if "HTTP 404" in str(error):
                return {
                    "score": 0,
                    "summary": {
                        "status": "not_found",
                        "malicious_engines": 0,
                        "suspicious_engines": 0,
                        "total_engines": 0,
                    },
                }
            raise
        try:
            attributes = response["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            counts = [
                stats[key]
                for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
            ]
        except (KeyError, TypeError) as error:
            raise ThreatIntelError("VirusTotal response did not contain file reputation data.") from error
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ThreatIntelError("VirusTotal returned invalid file-analysis statistics.")
        malicious, suspicious, *_ = counts
        total = sum(counts)
        score = round(100 * (malicious + suspicious) / total) if total else 0
        return {
            "score": score,
            "summary": {
                "status": "analyzed",
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "community_reputation": attributes.get("reputation"),
            },
        }


def create_provider(provider_name, config):
    if provider_name == "mock":
        return MockProvider()
    if provider_name == "abuseipdb":
        return AbuseIPDBProvider(config.get("ABUSEIPDB_API_KEY"))
    if provider_name == "virustotal":
        return VirusTotalProvider(config.get("VIRUSTOTAL_API_KEY"))
    raise ThreatIntelError("Threat intelligence provider is disabled or unsupported.")


def validate_public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ThreatIntelError("Only valid IPv4 or IPv6 addresses can be looked up.") from error
    if not address.is_global:
        raise ThreatIntelError("Only globally routable IP addresses can be sent to a provider.")
    return str(address)
