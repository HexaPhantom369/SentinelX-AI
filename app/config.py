import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SENTINELX_SECRET_KEY")
    DATABASE = os.environ.get(
        "SENTINELX_DATABASE",
        str(PROJECT_ROOT / "instance" / "sentinelx.db"),
    )
    DEBUG = os.environ.get("SENTINELX_DEBUG", "0").lower() in {"1", "true", "yes"}
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SENTINELX_ENV", "development").lower() == "production"
    ABUSEIPDB_API_KEY = os.environ.get("SENTINELX_ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY = os.environ.get("SENTINELX_VIRUSTOTAL_API_KEY")
    AGENT_TOKEN = os.environ.get("SENTINELX_AGENT_TOKEN")
