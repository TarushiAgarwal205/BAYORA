import os
from pathlib import Path


HOST = os.environ.get("BAYORA_HOST", "127.0.0.1")
PORT = int(os.environ.get("BAYORA_PORT", "8000"))
APP_ENV = os.environ.get("APP_ENV", "development")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DB_PATH = Path(
    os.environ.get("BAYORA_AUDIT_DB", str(PROJECT_ROOT / "data" / "bayora_audit.sqlite3"))
)
if not AUDIT_DB_PATH.is_absolute():
    AUDIT_DB_PATH = PROJECT_ROOT / AUDIT_DB_PATH
BLUE_SERVICE_URL = os.environ.get("BAYORA_BLUE_SERVICE_URL", "http://127.0.0.1:8001")
BLUE_SERVICE_TOKEN = os.environ.get("BAYORA_BLUE_SERVICE_TOKEN", "")
