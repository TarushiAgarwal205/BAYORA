import os
from pathlib import Path
import shlex


HOST = os.environ.get("BAYORA_HOST", "127.0.0.1")
PORT = int(os.environ.get("BAYORA_PORT", "8000"))
APP_ENV = os.environ.get("APP_ENV", "development")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("BAYORA_DATA_DIR", str(PROJECT_ROOT / "data")))
AUDIT_DB_PATH = Path(
    os.environ.get("BAYORA_AUDIT_DB", str(PROJECT_ROOT / "data" / "bayora_audit.sqlite3"))
)
if not AUDIT_DB_PATH.is_absolute():
    AUDIT_DB_PATH = PROJECT_ROOT / AUDIT_DB_PATH
SECURITY_CONFIG_PATH = Path(
    os.environ.get("BAYORA_SECURITY_CONFIG", str(DATA_DIR / "security-config.json"))
)
if not SECURITY_CONFIG_PATH.is_absolute():
    SECURITY_CONFIG_PATH = PROJECT_ROOT / SECURITY_CONFIG_PATH
BLUE_SERVICE_URL = os.environ.get("BAYORA_BLUE_SERVICE_URL", "http://127.0.0.1:8001")
BLUE_SERVICE_TOKEN = os.environ.get("BAYORA_BLUE_SERVICE_TOKEN", "")


def _read_local_env(names, env_path=None):
    """Read selected simple .env assignments without logging their values."""
    values = {}
    path = Path(env_path) if env_path is not None else PROJECT_ROOT / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        if tokens and tokens[0] == "export":
            tokens = tokens[1:]
        for token in tokens:
            key, separator, value = token.partition("=")
            if separator and key in names:
                values[key] = value
    return values


_LOCAL_CONFIG_ENV = _read_local_env({
    "BAYORA_OPENROUTER_API_KEY",
    "BAYORA_LLM_MODEL",
    "BAYORA_GATEWAY_RED_TOKEN",
    "BAYORA_GATEWAY_BLUE_TOKEN",
    "BAYORA_GATEWAY_ADMIN_TOKEN",
})
OPENROUTER_API_KEY = os.environ.get(
    "BAYORA_OPENROUTER_API_KEY", _LOCAL_CONFIG_ENV.get("BAYORA_OPENROUTER_API_KEY", "")
)
LLM_MODEL = os.environ.get(
    "BAYORA_LLM_MODEL", _LOCAL_CONFIG_ENV.get("BAYORA_LLM_MODEL", "openrouter/free")
)
GATEWAY_CALLER_TOKENS = {
    "red": os.environ.get(
        "BAYORA_GATEWAY_RED_TOKEN", _LOCAL_CONFIG_ENV.get("BAYORA_GATEWAY_RED_TOKEN", "")
    ),
    "blue": os.environ.get(
        "BAYORA_GATEWAY_BLUE_TOKEN", _LOCAL_CONFIG_ENV.get("BAYORA_GATEWAY_BLUE_TOKEN", "")
    ),
    "admin": os.environ.get(
        "BAYORA_GATEWAY_ADMIN_TOKEN", _LOCAL_CONFIG_ENV.get("BAYORA_GATEWAY_ADMIN_TOKEN", "")
    ),
}
