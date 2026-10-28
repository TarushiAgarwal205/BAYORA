from urllib.parse import urlsplit


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
PROVIDER_HOST = urlsplit(OPENROUTER_URL).hostname
PROVIDER_PORT = 443
PROVIDER_AUTHORITY = f"{PROVIDER_HOST}:{PROVIDER_PORT}"
